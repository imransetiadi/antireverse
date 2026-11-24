// Slice 18h: the kill-switch drill (gate criterion gate-kill-switch-drill). Every switch that exists today is thrown
// and taken back, over HTTP, and the effect is observed where it matters: at a real Shield in front of a real handler,
// or at the Campaign routes. on → effect → off → normal again, and what the API records of each: an audit entry for
// every switch that writes one, the switch's own state where it writes none (lifting the Campaign kill switch), and
// nothing for the two that live in a deployment's environment. Local: one API process, one Shield, loopback. Not a
// drill in staging.
//
// Switches the specification names that do not exist in code, and so are not drilled: App safe mode, global safe mode
// and the Guard kill switch (OPERATION §15).
import http from "node:http";
import type { AddressInfo } from "node:net";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  AuditExportLineSchema,
  BLOCK_RESPONSE_BODY,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  ListCampaignsResponseSchema,
  PolicyResponseSchema,
  type PolicyRuleInput,
  ProblemSchema,
  ProveOperatorStateSchema,
} from "@antireverse/protocol";
import { createShield, type Shield } from "@antireverse/shield-node";
import express from "express";
import { afterAll, afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import {
  auditOf,
  call,
  campaignBody,
  createCampaign,
  type Harness,
  OPS_TOKEN,
  type Org,
  ops,
  readCampaign,
  runCampaign,
  scripted,
  setupOrg,
  silent,
  startHarness,
  until,
} from "./fixtures/campaign-harness.ts";

/** PB-16: a published Policy is applied within 15 seconds. */
const APPLIED_BUDGET_MS = 15_000;
const ADMIN_RULE: PolicyRuleInput = { name: "Admin area", path: "/api/admin/**", methods: [], mode: "enforce" };

interface Customer {
  shield: Shield;
  url: string;
  handled: string[];
  close(): Promise<void>;
}

/** A customer's server: Express behind a real Shield that polls the API for its Policy. */
async function startCustomer(
  api: RunningApi,
  shieldKey: string,
  options: { disabled?: boolean } = {},
): Promise<Customer> {
  const signingKey = (await (await fetch(`${api.url}/v1/signing-key`)).json()) as { public_key: string };
  const shield = createShield({
    key: shieldKey,
    endpoint: api.url,
    policyPublicKey: signingKey.public_key,
    flushIntervalMs: 200,
    // The default is 5 s; the drill has many publishes to wait for. The poll itself is the real one.
    policyPollIntervalMs: 250,
    logger: { warn() {} },
    ...options,
  });
  const handled: string[] = [];
  const app = express();
  app.use(shield.express());
  app.get("/api/admin/reports", (_req, res) => {
    handled.push("/api/admin/reports");
    res.json({ reports: [] });
  });
  app.get("/api/products/:id", (req, res) => {
    handled.push("/api/products/:id");
    res.json({ id: req.params.id });
  });
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return {
    shield,
    url: `http://127.0.0.1:${(server.address() as AddressInfo).port}`,
    handled,
    close: async () => {
      await shield.close();
      server.closeAllConnections();
      await new Promise<void>((resolve) => server.close(() => resolve()));
    },
  };
}

async function untilApplied(shield: Shield, version: number): Promise<void> {
  const started = Date.now();
  while (shield.stats().policyVersion !== version) {
    if (Date.now() - started > APPLIED_BUDGET_MS) throw new Error(`version ${version} not applied in time`);
    await new Promise((resolve) => setTimeout(resolve, 25));
  }
}

describe("kill-switch drill: the switches a customer throws, as Shield sees them", () => {
  let api: RunningApi;
  let customer: Customer;
  let adminKey: string;
  let shieldKey: string;
  let appId: string;
  let organizationId: string;
  let enforced: number;

  const policy = (rest = "") => `/v1/apps/${appId}/policies/development${rest}`;
  /** Publishes and waits until the customer's Shield applies the version. `reason: null`: without a reason. */
  const publish = async (rules: PolicyRuleInput[], reason?: string | null): Promise<number> => {
    const response = await call(api, policy(), {
      method: "PUT",
      key: adminKey,
      body: { rules },
      ...(reason === undefined ? {} : { reason }),
    });
    expect(response.status, await response.clone().text()).toBe(201);
    const { version } = PolicyResponseSchema.parse(await response.json()).policy;
    await untilApplied(customer.shield, version);
    return version;
  };
  /** One request to the customer's server: the status, and whether the customer's own handler ran. */
  const request = async (path: string): Promise<{ status: number; handled: boolean; body: string }> => {
    const before = customer.handled.length;
    const response = await fetch(`${customer.url}${path}`);
    return { status: response.status, handled: customer.handled.length > before, body: await response.text() };
  };
  const policyAudit = async (): Promise<ReturnType<typeof AuditExportLineSchema.parse>[]> => {
    const exported = await (await call(api, "/v1/audit/export", { key: adminKey })).text();
    return exported
      .trim()
      .split("\n")
      .slice(1)
      .map((line) => AuditExportLineSchema.parse(JSON.parse(line)))
      .filter((entry) => entry.target.kind === "policy");
  };

  beforeAll(async () => {
    api = await startApi({ logger: silent, ops: { token: OPS_TOKEN, webhook: null } });
    const organization = CreateOrganizationResponseSchema.parse(
      await (await call(api, "/v1/organizations", { method: "POST", body: { name: "Acme" } })).json(),
    );
    adminKey = organization.admin_key.key;
    organizationId = organization.organization.id;
    const created = CreateAppResponseSchema.parse(
      await (await call(api, "/v1/apps", { method: "POST", key: adminKey, body: { name: "shop-web" } })).json(),
    );
    appId = created.app.id;
    shieldKey = created.shield_key.key;
    customer = await startCustomer(api, shieldKey);
  });

  afterAll(async () => {
    await customer?.close();
    await api?.close();
  });

  afterEach(() => {
    vi.unstubAllEnvs();
  });

  it("Rule back to monitor: the block stops at once, the Rule keeps observing, and promoting it blocks again", async () => {
    // Normal: the Rule enforces.
    await publish([ADMIN_RULE], "Protect the admin area");
    const blocked = await request("/api/admin/reports");
    expect(blocked).toMatchObject({ status: 403, handled: false });
    expect(blocked.body).toBe(BLOCK_RESPONSE_BODY);

    // The switch: the same Rule in Monitor mode. It needs no reason: it takes protection away, it is the fast move.
    const monitored = await publish([{ ...ADMIN_RULE, mode: "monitor" }], null);
    expect(await request("/api/admin/reports")).toMatchObject({ status: 200, handled: true });
    expect(customer.shield.stats().policyVersion).toBe(monitored);

    // Back: promoting the Rule again needs a reason, and blocks again.
    const refused = await call(api, policy(), {
      method: "PUT",
      key: adminKey,
      body: { rules: [ADMIN_RULE] },
      reason: null,
    });
    expect(refused.status).toBe(400);
    expect(await request("/api/admin/reports")).toMatchObject({ status: 200, handled: true });
    enforced = await publish([ADMIN_RULE], "False alarm: enforce again");
    expect(await request("/api/admin/reports")).toMatchObject({ status: 403, handled: false });

    expect((await policyAudit()).map((entry) => [entry.action, entry.reason])).toEqual([
      ["policy.rule.promote", "Protect the admin area"],
      ["policy.publish", undefined],
      ["policy.rule.promote", "False alarm: enforce again"],
    ]);
    for (const entry of await policyAudit()) {
      expect(entry).toMatchObject({ organization_id: organizationId, actor: { kind: "admin_key" }, app_id: appId });
    }
  });

  it("Policy roll back: a version that blocks legitimate traffic is undone, and the earlier Rules hold again", async () => {
    // Normal: the catalogue is served, the admin area is blocked.
    expect(await request("/api/products/7")).toMatchObject({ status: 200, handled: true });

    // A bad change goes out: it blocks the catalogue.
    const bad = await publish(
      [ADMIN_RULE, { name: "Catalogue", path: "/api/products/**", methods: [], mode: "enforce" }],
      "Block scraping of the catalogue",
    );
    expect(await request("/api/products/7")).toMatchObject({ status: 403, handled: false });

    // The switch: roll back to the version before it.
    const rolled = await call(api, policy("/rollback"), {
      method: "POST",
      key: adminKey,
      body: { version: enforced },
      reason: "Customers cannot see products",
    });
    expect(rolled.status, await rolled.clone().text()).toBe(201);
    const { version } = PolicyResponseSchema.parse(await rolled.json()).policy;
    expect(version).toBe(bad + 1);
    await untilApplied(customer.shield, version);

    // Normal again: the catalogue is served, and the admin area is still blocked.
    expect(await request("/api/products/7")).toMatchObject({ status: 200, handled: true });
    expect(await request("/api/admin/reports")).toMatchObject({ status: 403, handled: false });

    const entry = (await policyAudit()).at(-1);
    expect(entry).toMatchObject({
      action: "policy.rollback",
      actor: { kind: "admin_key" },
      reason: "Customers cannot see products",
    });
    expect(entry?.summary).toContain(`back to the Rules of version ${enforced}`);
  });

  it("AR_SHIELD_DISABLED=1: a server deployed with it serves everything, and one deployed without it blocks again", async () => {
    // Normal: the running server blocks the admin area.
    expect(await request("/api/admin/reports")).toMatchObject({ status: 403, handled: false });
    const applied = customer.shield.stats().policyVersion;

    // The switch is read when Shield is created: the customer deploys with the variable set.
    vi.stubEnv("AR_SHIELD_DISABLED", "1");
    const off = await startCustomer(api, shieldKey);
    try {
      expect(off.shield.stats().disabledReason).toContain("AR_SHIELD_DISABLED");
      // Long enough for an enabled Shield to have fetched and applied the Policy; this one never does.
      await new Promise((resolve) => setTimeout(resolve, 500));
      const response = await fetch(`${off.url}/api/admin/reports`);
      expect(response.status).toBe(200);
      expect(off.handled).toEqual(["/api/admin/reports"]);
      expect(off.shield.stats().policyVersion).toBe(0);
    } finally {
      await off.close();
    }

    // Back: deployed without the variable, the same key and the same Policy block again.
    vi.stubEnv("AR_SHIELD_DISABLED", "");
    const on = await startCustomer(api, shieldKey);
    try {
      expect(on.shield.stats().disabledReason).toBeNull();
      await untilApplied(on.shield, applied);
      const response = await fetch(`${on.url}/api/admin/reports`);
      expect(response.status).toBe(403);
      expect(on.handled).toEqual([]);
    } finally {
      await on.close();
    }
    // The switch lives in the customer's deployment: the API saw no administrative action, so there is no entry.
    expect((await policyAudit()).at(-1)?.action).toBe("policy.rollback");
  });

  it("Shield's disabled option: the same switch in code, on and off", async () => {
    expect(await request("/api/admin/reports")).toMatchObject({ status: 403, handled: false });
    const applied = customer.shield.stats().policyVersion;

    const off = await startCustomer(api, shieldKey, { disabled: true });
    try {
      expect(off.shield.stats().disabledReason).toEqual(expect.any(String));
      await new Promise((resolve) => setTimeout(resolve, 500));
      expect((await fetch(`${off.url}/api/admin/reports`)).status).toBe(200);
      expect(off.handled).toEqual(["/api/admin/reports"]);
      expect(off.shield.stats().policyVersion).toBe(0);
    } finally {
      await off.close();
    }

    // Back — and the option wins over the variable: `disabled: false` enforces even where AR_SHIELD_DISABLED=1 is set.
    vi.stubEnv("AR_SHIELD_DISABLED", "1");
    const on = await startCustomer(api, shieldKey, { disabled: false });
    try {
      expect(on.shield.stats().disabledReason).toBeNull();
      await untilApplied(on.shield, applied);
      expect((await fetch(`${on.url}/api/admin/reports`)).status).toBe(403);
      expect(on.handled).toEqual([]);
    } finally {
      await on.close();
    }
  });
});

describe("kill-switch drill: the operator's switches for Pentest Campaigns", () => {
  let h: Harness;
  const slow: NonNullable<Harness["target"]["intercept"]> = (_req, res) => {
    setTimeout(() => res.end("ok"), 150).unref();
  };
  /** A Campaign of `org` that is sending requests, slowly, until something stops it. */
  const startLong = async (org: Org) => {
    h.target.token = org.token;
    h.target.intercept = slow;
    h.engine.run = scripted(async ({ request }) => {
      for (let i = 0; i < 40; i++) await request({ method: "GET", path: "/" });
    });
    const campaign = await createCampaign(h, org);
    await until(() => h.target.probes().length >= 1, "a request at the target");
    return campaign;
  };
  /** Back to the stand-in engine and a target that answers at once. */
  const calm = (org: Org) => {
    h.engine.run = null;
    h.target.intercept = null;
    h.target.token = org.token;
  };
  const operatorEntries = async (org: Org) =>
    (await auditOf(h, org)).filter((entry) => entry.actor.kind === "operator");

  beforeAll(async () => {
    h = await startHarness();
  });

  afterAll(async () => {
    await h?.close();
  });

  it("the Campaign kill switch: the running Campaign stops, none can be created, and after enabling one runs again", async () => {
    const acme = await setupOrg(h, "Drill kill");
    // Normal: a Campaign runs to its end.
    calm(acme);
    expect((await runCampaign(h, acme, "passive")).status).toBe("completed");

    // The switch.
    h.target.reset();
    const running = await startLong(acme);
    const state = async () => ProveOperatorStateSchema.parse(await (await ops(h.api, "/v1/ops/prove")).json());
    expect(await state()).toMatchObject({ killed: false, killed_at: null });
    const killed = await ops(h.api, "/v1/ops/prove/kill", { reason: "Drill: kill switch" });
    expect(ProveOperatorStateSchema.parse(await killed.json())).toMatchObject({ killed: true, stopped: 1, active: 0 });
    // The switch itself records when it was thrown.
    expect(await state()).toMatchObject({ killed: true, killed_at: new Date(h.clock.ms).toISOString() });
    await h.api.campaigns.idle();
    const atKill = h.target.probes().length;
    expect(await readCampaign(h, acme, running.id)).toMatchObject({ status: "stopped", end_reason: "operator_kill" });
    const refused = await call(h.api, "/v1/campaigns", { method: "POST", key: acme.key, body: campaignBody(acme) });
    expect(refused.status).toBe(403);
    expect(ProblemSchema.parse(await refused.json()).type).toMatch(/campaigns-stopped$/);
    expect(
      ListCampaignsResponseSchema.parse(await (await call(h.api, "/v1/campaigns", { key: acme.key })).json()).blocked,
    ).toBe("operator_kill");
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(h.target.probes()).toHaveLength(atKill);
    // The stop is in the affected Organization's audit chain: the operator as the actor (no key), with the reason.
    const stopEntries = await operatorEntries(acme);
    expect(stopEntries).toMatchObject([
      {
        organization_id: acme.id,
        actor: { kind: "operator" },
        action: "campaign.operator_kill",
        target: { kind: "campaign", id: running.id },
        reason: "Drill: kill switch",
      },
    ]);
    expect(stopEntries[0]?.actor.key_id).toBeUndefined();

    // Back. Lifting the switch writes no audit entry (no Organization is affected by it): what records it is the
    // switch's own state, read back here, and the API's log.
    const enabled = await ops(h.api, "/v1/ops/prove/enable", { reason: "Drill over" });
    expect(ProveOperatorStateSchema.parse(await enabled.json())).toMatchObject({ killed: false, active: 0 });
    expect(await state()).toMatchObject({ killed: false, killed_at: null });
    expect(await operatorEntries(acme)).toHaveLength(1);
    calm(acme);
    expect((await runCampaign(h, acme, "passive")).status).toBe("completed");
    // What the switch stopped stays stopped.
    expect((await readCampaign(h, acme, running.id)).status).toBe("stopped");
  });

  it("suspending one Organization: its Campaign stops and none can be created; after the resume one runs again", async () => {
    const acme = await setupOrg(h, "Drill suspend");
    h.target.reset();
    const running = await startLong(acme);

    // The switch.
    const suspended = await ops(h.api, `/v1/ops/prove/organizations/${acme.id}/suspend`, {
      reason: "Drill: suspension",
    });
    expect(ProveOperatorStateSchema.parse(await suspended.json())).toMatchObject({
      killed: false,
      stopped: 1,
      suspended: [{ organization_id: acme.id }],
    });
    await h.api.campaigns.idle();
    expect(await readCampaign(h, acme, running.id)).toMatchObject({
      status: "stopped",
      end_reason: "organization_suspended",
    });
    const refused = await call(h.api, "/v1/campaigns", { method: "POST", key: acme.key, body: campaignBody(acme) });
    expect(refused.status).toBe(403);
    expect(ProblemSchema.parse(await refused.json()).type).toMatch(/campaigns-suspended$/);

    // Back.
    const resumed = await ops(h.api, `/v1/ops/prove/organizations/${acme.id}/resume`, { reason: "Drill over" });
    expect(ProveOperatorStateSchema.parse(await resumed.json()).suspended).toEqual([]);
    calm(acme);
    expect((await runCampaign(h, acme, "passive")).status).toBe("completed");

    const entries = await operatorEntries(acme);
    expect(entries.map((entry) => [entry.action, entry.target.kind, entry.reason])).toEqual([
      ["campaign.operator_suspend", "organization", "Drill: suspension"],
      ["campaign.operator_kill", "campaign", "Drill: suspension"],
      ["campaign.operator_resume", "organization", "Drill over"],
    ]);
    for (const entry of entries) {
      expect(entry).toMatchObject({ organization_id: acme.id, actor: { kind: "operator" } });
      expect(entry.actor.key_id).toBeUndefined();
    }
  });
});

describe("kill-switch drill: the service flag of Pentest Campaigns", () => {
  afterEach(() => {
    vi.unstubAllEnvs();
  });

  /**
   * An API whose Campaigns are on or off by the environment alone, as outside tests, and one Organization that has
   * everything a Campaign needs. Answers what happened when it asked for one.
   */
  const withFlag = async (value: string): Promise<{ enabled: boolean; status: string; problem: string | null }> => {
    vi.stubEnv("AR_PROVE_CAMPAIGNS", value);
    const h = await startHarness({ enabled: "environment" });
    try {
      const org = await setupOrg(h, "Flag");
      const list = ListCampaignsResponseSchema.parse(
        await (await call(h.api, "/v1/campaigns", { key: org.key })).json(),
      );
      const created = await call(h.api, "/v1/campaigns", {
        method: "POST",
        key: org.key,
        body: campaignBody(org, "passive"),
      });
      if (created.status !== 202) {
        return {
          enabled: list.enabled,
          status: String(created.status),
          problem: ProblemSchema.parse(await created.json()).type,
        };
      }
      const { id } = ((await created.json()) as { campaign: { id: string } }).campaign;
      await h.api.campaigns.idle();
      return { enabled: list.enabled, status: (await readCampaign(h, org, id)).status, problem: null };
    } finally {
      await h.close();
    }
  };

  it("AR_PROVE_CAMPAIGNS: without it a Campaign is refused; with it one is created and runs; without it again, refused", async () => {
    const off = await withFlag("");
    expect(off).toMatchObject({ enabled: false, status: "403" });
    expect(off.problem).toMatch(/campaigns-disabled$/);

    expect(await withFlag("1")).toEqual({ enabled: true, status: "completed", problem: null });

    const offAgain = await withFlag("0");
    expect(offAgain).toMatchObject({ enabled: false, status: "403" });
    expect(offAgain.problem).toMatch(/campaigns-disabled$/);
  });
});
