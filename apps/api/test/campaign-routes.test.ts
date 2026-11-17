import {
  CAMPAIGN_LIMITS,
  type Campaign,
  CampaignResponseSchema,
  campaignAuthorisationPhrase,
  confirmationPhrase,
  type Intensity,
  ListCampaignsResponseSchema,
  ProveOperatorStateSchema,
  TargetResponseSchema,
} from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import type { CampaignService } from "../src/campaign/runner.ts";
import type { Fetcher, Resolver } from "../src/prove/verify.ts";
import { auditEntriesAfter } from "../src/stores/audit.ts";
import { claimCampaign, endCampaign } from "../src/stores/campaigns.ts";
import { bearer, createOrganization, expectProblem, json, makeTestApi, type TestApi, withReason } from "./helpers.ts";

// Slice 15a: creating, reading and stopping Campaigns over the routes, with a runner that takes nothing (a created
// Campaign stays queued), and the operator's switches. What a running Campaign does is the e2e suites' subject.

const T0 = Date.parse("2026-11-16T10:00:00.000Z"); // a Monday, 10:00 UTC
const DAY = 86_400_000;
const HOST = "shop.acme-shop.io";
const OPS = "ops-token-for-campaign-route-tests-0001";
const type = (kind: string) => `https://antireverse.dev/problems/${kind}`;

describe("Campaign routes", () => {
  let api: TestApi;
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  const txt = new Map<string, string[][]>();
  const resolver: Resolver = {
    async txt(name) {
      const records = txt.get(name);
      if (records === undefined) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
      return records;
    },
    async addresses() {
      throw new Error("not used");
    },
  };
  const fetcher: Fetcher = async () => ({ ok: false, reason: "status" });
  const woken: number[] = [];
  const aborted: string[] = [];
  /** Campaigns the (stand-in) runner says it is running in this process. */
  const activeHere = new Set<string>();
  const service: CampaignService & { enabled: boolean } = {
    enabled: true,
    wake: () => void woken.push(1),
    abort: async (id) => void aborted.push(id),
    isActive: (id) => activeHere.has(id),
    cut() {},
    operatorStop: async () => 0,
    activeCount: async () => 0,
  };

  interface Org {
    id: string;
    admin: string;
    targetId: string;
  }
  let n = 0;

  const post = (org: Org, path: string, body: unknown, headers: Record<string, string> = withReason()) =>
    api.app.request(path, json(body, { ...bearer(org.admin), ...headers }));
  const get = (org: Org, path: string) => api.app.request(path, { headers: bearer(org.admin) });
  const body = (org: Org, overrides: Record<string, unknown> = {}) => ({
    target_id: org.targetId,
    intensity: "passive",
    confirm: campaignAuthorisationPhrase(HOST),
    staging: true,
    ...overrides,
  });

  async function addTarget(org: Pick<Org, "admin">, host: string, verify = true): Promise<string> {
    const added = TargetResponseSchema.parse(
      await (await api.app.request("/v1/targets", json({ host }, bearer(org.admin)))).json(),
    );
    if (verify) {
      txt.set(added.verification.dns_name, [[added.verification.dns_value]]);
      await api.app.request(`/v1/targets/${added.target.id}/verify`, { method: "POST", headers: bearer(org.admin) });
    }
    return added.target.id;
  }

  async function sign(
    org: Pick<Org, "admin">,
    scope: string[],
    intensity: Intensity = "safe-active",
    exclusions: string[] = [],
  ): Promise<void> {
    const res = await api.app.request(
      "/v1/rules-of-engagement",
      json(
        {
          scope,
          exclusions,
          intensity,
          window: { days: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"], from: "00:00", to: "24:00" },
          contacts: ["security@acme.test"],
          confirm: confirmationPhrase(intensity),
        },
        { ...bearer(org.admin), ...withReason() },
      ),
    );
    expect(res.status).toBe(201);
  }

  /** A new Organization with the host verified and, unless told otherwise, Rules of Engagement that cover it. */
  async function organization(options: { rules?: Intensity | null } = {}): Promise<Org> {
    const created = await createOrganization(api, `Org ${++n}`);
    const org = { id: created.organization.id, admin: created.admin_key.key, targetId: "" };
    org.targetId = await addTarget(org, HOST);
    if (options.rules !== null) await sign(org, [org.targetId], options.rules ?? "safe-active");
    return org;
  }

  async function create(org: Org, overrides: Record<string, unknown> = {}): Promise<Campaign> {
    const res = await post(org, "/v1/campaigns", body(org, overrides));
    expect(res.status, await res.clone().text()).toBe(202);
    return CampaignResponseSchema.parse(await res.json()).campaign;
  }
  const finish = (org: Org, id: string) =>
    api.db.tx({ organizationId: org.id }, (q) =>
      // Fourth review (D-108): a queued Campaign cannot be written as completed; it ends as stopped here.
      endCampaign(q, id, { reason: "owner_stop", started: false, checks: null, at: now() }),
    );
  const entries = (org: Org) => api.db.tx({ organizationId: org.id }, (q) => auditEntriesAfter(q, 0, 1000));

  beforeAll(async () => {
    api = await makeTestApi({ now, prove: { resolver, fetcher }, campaigns: service, opsToken: OPS });
  });
  afterAll(async () => {
    await api.close();
  });

  it("creates a queued Campaign bound to the current Rules of Engagement, and wakes the runner", async () => {
    const org = await organization();
    const before = woken.length;
    const campaign = await create(org, { intensity: "safe-active" });
    expect(campaign).toMatchObject({
      target_id: org.targetId,
      host: HOST,
      intensity: "safe-active",
      status: "queued",
      staging_declared: true,
      engine: { name: "stand-in", version: "1", model: "stand-in" },
      created_at: now().toISOString(),
    });
    expect(woken.length).toBe(before + 1);
    expect((await entries(org)).at(-1)).toMatchObject({
      action: "campaign.create",
      actor: { kind: "admin_key", key_id: campaign.created_by },
      target: { kind: "campaign", id: campaign.id },
      reason: "Test change",
    });
    expect(
      CampaignResponseSchema.parse(await (await get(org, `/v1/campaigns/${campaign.id}`)).json()).campaign,
    ).toEqual(campaign);
  });

  it("refuses without a reason, the typed phrase, the staging declaration, or with intensity full", async () => {
    const org = await organization();
    const before = (await entries(org)).length;
    expect((await expectProblem(await post(org, "/v1/campaigns", body(org), {}), 400)).type).toBe(
      type("reason-required"),
    );
    const invalid: [Record<string, unknown>, string][] = [
      [{ confirm: "I authorise a test" }, "confirm"],
      [{ confirm: "i authorise a test of shop.acme-shop.io" }, "confirm"],
      [{ confirm: campaignAuthorisationPhrase("other.acme-shop.io") }, "confirm"],
      [{ confirm: undefined }, "confirm"],
      [{ staging: false }, "staging"],
      [{ staging: undefined }, "staging"],
      [{ staging: "yes" }, "staging"],
      [{ intensity: "full" }, "intensity"],
      [{ intensity: undefined }, "intensity"],
      [{ target_id: "tgt_ffffffffffffffffffffffff" }, "target_id"],
      [{ target_id: "shop.acme-shop.io" }, "target_id"],
    ];
    for (const [overrides, path] of invalid) {
      const problem = await expectProblem(await post(org, "/v1/campaigns", body(org, overrides)), 400);
      expect({ overrides, paths: problem.errors?.map((error) => error.path) }).toEqual({ overrides, paths: [path] });
    }
    expect(await entries(org)).toHaveLength(before);
    expect(ListCampaignsResponseSchema.parse(await (await get(org, "/v1/campaigns")).json()).campaigns).toEqual([]);
  });

  it("refuses a target that is not verified, not in scope, or without current Rules of Engagement", async () => {
    const none = await organization({ rules: null });
    expect((await expectProblem(await post(none, "/v1/campaigns", body(none)), 409)).reason).toBe("campaign-no-rules");

    const org = await organization();
    // A pending target, and a verified one the Rules do not name.
    const pending = await addTarget(org, "pending.acme-shop.io", false);
    const extra = await addTarget(org, "extra.acme-shop.io");
    const phrase = (host: string) => ({ confirm: campaignAuthorisationPhrase(host) });
    expect(
      (
        await expectProblem(
          await post(org, "/v1/campaigns", body(org, { target_id: pending, ...phrase("pending.acme-shop.io") })),
          409,
        )
      ).reason,
    ).toBe("campaign-target-not-verified");
    expect(
      (
        await expectProblem(
          await post(org, "/v1/campaigns", body(org, { target_id: extra, ...phrase("extra.acme-shop.io") })),
          409,
        )
      ).reason,
    ).toBe("campaign-target-out-of-scope");

    // More than the signed intensity.
    const passive = await organization({ rules: "passive" });
    expect(
      (await expectProblem(await post(passive, "/v1/campaigns", body(passive, { intensity: "safe-active" })), 409))
        .reason,
    ).toBe("campaign-intensity-exceeds");
    expect((await create(passive)).intensity).toBe("passive");

    // A target whose last ownership check is older than 26 hours.
    const saved = clock.ms;
    try {
      clock.ms = T0 + 27 * 3_600_000;
      expect((await expectProblem(await post(org, "/v1/campaigns", body(org)), 409)).reason).toBe(
        "campaign-target-not-verified",
      );
    } finally {
      clock.ms = saved;
    }
  });

  it("review L3: refuses at once when the Rules of Engagement exclude the ownership file's path", async () => {
    for (const exclusions of [["/.well-known"], ["/.well-known/airverse-verification.txt"], ["/"], ["/.WELL-KNOWN"]]) {
      const org = await organization({ rules: null });
      await sign(org, [org.targetId], "safe-active", exclusions);
      const problem = await expectProblem(await post(org, "/v1/campaigns", body(org)), 409);
      expect({ exclusions, reason: problem.reason }).toEqual({
        exclusions,
        reason: "campaign-verification-path-excluded",
      });
      expect(problem.detail).toContain("/.well-known/airverse-verification.txt");
    }
    // Another exclusion does not stand in the way.
    const org = await organization({ rules: null });
    await sign(org, [org.targetId], "safe-active", ["/admin", "/.well-known-not"]);
    expect((await create(org)).status).toBe("queued");
  });

  it("refuses Rules of Engagement signed more than 90 days ago", async () => {
    const org = await organization();
    const saved = clock.ms;
    try {
      const verify = () =>
        api.app.request(`/v1/targets/${org.targetId}/verify`, { method: "POST", headers: bearer(org.admin) });
      clock.ms = T0 + CAMPAIGN_LIMITS.roeMaxAgeDays * DAY + 60_000;
      await verify();
      expect((await expectProblem(await post(org, "/v1/campaigns", body(org)), 409)).reason).toBe(
        "campaign-rules-too-old",
      );
      // Exactly 90 days is still good.
      clock.ms = T0 + CAMPAIGN_LIMITS.roeMaxAgeDays * DAY;
      await verify();
      expect((await create(org)).status).toBe("queued");
    } finally {
      clock.ms = saved;
    }
  });

  it("admits one queued or running Campaign per Organization", async () => {
    const org = await organization();
    const first = await create(org);
    expect((await expectProblem(await post(org, "/v1/campaigns", body(org)), 409)).reason).toBe("campaign-active");
    await finish(org, first.id);
    expect((await create(org)).status).toBe("queued");
  });

  it("caps creation at 3 per target and 5 per Organization in 24 hours, with Retry-After", async () => {
    const saved = clock.ms;
    try {
      const org = await organization();
      for (let i = 0; i < CAMPAIGN_LIMITS.createdPerTargetPerDay; i++) {
        await finish(org, (await create(org)).id);
        clock.ms += 60_000;
      }
      const capped = await post(org, "/v1/campaigns", body(org));
      expect((await expectProblem(capped, 429)).type).toBe(type("too-many-requests"));
      // The first was created at T0: its day ends 24 hours later, 3 minutes from the clock's time less.
      expect(Number(capped.headers.get("retry-after"))).toBe(86_400 - 180);

      // A second target of the same Organization: two more, then the Organization's cap.
      const second = await addTarget(org, "second.acme-shop.io");
      clock.ms += 1000;
      await sign(org, [org.targetId, second]);
      const other = { target_id: second, confirm: campaignAuthorisationPhrase("second.acme-shop.io") };
      for (let i = 0; i < 2; i++) await finish(org, (await create(org, other)).id);
      const organizationCapped = await post(org, "/v1/campaigns", body(org, other));
      expect((await expectProblem(organizationCapped, 429)).type).toBe(type("too-many-requests"));
      expect(Number(organizationCapped.headers.get("retry-after"))).toBeGreaterThan(80_000);

      // A day after the first, one more is possible (the target was verified again meanwhile).
      clock.ms = saved + DAY + 1000;
      await api.app.request(`/v1/targets/${second}/verify`, { method: "POST", headers: bearer(org.admin) });
      expect((await create(org, other)).status).toBe("queued");
    } finally {
      clock.ms = saved;
    }
  });

  it("answers 403 while Campaigns are off, and says how they are turned on", async () => {
    const org = await organization();
    service.enabled = false;
    try {
      const problem = await expectProblem(await post(org, "/v1/campaigns", body(org)), 403);
      expect(problem.type).toBe(type("campaigns-disabled"));
      expect(problem.detail).toContain("AR_PROVE_CAMPAIGNS");
      expect(ListCampaignsResponseSchema.parse(await (await get(org, "/v1/campaigns")).json())).toMatchObject({
        campaigns: [],
        enabled: false,
      });
    } finally {
      service.enabled = true;
    }
  });

  it("stops a queued Campaign with a reason; a stop is final", async () => {
    const org = await organization();
    const campaign = await create(org);
    const path = `/v1/campaigns/${campaign.id}/stop`;
    expect((await expectProblem(await post(org, path, undefined, {}), 400)).type).toBe(type("reason-required"));
    const res = await api.app.request(path, { method: "POST", headers: { ...bearer(org.admin), ...withReason() } });
    expect(res.status).toBe(200);
    expect(CampaignResponseSchema.parse(await res.json()).campaign).toMatchObject({
      status: "stopped",
      end_reason: "owner_stop",
      started_at: null,
      stop: { requested_at: now().toISOString(), requested_by: campaign.created_by, reason: "Test change" },
    });
    // The run in this process, if any, is cut too.
    expect(aborted).toContain(campaign.id);
    expect((await entries(org)).at(-1)).toMatchObject({ action: "campaign.stop", reason: "Test change" });
    const again = await api.app.request(path, { method: "POST", headers: { ...bearer(org.admin), ...withReason() } });
    expect((await expectProblem(again, 409)).reason).toBe("campaign-ended");
  });

  it("review2 L3: a stop ends a running Campaign that no run in this process will end", async () => {
    const org = await organization();
    const campaign = await create(org);
    // Running in the database, and not active here: its run died without being able to write its end.
    await api.db.tx({ organizationId: org.id }, (q) => claimCampaign(q, campaign.id, now(), "203.0.113.10"));
    const res = await api.app.request(`/v1/campaigns/${campaign.id}/stop`, {
      method: "POST",
      headers: { ...bearer(org.admin), ...withReason() },
    });
    expect(res.status).toBe(200);
    expect(CampaignResponseSchema.parse(await res.json()).campaign).toMatchObject({
      status: "stopped",
      end_reason: "owner_stop",
      stop: { reason: "Test change" },
    });
    const written = (await entries(org)).filter((entry) => entry.target.id === campaign.id);
    expect(written.map((entry) => [entry.action, entry.actor.kind])).toEqual([
      ["campaign.create", "admin_key"],
      ["campaign.stop", "admin_key"],
      ["campaign.end", "system"],
    ]);
  });

  it("review2: a second stop cuts the run again; it writes no second entry and ends what the first could not", async () => {
    const org = await organization();
    const campaign = await create(org);
    await api.db.tx({ organizationId: org.id }, (q) => claimCampaign(q, campaign.id, now(), "203.0.113.10"));
    const stop = () =>
      api.app.request(`/v1/campaigns/${campaign.id}/stop`, {
        method: "POST",
        headers: { ...bearer(org.admin), ...withReason() },
      });
    // The run is active here and does not end at once (the stand-in runner never ends it).
    activeHere.add(campaign.id);
    const cuts = () => aborted.filter((id) => id === campaign.id).length;
    const first = await stop();
    expect(first.status).toBe(200);
    expect(CampaignResponseSchema.parse(await first.json()).campaign).toMatchObject({
      status: "running",
      stop: { reason: "Test change" },
    });
    expect(cuts()).toBe(1);
    const second = await stop();
    expect(second.status).toBe(200);
    expect(cuts()).toBe(2);
    // The run is gone without an end: the next stop writes it.
    activeHere.delete(campaign.id);
    const third = await stop();
    expect(CampaignResponseSchema.parse(await third.json()).campaign).toMatchObject({
      status: "stopped",
      end_reason: "owner_stop",
    });
    expect(cuts()).toBe(3);
    const actions = (await entries(org))
      .filter((entry) => entry.target.id === campaign.id)
      .map((entry) => entry.action);
    expect(actions).toEqual(["campaign.create", "campaign.stop", "campaign.end"]);
    // Ended: a stop is final.
    expect((await expectProblem(await stop(), 409)).reason).toBe("campaign-ended");
  });

  it("tenancy and keys: another Organization gets 404; a Shield key and no key are refused", async () => {
    const org = await organization();
    const other = await organization();
    const campaign = await create(org);
    for (const path of ["", "/requests", "/findings", "/report"]) {
      expect((await get(other, `/v1/campaigns/${campaign.id}${path}`)).status).toBe(404);
      expect((await get(org, `/v1/campaigns/${campaign.id}${path}`)).status).toBe(200);
    }
    expect((await post(other, `/v1/campaigns/${campaign.id}/stop`, undefined)).status).toBe(404);
    expect((await get(org, "/v1/campaigns/not-an-id")).status).toBe(404);
    expect((await api.app.request("/v1/campaigns")).status).toBe(401);
    expect((await api.app.request("/v1/campaigns", json(body(org)))).status).toBe(401);
    const app = (await (await api.app.request("/v1/apps", json({ name: "Shop" }, bearer(org.admin)))).json()) as {
      shield_key: { key: string };
    };
    api.issuedKeys.push(app.shield_key.key);
    expect((await api.app.request("/v1/campaigns", { headers: bearer(app.shield_key.key) })).status).toBe(403);
    // Another Organization cannot launch against this one's target.
    const foreign = await expectProblem(
      await post(other, "/v1/campaigns", body(other, { target_id: org.targetId })),
      400,
    );
    expect(foreign.errors?.map((error) => error.path)).toEqual(["target_id"]);
  });

  describe("the operator's switches", () => {
    const opsCall = (path: string, payload?: unknown, token: string | null = OPS) =>
      api.app.request(
        path,
        payload === undefined
          ? { headers: token === null ? {} : bearer(token) }
          : json(payload, token === null ? {} : bearer(token)),
      );

    it("take the operator token only", async () => {
      const org = await organization();
      for (const path of [
        "/v1/ops/prove/kill",
        "/v1/ops/prove/enable",
        `/v1/ops/prove/organizations/${org.id}/suspend`,
      ]) {
        expect((await opsCall(path, { reason: "x" }, null)).status).toBe(401);
        expect((await opsCall(path, { reason: "x" }, org.admin)).status).toBe(401);
      }
      expect((await opsCall("/v1/ops/prove", undefined, org.admin)).status).toBe(401);
      expect((await opsCall("/v1/ops/prove/kill", {})).status).toBe(400);
      expect((await opsCall("/v1/ops/prove/kill", { reason: "  " })).status).toBe(400);
    });

    it("do not exist without an operator token configured", async () => {
      const bare = await makeTestApi({ campaigns: service });
      try {
        expect((await bare.app.request("/v1/ops/prove", { headers: bearer(OPS) })).status).toBe(404);
        expect((await bare.app.request("/v1/ops/prove/kill", json({ reason: "x" }, bearer(OPS)))).status).toBe(404);
      } finally {
        await bare.close();
      }
    });

    it("kill refuses new Campaigns for everyone until re-enabled; a suspension refuses one Organization", async () => {
      const org = await organization();
      const other = await organization();
      expect(ProveOperatorStateSchema.parse(await (await opsCall("/v1/ops/prove")).json())).toMatchObject({
        enabled: true,
        killed: false,
        killed_at: null,
        suspended: [],
      });

      const killed = ProveOperatorStateSchema.parse(
        await (await opsCall("/v1/ops/prove/kill", { reason: "Incident 7" })).json(),
      );
      expect(killed).toMatchObject({ killed: true, killed_at: now().toISOString() });
      for (const who of [org, other]) {
        expect((await expectProblem(await post(who, "/v1/campaigns", body(who)), 403)).type).toBe(
          type("campaigns-stopped"),
        );
        expect(ListCampaignsResponseSchema.parse(await (await get(who, "/v1/campaigns")).json()).blocked).toBe(
          "operator_kill",
        );
      }
      expect(
        ProveOperatorStateSchema.parse(await (await opsCall("/v1/ops/prove/enable", { reason: "Over" })).json()).killed,
      ).toBe(false);

      const suspend = `/v1/ops/prove/organizations/${org.id}/suspend`;
      const suspended = ProveOperatorStateSchema.parse(
        await (await opsCall(suspend, { reason: "Abuse report" })).json(),
      );
      expect(suspended.suspended).toEqual([{ organization_id: org.id, suspended_at: now().toISOString() }]);
      // Again: nothing changes, and no second entry is written.
      expect((await opsCall(suspend, { reason: "Again" })).status).toBe(200);
      expect((await expectProblem(await post(org, "/v1/campaigns", body(org)), 403)).type).toBe(
        type("campaigns-suspended"),
      );
      expect(ListCampaignsResponseSchema.parse(await (await get(org, "/v1/campaigns")).json()).blocked).toBe(
        "organization_suspended",
      );
      expect((await create(other)).status).toBe("queued");
      expect((await opsCall(`/v1/ops/prove/organizations/${org.id}/resume`, { reason: "Cleared" })).status).toBe(200);
      expect(
        (await opsCall("/v1/ops/prove/organizations/org_ffffffffffffffffffffffff/suspend", { reason: "x" })).status,
      ).toBe(404);
      expect((await opsCall("/v1/ops/prove/organizations/nope/suspend", { reason: "x" })).status).toBe(404);
      expect((await create(org)).status).toBe("queued");

      const operator = (await entries(org)).filter((entry) => entry.actor.kind === "operator");
      expect(operator.map((entry) => [entry.action, entry.reason, entry.target.id, entry.actor.key_id])).toEqual([
        ["campaign.operator_suspend", "Abuse report", org.id, undefined],
        ["campaign.operator_resume", "Cleared", org.id, undefined],
      ]);
      expect((await entries(other)).some((entry) => entry.actor.kind === "operator")).toBe(false);
      const verify = (await (await get(org, "/v1/audit/verify")).json()) as { verify: { valid: boolean } };
      expect(verify.verify.valid).toBe(true);
    });
  });
});
