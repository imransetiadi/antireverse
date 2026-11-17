// @vitest-environment node
import {
  CAMPAIGN_LIMITS,
  CAMPAIGN_STAND_IN_NOTICE,
  type Campaign,
  CampaignReportResponseSchema,
  CampaignResponseSchema,
  campaignAuthorisationPhrase,
  campaignChecksSentence,
  ListCampaignFindingsResponseSchema,
  ListCampaignRequestsResponseSchema,
  ListCampaignsResponseSchema,
  ListTargetsResponseSchema,
  ProblemSchema,
  ProveOperatorStateSchema,
  STAND_IN_ENGINE,
  type Target,
} from "@antireverse/protocol";
import { Hono } from "hono";
import { describe, expect, it } from "vitest";
import { createCampaignStore, createProveOperator, createProveSwitch } from "../scripts/stub-campaigns.mjs";
import { createProveStore } from "../scripts/stub-prove.mjs";

// Slice 15a: the stand-in API answers Pentest Campaigns and the operator's switches in the shape of the protocol,
// with the API's order of checks and its problem documents. Every 2xx body is parsed with its response schema and
// must come back unchanged.

const KEY_ID = "key_0123456789abcdef01234567";
const ORG = "org_0123456789abcdef01234567";
const OTHER_ORG = "org_aaaaaaaaaaaaaaaaaaaaaaaa";
const TOKEN = "stub-operator-token-".padEnd(40, "z");
const PROBLEMS = "https://antireverse.dev/problems/";
/** Wednesday 2026-11-11 10:00 UTC. */
const NOW = Date.parse("2026-11-11T10:00:00.000Z");
const REASON = "Quarterly test of the staging shop";

interface Answer {
  status: number;
  body: unknown;
  headers?: Record<string, string>;
}
interface Recorded {
  actor: string;
  action: string;
  target: { kind: string; id: string };
  reason?: string;
  summary: string;
}

function parsed<T>(
  schema: { safeParse(value: unknown): { success: boolean; data?: T; error?: unknown } },
  body: unknown,
): T {
  const result = schema.safeParse(body);
  expect(result.success ? [] : (result.error as { issues: unknown[] }).issues).toEqual([]);
  expect(result.data).toEqual(body);
  return result.data as T;
}
function problemOf(answer: Answer, status: number, name: string): Record<string, unknown> {
  expect(answer.status).toBe(status);
  const body = ProblemSchema.parse(answer.body);
  expect(body.type).toBe(`${PROBLEMS}${name}`);
  expect(body.status).toBe(status);
  return body as Record<string, unknown>;
}

function setup(options: { enabled?: boolean; seed?: boolean } = {}) {
  const clock = { ms: NOW };
  const now = () => clock.ms;
  const recorded: Recorded[] = [];
  const prove = createProveStore({ keyId: KEY_ID, now });
  const control = createProveSwitch({ enabled: options.enabled ?? true });
  const store = createCampaignStore({
    organizationId: ORG,
    keyId: KEY_ID,
    prove,
    control,
    record: (entry: Recorded) => recorded.push(entry),
    now,
    seed: options.seed ?? false,
  });
  const stores = new Map([[ORG, store]]);
  const operator = createProveOperator({
    token: TOKEN,
    control,
    stores: () => stores,
    isOrganization: (id: string) => id === ORG || id === OTHER_ORG,
    now,
  });
  const call = (method: string, path: string, body?: unknown, reason?: string): Answer => {
    const answer = store.handle(method, path, body, reason);
    if (answer === null) throw new Error(`no answer for ${method} ${path}`);
    return answer as Answer;
  };
  const ops = (method: string, path: string, body?: unknown, authorization = `Bearer ${TOKEN}`): Answer => {
    const answer = operator.handle(method, path, authorization, body);
    if (answer === null) throw new Error(`no operator answer for ${method} ${path}`);
    return answer as Answer;
  };
  const targets = parsed(ListTargetsResponseSchema, prove.handle("GET", "/v1/targets")?.body).targets;
  const target = (host: string): Target => targets.find((one) => one.host === host) as Target;
  const request = (host = "shop.acme-shop.io", overrides: Record<string, unknown> = {}) => ({
    target_id: target(host).id,
    intensity: "safe-active",
    confirm: campaignAuthorisationPhrase(host),
    staging: true,
    ...overrides,
  });
  const create = (host?: string): Campaign =>
    parsed(CampaignResponseSchema, call("POST", "/v1/campaigns", request(host), REASON).body).campaign;
  const read = (id: string): Campaign =>
    parsed(CampaignResponseSchema, call("GET", `/v1/campaigns/${id}`).body).campaign;
  return { clock, prove, control, store, operator, call, ops, recorded, target, request, create, read };
}

describe("stub Campaigns: creation", () => {
  it("queues a Campaign with the stand-in engine and notice, and records it with the reason", () => {
    const { call, request, recorded } = setup();
    const answer = call("POST", "/v1/campaigns", request(), REASON);
    expect(answer.status).toBe(202);
    const { campaign } = parsed(CampaignResponseSchema, answer.body);
    expect(campaign).toMatchObject({
      host: "shop.acme-shop.io",
      status: "queued",
      end_reason: null,
      intensity: "safe-active",
      engine: STAND_IN_ENGINE,
      notice: CAMPAIGN_STAND_IN_NOTICE,
      staging_declared: true,
      created_by: KEY_ID,
      checks: null,
    });
    expect(recorded).toEqual([
      expect.objectContaining({
        actor: "admin_key",
        action: "campaign.create",
        target: { kind: "campaign", id: campaign.id },
        reason: REASON,
      }),
    ]);
  });

  it("checks in the API's order: the body, the reason, the switches, the target, the phrase, the conflicts", () => {
    const { call, request, control, target } = setup({ enabled: false });
    // 1. The body, before anything else — also while Campaigns are off and without a reason.
    const invalid = problemOf(
      call("POST", "/v1/campaigns", { target_id: "nope", intensity: "full", confirm: 1, staging: false }),
      400,
      "validation",
    );
    expect((invalid.errors as Array<{ path: string }>).map((error) => error.path)).toEqual([
      "target_id",
      "intensity",
      "confirm",
      "staging",
    ]);
    // 2. The reason.
    problemOf(call("POST", "/v1/campaigns", request()), 400, "reason-required");
    // 3. Off, then the kill switch, then the suspension.
    problemOf(call("POST", "/v1/campaigns", request(), REASON), 403, "campaigns-disabled");
    control.enabled = true;
    control.kill(NOW);
    control.suspend(ORG, NOW);
    problemOf(call("POST", "/v1/campaigns", request(), REASON), 403, "campaigns-stopped");
    control.enable();
    problemOf(call("POST", "/v1/campaigns", request(), REASON), 403, "campaigns-suspended");
    control.resume(ORG);
    // 4. A target of the Organization.
    const unknown = problemOf(
      call(
        "POST",
        "/v1/campaigns",
        request("shop.acme-shop.io", { target_id: "tgt_ffffffffffffffffffffffff" }),
        REASON,
      ),
      400,
      "validation",
    );
    expect(unknown.errors).toEqual([{ path: "target_id", message: "Must be a target of the Organization." }]);
    // 5. The phrase, against the target's host.
    const phrase = problemOf(
      call(
        "POST",
        "/v1/campaigns",
        request("shop.acme-shop.io", { confirm: "I authorise a test of api.acme-shop.io" }),
        REASON,
      ),
      400,
      "validation",
    );
    expect((phrase.errors as Array<{ path: string }>)[0]?.path).toBe("confirm");
    // 6. The conflicts, each with its reason.
    for (const [host, reason] of [
      ["legacy.acme-shop.io", "campaign-target-not-verified"],
      ["staging.acme-shop.io", "campaign-target-not-verified"],
    ] as const) {
      expect(problemOf(call("POST", "/v1/campaigns", request(host), REASON), 409, "conflict").reason).toBe(reason);
    }
    expect(target("shop.acme-shop.io").status).toBe("verified");
  });

  it("refuses a target outside the scope, an intensity above the signed one, and a second active Campaign", () => {
    const { call, request, prove, create } = setup();
    // dns.acme-shop.io verifies at once, but the current Rules of Engagement do not name it.
    const added = prove.handle("POST", "/v1/targets", { host: "dns.acme-shop.io" })?.body as { target: Target };
    prove.handle("POST", `/v1/targets/${added.target.id}/verify`);
    const outOfScope = {
      target_id: added.target.id,
      intensity: "passive",
      confirm: campaignAuthorisationPhrase("dns.acme-shop.io"),
      staging: true,
    };
    expect(problemOf(call("POST", "/v1/campaigns", outOfScope, REASON), 409, "conflict").reason).toBe(
      "campaign-target-out-of-scope",
    );
    create();
    expect(problemOf(call("POST", "/v1/campaigns", request("api.acme-shop.io"), REASON), 409, "conflict").reason).toBe(
      "campaign-active",
    );
  });

  it("refuses an intensity above the signed one, Rules older than 90 days, and no Rules at all", () => {
    const passive = setup();
    const shop = passive.target("shop.acme-shop.io");
    passive.prove.handle("POST", "/v1/rules-of-engagement", {
      scope: [shop.id],
      exclusions: [],
      intensity: "passive",
      window: { days: ["wed"], from: "00:00", to: "24:00" },
      contacts: ["security@acme-shop.io"],
      confirm: "I authorise passive testing",
    });
    expect(problemOf(passive.call("POST", "/v1/campaigns", passive.request(), REASON), 409, "conflict").reason).toBe(
      "campaign-intensity-exceeds",
    );

    // Rules that exclude the ownership file's path can never be met: refused before the active check, as in the API.
    const excluded = setup();
    excluded.create();
    excluded.prove.handle("POST", "/v1/rules-of-engagement", {
      scope: [excluded.target("shop.acme-shop.io").id],
      exclusions: ["/.well-known"],
      intensity: "safe-active",
      window: { days: ["wed"], from: "00:00", to: "24:00" },
      contacts: ["security@acme-shop.io"],
      confirm: "I authorise safe-active testing",
    });
    expect(problemOf(excluded.call("POST", "/v1/campaigns", excluded.request(), REASON), 409, "conflict").reason).toBe(
      "campaign-verification-path-excluded",
    );

    const old = setup();
    old.clock.ms = NOW + 91 * 86_400_000;
    // The targets' checks are older than 26 hours by then: that conflict comes first, as in the API.
    expect(problemOf(old.call("POST", "/v1/campaigns", old.request(), REASON), 409, "conflict").reason).toBe(
      "campaign-target-not-verified",
    );
    old.prove.handle("POST", `/v1/targets/${old.target("shop.acme-shop.io").id}/verify`);
    old.prove.handle("POST", `/v1/targets/${old.target("shop.acme-shop.io").id}/verify`);
    expect(problemOf(old.call("POST", "/v1/campaigns", old.request(), REASON), 409, "conflict").reason).toBe(
      "campaign-rules-too-old",
    );
  });

  it("allows 3 Campaigns per target and 5 per Organization in 24 hours, then answers 429 with Retry-After", () => {
    const { call, request, create, clock } = setup();
    for (let i = 0; i < CAMPAIGN_LIMITS.createdPerTargetPerDay; i++) {
      const campaign = create();
      call("POST", `/v1/campaigns/${campaign.id}/stop`, undefined, "Next one");
      clock.ms += 60_000;
    }
    const limited = call("POST", "/v1/campaigns", request(), REASON);
    problemOf(limited, 429, "too-many-requests");
    expect(Number(limited.headers?.["retry-after"])).toBeGreaterThan(23 * 3600);
    expect(Number(limited.headers?.["retry-after"])).toBeLessThanOrEqual(24 * 3600);
    // Another target of the Organization still has room.
    expect(call("POST", "/v1/campaigns", request("api.acme-shop.io"), REASON).status).toBe(202);
  });
});

describe("stub Campaigns: a run", () => {
  it("goes from queued to running to completed by the clock, one request per second, with Findings and a report", () => {
    const { create, read, call, clock, recorded } = setup();
    const { id } = create();
    expect(read(id).status).toBe("queued");
    clock.ms += 3_000;
    const running = read(id);
    expect(running.status).toBe("running");
    expect(running.started_at).not.toBeNull();
    expect(running.requests_sent).toBeGreaterThan(0);
    expect(running.checks).toBeNull();
    const log = parsed(ListCampaignRequestsResponseSchema, call("GET", `/v1/campaigns/${id}/requests`).body).requests;
    expect(log).toHaveLength(running.requests_sent + running.requests_refused);
    expect(log.every((row) => row.method === "GET" || row.method === "HEAD")).toBe(true);

    clock.ms += 60_000;
    const done = read(id);
    expect(done).toMatchObject({ status: "completed", end_reason: "checks_complete" });
    expect(done.checks).toEqual({ ran: 6, reported: 6, inconclusive: 0, skipped: 0 });
    expect(done.requests_sent).toBeLessThanOrEqual(CAMPAIGN_LIMITS.requestsMax);
    const findings = parsed(ListCampaignFindingsResponseSchema, call("GET", `/v1/campaigns/${id}/findings`).body);
    expect(findings.notice).toBe(CAMPAIGN_STAND_IN_NOTICE);
    expect(findings.engine).toEqual(STAND_IN_ENGINE);
    expect(findings.findings.map((finding) => finding.check_id)).toEqual([
      "RW-01",
      "RW-02",
      "RW-03",
      "RW-04",
      "RW-05",
      "RW-06",
    ]);
    expect(findings.findings.every((finding) => finding.state === "confirmed")).toBe(true);
    // Evidence is redacted: no email address and no key survives in an excerpt.
    for (const finding of findings.findings) expect(finding.evidence.excerpt).not.toMatch(/@|aro_|ark_/);
    // Third review (D-107): as the API — a window of at most 200 characters, none for a check that reads no body, and
    // no hash of the body.
    const raw = call("GET", `/v1/campaigns/${id}/findings`).body as { findings: { evidence: object }[] };
    expect(raw.findings.every((finding) => !("body_sha256" in finding.evidence))).toBe(true);
    expect(findings.findings.every((finding) => finding.evidence.excerpt.length <= 200)).toBe(true);
    expect(findings.findings.filter((finding) => finding.evidence.excerpt === "").map((f) => f.check_id)).toEqual([
      "RW-01",
      "RW-06",
    ]);
    const { report } = parsed(CampaignReportResponseSchema, call("GET", `/v1/campaigns/${id}/report`).body);
    expect(report.notice).toBe(CAMPAIGN_STAND_IN_NOTICE);
    expect(report.summary).toBe(campaignChecksSentence({ ran: 6, reported: 6, inconclusive: 0, skipped: 0 }));
    expect(report.limits.length).toBeGreaterThan(0);
    expect(recorded.map((entry) => `${entry.actor} ${entry.action}`)).toEqual([
      "admin_key campaign.create",
      "system campaign.start",
      "system campaign.end",
    ]);
  });

  it("skips the safe-active checks of a passive Campaign", () => {
    const { call, request, read, clock } = setup();
    const { campaign } = parsed(
      CampaignResponseSchema,
      call("POST", "/v1/campaigns", request("shop.acme-shop.io", { intensity: "passive" }), REASON).body,
    );
    clock.ms += 120_000;
    const done = read(campaign.id);
    expect(done.status).toBe("completed");
    expect(done.checks?.skipped).toBeGreaterThan(0);
    expect((done.checks?.ran ?? 0) + (done.checks?.skipped ?? 0)).toBe(6);
  });

  it("stops a queued Campaign and a running one for good, with a reason; a second stop is campaign-ended", () => {
    const { create, call, clock, recorded } = setup();
    const first = create();
    problemOf(call("POST", `/v1/campaigns/${first.id}/stop`), 400, "reason-required");
    const stoppedQueued = parsed(
      CampaignResponseSchema,
      call("POST", `/v1/campaigns/${first.id}/stop`, undefined, "Wrong window").body,
    ).campaign;
    expect(stoppedQueued).toMatchObject({ status: "stopped", end_reason: "owner_stop", requests_sent: 0 });
    expect(stoppedQueued.stop).toMatchObject({ requested_by: KEY_ID, reason: "Wrong window" });
    expect(problemOf(call("POST", `/v1/campaigns/${first.id}/stop`, undefined, "Again"), 409, "conflict").reason).toBe(
      "campaign-ended",
    );

    const second = create();
    clock.ms += 5_000;
    const stoppedRunning = parsed(
      CampaignResponseSchema,
      call("POST", `/v1/campaigns/${second.id}/stop`, undefined, "Enough").body,
    ).campaign;
    expect(stoppedRunning.status).toBe("stopped");
    expect(stoppedRunning.requests_sent).toBeGreaterThan(0);
    const sent = stoppedRunning.requests_sent;
    clock.ms += 120_000;
    // A stop is final: nothing is sent after it.
    expect(parsed(CampaignResponseSchema, call("GET", `/v1/campaigns/${second.id}`).body).campaign.requests_sent).toBe(
      sent,
    );
    expect(recorded.filter((entry) => entry.action === "campaign.stop")).toHaveLength(2);
    problemOf(call("POST", "/v1/campaigns/cmp_ffffffffffffffffffffffff/stop", undefined, "x"), 404, "not-found");
    problemOf(call("GET", "/v1/campaigns/nope"), 404, "not-found");
  });

  it("lists the newest first with whether one can be created, and seeds every kind of end to look at", () => {
    const { call, control } = setup({ seed: true });
    const list = parsed(ListCampaignsResponseSchema, call("GET", "/v1/campaigns").body);
    expect(list).toMatchObject({ enabled: true, blocked: null, notice: CAMPAIGN_STAND_IN_NOTICE });
    expect(new Set(list.campaigns.map((campaign) => campaign.status))).toEqual(
      new Set(["completed", "stopped", "refused", "failed"]),
    );
    const created = list.campaigns.map((campaign) => campaign.created_at);
    expect([...created].sort().reverse()).toEqual(created);
    const refusedRows = list.campaigns
      .flatMap(
        (campaign) =>
          parsed(ListCampaignRequestsResponseSchema, call("GET", `/v1/campaigns/${campaign.id}/requests`).body)
            .requests,
      )
      .filter((row) => row.outcome === "refused");
    expect(refusedRows.length).toBeGreaterThan(0);
    expect(refusedRows.every((row) => row.reason !== null && row.status === null)).toBe(true);
    // The seed is older than a day: it takes nothing from today's budget.
    expect(call("POST", "/v1/campaigns", setup().request(), REASON).status).not.toBe(429);
    control.kill(NOW);
    expect(parsed(ListCampaignsResponseSchema, call("GET", "/v1/campaigns").body).blocked).toBe("operator_kill");
    control.enable();
    control.suspend(ORG, NOW);
    expect(parsed(ListCampaignsResponseSchema, call("GET", "/v1/campaigns").body).blocked).toBe(
      "organization_suspended",
    );
  });

  it("says Campaigns are off in the list, and leaves other paths alone", () => {
    const { call, store } = setup({ enabled: false });
    expect(parsed(ListCampaignsResponseSchema, call("GET", "/v1/campaigns").body).enabled).toBe(false);
    expect(store.handle("GET", "/v1/targets")).toBeNull();
  });
});

describe("stub operator switches of Campaigns", () => {
  it("reads the state, kills (ending every active Campaign), and enables again", () => {
    const { ops, create, read, recorded, call, request } = setup();
    const { id } = create();
    expect(parsed(ProveOperatorStateSchema, ops("GET", "/v1/ops/prove").body)).toEqual({
      enabled: true,
      killed: false,
      killed_at: null,
      suspended: [],
      active: 1,
      stopped: 0,
    });
    const killed = parsed(ProveOperatorStateSchema, ops("POST", "/v1/ops/prove/kill", { reason: "Incident 42" }).body);
    expect(killed).toMatchObject({ killed: true, active: 0, stopped: 1 });
    expect(killed.killed_at).not.toBeNull();
    expect(read(id)).toMatchObject({ status: "stopped", end_reason: "operator_kill" });
    expect(recorded.map((entry) => `${entry.actor} ${entry.action}`).slice(-2)).toEqual([
      "operator campaign.operator_kill",
      "system campaign.refuse",
    ]);
    expect(recorded.at(-2)?.reason).toBe("Incident 42");
    problemOf(call("POST", "/v1/campaigns", request(), REASON), 403, "campaigns-stopped");
    const enabled = parsed(ProveOperatorStateSchema, ops("POST", "/v1/ops/prove/enable", { reason: "Closed" }).body);
    expect(enabled).toMatchObject({ killed: false, killed_at: null, stopped: 0 });
    // Nothing that was stopped runs again.
    expect(read(id).status).toBe("stopped");
  });

  it("suspends and resumes one Organization, and answers 404 for one it does not know or that is already so", () => {
    const { ops, create, read, recorded } = setup();
    const { id } = create();
    const suspended = parsed(
      ProveOperatorStateSchema,
      ops("POST", `/v1/ops/prove/organizations/${ORG}/suspend`, { reason: "Abuse report" }).body,
    );
    expect(suspended.suspended.map((entry) => entry.organization_id)).toEqual([ORG]);
    expect(suspended.stopped).toBe(1);
    expect(read(id)).toMatchObject({ status: "stopped", end_reason: "organization_suspended" });
    expect(recorded.some((entry) => entry.actor === "operator" && entry.action === "campaign.operator_suspend")).toBe(
      true,
    );
    // Already suspended: unchanged, answered with the state.
    expect(ops("POST", `/v1/ops/prove/organizations/${ORG}/suspend`, { reason: "Again" }).status).toBe(200);
    problemOf(
      ops("POST", "/v1/ops/prove/organizations/org_ffffffffffffffffffffffff/suspend", { reason: "x" }),
      404,
      "not-found",
    );
    // Resuming an Organization that is not suspended changes nothing and answers the state, as the API does.
    expect(ops("POST", `/v1/ops/prove/organizations/${OTHER_ORG}/resume`, { reason: "x" }).status).toBe(200);
    problemOf(ops("POST", "/v1/ops/prove/organizations/nope/suspend", { reason: "x" }), 404, "not-found");
    const resumed = parsed(
      ProveOperatorStateSchema,
      ops("POST", `/v1/ops/prove/organizations/${ORG}/resume`, { reason: "Cleared" }).body,
    );
    expect(resumed.suspended).toEqual([]);
  });

  it("needs a reason, the operator token and a configured token, as the API does", async () => {
    const { ops, operator, control } = setup();
    const invalid = problemOf(ops("POST", "/v1/ops/prove/kill", { reason: "  " }), 400, "validation");
    expect((invalid.errors as Array<{ path: string }>)[0]?.path).toBe("reason");
    expect(control.killed).toBe(false);

    // The API's own operator routes, with stand-ins that are never reached: what the stub's refusals must equal.
    const OPS_ROUTES = new URL("../../api/src/routes/ops.ts", import.meta.url).href;
    const { opsRoutes } = (await import(/* @vite-ignore */ OPS_ROUTES)) as {
      opsRoutes: (deps: { token?: string | undefined; prove?: unknown }) => Hono;
    };
    const real = async (token: string | undefined, authorization?: string): Promise<Answer> => {
      const app = new Hono();
      app.route("/", opsRoutes({ token, prove: { db: {}, campaigns: {} } }));
      const response = await app.request("/v1/ops/prove", {
        headers: authorization === undefined ? {} : { authorization },
      });
      const challenge = response.headers.get("www-authenticate");
      return {
        status: response.status,
        body: await response.json(),
        ...(challenge === null ? {} : { headers: { "www-authenticate": challenge } }),
      };
    };
    for (const authorization of [undefined, `Bearer ${TOKEN}x`, "Bearer aro_0123456789abcdef", TOKEN]) {
      expect(operator.handle("GET", "/v1/ops/prove", authorization, undefined)).toEqual(
        await real(TOKEN, authorization),
      );
    }
    const off = createProveOperator({
      token: undefined,
      control,
      stores: () => new Map(),
      isOrganization: () => false,
      now: () => NOW,
    });
    expect(off.handle("GET", "/v1/ops/prove", `Bearer ${TOKEN}`, undefined)).toEqual(
      await real(undefined, `Bearer ${TOKEN}`),
    );
    expect(off.handle("GET", "/v1/ops/slo", `Bearer ${TOKEN}`, undefined)).toBeNull();
  });
});
