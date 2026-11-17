// Slice 15a, the scope-escape suite: whatever a target answers, whatever a resolver says and whatever an engine asks
// for, no Campaign request leaves its scope — and a stop, by the owner or the operator, ends it at once. Every case is
// proven from the test target's own request log (and, for redirects, from a second local server that must see
// nothing). Real API, real gate, real transport; the target and every other server bind 127.0.0.1.
import type { IncomingMessage, ServerResponse } from "node:http";
import {
  CAMPAIGN_LIMITS,
  ListCampaignsResponseSchema,
  ProblemSchema,
  ProveOperatorStateSchema,
} from "@antireverse/protocol";
import { STAND_IN_CATALOG } from "@antireverse/prove";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  auditOf,
  call,
  campaignBody,
  createCampaign,
  findingsOf,
  type Harness,
  HOST,
  type Org,
  ops,
  readCampaign,
  requestsOf,
  runCampaign,
  scripted,
  setupOrg,
  signRoe,
  startDecoy,
  startHarness,
  T0,
  until,
} from "./fixtures/campaign-harness.ts";

const CATALOG_PATHS = new Set(STAND_IN_CATALOG.map((check) => check.probe.path));
const GET = (path: string, query?: Record<string, string>) => ({ method: "GET", path, ...(query ? { query } : {}) });
const slowly =
  (ms: number) =>
  (_req: IncomingMessage, res: ServerResponse): void => {
    setTimeout(() => res.end("ok"), ms).unref();
  };

describe("scope escape", () => {
  let h: Harness;
  let n = 0;
  const org = (roe: Parameters<typeof setupOrg>[2] = {}) => setupOrg(h, `Scope ${++n}`, roe);

  beforeAll(async () => {
    h = await startHarness();
  });
  afterAll(async () => {
    await h?.close();
  });
  beforeEach(async () => {
    await h.api.campaigns.idle();
    h.target.reset();
    h.engine.run = null;
    h.clock.ms = T0;
    h.dns.addresses.set(HOST, ["127.0.0.1"]);
  });

  it("redirect to another host: never followed, whatever the status or the form of the Location", async () => {
    const decoy = await startDecoy();
    try {
      const locations = [
        `https://${HOST}:${decoy.port}/landing`,
        `https://127.0.0.1:${decoy.port}/landing`,
        `//127.0.0.1:${decoy.port}/landing`,
        `https://localhost:${decoy.port}/`,
      ];
      let served = 0;
      h.target.intercept = (_req, res) => {
        const status = [301, 302, 303, 307, 308][served % 5] as number;
        res.writeHead(status, { location: locations[served++ % locations.length], refresh: `0; url=${locations[0]}` });
        res.end(`<meta http-equiv="refresh" content="0; url=${locations[0]}"><a href="${locations[1]}">moved</a>`);
      };
      const acme = await org();
      const campaign = await runCampaign(h, acme);
      expect(campaign).toMatchObject({ status: "completed", end_reason: "checks_complete" });
      expect(decoy.hits).toEqual([]);
      const probes = h.target.probes();
      expect(probes.length).toBeGreaterThanOrEqual(STAND_IN_CATALOG.length);
      for (const hit of probes) {
        expect(hit.method).toBe("GET");
        expect(CATALOG_PATHS.has(hit.url.split("?")[0] as string)).toBe(true);
      }
      // What is kept of the redirects is their category only.
      // What is kept of a Location header is its category only (the page's own text is evidence like any other).
      const findings = await findingsOf(h, acme, campaign.id);
      const stored = JSON.stringify([
        findings.map((finding) => [finding.evidence.headers, finding.evidence.location, finding.evidence.target]),
        await requestsOf(h, acme, campaign.id),
      ]);
      expect(stored).not.toContain(String(decoy.port));
      expect(findings.find((finding) => finding.check_id === "RW-06")?.evidence).toMatchObject({
        location: "other-host",
        headers: { location: "other-host" },
      });
    } finally {
      await decoy.close();
    }
  });

  it("a resolver that changes its answer: the address is resolved once and pinned for the whole run", async () => {
    const acme = await org();
    let asked = 0;
    // After the first answer the name "moves" to an internal address: a second lookup would be an escape.
    h.dns.addresses.set(HOST, () => (asked++ === 0 ? ["127.0.0.1"] : ["10.0.0.99"]));
    const campaign = await runCampaign(h, acme);
    expect(campaign).toMatchObject({ status: "completed", requests_sent: 13 });
    expect(asked).toBe(1);
    expect(h.target.probes()).toHaveLength(12);
  });

  it("private and metadata addresses: the Campaign is refused before any connection", async () => {
    const answers = [
      ["10.0.0.7"],
      ["169.254.169.254"],
      ["127.0.0.1", "10.0.0.1"],
      ["::ffff:169.254.169.254"],
      ["100.64.0.1"],
      ["192.168.1.1", "127.0.0.1"],
      ["fd00::1"],
      ["0.0.0.0"],
      [],
    ];
    let acme = await org();
    for (const [index, answer] of answers.entries()) {
      // Three Campaigns per target in 24 hours: a new Organization for every three answers.
      if (index > 0 && index % 3 === 0) acme = await org();
      h.target.hits.length = 0;
      h.dns.addresses.set(HOST, answer);
      const campaign = await runCampaign(h, acme, "passive");
      expect({ answer, status: campaign.status, reason: campaign.end_reason }).toEqual({
        answer,
        status: "refused",
        reason: "target_not_reachable",
      });
      expect(h.target.hits).toEqual([]);
      expect(campaign.requests_sent).toBe(0);
    }
  });

  it("without the test-only option even loopback is refused: the production transport never reaches the target", async () => {
    const production = await startHarness({ production: true });
    try {
      const acme = await setupOrg(production, "Production");
      const campaign = await runCampaign(production, acme, "passive");
      expect(campaign).toMatchObject({ status: "refused", end_reason: "target_not_reachable", requests_sent: 0 });
      expect(production.target.hits).toEqual([]);
    } finally {
      await production.close();
    }
  });

  it("an excluded path is never requested, in any spelling", async () => {
    const acme = await org({ exclusions: ["/api/admin"] });
    const campaign = await runCampaign(h, acme);
    expect(campaign).toMatchObject({
      status: "completed",
      requests_refused: 1,
      checks: { ran: 5, reported: 5, skipped: 1 },
    });
    expect((await requestsOf(h, acme, campaign.id)).filter((r) => r.outcome === "refused")).toMatchObject([
      { method: "GET", target: "/api/admin/reports", reason: "path_excluded", status: null },
    ]);
    expect((await findingsOf(h, acme, campaign.id)).map((f) => f.check_id)).not.toContain("RW-03");

    // An engine that tries to reach it by other spellings.
    const spellings = [
      "/API/ADMIN/reports",
      "/api/admin",
      "/api/admin/",
      "/Api/Admin/Reports",
      "/api//admin/reports",
      "/api/%61dmin/reports",
      "/api/admin;x=1/reports",
      "/x/../api/admin/reports",
      "/api/./admin/reports",
      "/api\\admin\\reports",
      "/api/admin%2freports",
      "/api/admin./reports",
    ];
    // Fourth review (D-110): none of these is a probe of the engine's catalog. The first ends the Campaign, and
    // nothing the engine asks afterwards is sent. (Each spelling alone is refused: `campaign-gate.test.ts`.)
    const answers: unknown[] = [];
    h.engine.run = scripted(async ({ request }) => {
      for (const path of spellings) answers.push(await request(GET(path)));
      answers.push(await request(GET("/")));
    });
    const before = h.target.probes().length;
    const second = await runCampaign(h, acme);
    await until(() => answers.length === spellings.length + 1, "the engine's last request");
    expect(answers[0]).toEqual({ ok: false, refused: "not_in_catalog", fatal: true });
    expect(answers.slice(1).every((answer) => (answer as { refused?: string }).refused === "campaign_ended")).toBe(
      true,
    );
    expect(second).toMatchObject({ status: "failed", end_reason: "not_in_catalog", requests_refused: 1 });
    expect(h.target.probes().slice(before)).toEqual([]);
    expect(h.target.hits.some((hit) => /admin/i.test(hit.url))).toBe(false);
    // The refused row keeps no spelling.
    expect((await requestsOf(h, acme, second.id)).filter((r) => r.outcome === "refused")).toMatchObject([
      { method: "GET", target: null, asked_chars: spellings[0]?.length },
    ]);
  });

  // Fourth review (D-110): each of these used to be refused and the Campaign went on to its one valid GET. Now the
  // first ends the Campaign, so nothing at all follows it; each alone is refused in `campaign-gate.test.ts`.
  it("other methods, absolute URLs, hosts, bodies, headers and cookies: nothing is sent, and the first ends the Campaign", async () => {
    const acme = await org();
    const hostile: unknown[] = [
      { method: "POST", path: "/api/trap/reset" },
      { method: "DELETE", path: "/api/orders/1001" },
      { method: "PUT", path: "/" },
      { method: "PATCH", path: "/" },
      { method: "OPTIONS", path: "/" },
      { method: "TRACE", path: "/" },
      { method: "CONNECT", path: "/" },
      GET("https://evil.acme-shop.io/"),
      GET("//evil.acme-shop.io/x"),
      GET("http://169.254.169.254/latest/meta-data/"),
      { ...GET("/"), host: "evil.acme-shop.io" },
      { ...GET("/"), port: 8443 },
      { ...GET("/"), body: '{"confirm":true}' },
      { ...GET("/"), headers: { cookie: "session=1", authorization: "Bearer x" } },
      { ...GET("/"), cookies: "session=1" },
      GET("/api/trap/reset\r\nX-Injected: 1"),
      { ...GET("/"), query: { "a\r\nHost": "evil" } },
      "GET https://evil.acme-shop.io/",
    ];
    const answers: unknown[] = [];
    h.engine.run = scripted(async ({ request }) => {
      for (const probe of hostile) answers.push(await request(probe));
      answers.push(await request(GET("/")));
    });
    const campaign = await runCampaign(h, acme);
    await until(() => answers.length === hostile.length + 1, "the engine's last request");
    expect(answers.every((answer) => (answer as { ok: boolean; fatal?: boolean }).ok === false)).toBe(true);
    expect(answers[0]).toEqual({ ok: false, refused: "method_not_allowed", fatal: true });
    expect(campaign).toMatchObject({
      status: "failed",
      end_reason: "method_not_allowed",
      requests_sent: 1,
      requests_refused: 1,
    });
    expect(h.target.probes()).toEqual([]);
    expect(h.target.range.trapHits()).toEqual([]);
    // The log names no method of the engine's choosing and no path it asked for.
    expect((await requestsOf(h, acme, campaign.id)).filter((r) => r.outcome === "refused")).toMatchObject([
      { method: "OTHER", target: null, asked_chars: 15 },
    ]);
  });

  it("twenty refusals end the Campaign: what the engine asks afterwards is not sent", async () => {
    // Fourth review (D-110): a probe outside the catalog ends the Campaign at once, so the twenty are refusals a
    // Campaign survives — a catalog probe whose path the Rules exclude.
    const acme = await org({ exclusions: ["/api/admin"] });
    let last: unknown;
    h.engine.run = scripted(async ({ request }) => {
      for (let i = 0; i < 25; i++) await request(GET("/api/admin/reports"));
      last = await request(GET("/"));
    });
    const campaign = await runCampaign(h, acme);
    await until(() => last !== undefined, "the engine's last request");
    expect(campaign).toMatchObject({
      status: "failed",
      end_reason: "refusal_limit",
      requests_sent: 1,
      requests_refused: 20,
    });
    expect(last).toEqual({ ok: false, refused: "campaign_ended", fatal: true });
    expect(h.target.probes()).toEqual([]);
  });

  it("over the request budget: exactly 60 requests reach the target", async () => {
    const acme = await org();
    h.engine.run = scripted(async ({ request }) => {
      for (let i = 0; i < CAMPAIGN_LIMITS.requestsMax + 15; i++) await request(GET("/"));
    });
    const campaign = await runCampaign(h, acme);
    expect(campaign).toMatchObject({ status: "failed", end_reason: "request_budget", requests_sent: 60 });
    // 60 in all: the ownership check and 59 probes.
    expect(h.target.hits).toHaveLength(60);
    expect(h.target.probes()).toHaveLength(59);
  });

  it("over the byte budget: at most 64 KB of a 5 MB answer is read, and 2 MB in all", async () => {
    const acme = await org();
    h.target.serve({ hostile: "large" });
    h.engine.run = scripted(async ({ request }) => {
      for (let i = 0; i < 50; i++) await request(GET("/"));
    });
    const campaign = await runCampaign(h, acme);
    expect(campaign).toMatchObject({ status: "failed", end_reason: "byte_budget" });
    // What the connections read is counted — the handshake, the headers and whatever arrived before a connection
    // over its cap was dropped — and no request starts without room for that: never over 2 MB.
    expect(campaign.response_bytes).toBeLessThanOrEqual(CAMPAIGN_LIMITS.responseBytesMax);
    expect(campaign.response_bytes).toBeGreaterThan(CAMPAIGN_LIMITS.responseBytesMax - 400_000);
    const logged = await requestsOf(h, acme, campaign.id);
    const largest = Math.max(...logged.map((r) => r.bytes));
    expect(largest).toBeGreaterThan(CAMPAIGN_LIMITS.responseReadBytesMax);
    // A row says what its connection read: the 64 KB handed on, and at most a few socket reads more.
    expect(largest).toBeLessThan(4 * CAMPAIGN_LIMITS.responseReadBytesMax);
    expect(h.target.probes().length).toBeLessThanOrEqual(32);
    expect(h.target.probes().length).toBeGreaterThanOrEqual(8);
  });

  it("the owner's stop: durable, cuts the request in flight, and no request follows it (TC-PRV-008)", async () => {
    const acme = await org();
    h.target.intercept = slowly(150);
    const afterStop: unknown[] = [];
    let stopped = false;
    h.engine.run = scripted(async ({ request }) => {
      for (let i = 0; i < 40; i++) {
        const exchange = await request(GET("/"));
        if (stopped) afterStop.push(exchange);
      }
    });
    const created = await createCampaign(h, acme);
    await until(() => h.target.probes().length >= 2, "two requests at the target");

    // A stop needs a reason.
    const bare = await call(h.api, `/v1/campaigns/${created.id}/stop`, { method: "POST", key: acme.key, reason: null });
    expect(bare.status).toBe(400);
    expect(ProblemSchema.parse(await bare.json()).type).toMatch(/reason-required$/);

    const started = Date.now();
    stopped = true;
    const response = await call(h.api, `/v1/campaigns/${created.id}/stop`, {
      method: "POST",
      key: acme.key,
      reason: "Wrong system",
    });
    expect(response.status).toBe(200);
    const { campaign } = (await response.json()) as { campaign: Awaited<ReturnType<typeof readCampaign>> };
    expect(Date.now() - started).toBeLessThan(5000);
    expect(campaign).toMatchObject({
      status: "stopped",
      end_reason: "owner_stop",
      stop: { requested_by: created.created_by, reason: "Wrong system" },
    });
    const atStop = h.target.probes().length;
    await new Promise((resolve) => setTimeout(resolve, 500));
    await h.api.campaigns.idle();
    // Nothing followed the stop, although the engine kept asking.
    expect(h.target.probes()).toHaveLength(atStop);
    expect(atStop).toBeLessThan(10);
    expect(afterStop.length).toBeGreaterThan(30);
    expect(afterStop.slice(1).every((e) => (e as { refused?: string }).refused === "campaign_ended")).toBe(true);
    // The request in flight was cut, not awaited.
    expect(h.target.probes().at(-1)?.aborted).toBe(true);
    expect((await requestsOf(h, acme, created.id)).at(-1)).toMatchObject({ outcome: "sent", failure: "aborted" });

    // A stop is final.
    const again = await call(h.api, `/v1/campaigns/${created.id}/stop`, { method: "POST", key: acme.key });
    expect(again.status).toBe(409);
    expect(ProblemSchema.parse(await again.json()).reason).toBe("campaign-ended");
    expect((await readCampaign(h, acme, created.id)).status).toBe("stopped");
    const entries = (await auditOf(h, acme)).filter((entry) => entry.target.id === created.id);
    expect(entries.map((entry) => [entry.action, entry.actor.kind, entry.reason])).toEqual([
      ["campaign.create", "admin_key", "End-to-end test"],
      ["campaign.start", "system", undefined],
      ["campaign.stop", "admin_key", "Wrong system"],
      ["campaign.end", "system", undefined],
    ]);
  });

  it("the owner's stop terminates the real engine in its worker", async () => {
    const acme = await org();
    h.target.intercept = slowly(200);
    const created = await createCampaign(h, acme);
    await until(() => h.target.probes().length >= 1, "a request at the target");
    const response = await call(h.api, `/v1/campaigns/${created.id}/stop`, { method: "POST", key: acme.key });
    expect(response.status).toBe(200);
    const atStop = h.target.probes().length;
    await new Promise((resolve) => setTimeout(resolve, 600));
    expect(h.target.probes()).toHaveLength(atStop);
    expect(await readCampaign(h, acme, created.id)).toMatchObject({ status: "stopped", end_reason: "owner_stop" });
  });

  it("a queued Campaign can be stopped before it sends anything; one host has one Campaign at a time", async () => {
    const first = await org();
    const second = await org();
    h.target.token = first.token;
    h.target.intercept = slowly(150);
    h.engine.run = scripted(async ({ request }) => {
      for (let i = 0; i < 40; i++) await request(GET("/"));
    });
    const running = await createCampaign(h, first);
    await until(() => h.target.probes().length >= 1, "the first Campaign's request");
    // Another Organization, the same host: it waits.
    const waiting = await createCampaign(h, second);
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(await readCampaign(h, second, waiting.id)).toMatchObject({ status: "queued", requests_sent: 0 });
    const stopped = await call(h.api, `/v1/campaigns/${waiting.id}/stop`, { method: "POST", key: second.key });
    expect(stopped.status).toBe(200);
    expect(await readCampaign(h, second, waiting.id)).toMatchObject({
      status: "stopped",
      end_reason: "owner_stop",
      started_at: null,
      requests_sent: 0,
    });
    await call(h.api, `/v1/campaigns/${running.id}/stop`, { method: "POST", key: first.key });
    await h.api.campaigns.idle();
    // Every request the target saw named the first Campaign.
    expect(new Set(h.target.hits.map((hit) => hit.campaign))).toEqual(new Set([running.id]));
  });

  it("the operator's kill switch: everything stops, nothing new is created, and re-enabling resumes nothing", async () => {
    const first = await org();
    const second = await org();
    h.target.token = first.token;
    h.target.intercept = slowly(150);
    h.engine.run = scripted(async ({ request }) => {
      for (let i = 0; i < 40; i++) await request(GET("/"));
    });
    const running = await createCampaign(h, first);
    await until(() => h.target.probes().length >= 2, "two requests at the target");
    const queued = await createCampaign(h, second);

    // The operator routes take the operator token only.
    expect((await call(h.api, "/v1/ops/prove/kill", { method: "POST", body: { reason: "x" } })).status).toBe(401);
    expect(
      (await call(h.api, "/v1/ops/prove/kill", { method: "POST", key: first.key, body: { reason: "x" } })).status,
    ).toBe(401);
    expect((await ops(h.api, "/v1/ops/prove/kill", {})).status).toBe(400);

    const killed = await ops(h.api, "/v1/ops/prove/kill", { reason: "Incident 2026-11-16: wrong target reported" });
    expect(killed.status).toBe(200);
    expect(ProveOperatorStateSchema.parse(await killed.json())).toMatchObject({ killed: true, stopped: 2, active: 0 });
    const atKill = h.target.probes().length;
    await new Promise((resolve) => setTimeout(resolve, 500));
    await h.api.campaigns.idle();
    expect(h.target.probes()).toHaveLength(atKill);
    expect(await readCampaign(h, first, running.id)).toMatchObject({ status: "stopped", end_reason: "operator_kill" });
    expect(await readCampaign(h, second, queued.id)).toMatchObject({
      status: "stopped",
      end_reason: "operator_kill",
      requests_sent: 0,
      started_at: null,
    });

    // Nothing new while it holds.
    const refused = await call(h.api, "/v1/campaigns", { method: "POST", key: first.key, body: campaignBody(first) });
    expect(refused.status).toBe(403);
    expect(ProblemSchema.parse(await refused.json()).type).toMatch(/campaigns-stopped$/);
    const list = ListCampaignsResponseSchema.parse(
      await (await call(h.api, "/v1/campaigns", { key: first.key })).json(),
    );
    expect(list.blocked).toBe("operator_kill");

    // One operator entry in each affected Organization's chain, with the operator's reason.
    for (const [who, id] of [
      [first, running.id],
      [second, queued.id],
    ] as const) {
      const entries = (await auditOf(h, who)).filter((entry) => entry.action === "campaign.operator_kill");
      expect(entries).toMatchObject([
        {
          actor: { kind: "operator" },
          target: { kind: "campaign", id },
          reason: "Incident 2026-11-16: wrong target reported",
        },
      ]);
      expect(entries[0]?.actor.key_id).toBeUndefined();
    }

    const enabled = await ops(h.api, "/v1/ops/prove/enable", { reason: "Incident closed" });
    expect(ProveOperatorStateSchema.parse(await enabled.json())).toMatchObject({ killed: false, active: 0 });
    await h.api.campaigns.idle();
    expect(h.target.probes()).toHaveLength(atKill);
    expect((await readCampaign(h, first, running.id)).status).toBe("stopped");
    // New Campaigns are possible again.
    h.engine.run = null;
    h.target.intercept = null;
    expect((await runCampaign(h, first, "passive")).status).toBe("completed");
  });

  it("the operator suspends one Organization: its Campaign stops, others go on", async () => {
    const acme = await org();
    const other = await org();
    h.target.token = acme.token;
    h.target.intercept = slowly(150);
    h.engine.run = scripted(async ({ request }) => {
      for (let i = 0; i < 40; i++) await request(GET("/"));
    });
    const running = await createCampaign(h, acme);
    await until(() => h.target.probes().length >= 1, "a request at the target");
    const suspended = await ops(h.api, `/v1/ops/prove/organizations/${acme.id}/suspend`, { reason: "Abuse report 7" });
    expect(ProveOperatorStateSchema.parse(await suspended.json())).toMatchObject({
      killed: false,
      stopped: 1,
      suspended: [{ organization_id: acme.id }],
    });
    const atSuspend = h.target.probes().length;
    await new Promise((resolve) => setTimeout(resolve, 400));
    expect(h.target.probes()).toHaveLength(atSuspend);
    expect(await readCampaign(h, acme, running.id)).toMatchObject({
      status: "stopped",
      end_reason: "organization_suspended",
    });
    const refused = await call(h.api, "/v1/campaigns", { method: "POST", key: acme.key, body: campaignBody(acme) });
    expect(refused.status).toBe(403);
    expect(ProblemSchema.parse(await refused.json()).type).toMatch(/campaigns-suspended$/);
    expect((await auditOf(h, acme)).filter((e) => e.actor.kind === "operator").map((e) => e.action)).toEqual([
      "campaign.operator_suspend",
      "campaign.operator_kill",
    ]);
    expect(
      (await ops(h.api, "/v1/ops/prove/organizations/org_ffffffffffffffffffffffff/suspend", { reason: "x" })).status,
    ).toBe(404);

    // Another Organization is not affected.
    h.engine.run = null;
    h.target.intercept = null;
    h.target.token = other.token;
    expect((await runCampaign(h, other, "passive")).status).toBe("completed");
    expect((await auditOf(h, other)).some((e) => e.actor.kind === "operator")).toBe(false);

    const resumed = await ops(h.api, `/v1/ops/prove/organizations/${acme.id}/resume`, { reason: "Cleared" });
    expect(ProveOperatorStateSchema.parse(await resumed.json()).suspended).toEqual([]);
    h.target.token = acme.token;
    expect((await runCampaign(h, acme, "passive")).status).toBe("completed");
  });

  /** A run of two requests, then `change`, then more: what the gate answers after the change, and what the target saw. */
  async function midRun(acme: Org, change: () => Promise<void> | void) {
    const after: unknown[] = [];
    h.engine.run = scripted(async ({ request }) => {
      await request(GET("/"));
      await request(GET("/"));
      await change();
      for (let i = 0; i < 5; i++) after.push(await request(GET("/")));
    });
    const campaign = await runCampaign(h, acme);
    await until(() => after.length === 5, "the engine's requests after the change");
    return { campaign, after };
  }

  it("the target lapses mid-run: the next request is refused and the Campaign ends", async () => {
    const acme = await org();
    const { campaign, after } = await midRun(acme, async () => {
      await h.api.db.tx({ organizationId: acme.id }, (q) =>
        q.query("UPDATE targets SET status = 'lapsed', lapsed_reason = 'DNS: no_record; file: status' WHERE id = $1", [
          acme.targetId,
        ]),
      );
    });
    expect(campaign).toMatchObject({ status: "failed", end_reason: "target_not_verified", requests_sent: 3 });
    expect(after[0]).toEqual({ ok: false, refused: "target_not_verified", fatal: true });
    expect(h.target.probes()).toHaveLength(2);
  });

  it("the Rules of Engagement are replaced mid-run: the Campaign ends, even though the new version allows the same", async () => {
    const acme = await org();
    const { campaign, after } = await midRun(acme, async () => {
      h.clock.ms += 1000;
      await signRoe(h, acme);
    });
    expect(campaign).toMatchObject({
      status: "failed",
      end_reason: "rules_replaced",
      requests_sent: 3,
      roe_id: acme.roeId,
    });
    expect(after[0]).toEqual({ ok: false, refused: "rules_replaced", fatal: true });
    expect(h.target.probes()).toHaveLength(2);
  });

  it("the window ends mid-run: the Campaign ends", async () => {
    const acme = await org({ window: { days: ["mon"], from: "09:00", to: "17:00" } });
    const { campaign, after } = await midRun(acme, () => {
      h.clock.ms = Date.parse("2026-11-16T17:00:00.000Z");
    });
    expect(campaign).toMatchObject({ status: "failed", end_reason: "outside_window", requests_sent: 3 });
    expect(after[0]).toEqual({ ok: false, refused: "outside_window", fatal: true });
    expect(h.target.probes()).toHaveLength(2);
  });

  it("a Campaign outside the window, or under replaced Rules, does not start", async () => {
    const acme = await org({ window: { days: ["tue"], from: "09:00", to: "17:00" } });
    expect(await runCampaign(h, acme, "passive")).toMatchObject({ status: "refused", end_reason: "outside_window" });
    expect(h.target.hits).toEqual([]);
    // Queued behind another Campaign of the same host, then the Rules change before it starts.
    const blocker = await org();
    h.target.token = blocker.token;
    h.target.intercept = slowly(150);
    h.engine.run = scripted(async ({ request }) => {
      for (let i = 0; i < 6; i++) await request(GET("/"));
    });
    const waiter = await org();
    h.target.token = blocker.token;
    const running = await createCampaign(h, blocker);
    await until(() => h.target.probes().length >= 1, "the blocking Campaign's request");
    const queued = await createCampaign(h, waiter);
    h.clock.ms += 1000;
    await signRoe(h, waiter);
    h.target.token = waiter.token;
    await h.api.campaigns.idle();
    expect((await readCampaign(h, blocker, running.id)).status).toBe("completed");
    expect(await readCampaign(h, waiter, queued.id)).toMatchObject({
      status: "refused",
      end_reason: "rules_replaced",
      requests_sent: 0,
    });
    expect(new Set(h.target.probes().map((hit) => hit.campaign))).toEqual(new Set([running.id]));
  });

  it("a 429, or a 503 with Retry-After, ends the Campaign after that one request", async () => {
    for (const [status, headers, reason] of [
      [429, {}, "target_rate_limited"],
      [503, { "retry-after": "120" }, "target_unavailable"],
    ] as const) {
      const acme = await org();
      h.target.hits.length = 0;
      h.target.intercept = (_req, res) => {
        res.writeHead(status, headers);
        res.end("slow down");
      };
      const campaign = await runCampaign(h, acme);
      expect(campaign).toMatchObject({ status: "failed", end_reason: reason, requests_sent: 2 });
      expect(h.target.probes()).toHaveLength(1);
    }
  });

  it("five failures in a row end the Campaign: a target that stops answering is left alone", async () => {
    const acme = await org();
    h.target.intercept = () => {};
    const campaign = await runCampaign(h, acme);
    expect(campaign).toMatchObject({ status: "failed", end_reason: "target_unhealthy", requests_sent: 6 });
    expect(h.target.probes()).toHaveLength(5);
    expect((await requestsOf(h, acme, campaign.id)).slice(1).map((r) => r.failure)).toEqual(Array(5).fill("timeout"));
  });
});
