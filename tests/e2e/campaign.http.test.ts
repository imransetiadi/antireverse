// Slice 15a over HTTP: a Pentest Campaign from creation to report against a real API (startApi) and a local test
// target — apps/range with its seeded weaknesses behind node:https and the TLS fixture, reached through the stand-in
// resolver. The engine is the real scripted stand-in in its worker thread. No request leaves the machine.
import {
  AuditExportLineSchema,
  CAMPAIGN_STAND_IN_NOTICE,
  CampaignReportResponseSchema,
  ListCampaignFindingsResponseSchema,
  ListCampaignsResponseSchema,
  ProblemSchema,
  STAND_IN_ENGINE,
  VERIFICATION_FILE_PATH,
} from "@antireverse/protocol";
import { STAND_IN_MARKER, STAND_IN_REDIRECT } from "@antireverse/prove";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  call,
  campaignBody,
  createCampaign,
  findingsOf,
  type Harness,
  HOST,
  type Org,
  readCampaign,
  requestsOf,
  runCampaign,
  setupOrg,
  startHarness,
} from "./fixtures/campaign-harness.ts";

const q = encodeURIComponent(STAND_IN_MARKER);
const to = encodeURIComponent(STAND_IN_REDIRECT);
/** What the stand-in sends at safe-active against ar-range with weaknesses: each probe, then its one repeat. */
const EXPECTED_TARGETS = [
  "/",
  "/api/orders/x",
  "/api/admin/reports",
  "/api/orders/1001",
  `/search?q=${q}`,
  `/go?to=${to}`,
];

describe("a Campaign with the scripted stand-in, end to end", () => {
  let h: Harness;
  let org: Org;

  beforeAll(async () => {
    h = await startHarness();
    org = await setupOrg(h, "Acme");
  });
  afterAll(async () => {
    await h?.close();
  });

  it("runs every check, reports the exact Findings, and its request log equals the target's own", async () => {
    const campaign = await runCampaign(h, org);
    expect(campaign).toMatchObject({
      host: HOST,
      target_id: org.targetId,
      roe_id: org.roeId,
      intensity: "safe-active",
      engine: STAND_IN_ENGINE,
      notice: CAMPAIGN_STAND_IN_NOTICE,
      status: "completed",
      end_reason: "checks_complete",
      staging_declared: true,
      // The ownership check and twelve probes.
      requests_sent: 13,
      findings_dropped: 0,
      requests_refused: 0,
      checks: { ran: 6, reported: 6, skipped: 0 },
      stop: null,
    });

    // The API's log and the target's log say the same thing, request by request.
    const all = await requestsOf(h, org, campaign.id);
    // The first row is the ownership check: it went through the gate like every other request.
    expect(all[0]).toMatchObject({
      seq: 1,
      method: "GET",
      target: VERIFICATION_FILE_PATH,
      outcome: "sent",
      status: 200,
    });
    expect(h.target.hits.map((hit) => [hit.method, hit.url])).toEqual(all.map((r) => [r.method, r.target]));
    const logged = all.slice(1);
    expect(logged.map((r) => [r.seq, r.method, r.target, r.outcome])).toEqual(
      EXPECTED_TARGETS.flatMap((target) => [target, target]).map((target, index) => [index + 2, "GET", target, "sent"]),
    );
    expect(logged.map((r) => r.status)).toEqual([200, 200, 500, 500, 200, 200, 200, 200, 200, 200, 302, 302]);
    expect(h.target.probes().map((hit) => [hit.method, hit.url])).toEqual(logged.map((r) => [r.method, r.target]));
    expect(h.target.range.entries.map((entry) => [entry.method, entry.url])).toEqual(
      logged.map((r) => [r.method, r.target]),
    );
    // Ownership was checked once, from the pinned address, before any probe.
    expect(h.target.hits[0]).toMatchObject({ method: "GET", url: VERIFICATION_FILE_PATH });
    expect(h.target.hits.filter((hit) => hit.url === VERIFICATION_FILE_PATH)).toHaveLength(1);
    // Every request names the Campaign and carries nothing else.
    for (const hit of h.target.hits) {
      expect(hit).toMatchObject({
        host: HOST,
        userAgent: "Airverse-Campaign/1",
        campaign: campaign.id,
        cookie: false,
        bodyBytes: 0,
      });
    }
    expect(h.target.range.trapHits()).toEqual([]);

    const findings = await findingsOf(h, org, campaign.id);
    expect(findings.map((f) => [f.check_id, f.path, f.severity, f.state, f.title])).toEqual([
      ["RW-01", "/", "low", "confirmed", "Missing security headers"],
      ["RW-02", "/api/orders/x", "medium", "confirmed", "Error with a stack trace"],
      ["RW-03", "/api/admin/reports", "high", "confirmed", "Admin data without authentication"],
      ["RW-04", "/api/orders/1001", "high", "confirmed", "Synthetic order readable by a guessable id"],
      ["RW-05", "/search", "medium", "confirmed", "Marker reflected unencoded"],
      ["RW-06", "/go", "low", "confirmed", "Redirect to another host"],
    ]);
    const evidence = Object.fromEntries(findings.map((f) => [f.check_id, f.evidence]));
    expect(evidence["RW-02"]).toMatchObject({ method: "GET", target: "/api/orders/x", status: 500 });
    expect(evidence["RW-02"]?.excerpt).toContain("at loadOrder (/srv/ar-range/orders.js:42:11)");
    expect(evidence["RW-05"]?.excerpt).toContain(STAND_IN_MARKER);
    // The redirect is reported by its category: the URL it pointed to is kept nowhere but in the request itself.
    expect(evidence["RW-06"]).toMatchObject({
      status: 302,
      location: "other-host",
      headers: { location: "other-host" },
    });
    // Third review (D-107): of a response body, a window of at most 200 characters around the match is kept, and
    // no hash of the body. A check that reads no body keeps none of it.
    for (const finding of findings) {
      expect(finding.evidence).not.toHaveProperty("body_sha256");
      expect(finding.evidence.excerpt.length).toBeLessThanOrEqual(200);
    }
    expect(evidence["RW-01"]?.excerpt).toBe("");
    expect(evidence["RW-06"]?.excerpt).toBe("");
  });

  it("says what it is everywhere: the engine tag and the sentence on the list, the Findings and the report", async () => {
    const list = ListCampaignsResponseSchema.parse(await (await call(h.api, "/v1/campaigns", { key: org.key })).json());
    expect(list).toMatchObject({ enabled: true, blocked: null, notice: CAMPAIGN_STAND_IN_NOTICE });
    expect(list.campaigns).toHaveLength(1);
    const campaign = list.campaigns[0];
    expect(campaign).toMatchObject({ engine: STAND_IN_ENGINE, notice: CAMPAIGN_STAND_IN_NOTICE });
    const id = campaign?.id ?? "";
    const findings = ListCampaignFindingsResponseSchema.parse(
      await (await call(h.api, `/v1/campaigns/${id}/findings`, { key: org.key })).json(),
    );
    expect(findings).toMatchObject({ engine: STAND_IN_ENGINE, notice: CAMPAIGN_STAND_IN_NOTICE });
    const { report } = CampaignReportResponseSchema.parse(
      await (await call(h.api, `/v1/campaigns/${id}/report`, { key: org.key })).json(),
    );
    expect(report).toMatchObject({
      engine: STAND_IN_ENGINE,
      notice: "Scripted checks. They measure the pipeline and its safety controls. This is not a penetration test.",
      summary: "6 checks ran, 6 reported a finding, 0 were skipped.",
      checks: { ran: 6, reported: 6, skipped: 0 },
    });
    expect(report.findings).toHaveLength(6);
    expect(report.limits.length).toBeGreaterThan(0);
    expect(JSON.stringify(report)).not.toMatch(/no vulnerabilit/i);
  });

  it("passive: one check runs, five are skipped, and the report says so", async () => {
    h.target.reset();
    h.target.token = org.token;
    const campaign = await runCampaign(h, org, "passive");
    expect(campaign).toMatchObject({
      status: "completed",
      requests_sent: 3,
      checks: { ran: 1, reported: 1, skipped: 5 },
    });
    expect(h.target.probes().map((hit) => hit.url)).toEqual(["/", "/"]);
    const { report } = CampaignReportResponseSchema.parse(
      await (await call(h.api, `/v1/campaigns/${campaign.id}/report`, { key: org.key })).json(),
    );
    expect(report.summary).toBe("1 check ran, 1 reported a finding, 5 were skipped.");
  });

  it("audits create (admin key, with the reason) and start and end (system)", async () => {
    const campaigns = ListCampaignsResponseSchema.parse(
      await (await call(h.api, "/v1/campaigns", { key: org.key })).json(),
    );
    // (The test clock stands still, so the list's order does not tell the two apart: the first was safe-active.)
    const first = campaigns.campaigns.find((campaign) => campaign.intensity === "safe-active");
    const exported = await (await call(h.api, "/v1/audit/export", { key: org.key })).text();
    const entries = exported
      .trim()
      .split("\n")
      .slice(1)
      .map((line) => AuditExportLineSchema.parse(JSON.parse(line)))
      .filter((entry) => entry.target.id === first?.id);
    expect(entries.map((entry) => [entry.action, entry.actor.kind])).toEqual([
      ["campaign.create", "admin_key"],
      ["campaign.start", "system"],
      ["campaign.end", "system"],
    ]);
    expect(entries[0]).toMatchObject({ reason: "End-to-end test", actor: { key_id: first?.created_by } });
    expect(entries[0]?.summary).toMatch(/staging/i);
    expect(entries[2]?.summary).toContain("13 requests sent (the ownership check included)");
    const verified = await (await call(h.api, "/v1/audit/verify", { key: org.key })).json();
    expect(verified).toMatchObject({ verify: { valid: true } });
  });

  it("tenancy: another Organization sees none of it", async () => {
    const mine = ListCampaignsResponseSchema.parse(await (await call(h.api, "/v1/campaigns", { key: org.key })).json());
    const id = mine.campaigns[0]?.id ?? "";
    const other = await setupOrg(h, "Globex");
    h.target.token = org.token;
    const theirs = ListCampaignsResponseSchema.parse(
      await (await call(h.api, "/v1/campaigns", { key: other.key })).json(),
    );
    expect(theirs.campaigns).toEqual([]);
    for (const path of ["", "/requests", "/findings", "/report"]) {
      expect((await call(h.api, `/v1/campaigns/${id}${path}`, { key: other.key })).status).toBe(404);
    }
    expect((await call(h.api, `/v1/campaigns/${id}/stop`, { method: "POST", key: other.key })).status).toBe(404);
    // The other Organization cannot launch against a target that is not its own.
    const foreign = await call(h.api, "/v1/campaigns", {
      method: "POST",
      key: other.key,
      body: { ...campaignBody(other), target_id: org.targetId },
    });
    expect(foreign.status).toBe(400);
    expect(ProblemSchema.parse(await foreign.json()).errors?.map((error) => error.path)).toEqual(["target_id"]);
  });

  it("ownership at start: without the Organization's own file at the pinned address the Campaign is refused unsent", async () => {
    const fresh = await setupOrg(h, "Initech");
    h.target.reset();
    // The target serves another Organization's token, then nothing at all.
    for (const token of [org.token, null]) {
      h.target.hits.length = 0;
      h.target.token = token;
      const campaign = await runCampaign(h, fresh, "passive");
      // The one request was the ownership check; no probe followed it.
      expect(campaign).toMatchObject({
        status: "refused",
        end_reason: "target_not_verified",
        requests_sent: 1,
        started_at: null,
      });
      expect(h.target.hits.map((hit) => hit.url)).toEqual([VERIFICATION_FILE_PATH]);
      expect(h.target.probes()).toEqual([]);
      expect(await requestsOf(h, fresh, campaign.id)).toMatchObject([
        { seq: 1, target: VERIFICATION_FILE_PATH, outcome: "sent", status: token === null ? 404 : 200 },
      ]);
    }
    h.target.token = fresh.token;
    expect(await runCampaign(h, fresh, "passive")).toMatchObject({ status: "completed" });
    // A third in 24 hours is the last this target may have.
    const fourth = await call(h.api, "/v1/campaigns", {
      method: "POST",
      key: fresh.key,
      body: campaignBody(fresh, "passive"),
    });
    expect(fourth.status).toBe(429);
    expect(Number(fourth.headers.get("retry-after"))).toBeGreaterThan(0);
  });

  it("creation is off unless the service has Campaigns on", async () => {
    const off = await startHarness({ enabled: false });
    try {
      const idle = await setupOrg(off, "Hooli");
      const response = await call(off.api, "/v1/campaigns", {
        method: "POST",
        key: idle.key,
        body: campaignBody(idle),
      });
      expect(response.status).toBe(403);
      const problem = ProblemSchema.parse(await response.json());
      expect(problem.type).toBe("https://antireverse.dev/problems/campaigns-disabled");
      expect(problem.detail).toMatch(/AR_PROVE_CAMPAIGNS/);
      const list = ListCampaignsResponseSchema.parse(
        await (await call(off.api, "/v1/campaigns", { key: idle.key })).json(),
      );
      expect(list).toMatchObject({ campaigns: [], enabled: false });
      expect(off.target.hits).toEqual([]);
    } finally {
      await off.close();
    }
  });

  it("a created Campaign is queued first, and one Organization has one at a time", async () => {
    const solo = await setupOrg(h, "Umbrella");
    h.target.reset();
    h.target.token = solo.token;
    h.target.serve({ hostile: "slow", slowMs: 250 });
    const first = await createCampaign(h, solo, "passive");
    expect(first).toMatchObject({ status: "queued", end_reason: null, started_at: null, finished_at: null });
    const second = await call(h.api, "/v1/campaigns", {
      method: "POST",
      key: solo.key,
      body: campaignBody(solo, "passive"),
    });
    expect(second.status).toBe(409);
    expect(ProblemSchema.parse(await second.json()).reason).toBe("campaign-active");
    await h.api.campaigns.idle();
    expect(await readCampaign(h, solo, first.id)).toMatchObject({ status: "completed" });
  });
});
