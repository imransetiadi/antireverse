// Slice 15a, independent safety review, over HTTP: every request that reached the target is in the request log (M2),
// what a refused Campaign's audit entry says was sent (L2), an excluded verification path (L3), Findings that are
// never dropped silently (L1), and secrets that do not reach a stored Finding (M3). Real API, gate and transport;
// everything binds 127.0.0.1.
import type { IncomingMessage, ServerResponse } from "node:http";
import { CAMPAIGN_LIMITS, CampaignReportResponseSchema, VERIFICATION_FILE_PATH } from "@antireverse/protocol";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import {
  auditOf,
  call,
  createCampaign,
  findingsOf,
  type Harness,
  HOST,
  readCampaign,
  requestsOf,
  runCampaign,
  scripted,
  setupOrg,
  startHarness,
  T0,
  until,
} from "./fixtures/campaign-harness.ts";

const GET = (path: string, query?: Record<string, string>) => ({ method: "GET", path, ...(query ? { query } : {}) });

describe("review 15a over HTTP", () => {
  let h: Harness;
  let n = 0;
  const org = (roe: Parameters<typeof setupOrg>[2] = {}) => setupOrg(h, `Review ${++n}`, roe);

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

  /** The log's sent rows and the target's own log, side by side: they must be the same requests. */
  async function logAndTarget(acme: Awaited<ReturnType<typeof org>>, id: string) {
    // A request a stop cut off may never have reached the target: the log may hold more than the target saw, never
    // less. So both sides are compared without the requests that were cut.
    const log = (await requestsOf(h, acme, id)).filter((row) => row.outcome !== "refused" && row.failure !== "aborted");
    return {
      log: log.map((row) => `${row.method} ${row.target}`),
      target: h.target.hits.filter((hit) => !hit.aborted).map((hit) => `${hit.method} ${hit.url}`),
    };
  }

  it("M2: a request target over 1,024 characters is refused, and the log equals what the target saw", async () => {
    const acme = await org();
    const long = "x".repeat(512);
    let first: unknown;
    h.engine.run = scripted(async ({ request }) => {
      first = await request(GET("/", { a: long, b: long, c: long }));
      await request(GET("/after"));
    });
    const ended = await runCampaign(h, acme);
    expect(first).toEqual({ ok: false, refused: "query_not_canonical", fatal: false });
    const { log, target } = await logAndTarget(acme, ended.id);
    expect(target).toEqual([`GET ${VERIFICATION_FILE_PATH}`, "GET /after"]);
    expect(log).toEqual(target);
    expect(ended).toMatchObject({ status: "completed", requests_sent: 2, requests_refused: 1 });
  });

  it("M2: a status outside 100 to 599 is a failed request in the log, and the engine is not handed it", async () => {
    const acme = await org();
    h.target.intercept = (_req: IncomingMessage, res: ServerResponse) => {
      res.writeHead(999).end("odd");
    };
    let handed: unknown;
    h.engine.run = scripted(async ({ request }) => {
      handed = await request(GET("/"));
    });
    const ended = await runCampaign(h, acme);
    expect(handed).toEqual({ ok: false, seq: 2, error: "invalid_response" });
    const { log, target } = await logAndTarget(acme, ended.id);
    expect(log).toEqual(target);
    expect((await requestsOf(h, acme, ended.id)).at(-1)).toMatchObject({
      outcome: "sent",
      status: null,
      failure: "invalid_response",
    });
    expect(ended.requests_sent).toBe(2);
    // The audit entry counts what was really sent.
    const entry = (await auditOf(h, acme)).find((line) => line.action === "campaign.end");
    expect(entry?.summary).toContain("2 requests sent (the ownership check included)");
  });

  it("M1: the ownership check is the first row of the log and counts in the 60 requests", async () => {
    const acme = await org();
    h.engine.run = scripted(async ({ request }) => {
      for (let i = 0; i < CAMPAIGN_LIMITS.requestsMax + 5; i++) await request(GET("/"));
    });
    const ended = await runCampaign(h, acme);
    expect(ended).toMatchObject({ status: "failed", end_reason: "request_budget", requests_sent: 60 });
    // 60 in all reached the target: the ownership file and 59 probes.
    expect(h.target.hits).toHaveLength(60);
    expect(h.target.probes()).toHaveLength(59);
    const log = await requestsOf(h, acme, ended.id);
    expect(log[0]).toMatchObject({
      seq: 1,
      method: "GET",
      target: VERIFICATION_FILE_PATH,
      outcome: "sent",
      status: 200,
    });
    expect(log.filter((row) => row.outcome === "sent")).toHaveLength(60);
  });

  it("L2: a refused Campaign's audit entry says exactly what was sent", async () => {
    const acme = await org();
    h.target.token = null; // The ownership file is missing: the start check fails after its GET.
    const ended = await runCampaign(h, acme);
    expect(ended).toMatchObject({ status: "refused", end_reason: "target_not_verified", requests_sent: 1 });
    expect(h.target.hits).toHaveLength(1);
    const entry = (await auditOf(h, acme)).find((line) => line.action === "campaign.refuse");
    expect(entry?.summary).toContain("The ownership check was requested; no probe was sent.");
    expect(entry?.summary).not.toMatch(/No request was sent|Nothing was sent/);
    expect(await requestsOf(h, acme, ended.id)).toMatchObject([
      { seq: 1, target: VERIFICATION_FILE_PATH, outcome: "sent", status: 404 },
    ]);

    // Refused before anything went out: the entry says that instead.
    const other = await org({ window: { days: ["tue"], from: "09:00", to: "17:00" } });
    h.target.hits.length = 0;
    const unsent = await runCampaign(h, other);
    expect(unsent).toMatchObject({ status: "refused", end_reason: "outside_window", requests_sent: 0 });
    expect(h.target.hits).toEqual([]);
    expect((await auditOf(h, other)).find((line) => line.action === "campaign.refuse")?.summary).toContain(
      "Nothing was sent.",
    );
  });

  it("L3: Rules of Engagement that exclude the verification path cannot launch a Campaign, and nothing is fetched", async () => {
    for (const exclusions of [["/.well-known"], ["/"]]) {
      const acme = await org({ exclusions });
      h.target.hits.length = 0;
      const response = await call(h.api, "/v1/campaigns", {
        method: "POST",
        key: acme.key,
        body: {
          target_id: acme.targetId,
          intensity: "passive",
          confirm: `I authorise a test of ${HOST}`,
          staging: true,
        },
      });
      expect(response.status).toBe(409);
      expect(((await response.json()) as { reason: string }).reason).toBe("campaign-verification-path-excluded");
      await h.api.campaigns.idle();
      expect(h.target.hits).toEqual([]);
    }
  });

  it("L1: a NUL in a body withholds the body; the Findings and the report agree, and none is dropped", async () => {
    const acme = await org();
    h.target.intercept = (req: IncomingMessage, res: ServerResponse) => {
      if (req.url === "/api/admin/reports") res.end('\u0000{"reports":[{"id":"real"}]}');
      else res.writeHead(404).end("no");
    };
    const ended = await runCampaign(h, acme);
    const findings = await findingsOf(h, acme, ended.id);
    // The one check that got that body could not read it: inconclusive, not "ran, nothing reported".
    expect(ended).toMatchObject({
      status: "completed",
      findings_dropped: 0,
      checks: { ran: 5, reported: 0, inconclusive: 1, skipped: 0 },
    });
    expect(findings).toHaveLength(ended.checks?.reported ?? -1);
    const { report } = CampaignReportResponseSchema.parse(
      await (await call(h.api, `/v1/campaigns/${ended.id}/report`, { key: acme.key })).json(),
    );
    expect(report.findings_dropped).toBe(0);
    expect(report.summary).toContain("1 was inconclusive (1 response could not be read as text or in full)");
    expect(report.findings).toHaveLength(report.checks?.reported ?? -1);
  });

  it("L1: control characters in a body do not lose a Finding", async () => {
    const acme = await org();
    h.target.intercept = (req: IncomingMessage, res: ServerResponse) => {
      if (req.url === "/api/admin/reports") res.end('\u0001\u001b[31m{"reports":[{"id":"real\u0007"}]}');
      else res.writeHead(404).end("no");
    };
    const ended = await runCampaign(h, acme);
    const findings = await findingsOf(h, acme, ended.id);
    expect(ended).toMatchObject({ status: "completed", findings_dropped: 0, checks: { reported: 1 } });
    expect(findings.map((finding) => [finding.check_id, finding.state])).toEqual([["RW-03", "confirmed"]]);
    // biome-ignore lint/suspicious/noControlCharactersInRegex: the excerpt must hold none.
    expect(findings[0]?.evidence.excerpt).not.toMatch(/[\u0000-\u0008\u000b-\u001f]/);
    expect(findings[0]?.evidence.excerpt).toContain('"reports"');
  });

  it("M3: secrets and card numbers do not reach a stored Finding, and its hash is of the redacted body", async () => {
    const acme = await org();
    const secrets = [
      "hunter2hunter2",
      "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
      "4111 1111 1111 1111",
      "horse battery staple",
    ];
    const body = `{"reports":[{"user_password":"${secrets[0]}","aws_secret_access_key":"${secrets[1]}","note":"order 1001 ${secrets[2]} paid","password":"correct ${secrets[3]}"}]}`;
    h.target.intercept = (req: IncomingMessage, res: ServerResponse) => {
      if (req.url === "/api/admin/reports") res.end(body);
      else res.writeHead(404).end("no");
    };
    const ended = await runCampaign(h, acme);
    const findings = await findingsOf(h, acme, ended.id);
    expect(findings.map((finding) => finding.check_id)).toEqual(["RW-03"]);
    const stored = JSON.stringify([findings, await requestsOf(h, acme, ended.id), ended]);
    for (const secret of secrets) expect(stored, secret).not.toContain(secret);
    const { createHash } = await import("node:crypto");
    const evidence = findings[0]?.evidence;
    expect(evidence?.body_sha256).not.toBe(createHash("sha256").update(body).digest("hex"));
    expect(evidence?.body_sha256).toBe(
      createHash("sha256")
        .update(evidence?.excerpt ?? "")
        .digest("hex"),
    );
  });

  it("the window bounds the last request too: none is started that could still run when it ends", async () => {
    const acme = await org({ window: { days: ["mon"], from: "09:00", to: "17:00" } });
    const after: unknown[] = [];
    h.engine.run = scripted(async ({ request }) => {
      await request(GET("/"));
      // 200 ms before the window ends; a request may take 400 ms here.
      h.clock.ms = Date.parse("2026-11-16T16:59:59.800Z");
      after.push(await request(GET("/")));
    });
    const ended = await runCampaign(h, acme);
    await until(() => after.length === 1, "the engine's last request");
    expect(after[0]).toEqual({ ok: false, refused: "outside_window", fatal: true });
    expect(ended).toMatchObject({ status: "failed", end_reason: "outside_window" });
    expect(h.target.probes()).toHaveLength(1);
  });

  it("a stop during the spacing wait sends nothing more", async () => {
    const acme = await org();
    h.engine.run = scripted(async ({ request }) => {
      for (let i = 0; i < 30; i++) await request(GET("/"));
    });
    const created = await createCampaign(h, acme);
    await until(() => h.target.probes().length >= 3, "three requests");
    const response = await call(h.api, `/v1/campaigns/${created.id}/stop`, { method: "POST", key: acme.key });
    const atAck = h.target.probes().length;
    expect(response.status).toBe(200);
    await new Promise((resolve) => setTimeout(resolve, 500));
    await h.api.campaigns.idle();
    expect(h.target.probes()).toHaveLength(atAck);
    expect(await readCampaign(h, acme, created.id)).toMatchObject({ status: "stopped", end_reason: "owner_stop" });
    expect((await call(h.api, `/v1/campaigns/${created.id}/stop`, { method: "POST", key: acme.key })).status).toBe(409);
    const { log, target } = await logAndTarget(acme, created.id);
    expect(log).toEqual(target);
  });

  it("engine output cannot smuggle a header, a second request or another host", async () => {
    const acme = await org();
    const tries: unknown[] = [
      GET("/", { q: "x HTTP/1.1\r\nHost: evil.example\r\n\r\nGET /api/trap/reset" }),
      GET("/", { "q HTTP/1.1\r\nX-Evil": "1" }),
      GET("/x HTTP/1.1\r\nHost: evil.example"),
      { method: "GET", path: "/", query: { q: "1" }, headers: { cookie: "a=b" } },
      { method: "GET", path: "/", body: "x" },
      { method: "GET ", path: "/" },
      { method: "get", path: "/" },
      { method: "GET\r\nX: y", path: "/" },
      { method: "POST", path: "/api/trap/reset" },
      { method: "GET", path: "https://127.0.0.1/" },
      { method: "GET", path: "//127.0.0.1/" },
      { method: "GET", path: "/", query: { url: "https://evil.example/" } },
      { method: "HEAD", path: "/" },
    ];
    h.engine.run = scripted(async ({ request }) => {
      for (const probe of tries) await request(probe);
    });
    const ended = await runCampaign(h, acme);
    const seen = h.target.hits;
    expect(seen.every((hit) => hit.host === HOST && hit.bodyBytes === 0 && !hit.cookie)).toBe(true);
    expect(seen.every((hit) => hit.method === "GET" || hit.method === "HEAD")).toBe(true);
    expect(h.target.range.trapHits()).toEqual([]);
    expect(ended.requests_sent).toBe(seen.length);
    const { log, target } = await logAndTarget(acme, ended.id);
    expect(log).toEqual(target);
  });
});
