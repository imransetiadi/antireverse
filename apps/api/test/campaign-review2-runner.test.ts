import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { type CampaignExchange, STAND_IN_ENGINE, VERIFICATION_FILE_PATH } from "@antireverse/protocol";
import { generateVerificationToken, newId } from "@antireverse/protocol/server";
import { standInEngine } from "@antireverse/prove";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { type CampaignEngineRunner, createCampaignRunner } from "../src/campaign/runner.ts";
import type { Db } from "../src/db/db.ts";
import { createAuthorize } from "../src/prove/authorize.ts";
import type { Resolver } from "../src/prove/verify.ts";
import { auditEntriesAfter } from "../src/stores/audit.ts";
import { findCampaign, insertCampaign, listCampaignFindings, listCampaignRequests } from "../src/stores/campaigns.ts";
import { insertVersion } from "../src/stores/rules-of-engagement.ts";
import { insertTarget, recordCheck } from "../src/stores/targets.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 15a, second independent safety review: the runner against a real local TLS target (loopback, test CA) —
// bodies that cannot be read (M3), a Finding whose write fails after a stop (L2), an ended Campaign's history (L4),
// and the reviewer's checks that held (the 60 requests across shutdowns, excluded spellings, the whole-body token).

const fixture = (name: string) => readFileSync(new URL(`./fixtures/prove-tls/${name}`, import.meta.url), "utf8");
const HOST = "shop.acme-shop.io";
const T0 = Date.parse("2026-11-16T10:00:00.000Z");
const KEY = "key_0123456789abcdef01234567";
const now = () => new Date(T0);
const silent = { info() {}, warn() {} };

describe("review2 15a: the runner", () => {
  let api: TestApi;
  let server: Server;
  let port = 0;
  let hits: { at: number; line: string; host: string | undefined }[] = [];
  const tokens = new Map<string, string>();
  let handler: ((req: IncomingMessage, res: ServerResponse) => void) | null = null;
  let n = 0;

  beforeAll(async () => {
    api = await makeTestApi({ now });
    server = createServer({ key: fixture("key.pem"), cert: fixture("cert.pem") }, (req, res) => {
      hits.push({ at: performance.now(), line: `${req.method} ${req.url}`, host: req.headers.host });
      if (handler !== null) return handler(req, res);
      const token = tokens.get(String(req.headers["x-airverse-campaign"]));
      if (req.url === VERIFICATION_FILE_PATH && token !== undefined) res.end(`${token}\n`);
      else res.end('{"reports":[]}');
    });
    await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
    port = (server.address() as AddressInfo).port;
  });
  afterAll(async () => {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server.close(() => resolve()));
    await api.close();
  });
  beforeEach(() => {
    hits = [];
    handler = null;
  });

  interface Seeded {
    organizationId: string;
    campaignId: string;
  }

  /** An Organization with `host` verified, Rules of Engagement that cover it, and a queued Campaign. */
  async function seed(host = HOST, exclusions: string[] = []): Promise<Seeded> {
    const organizationId = (await createOrganization(api, `Review ${++n}`)).organization.id;
    const targetId = newId("tgt");
    const roeId = newId("roe");
    const campaignId = newId("cmp");
    const token = generateVerificationToken();
    tokens.set(campaignId, token);
    await api.db.tx({ organizationId }, async (q) => {
      await insertTarget(q, { organizationId, id: targetId, host, token, createdAt: now() });
      await recordCheck(q, targetId, { verified: true, method: "file" }, now());
      await insertVersion(q, {
        organizationId,
        id: roeId,
        content: {
          scope: [targetId],
          exclusions,
          intensity: "safe-active",
          window: { days: ["mon", "tue", "wed", "thu", "fri", "sat", "sun"], from: "00:00", to: "24:00" },
          contacts: ["s@acme.test"],
        },
        signedBy: KEY,
        signedAt: now(),
        contentSha256: "a".repeat(64),
      });
      await insertCampaign(q, {
        organizationId,
        id: campaignId,
        targetId,
        host,
        roeId,
        roeSha256: "a".repeat(64),
        intensity: "safe-active",
        engine: STAND_IN_ENGINE,
        createdBy: KEY,
        createdAt: now(),
      });
    });
    return { organizationId, campaignId };
  }

  const resolver: Resolver = { txt: async () => [], addresses: async () => ["127.0.0.1"] };
  const runner = (db: Db, engine: CampaignEngineRunner | undefined, minSpacingMs = 15) =>
    createCampaignRunner({
      db,
      enabled: true,
      resolver,
      authorize: createAuthorize({ db, now }),
      now,
      logger: silent,
      engine,
      // Fourth review (D-110): what the scripted engines of this file may send, beside the stand-in's own catalog.
      probes: [
        ...standInEngine.probes,
        ...Array.from({ length: 40 }, (_, i) => ({ method: "GET" as const, path: `/p${i}` })),
      ],
      testing: { ca: fixture("ca.pem"), port, allowLoopback: true, minSpacingMs, requestTimeoutMs: 1000 },
    });
  const read = (s: Seeded) => api.db.tx({ organizationId: s.organizationId }, (q) => findCampaign(q, s.campaignId));
  const audited = async (s: Seeded) =>
    (await api.db.tx({ organizationId: s.organizationId }, (q) => auditEntriesAfter(q, 0, 100))).filter(
      (entry) => entry.target.id === s.campaignId,
    );
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
  const waitFor = async (condition: () => boolean | Promise<boolean>) => {
    const started = Date.now();
    while (!(await condition())) {
      if (Date.now() - started > 5000) throw new Error("timed out");
      await sleep(10);
    }
  };

  const requests = (s: Seeded) =>
    api.db.tx({ organizationId: s.organizationId }, (q) => listCampaignRequests(q, s.campaignId));
  const findings = (s: Seeded) =>
    api.db.tx({ organizationId: s.organizationId }, (q) => listCampaignFindings(q, s.campaignId));

  /** A target with every seeded weakness of the catalog; `tail` is appended to every body. */
  const weak =
    (tail: string) =>
    (req: IncomingMessage, res: ServerResponse): void => {
      const url = new URL(req.url ?? "/", "https://x");
      const token = tokens.get(String(req.headers["x-airverse-campaign"]));
      if (url.pathname === VERIFICATION_FILE_PATH) return void res.end(`${token}\n`);
      if (url.pathname === "/api/orders/x") {
        res.statusCode = 500;
        return void res.end(`Error: boom\n    at handler (/srv/app/orders.js:10:5)\n${tail}`);
      }
      if (url.pathname === "/api/admin/reports") return void res.end(`{"reports":[{"id":1}]}${tail}`);
      if (url.pathname === "/api/orders/1001") return void res.end(`{"order_id":1001}${tail}`);
      if (url.pathname === "/search") return void res.end(`<p>${url.searchParams.get("q")}</p>${tail}`);
      if (url.pathname === "/go") {
        res.writeHead(302, { location: String(url.searchParams.get("to")) });
        return void res.end();
      }
      res.end(`<html>home</html>${tail}`);
    };

  it("control: the real engine reports all six seeded weaknesses", async () => {
    const s = await seed();
    handler = weak("");
    const started = runner(api.db, undefined);
    await started.start();
    await started.idle();
    await started.stop();
    expect(await read(s)).toMatchObject({
      status: "completed",
      checks: { ran: 6, reported: 6, inconclusive: 0, skipped: 0 },
    });
    expect((await findings(s)).map((f) => `${f.check_id} ${f.state}`)).toEqual([
      "RW-01 confirmed",
      "RW-02 confirmed",
      "RW-03 confirmed",
      "RW-04 confirmed",
      "RW-05 confirmed",
      "RW-06 confirmed",
    ]);
  }, 30_000);

  it("F: one NUL byte in a body must not turn a check into 'ran, nothing reported'", async () => {
    const s = await seed();
    handler = weak("\u0000");
    const started = runner(api.db, undefined);
    await started.start();
    await started.idle();
    await started.stop();
    const campaign = await read(s);
    const stored = (await findings(s)).map((f) => f.check_id);
    // Four checks could not read their response body: they are inconclusive — not Findings, not "ran, nothing
    // reported", not skipped. The Campaign still completes, and its end says how many and why.
    expect(campaign).toMatchObject({
      status: "completed",
      end_reason: "checks_complete",
      checks: { ran: 2, reported: 2, inconclusive: 4, skipped: 0 },
      findings_dropped: 0,
    });
    expect(stored).toEqual(["RW-01", "RW-06"]);
    expect(campaign?.checks?.ran).toBe(stored.length);
    expect((await audited(s)).at(-1)?.summary).toContain(
      "4 were inconclusive (4 responses could not be read as text or in full)",
    );
  }, 30_000);

  it("F: a Finding whose write fails after a stop is not silently lost", async () => {
    const s = await seed();
    handler = weak("");
    let inserting = 0;
    const db = new Proxy(api.db, {
      get(target, property) {
        if (property === "tx") {
          return (scope: unknown, fn: (q: unknown) => unknown) =>
            (target.tx as (s: unknown, f: (q: unknown) => unknown) => unknown)(scope, (q) =>
              fn(
                new Proxy(q as object, {
                  get(inner, name) {
                    if (name === "query") {
                      return async (sql: string, params?: unknown[]) => {
                        if (/INSERT INTO campaign_findings/.test(sql)) {
                          inserting++;
                          await sleep(300);
                          throw new Error("could not extend file: No space left on device");
                        }
                        return (inner as { query: (s: string, p?: unknown[]) => unknown }).query(sql, params);
                      };
                    }
                    const value = Reflect.get(inner, name);
                    return typeof value === "function" ? value.bind(inner) : value;
                  },
                }),
              ),
            );
        }
        const value = Reflect.get(target, property);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as Db;
    const started = runner(db, undefined, 1000);
    await started.start();
    await waitFor(() => inserting === 1);
    // The owner's stop arrives while the Finding is being written.
    await started.abort(s.campaignId, "owner_stop");
    await sleep(600);
    await started.stop();
    const campaign = await read(s);
    const stored = (await findings(s)).map((f) => f.check_id);
    expect(campaign).toMatchObject({ status: "stopped", end_reason: "owner_stop" });
    expect((await audited(s)).at(-1)?.summary).toContain("1 Finding could not be stored");
    expect(inserting).toBe(1);
    expect(stored).toEqual([]);
    // The engine reported one Finding and it is not stored: the Campaign must say so.
    expect(campaign?.findings_dropped).toBe(1);
  }, 30_000);

  it("sound? at most 60 requests in all, across a shutdown during the ownership check, the ownership checks included", async () => {
    const s = await seed();
    const held: ServerResponse[] = [];
    handler = (_req, res) => void held.push(res);
    const greedy: CampaignEngineRunner = async (options) => {
      for (let i = 0; i < 100; i++) {
        // Forty declared paths, asked for again and again (a catalog holds at most 64 probes).
        const exchange = (await options.request({ method: "GET", path: `/p${i % 40}` })) as CampaignExchange;
        if (!exchange.ok && "refused" in exchange && exchange.fatal) return;
      }
    };
    for (let restart = 0; restart < 3; restart++) {
      const cut = runner(api.db, greedy, 1);
      await cut.start();
      await waitFor(() => hits.length === restart + 1);
      await cut.stop();
      expect((await read(s))?.status).toBe("queued");
    }
    for (const res of held) res.destroy();
    handler = null;
    const last = runner(api.db, greedy, 1);
    await last.start();
    await last.idle();
    await last.stop();
    const campaign = await read(s);
    const log = await requests(s);
    expect(hits.length).toBeLessThanOrEqual(60);
    expect(campaign?.requests_sent).toBe(60);
    expect(campaign).toMatchObject({ status: "failed", end_reason: "request_budget" });
    expect(log.map((r) => r.seq)).toEqual(Array.from({ length: log.length }, (_, i) => i + 1));
  }, 30_000);

  it("sound? Rules that exclude the ownership file in any spelling: nothing is fetched", async () => {
    const SPELLINGS = [
      "/",
      "/.well-known",
      "/.WELL-KNOWN",
      "/.well-known/",
      "/.Well-Known/Airverse-Verification.TXT",
      "/.well-known/airverse-verification.txt",
      "/.well-known/airverse-verification.txt/",
      "/%2ewell-known",
      "/%2Ewell-known/airverse-verification%2Etxt",
      "//.well-known",
      "/.well-known/.",
      "/x/../.well-known",
      "/.well-known;x",
      "/.well-known/airverse-verification.txt;v=1",
      "/.well-known./",
      "\\.well-known",
      "/.well-known/airverse-verification.txt::$DATA",
      "/.well%2dknown",
      "/%252ewell-known",
    ];
    const seeded: Seeded[] = [];
    for (const exclusion of SPELLINGS) seeded.push(await seed(HOST, [exclusion]));
    const started = runner(api.db, async () => {});
    await started.start();
    await started.idle();
    await started.stop();
    const outcomes: string[] = [];
    for (const [index, s] of seeded.entries()) {
      const campaign = await read(s);
      outcomes.push(
        `${SPELLINGS[index]} -> ${campaign?.status} ${campaign?.end_reason} sent=${campaign?.requests_sent}`,
      );
    }
    expect(hits).toEqual([]);
    expect(outcomes.filter((line) => !line.endsWith("refused verification_path_excluded sent=0"))).toEqual([]);
  }, 60_000);

  it("sound? siblings of the ownership path do not block it", async () => {
    const s = await seed(HOST, [
      "/.well-known/airverse-verification",
      "/.well-known/other",
      "/.well",
      "/well-known",
      "/.well-known/airverse-verification.txt.bak",
    ]);
    const started = runner(api.db, async () => {});
    await started.start();
    await started.idle();
    await started.stop();
    expect((await read(s))?.status).toBe("completed");
  });

  it("the token must be the whole body: a body that merely contains it does not pass", async () => {
    const BODIES = (token: string) => [
      `<html>${token}</html>`,
      `token=${token}`,
      `${token} ${token}`,
      `x\n${token}`,
      `${token}\nx`,
      `"${token}"`,
      token.toUpperCase(),
      token.slice(0, -1),
      `${token}\u0000`,
      `﻿${token}x`,
    ];
    const seeded: Seeded[] = [];
    const count = BODIES("x").length;
    for (let i = 0; i < count; i++) seeded.push(await seed());
    handler = (req, res) => {
      const id = String(req.headers["x-airverse-campaign"]);
      const index = seeded.findIndex((s) => s.campaignId === id);
      res.end(BODIES(tokens.get(id) ?? "")[index]);
    };
    let engineRuns = 0;
    const started = runner(api.db, async () => void engineRuns++);
    await started.start();
    await started.idle();
    await started.stop();
    const statuses = [];
    for (const s of seeded) statuses.push(`${(await read(s))?.status} ${(await read(s))?.end_reason}`);
    expect(engineRuns).toBe(0);
    expect(new Set(statuses)).toEqual(new Set(["refused target_not_verified"]));
  }, 60_000);

  it("F: the request role cannot add to or change the history of a Campaign that ended", async () => {
    const s = await seed();
    const started = runner(api.db, async (options) => {
      const exchange = (await options.request({ method: "GET", path: "/api/admin/reports" })) as CampaignExchange;
      await options.onFinding({
        check_id: "RW-03",
        path: "/api/admin/reports",
        title: "Admin data",
        severity: "high",
        seq: exchange.ok ? exchange.seq : 0,
        window: "",
      });
    });
    await started.start();
    await started.idle();
    await started.stop();
    const before = await read(s);
    expect(before).toMatchObject({ status: "completed", requests_sent: 2 });
    const tenant = <T>(sql: string, params: unknown[] = []) =>
      api.db
        .tx({ organizationId: s.organizationId }, (q) => q.query(sql, params))
        .then(
          () => "accepted",
          (error: { code?: string }) => `refused ${error.code}`,
        ) as Promise<T | string>;
    const results = {
      insertRequest: await tenant(
        `INSERT INTO campaign_requests (organization_id, campaign_id, seq, at, method, target, outcome)
         VALUES ($1, $2, 150, now(), 'GET', '/never-sent', 'sending')`,
        [s.organizationId, s.campaignId],
      ),
      insertRefusal: await tenant(
        `INSERT INTO campaign_requests (organization_id, campaign_id, seq, at, method, target, outcome, reason)
         VALUES ($1, $2, 151, now(), 'GET', '/x', 'refused', 'owner_stop')`,
        [s.organizationId, s.campaignId],
      ),
      insertFinding: await tenant(
        `INSERT INTO campaign_findings (organization_id, campaign_id, check_id, path, title, severity, state, evidence, first_seen_at, last_seen_at)
         VALUES ($1, $2, 'RW-04', '/later', 'Added later', 'high', 'confirmed', '{}'::jsonb, now(), now())`,
        [s.organizationId, s.campaignId],
      ),
      rewriteEvidence: await tenant(
        `UPDATE campaign_findings SET evidence = '{"excerpt":"rewritten"}'::jsonb, state = 'confirmed' WHERE campaign_id = $1`,
        [s.campaignId],
      ),
      deleteRequest: await tenant("DELETE FROM campaign_requests WHERE campaign_id = $1", [s.campaignId]),
      deleteFinding: await tenant("DELETE FROM campaign_findings WHERE campaign_id = $1", [s.campaignId]),
      seq201: await tenant(
        `INSERT INTO campaign_requests (organization_id, campaign_id, seq, at, method, target, outcome)
         VALUES ($1, $2, 201, now(), 'GET', '/x', 'sending')`,
        [s.organizationId, s.campaignId],
      ),
      unsettle: await tenant("UPDATE campaign_requests SET outcome = 'sending' WHERE campaign_id = $1 AND seq = 1", [
        s.campaignId,
      ]),
      retarget: await tenant("UPDATE campaign_requests SET target = '/x' WHERE campaign_id = $1 AND seq = 1", [
        s.campaignId,
      ]),
    };
    const after = await read(s);
    expect(results).toMatchObject({
      deleteRequest: expect.stringMatching(/^refused/),
      deleteFinding: expect.stringMatching(/^refused/),
      seq201: expect.stringMatching(/^refused/),
      unsettle: expect.stringMatching(/^refused/),
      retarget: expect.stringMatching(/^refused/),
    });
    expect(after?.requests_sent).toBe(before?.requests_sent);
    expect(results.insertFinding).toMatch(/^refused/);
    expect(results.rewriteEvidence).toMatch(/^refused/);
    expect(results.insertRequest).toMatch(/^refused/);
    expect(results.insertRefusal).toMatch(/^refused/);
    expect(after).toEqual(before);
    expect((await findings(s)).map((f) => `${f.check_id} ${f.path} ${f.state}`)).toEqual([
      "RW-03 /api/admin/reports unverified",
    ]);
  }, 30_000);

  it("unreproduced, kept: younger Campaigns are not starved behind ones this process cannot launch", async () => {
    // Three older Campaigns of Organizations whose deletion is pending (they stay queued), then one that can run.
    const stuck: Seeded[] = [];
    for (let i = 0; i < 3; i++) {
      const s = await seed(`stuck-${i}.acme-shop.io`);
      stuck.push(s);
      await api.db.owner((q) =>
        q.query(
          `INSERT INTO organization_deletions (id, organization_id, organization_name, requested_at, requested_by,
             reason, purge_after)
           VALUES ($1, $2, 'x', $3, $4, 'r', $5)`,
          [newId("del"), s.organizationId, now(), KEY, new Date(T0 + 30 * 86_400_000)],
        ),
      );
    }
    const young = await seed();
    let engineRuns = 0;
    const started = createCampaignRunner({
      db: api.db,
      enabled: true,
      resolver,
      authorize: createAuthorize({ db: api.db, now }),
      now,
      logger: silent,
      engine: async () => void engineRuns++,
      testing: { ca: fixture("ca.pem"), port, allowLoopback: true, minSpacingMs: 1, requestTimeoutMs: 1000 },
      // The queue is read two at a time here: the three that cannot start fill more than a page.
      queuePage: 2,
    });
    await started.start();
    await started.idle();
    await started.stop();
    expect((await read(young))?.status).toBe("completed");
    expect(engineRuns).toBe(1);
    for (const s of stuck) expect((await read(s))?.status).toBe("queued");
  });
});
