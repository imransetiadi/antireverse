import { randomUUID } from "node:crypto";
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
import {
  findCampaign,
  insertCampaign,
  listCampaignFindings,
  listCampaignRequests,
  requestStop,
  setKillSwitch,
} from "../src/stores/campaigns.ts";
import { insertVersion } from "../src/stores/rules-of-engagement.ts";
import { insertTarget, recordCheck } from "../src/stores/targets.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 15a, fourth independent safety review: the runner against a real local TLS target (loopback, test CA). An
// engine that carries a response out through its own probes (R1, D-110), the operator's stop while the queue moves
// (R2), a stop that lands while the last Finding is stored (R3), and a deletion requested while a Campaign runs.

const fixture = (name: string) => readFileSync(new URL(`./fixtures/prove-tls/${name}`, import.meta.url), "utf8");
const HOST = "shop.acme-shop.io";
const T0 = Date.parse("2026-11-16T10:00:00.000Z");
const KEY = "key_0123456789abcdef01234567";
const now = () => new Date(T0);
const silent = { info() {}, warn() {} };
const BODY = Array.from({ length: 300 }, (_, i) => `secret${String(i).padStart(3, "0")}`).join("");

describe("review4 15a: the runner", () => {
  let api: TestApi;
  let server: Server;
  let port = 0;
  let hits: string[] = [];
  const tokens = new Map<string, string>();
  let handler: ((req: IncomingMessage, res: ServerResponse) => void) | null = null;
  let n = 0;

  beforeAll(async () => {
    api = await makeTestApi({ now });
    server = createServer({ key: fixture("key.pem"), cert: fixture("cert.pem") }, (req, res) => {
      hits.push(`${req.method} ${req.url}`);
      if (handler !== null) return handler(req, res);
      const token = tokens.get(String(req.headers["x-airverse-campaign"]));
      if (req.url === VERIFICATION_FILE_PATH && token !== undefined) res.end(`${token}\n`);
      else res.end(`{"reports":[]}${BODY}`);
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
  async function seed(host = HOST, createdAt = now()): Promise<Seeded> {
    const organizationId = (await createOrganization(api, `Review4 ${++n}`)).organization.id;
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
          exclusions: [],
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
        createdAt,
      });
    });
    return { organizationId, campaignId };
  }

  /** `hang.acme-shop.io` never resolves: a Campaign for it stays in its start checks. */
  const resolver: Resolver = {
    txt: async () => [],
    addresses: (host) => (host.startsWith("hang.") ? new Promise<string[]>(() => {}) : Promise.resolve(["127.0.0.1"])),
  };
  const runner = (engine: CampaignEngineRunner | undefined, db: Db = api.db) =>
    createCampaignRunner({
      db,
      enabled: true,
      resolver,
      authorize: createAuthorize({ db, now }),
      now,
      logger: silent,
      engine,
      testing: { ca: fixture("ca.pem"), port, allowLoopback: true, minSpacingMs: 5, requestTimeoutMs: 2000 },
    });
  const read = (s: Seeded) => api.db.tx({ organizationId: s.organizationId }, (q) => findCampaign(q, s.campaignId));
  const audited = async (s: Seeded) =>
    (await api.db.tx({ organizationId: s.organizationId }, (q) => auditEntriesAfter(q, 0, 100))).filter(
      (entry) => entry.target.id === s.campaignId,
    );
  const requests = (s: Seeded) =>
    api.db.tx({ organizationId: s.organizationId }, (q) => listCampaignRequests(q, s.campaignId));
  const findings = (s: Seeded) =>
    api.db.tx({ organizationId: s.organizationId }, (q) => listCampaignFindings(q, s.campaignId));
  const sleep = (ms: number) => new Promise((resolve) => setTimeout(resolve, ms));
  const waitFor = async (condition: () => boolean | Promise<boolean>) => {
    const started = Date.now();
    while (!(await condition())) {
      if (Date.now() - started > 4000) throw new Error("timed out");
      await sleep(5);
    }
  };
  /** The database, with `onQuery` told each statement of an Organization's transactions before it runs. */
  function hooked(onQuery: (sql: string) => void): Db {
    return new Proxy(api.db, {
      get(target, property) {
        if (property === "tx") {
          return (scope: unknown, fn: (q: unknown) => unknown) =>
            (target.tx as (s: unknown, f: (q: unknown) => unknown) => unknown)(scope, (q) =>
              fn({
                query: (sql: string, params?: unknown[]) => {
                  onQuery(sql);
                  return (q as { query: (s: string, p?: unknown[]) => unknown }).query(sql, params);
                },
              }),
            );
        }
        const value = Reflect.get(target, property);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as Db;
  }

  it("R1: the review's engine — a response carried out as refused paths and query values — keeps none of it", async () => {
    const s = await seed();
    const answers: CampaignExchange[] = [];
    const started = runner(async (options) => {
      const first = (await options.request({ method: "GET", path: "/api/admin/reports" })) as CampaignExchange;
      const body = first.ok ? first.body : "";
      for (let i = 0; i < 8; i++) {
        answers.push(await options.request({ method: "TRACE", path: body.slice(i * 256, (i + 1) * 256) }));
      }
      answers.push(
        await options.request({
          method: "GET",
          path: "/search",
          query: { a: body.slice(0, 320), b: body.slice(320, 640) },
        }),
      );
      await options.onFinding({
        check_id: "RW-05",
        path: "/search",
        title: "Marker reflected unencoded",
        severity: "medium",
        seq: 11,
        window: "",
      });
    });
    await started.start();
    await started.idle();
    await started.stop();
    const campaign = await read(s);
    const log = await requests(s);
    expect(hits).toEqual([`GET ${VERIFICATION_FILE_PATH}`, "GET /api/admin/reports"]);
    // The first probe that is not of the catalog ended the Campaign: not `completed`.
    expect(campaign).toMatchObject({
      status: "failed",
      end_reason: "method_not_allowed",
      requests_sent: 2,
      requests_refused: 1,
    });
    expect(answers[0]).toEqual({ ok: false, refused: "method_not_allowed", fatal: true });
    expect(log.map((row) => [row.outcome, row.method, row.target, row.asked_chars])).toEqual([
      ["sent", "GET", VERIFICATION_FILE_PATH, null],
      ["sent", "GET", "/api/admin/reports", null],
      ["refused", "OTHER", null, 256],
    ]);
    const kept = JSON.stringify([campaign, log, await findings(s), await audited(s)]);
    expect(kept).not.toMatch(/secret\d/);
    expect(await findings(s)).toEqual([]);
  }, 30_000);

  it("R1: the catalog is the engine's definition on the host side — a running engine cannot add to it", async () => {
    const s = await seed();
    let tried: unknown;
    let answer: unknown;
    const started = runner(async (options) => {
      try {
        (standInEngine.probes as unknown as unknown[]).push({ method: "GET", path: "/later" });
      } catch (error) {
        tried = error;
      }
      // Nothing an engine is handed names the catalog.
      expect(Object.keys(options).sort()).toEqual(["intensity", "onCheck", "onFinding", "request", "signal"]);
      answer = await options.request({ method: "GET", path: "/later" });
    });
    await started.start();
    await started.idle();
    await started.stop();
    expect(tried).toBeInstanceOf(TypeError);
    expect(answer).toEqual({ ok: false, refused: "not_in_catalog", fatal: true });
    expect(hits).toEqual([`GET ${VERIFICATION_FILE_PATH}`]);
    expect(await read(s)).toMatchObject({ status: "failed", end_reason: "not_in_catalog" });
  }, 30_000);

  it("R2: a kill with two active Campaigns and one queued — each gets one operator entry, and the count is three", async () => {
    // Oldest first: one that hangs in its start checks (its name never resolves), one that runs, one that waits for
    // a free slot (two run at once in all).
    const hung = await seed("hang.acme-shop.io", new Date(T0 - 3000));
    const running = await seed(HOST, new Date(T0 - 2000));
    const queued = await seed("later.acme-shop.io", new Date(T0 - 1000));
    let engines = 0;
    const started = runner(async (options) => {
      engines++;
      await new Promise<void>((resolve) => options.signal?.addEventListener("abort", () => resolve(), { once: true }));
      throw new Error("stopped");
    });
    await started.start();
    await waitFor(() => engines === 1);
    expect(started.isActive(hung.campaignId)).toBe(true);
    expect((await read(queued))?.status).toBe("queued");
    await api.db.tx("none", (q) => setKillSwitch(q, true, now(), "review4"));
    let stopped: number;
    try {
      stopped = await started.operatorStop({
        reason: "operator_kill",
        requestId: randomUUID(),
        operatorReason: "review4",
      });
      await started.idle();
    } finally {
      await api.db.tx("none", (q) => setKillSwitch(q, false, now(), "review4 over"));
    }
    await started.stop();
    for (const s of [hung, running, queued]) {
      expect(await read(s)).toMatchObject({ status: "stopped", end_reason: "operator_kill" });
      const entries = (await audited(s)).filter((entry) => entry.action === "campaign.operator_kill");
      expect(entries.map((entry) => entry.actor.kind)).toEqual(["operator"]);
    }
    expect(stopped).toBe(3);
    expect(engines).toBe(1);
  }, 30_000);

  it("R2: while the operator's stop is at work, nothing new is launched; afterwards the queue moves again", async () => {
    const running = await seed(HOST, new Date(T0 - 2000));
    let engines = 0;
    const started = runner(async (options) => {
      engines++;
      await new Promise<void>((resolve) => options.signal?.addEventListener("abort", () => resolve(), { once: true }));
      throw new Error("stopped");
    });
    await started.start();
    await waitFor(() => engines === 1);
    // A suspension of another Organization: this one's Campaign is not touched, and the queue is held meanwhile.
    const other = started.operatorStop({
      reason: "organization_suspended",
      organizationId: "org_ffffffffffffffffffffffff",
      requestId: randomUUID(),
      operatorReason: "review4",
    });
    started.wake();
    expect(await other).toBe(0);
    expect((await read(running))?.status).toBe("running");
    await started.abort(running.campaignId, "owner_stop");
    // Released: a Campaign queued now is taken.
    const next = await seed(HOST, new Date(T0 - 1000));
    started.wake();
    await waitFor(() => engines === 2);
    await started.stop();
    expect((await read(next))?.status).toBe("interrupted");
  }, 30_000);

  for (const who of ["owner", "operator"] as const) {
    it(`R3: the ${who}'s stop while the last Finding is being stored — the Campaign ends stopped, not completed`, async () => {
      const s = await seed();
      let fired = false;
      let stopping: Promise<unknown> = Promise.resolve();
      // The stop lands on the first INSERT of a Finding: the engine has asked for everything and is about to be done.
      const db = hooked((sql) => {
        if (fired || !/INSERT INTO campaign_findings/.test(sql)) return;
        fired = true;
        stopping =
          who === "owner"
            ? api.db
                .tx({ organizationId: s.organizationId }, (q) =>
                  requestStop(q, s.campaignId, { keyId: KEY, reason: "stop", at: now() }),
                )
                .then(() => started.abort(s.campaignId, "owner_stop"))
            : started.operatorStop({ reason: "operator_kill", requestId: randomUUID(), operatorReason: "review4" });
      });
      const started = runner(async (options) => {
        const exchange = (await options.request({ method: "GET", path: "/api/admin/reports" })) as CampaignExchange;
        options.onCheck({ id: "RW-03", result: "reported" });
        await options.onFinding({
          check_id: "RW-03",
          path: "/api/admin/reports",
          title: "t",
          severity: "high",
          seq: exchange.ok ? exchange.seq : 0,
          window: '"reports"',
        });
      }, db);
      await started.start();
      await waitFor(() => fired);
      const result = await stopping;
      await started.idle();
      await started.stop();
      const campaign = await read(s);
      const reason = who === "owner" ? "owner_stop" : "operator_kill";
      expect(campaign).toMatchObject({ status: "stopped", end_reason: reason });
      // What it did is still said: the check that ran, and its Finding.
      expect(campaign?.checks).toMatchObject({ ran: 1, reported: 1 });
      expect((await findings(s)).map((f) => f.check_id)).toEqual(["RW-03"]);
      expect((await audited(s)).map((entry) => entry.action)).toContain("campaign.end");
      if (who === "operator") {
        expect(result).toBe(1);
        expect((await audited(s)).filter((entry) => entry.action === "campaign.operator_kill")).toHaveLength(1);
      }
    }, 30_000);
  }

  it("a deletion requested while a Campaign runs: `cut` aborts that Organization's Campaign at once, and no other's", async () => {
    const s = await seed();
    let signal: AbortSignal | undefined;
    const started = runner(async (options) => {
      signal = options.signal;
      await new Promise<void>((resolve) => options.signal?.addEventListener("abort", () => resolve(), { once: true }));
      throw new Error("stopped");
    });
    await started.start();
    await waitFor(() => signal !== undefined);
    started.cut("org_ffffffffffffffffffffffff", "deletion_pending");
    expect(signal?.aborted).toBe(false);
    started.cut(s.organizationId, "deletion_pending");
    // Synchronously: nothing is awaited between the call and the abort.
    expect(signal?.aborted).toBe(true);
    await started.idle();
    await started.stop();
    expect(await read(s)).toMatchObject({ status: "stopped", end_reason: "deletion_pending" });
  }, 30_000);
});
