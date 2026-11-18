import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { STAND_IN_ENGINE, VERIFICATION_FILE_PATH } from "@antireverse/protocol";
import { generateVerificationToken, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { type CampaignEngineRunner, createCampaignRunner } from "../src/campaign/runner.ts";
import type { Db } from "../src/db/db.ts";
import { createAuthorize } from "../src/prove/authorize.ts";
import type { Resolver } from "../src/prove/verify.ts";
import { auditEntriesAfter } from "../src/stores/audit.ts";
import {
  endCampaign,
  findCampaign,
  insertCampaign,
  listCampaignFindings,
  setKillSwitch,
} from "../src/stores/campaigns.ts";
import { insertVersion } from "../src/stores/rules-of-engagement.ts";
import { insertTarget, recordCheck } from "../src/stores/targets.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 15a, sixth independent safety review: the runner against a real local TLS target (loopback, test CA). An end
// that cannot be written at first (F1), a deletion request whose cut cannot read the queue (F2, D-112), a kill that
// would sign for an earlier kill's Campaign (F6), and an engine that ignores its abort.

const fixture = (name: string) => readFileSync(new URL(`./fixtures/prove-tls/${name}`, import.meta.url), "utf8");
const HOST = "shop.acme-shop.io";
const T0 = Date.parse("2026-11-16T10:00:00.000Z");
const KEY = "key_0123456789abcdef01234567";
const now = () => new Date(T0);
const silent = { info() {}, warn() {} };
const BODY = Array.from({ length: 300 }, (_, i) => `secret${String(i).padStart(3, "0")}`).join("");

describe("review6 15a: the runner", () => {
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
    const organizationId = (await createOrganization(api, `Review6 ${++n}`)).organization.id;
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
  const runner = (engine: CampaignEngineRunner | undefined, db: Db = api.db, abortWaitMs?: number) =>
    createCampaignRunner({
      db,
      enabled: true,
      resolver,
      authorize: createAuthorize({ db, now }),
      now,
      logger: silent,
      engine,
      testing: {
        ca: fixture("ca.pem"),
        port,
        allowLoopback: true,
        minSpacingMs: 5,
        requestTimeoutMs: 2000,
        ...(abortWaitMs === undefined ? {} : { abortWaitMs }),
      },
    });
  const read = (s: Seeded) => api.db.tx({ organizationId: s.organizationId }, (q) => findCampaign(q, s.campaignId));
  const audited = async (s: Seeded) =>
    (await api.db.tx({ organizationId: s.organizationId }, (q) => auditEntriesAfter(q, 0, 100))).filter(
      (entry) => entry.target.id === s.campaignId,
    );
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
  function hooked(onQuery: (sql: string, params?: unknown[]) => void): Db {
    return new Proxy(api.db, {
      get(target, property) {
        if (property === "tx") {
          return (scope: unknown, fn: (q: unknown) => unknown) =>
            (target.tx as (s: unknown, f: (q: unknown) => unknown) => unknown)(scope, (q) =>
              fn({
                query: (sql: string, params?: unknown[]) => {
                  onQuery(sql, params);
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

  const operatorEntries = async (s: Seeded) =>
    (await audited(s)).filter((entry) => entry.action === "campaign.operator_kill").length;
  const kill = (started: ReturnType<typeof runner>) =>
    started.operatorStop({ reason: "operator_kill", requestId: randomUUID(), operatorReason: "review6" });
  /** The target with every seeded weakness of the stand-in's catalog. */
  const weak = (req: IncomingMessage, res: ServerResponse): void => {
    const url = new URL(req.url ?? "/", "https://x");
    const token = tokens.get(String(req.headers["x-airverse-campaign"]));
    if (url.pathname === VERIFICATION_FILE_PATH) return void res.end(`${token}\n`);
    if (url.pathname === "/go") {
      res.writeHead(302, { location: String(url.searchParams.get("to")) });
      return void res.end();
    }
    if (url.pathname === "/api/orders/x") {
      res.statusCode = 500;
      return void res.end("Error: boom\n    at handler (/srv/app/orders.js:10:5)\n");
    }
    if (url.pathname === "/api/admin/reports") return void res.end('{"reports":[{"id":1}]}');
    if (url.pathname === "/api/orders/1001") return void res.end('{"order_id":1001}');
    if (url.pathname === "/search") return void res.end(`<p>${url.searchParams.get("q")}</p>`);
    res.end("<html>home</html>");
  };
  /** The database, failing the first write of the Campaign's end (`UPDATE campaigns SET status = $2`). */
  function endFailsOnce(): { db: Db; failed: () => boolean } {
    let failed = false;
    return {
      db: hooked((sql) => {
        if (!failed && /UPDATE campaigns SET status = \$2/.test(sql)) {
          failed = true;
          throw new Error("could not write: disk full");
        }
      }),
      failed: () => failed,
    };
  }

  it("F1: the end cannot be written at first — the same end is written again: six Findings, their counts, completed", async () => {
    const s = await seed();
    handler = weak;
    const { db, failed } = endFailsOnce();
    const started = runner(undefined, db);
    await started.start();
    await started.idle();
    await started.stop();
    expect(failed()).toBe(true);
    expect((await findings(s)).map((f) => f.check_id)).toEqual(["RW-01", "RW-02", "RW-03", "RW-04", "RW-05", "RW-06"]);
    // It had ended failed (engine_error) with no counts beside six stored Findings.
    expect(await read(s)).toMatchObject({
      status: "completed",
      end_reason: "checks_complete",
      checks: { ran: 6, reported: 6, inconclusive: 0, skipped: 0 },
      findings_dropped: 0,
    });
  }, 30_000);

  it("F1: under a kill — the Campaign ends as stopped by the operator, with its counts; the entry is written and counted", async () => {
    const s = await seed();
    const { db, failed } = endFailsOnce();
    let asked = false;
    const started = runner(async (options) => {
      await options.request({ method: "GET", path: "/" });
      options.onCheck({ id: "RW-01", result: "clean" });
      asked = true;
      if (options.signal?.aborted !== true) {
        await new Promise<void>((resolve) =>
          options.signal?.addEventListener("abort", () => resolve(), { once: true }),
        );
      }
      throw new Error("stopped");
    }, db);
    await started.start();
    await waitFor(() => asked);
    await api.db.tx("none", (q) => setKillSwitch(q, true, now(), "review6"));
    let first = -1;
    let again = -1;
    try {
      first = await kill(started);
      again = await kill(started);
    } finally {
      await api.db.tx("none", (q) => setKillSwitch(q, false, now(), "review6 over"));
    }
    await started.stop();
    expect(failed()).toBe(true);
    expect(await read(s)).toMatchObject({
      status: "stopped",
      end_reason: "operator_kill",
      checks: { ran: 1, reported: 0, inconclusive: 0, skipped: 5 },
    });
    expect([first, again]).toEqual([1, 0]);
    expect(await operatorEntries(s)).toBe(1);
  }, 30_000);

  it("F1: an end that can never be written leaves the Campaign for the next process, as before", async () => {
    const s = await seed();
    const db = hooked((sql) => {
      if (/UPDATE campaigns SET status = \$2/.test(sql)) throw new Error("could not write: disk full");
    });
    const started = runner(async () => {}, db);
    await started.start();
    await started.idle();
    await started.stop();
    expect((await read(s))?.status).toBe("running");
    // (Ended here, so that it is not the next test's to stop.)
    await api.db.tx({ organizationId: s.organizationId }, (q) =>
      endCampaign(q, s.campaignId, { reason: "owner_stop", started: true, checks: null, at: now() }),
    );
  }, 30_000);

  it("F2 (D-112): the cut cannot read the queue — it does not reject, and the Organization's Campaign is still ended", async () => {
    const hung = await seed("hang.acme-shop.io");
    let failing = true;
    const db = hooked(() => {});
    // Every read of the queue fails (it is read outside any Organization's transaction).
    const broken = new Proxy(db, {
      get(target, property) {
        if (property === "tx") {
          return (scope: unknown, fn: (q: unknown) => unknown) =>
            failing && scope === "none"
              ? Promise.reject(new Error("the queue is not readable"))
              : (target.tx as (s: unknown, f: (q: unknown) => unknown) => unknown)(scope, fn);
        }
        const value = Reflect.get(target, property);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as Db;
    const started = runner(async () => {}, broken);
    failing = false;
    await started.start();
    await waitFor(() => started.isActive(hung.campaignId));
    failing = true;
    await expect(started.cut(hung.organizationId, "deletion_pending")).resolves.toBeUndefined();
    failing = false;
    expect(await read(hung)).toMatchObject({ status: "stopped", end_reason: "deletion_pending", requests_sent: 0 });
    await started.stop();
  }, 30_000);

  it("F2 (D-112): a queued Campaign whose Organization's deletion is pending is ended by the queue, not skipped", async () => {
    // However it came to be queued under a pending deletion (the route's cut failed; another process recorded it).
    const s = await seed();
    await api.db.owner((q) =>
      q.query(
        `INSERT INTO organization_deletions (id, organization_id, organization_name, requested_at, requested_by,
           reason, purge_after)
         VALUES ($1, $2, 'x', $3, $4, 'r', $5)`,
        [newId("del"), s.organizationId, now(), KEY, new Date(T0 + 30 * 86_400_000)],
      ),
    );
    let engines = 0;
    const started = runner(async () => void engines++);
    await started.start();
    await started.idle();
    await waitFor(async () => (await read(s))?.status !== "queued");
    await started.stop();
    expect(await read(s)).toMatchObject({ status: "stopped", end_reason: "deletion_pending", requests_sent: 0 });
    expect((await audited(s)).at(-1)).toMatchObject({ action: "campaign.refuse", actor: { kind: "system" } });
    expect(engines).toBe(0);
    expect(hits).toEqual([]);
  }, 30_000);

  it("F4, F5 (D-114): the real stand-in against a target whose evidence stands among such characters — six of six, none dropped", async () => {
    const s = await seed();
    const cp = (code: number) => String.fromCodePoint(code);
    // Around the evidence of every body: a separating control, a zero-width character, a fullwidth word, a CR LF.
    const around = (body: string) =>
      `intro${cp(0x1f)}line${cp(0x85)}${cp(0x200b)}${body}${cp(0xad)}${cp(0x0b)}tail ${cp(0xff54)}${cp(0xff45)}\r\nend`;
    handler = (req, res) => {
      const url = new URL(req.url ?? "/", "https://x");
      const token = tokens.get(String(req.headers["x-airverse-campaign"]));
      if (url.pathname === VERIFICATION_FILE_PATH) return void res.end(`${token}\n`);
      if (url.pathname === "/go") {
        res.writeHead(302, { location: String(url.searchParams.get("to")) });
        return void res.end();
      }
      if (url.pathname === "/api/orders/x") {
        res.statusCode = 500;
        return void res.end(around("Error: boom\n    at handler (/srv/app/orders.js:10:5)\n"));
      }
      if (url.pathname === "/api/admin/reports") return void res.end(around('{"reports":[{"id":1}]}'));
      if (url.pathname === "/api/orders/1001") return void res.end(around('{"order_id":1001}'));
      if (url.pathname === "/search") return void res.end(around(`<p>${url.searchParams.get("q")}</p>`));
      res.end(around("<html>home</html>"));
    };
    const started = runner(undefined);
    await started.start();
    await started.idle();
    await started.stop();
    expect(await read(s)).toMatchObject({
      status: "completed",
      checks: { ran: 6, reported: 6, inconclusive: 0, skipped: 0 },
      findings_dropped: 0,
    });
    const stored = await findings(s);
    expect(stored.map((f) => `${f.check_id} ${f.state}`)).toEqual([
      "RW-01 confirmed",
      "RW-02 confirmed",
      "RW-03 confirmed",
      "RW-04 confirmed",
      "RW-05 confirmed",
      "RW-06 confirmed",
    ]);
    // What is stored is clean, in one form, and a fixed point of the cleaning.
    for (const finding of stored) {
      const window = finding.evidence.excerpt;
      expect(window).toBe(window.normalize("NFKC"));
      expect(window).not.toMatch(/[\p{Cf}\p{Default_Ignorable_Code_Point}]/u);
      expect(window.replace(/[\n\t]/g, "")).not.toMatch(/\p{Cc}/u);
    }
  }, 30_000);

  it("F6: a kill does not sign for a Campaign that ended under an earlier kill", async () => {
    // Yesterday: a kill ended a Campaign and its entry was never written; the kill was lifted.
    const earlier = await seed(HOST, new Date(T0 - 48 * 3_600_000));
    await api.db.tx({ organizationId: earlier.organizationId }, (q) =>
      endCampaign(q, earlier.campaignId, {
        reason: "operator_kill",
        started: false,
        checks: null,
        at: new Date(T0 - 23 * 3_600_000),
      }),
    );
    const today = await seed("hang.acme-shop.io");
    const started = runner(async () => {});
    await started.start();
    await waitFor(() => started.isActive(today.campaignId));
    await api.db.tx("none", (q) => setKillSwitch(q, true, now(), "review6"));
    let stopped = -1;
    try {
      stopped = await kill(started);
    } finally {
      await api.db.tx("none", (q) => setKillSwitch(q, false, now(), "review6 over"));
    }
    await started.stop();
    expect(stopped).toBe(1);
    expect(await operatorEntries(today)).toBe(1);
    // Not entered in today's name, and not counted: it stays without the entry.
    expect(await operatorEntries(earlier)).toBe(0);
  }, 30_000);

  it("an engine that ignores its abort does not hold the operator's stop for ever", async () => {
    const s = await seed();
    let running = false;
    // It never returns, whatever its signal says.
    const started = runner(
      async (options) => {
        await options.request({ method: "GET", path: "/" });
        running = true;
        await new Promise<void>(() => {});
      },
      api.db,
      200,
    );
    await started.start();
    await waitFor(() => running);
    await api.db.tx("none", (q) => setKillSwitch(q, true, now(), "review6"));
    const before = performance.now();
    let stopped = -1;
    try {
      stopped = await kill(started);
    } finally {
      await api.db.tx("none", (q) => setKillSwitch(q, false, now(), "review6 over"));
    }
    expect(performance.now() - before).toBeLessThan(3000);
    expect(stopped).toBe(1);
    expect(await read(s)).toMatchObject({ status: "stopped", end_reason: "operator_kill" });
    expect(await operatorEntries(s)).toBe(1);
    // The next stop is not queued behind it either.
    expect(await kill(started)).toBe(0);
  }, 30_000);
});
