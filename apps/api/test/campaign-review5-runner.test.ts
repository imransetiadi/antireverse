import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, type Server } from "node:https";
import type { AddressInfo } from "node:net";
import { type CampaignExchange, STAND_IN_ENGINE, VERIFICATION_FILE_PATH } from "@antireverse/protocol";
import { generateVerificationToken, newId } from "@antireverse/protocol/server";
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
  setKillSwitch,
  setSuspension,
} from "../src/stores/campaigns.ts";
import { insertVersion } from "../src/stores/rules-of-engagement.ts";
import { insertTarget, recordCheck } from "../src/stores/targets.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 15a, fifth independent safety review: the runner against a real local TLS target (loopback, test CA). An
// operator's stop that fails half-way or runs twice (1, 3), a switch committed while the engine returns (4), a
// deletion request and the Campaigns it leaves (6, D-112), a check whose Finding is stored and whose result never
// arrives (7), and a Finding reported on another check's request.

const fixture = (name: string) => readFileSync(new URL(`./fixtures/prove-tls/${name}`, import.meta.url), "utf8");
const HOST = "shop.acme-shop.io";
const T0 = Date.parse("2026-11-16T10:00:00.000Z");
const KEY = "key_0123456789abcdef01234567";
const now = () => new Date(T0);
const silent = { info() {}, warn() {} };
const BODY = Array.from({ length: 300 }, (_, i) => `secret${String(i).padStart(3, "0")}`).join("");

describe("review5 15a: the runner", () => {
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
    const organizationId = (await createOrganization(api, `Review5 ${++n}`)).organization.id;
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

  const waiting: CampaignEngineRunner = async (options) => {
    await options.request({ method: "GET", path: "/" });
    // (The stop may have come while that request was in flight: an abort that already happened fires no event.)
    if (options.signal?.aborted !== true) {
      await new Promise<void>((resolve) => options.signal?.addEventListener("abort", () => resolve(), { once: true }));
    }
    throw new Error("stopped");
  };
  const operatorEntries = async (s: Seeded) =>
    (await audited(s)).filter((entry) => entry.action === "campaign.operator_kill").length;
  const kill = (started: ReturnType<typeof runner>) =>
    started.operatorStop({ reason: "operator_kill", requestId: randomUUID(), operatorReason: "review5" });
  /** One Campaign hung in its start checks, one running, one queued behind them. */
  async function three() {
    const hung = await seed("hang.acme-shop.io", new Date(T0 - 3000));
    const running = await seed(HOST, new Date(T0 - 2000));
    const queued = await seed("later.acme-shop.io", new Date(T0 - 1000));
    return [hung, running, queued] as const;
  }

  it("1: a transaction of the operator's stop throws — the others still get their entry, and a retry completes it", async () => {
    const all = await three();
    // Every write of the operator's entry for the first Campaign fails, for as long as `failing` is set.
    let thrown = false;
    let failing = true;
    const db = hooked((sql, params) => {
      const entry = /INSERT INTO audit_entries/.test(sql) && params?.includes("campaign.operator_kill");
      if (failing && entry && params?.includes(all[0].campaignId)) {
        thrown = true;
        throw new Error("could not write: disk full");
      }
    });
    const started = runner(waiting, db);
    await started.start();
    await waitFor(() => hits.length === 2);
    await api.db.tx("none", (q) => setKillSwitch(q, true, now(), "review5"));
    let first = -1;
    let second = -1;
    try {
      first = await kill(started);
      await started.idle();
      // Every Campaign ended, whatever failed in between.
      for (const s of all) expect(await read(s)).toMatchObject({ status: "stopped", end_reason: "operator_kill" });
      expect(thrown).toBe(true);
      // The failure cost one entry, not all of them (it had cost all three, and the retry answered 0).
      expect(first).toBe(2);
      expect((await Promise.all(all.map(operatorEntries))).sort()).toEqual([0, 1, 1]);
      // The operator presses again: the switch is on already; the missing entry is written and counted.
      failing = false;
      second = await kill(started);
    } finally {
      await api.db.tx("none", (q) => setKillSwitch(q, false, now(), "review5 over"));
    }
    await started.stop();
    expect(second).toBe(1);
    expect(await Promise.all(all.map(operatorEntries))).toEqual([1, 1, 1]);
    // And a third time writes nothing more.
    expect(await kill(started)).toBe(0);
    expect(await Promise.all(all.map(operatorEntries))).toEqual([1, 1, 1]);
  }, 30_000);

  it("3: two operator stops at once — each Campaign gets one entry and is counted by one of them", async () => {
    const all = await three();
    const started = runner(waiting);
    await started.start();
    await waitFor(() => hits.length === 2);
    await api.db.tx("none", (q) => setKillSwitch(q, true, now(), "review5"));
    let counts: number[] = [];
    try {
      counts = await Promise.all([kill(started), kill(started)]);
      await started.idle();
    } finally {
      await api.db.tx("none", (q) => setKillSwitch(q, false, now(), "review5 over"));
    }
    await started.stop();
    expect(counts.reduce((sum, count) => sum + count, 0)).toBe(3);
    expect(counts).toEqual([3, 0]);
    expect(await Promise.all(all.map(operatorEntries))).toEqual([1, 1, 1]);
  }, 30_000);

  for (const which of ["kill", "suspension", "deletion"] as const) {
    it(`4: a ${which} committed while the engine returns, its abort still on the way — the Campaign does not end completed`, async () => {
      const s = await seed();
      // The engine has asked for everything; the switch is committed, and the engine returns before anyone aborts.
      const started = runner(async (options) => {
        await options.request({ method: "GET", path: "/" });
        options.onCheck({ id: "RW-01", result: "clean" });
        if (which === "kill") await api.db.tx("none", (q) => setKillSwitch(q, true, now(), "review5"));
        else if (which === "suspension") {
          await api.db.tx("none", (q) => setSuspension(q, s.organizationId, true, now(), "review5"));
        } else {
          await api.db.owner((q) =>
            q.query(
              `INSERT INTO organization_deletions (id, organization_id, organization_name, requested_at, requested_by,
                 reason, purge_after)
               VALUES ($1, $2, 'x', $3, $4, 'r', $5)`,
              [newId("del"), s.organizationId, now(), KEY, new Date(T0 + 30 * 86_400_000)],
            ),
          );
        }
      });
      const reason =
        which === "kill" ? "operator_kill" : which === "suspension" ? "organization_suspended" : "deletion_pending";
      let stopped = -1;
      try {
        await started.start();
        await started.idle();
        expect(await read(s)).toMatchObject({ status: "stopped", end_reason: reason, checks: { ran: 1 } });
        // The operator's stop that follows the commit finds it ended by that stop: its entry, and its count.
        if (which !== "deletion") {
          stopped = await started.operatorStop({
            reason: reason as "operator_kill" | "organization_suspended",
            ...(which === "suspension" ? { organizationId: s.organizationId } : {}),
            requestId: randomUUID(),
            operatorReason: "review5",
          });
        }
      } finally {
        await api.db.tx("none", (q) => setKillSwitch(q, false, now(), "review5 over"));
      }
      await started.stop();
      if (which !== "deletion") {
        expect(stopped).toBe(1);
        expect(await operatorEntries(s)).toBe(1);
      }
    }, 30_000);
  }

  it("6 (D-112): a deletion request ends the Organization's Campaign that is still in its start checks, and one still queued", async () => {
    const hung = await seed("hang.acme-shop.io", new Date(T0 - 3000));
    const running = await seed(HOST, new Date(T0 - 2000));
    const queued = await seed("later.acme-shop.io", new Date(T0 - 1000));
    const started = runner(waiting);
    await started.start();
    await waitFor(() => hits.length === 2);
    await started.cut(hung.organizationId, "deletion_pending");
    await started.cut(queued.organizationId, "deletion_pending");
    for (const s of [hung, queued]) {
      expect(await read(s)).toMatchObject({
        status: "stopped",
        end_reason: "deletion_pending",
        requests_sent: 0,
        started_at: null,
        checks: null,
      });
      expect((await audited(s)).at(-1)).toMatchObject({ action: "campaign.refuse", actor: { kind: "system" } });
    }
    // No other Organization's Campaign is touched.
    expect((await read(running))?.status).toBe("running");
    await started.cut(running.organizationId, "deletion_pending");
    expect(await read(running)).toMatchObject({ status: "stopped", end_reason: "deletion_pending" });
    await started.stop();
  }, 30_000);

  it("7: a stop between the storing of a Finding and its check's result — the check counts as reported", async () => {
    const s = await seed();
    let stored = false;
    const started = runner(async (options) => {
      const exchange = (await options.request({ method: "GET", path: "/api/admin/reports" })) as CampaignExchange;
      await options.onFinding({
        check_id: "RW-03",
        path: "/api/admin/reports",
        seq: exchange.ok ? exchange.seq : 0,
        window: '"reports"',
      });
      stored = true;
      // The stop lands here: the check's result is never told.
      await new Promise<void>((resolve) => options.signal?.addEventListener("abort", () => resolve(), { once: true }));
      throw new Error("stopped");
    });
    await started.start();
    await waitFor(() => stored);
    await started.abort(s.campaignId, "owner_stop");
    await started.stop();
    const campaign = await read(s);
    expect((await findings(s)).map((f) => f.check_id)).toEqual(["RW-03"]);
    // Never fewer reported than checks with a stored Finding; the four counts still sum to the catalog's six.
    expect(campaign).toMatchObject({
      status: "stopped",
      checks: { ran: 1, reported: 1, inconclusive: 0, skipped: 5 },
    });
    expect((await audited(s)).at(-1)?.summary).toContain("1 check ran, 1 reported a finding");
  }, 30_000);

  it("7: a check told as clean or skipped whose Finding is stored still counts as reported", async () => {
    const s = await seed();
    await (async () => {
      const started = runner(async (options) => {
        const exchange = (await options.request({ method: "GET", path: "/api/admin/reports" })) as CampaignExchange;
        options.onCheck({ id: "RW-03", result: "skipped" });
        options.onCheck({ id: "RW-01", result: "inconclusive" });
        await options.onFinding({
          check_id: "RW-03",
          path: "/api/admin/reports",
          seq: exchange.ok ? exchange.seq : 0,
          window: "",
        });
      });
      await started.start();
      await started.idle();
      await started.stop();
    })();
    expect(await read(s)).toMatchObject({
      status: "completed",
      checks: { ran: 1, reported: 1, inconclusive: 1, skipped: 4 },
    });
  }, 30_000);

  it("a Finding of one check reported on another check's request is rejected and counted", async () => {
    const s = await seed();
    const started = runner(async (options) => {
      const home = (await options.request({ method: "GET", path: "/" })) as CampaignExchange;
      // The home page's request, offered as the evidence of "admin data without authentication".
      await options.onFinding({
        check_id: "RW-03",
        path: "/",
        seq: home.ok ? home.seq : 0,
        window: "",
      });
      await options.onFinding({
        check_id: "RW-03",
        path: "/api/admin/reports",
        seq: home.ok ? home.seq : 0,
        window: "",
      });
    });
    await started.start();
    await started.idle();
    await started.stop();
    expect(await findings(s)).toEqual([]);
    expect(await read(s)).toMatchObject({ status: "failed", end_reason: "engine_error", findings_dropped: 2 });
  }, 30_000);
});
