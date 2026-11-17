import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import type { IncomingMessage, ServerResponse } from "node:http";
import { createServer, type Server } from "node:https";
import type { AddressInfo, Socket } from "node:net";
import { type CampaignExchange, STAND_IN_ENGINE, VERIFICATION_FILE_PATH } from "@antireverse/protocol";
import { generateVerificationToken, newId } from "@antireverse/protocol/server";
import { standInEngine } from "@antireverse/prove";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { type CampaignEngineRunner, createCampaignRunner } from "../src/campaign/runner.ts";
import type { Db } from "../src/db/db.ts";
import { createAuthorize } from "../src/prove/authorize.ts";
import {
  FRAMING_OVERHEAD_BYTES_MAX,
  RESPONSE_HEADER_BYTES_MAX,
  type Resolver,
  TLS_OVERHEAD_BYTES_MAX,
} from "../src/prove/verify.ts";
import { auditEntriesAfter } from "../src/stores/audit.ts";
import {
  findCampaign,
  insertCampaign,
  listCampaignFindings,
  listCampaignRequests,
  requestStop,
  setKillSwitch,
  setSuspension,
} from "../src/stores/campaigns.ts";
import { insertVersion } from "../src/stores/rules-of-engagement.ts";
import { insertTarget, recordCheck } from "../src/stores/targets.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 15a, third independent safety review: the runner against a real local TLS target (loopback, test CA). A
// target that floods chunk framing (F1), Findings the runner rejects (F2), bodies that cannot be read (F3), a kill
// committed while a Campaign starts (F4), and what is kept of a response (F5, D-107).

const fixture = (name: string) => readFileSync(new URL(`./fixtures/prove-tls/${name}`, import.meta.url), "utf8");
const HOST = "shop.acme-shop.io";
const T0 = Date.parse("2026-11-16T10:00:00.000Z");
const KEY = "key_0123456789abcdef01234567";
const now = () => new Date(T0);
const silent = { info() {}, warn() {} };

describe("review3 15a: the runner", () => {
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

  /** An Organization with the host verified, Rules of Engagement that cover it, and a queued Campaign. */
  async function seed(): Promise<Seeded> {
    const organizationId = (await createOrganization(api, `Review3 ${++n}`)).organization.id;
    const targetId = newId("tgt");
    const roeId = newId("roe");
    const campaignId = newId("cmp");
    const token = generateVerificationToken();
    tokens.set(campaignId, token);
    await api.db.tx({ organizationId }, async (q) => {
      await insertTarget(q, { organizationId, id: targetId, host: HOST, token, createdAt: now() });
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
        host: HOST,
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
      testing: { ca: fixture("ca.pem"), port, allowLoopback: true, minSpacingMs, requestTimeoutMs: 2000 },
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
      await sleep(5);
    }
  };
  const requests = (s: Seeded) =>
    api.db.tx({ organizationId: s.organizationId }, (q) => listCampaignRequests(q, s.campaignId));
  const findings = (s: Seeded) =>
    api.db.tx({ organizationId: s.organizationId }, (q) => listCampaignFindings(q, s.campaignId));
  const run = async (engine?: CampaignEngineRunner, db: Db = api.db) => {
    const started = runner(db, engine);
    await started.start();
    await started.idle();
    await started.stop();
  };

  /**
   * The database with hooks: `afterTx` runs after each transaction of an Organization has committed (and before the
   * caller goes on); `onQuery` may throw in place of a statement.
   */
  function hooked(hooks: {
    afterTx?: (count: number) => Promise<void> | void;
    onQuery?: (sql: string) => Promise<void> | void;
  }): Db {
    let count = 0;
    return new Proxy(api.db, {
      get(target, property) {
        if (property === "tx") {
          return async (scope: unknown, fn: (q: unknown) => unknown) => {
            const result = await (target.tx as (s: unknown, f: (q: unknown) => unknown) => unknown)(scope, (q) =>
              fn(
                new Proxy(q as object, {
                  get(inner, name) {
                    if (name === "query") {
                      return async (sql: string, params?: unknown[]) => {
                        await hooks.onQuery?.(sql);
                        return (inner as { query: (s: string, p?: unknown[]) => unknown }).query(sql, params);
                      };
                    }
                    const value = Reflect.get(inner, name);
                    return typeof value === "function" ? value.bind(inner) : value;
                  },
                }),
              ),
            );
            if (scope !== "none") await hooks.afterTx?.(++count);
            return result;
          };
        }
        const value = Reflect.get(target, property);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as Db;
  }

  /** A target with every seeded weakness of the catalog: `head` before and `tail` after each body. */
  const weak =
    (
      head: string,
      tail = "",
      headers: Record<string, string> = {},
      encode: (body: string) => string | Buffer = (b) => b,
    ) =>
    (req: IncomingMessage, res: ServerResponse): void => {
      const url = new URL(req.url ?? "/", "https://x");
      const token = tokens.get(String(req.headers["x-airverse-campaign"]));
      if (url.pathname === VERIFICATION_FILE_PATH) return void res.end(`${token}\n`);
      if (url.pathname === "/go") {
        res.writeHead(302, { location: String(url.searchParams.get("to")) });
        return void res.end();
      }
      for (const [name, value] of Object.entries(headers)) res.setHeader(name, value);
      const send = (body: string): void => void res.end(encode(`${head}${body}${tail}`));
      if (url.pathname === "/api/orders/x") {
        res.statusCode = 500;
        return void send("Error: boom\n    at handler (/srv/app/orders.js:10:5)\n");
      }
      if (url.pathname === "/api/admin/reports") return void send('{"reports":[{"id":1}]}');
      if (url.pathname === "/api/orders/1001") return void send('{"order_id":1001}');
      if (url.pathname === "/search") return void send(`<p>${url.searchParams.get("q")}</p>`);
      send("<html>home</html>");
    };

  const ALL_SIX = ["RW-01", "RW-02", "RW-03", "RW-04", "RW-05", "RW-06"];

  it("F1: a target that floods chunk extensions is cut at the read cap; the log says what was read; byte_budget", async () => {
    const s = await seed();
    handler = (req, res) => {
      const token = tokens.get(String(req.headers["x-airverse-campaign"]));
      if (req.url === VERIFICATION_FILE_PATH) return void res.end(`${token}\n`);
      const socket = req.socket as Socket;
      socket.write("HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n");
      const piece = `1;x=${"a".repeat(16_000)}\r\nX\r\n`;
      let written = 0;
      const pump = (): void => {
        while (!socket.destroyed && written < 100_000_000) {
          written += piece.length;
          if (!socket.write(piece)) return void socket.once("drain", pump);
        }
      };
      pump();
    };
    await run();
    const campaign = await read(s);
    const log = await requests(s);
    const cap = RESPONSE_HEADER_BYTES_MAX + 65_536 + TLS_OVERHEAD_BYTES_MAX + FRAMING_OVERHEAD_BYTES_MAX;
    expect(campaign).toMatchObject({ status: "failed", end_reason: "byte_budget", requests_sent: 2 });
    expect(log.map((row) => `${row.seq} ${row.outcome} ${row.status ?? row.failure}`)).toEqual([
      "1 sent 200",
      "2 sent read_limit",
    ]);
    // The row holds what the socket read: more than the cap, by a few socket reads at most. Nothing was cut to 1 MB,
    // and nowhere near the 100 MB the target was writing.
    expect(log[1]?.bytes).toBeGreaterThan(cap);
    expect(log[1]?.bytes).toBeLessThan(cap + 300_000);
    expect(campaign?.response_bytes).toBe((log[0]?.bytes ?? 0) + (log[1]?.bytes ?? 0));
    expect(hits).toHaveLength(2);
  }, 30_000);

  it("F2: the review's body — redaction lengthens it past 64 KB — and all six Findings are still stored", async () => {
    const s = await seed();
    handler = weak("a@b.cd ".repeat(9000));
    await run();
    const campaign = await read(s);
    const stored = await findings(s);
    expect(campaign).toMatchObject({
      status: "completed",
      checks: { ran: 6, reported: 6, inconclusive: 0, skipped: 0 },
      findings_dropped: 0,
    });
    expect(stored.map((f) => f.check_id)).toEqual(ALL_SIX);
    expect(campaign?.checks?.reported).toBe(stored.length);
  }, 30_000);

  it("F2: every Finding the runner rejects is counted, and the Campaign does not end as a clean completed", async () => {
    const s = await seed();
    handler = weak("");
    const rejected: Record<string, unknown>[] = [];
    await run(async (options) => {
      const exchange = (await options.request({ method: "GET", path: "/api/admin/reports" })) as CampaignExchange;
      const seq = exchange.ok ? exchange.seq : 0;
      const good = {
        check_id: "RW-03",
        path: "/api/admin/reports",
        title: "Admin data without authentication",
        severity: "high",
        seq,
        window: '{"reports"',
      };
      rejected.push(
        { ...good, window: "x".repeat(201) },
        { ...good, window: "not in the body" },
        { ...good, window: 7 },
        { ...good, window: undefined, at: 0 },
        { ...good, seq: 150 },
        { ...good, seq: 0 },
        { ...good, check_id: "ZZ-99" },
        { ...good, check_id: "nonsense" },
        { ...good, path: "/api/admin/../admin/reports" },
        { ...good, path: "/other" },
      );
      for (const finding of rejected) await options.onFinding(finding);
      await options.onFinding(null);
      await options.onFinding("a finding");
      await options.onFinding(good);
      // A title or a severity of the engine's own is not read at all: this is the same Finding again.
      await options.onFinding({ ...good, severity: "critical", title: "" });
      options.onCheck({ id: "RW-03", result: "reported" });
    });
    const campaign = await read(s);
    expect((await findings(s)).map((f) => `${f.check_id} ${f.state} ${f.severity} ${f.evidence.excerpt}`)).toEqual([
      'RW-03 confirmed high {"reports"',
    ]);
    expect(campaign?.findings_dropped).toBe(rejected.length + 2);
    expect(campaign).toMatchObject({ status: "failed", end_reason: "engine_error" });
    expect((await audited(s)).at(-1)?.summary).toContain(`${rejected.length + 2} Findings could not be stored`);
  }, 30_000);

  it("F5: a Finding's title and severity are the catalog's, never an engine's own words", async () => {
    const s = await seed();
    handler = weak("");
    await run(async (options) => {
      const exchange = (await options.request({ method: "GET", path: "/api/admin/reports" })) as CampaignExchange;
      await options.onFinding({
        check_id: "RW-03",
        path: "/api/admin/reports",
        title: 'copied from the body: {"reports":[{"id":1}]}',
        severity: "low",
        seq: exchange.ok ? exchange.seq : 0,
        window: "",
      });
    });
    expect(await findings(s)).toMatchObject([{ check_id: "RW-03", ...standInEngine.findings["RW-03"] }]);
    expect((await read(s))?.findings_dropped).toBe(0);
  }, 30_000);

  it("F5: of a response, a Finding keeps a window of at most 200 characters and nothing else", async () => {
    const s = await seed();
    const SECRETS = [
      "define('DB_PASSWORD', 'hunter2');",
      "user[password]=hunter2",
      '<add key="Password" value="hunter2" />',
      '<input type="password" id="pw" value="hunter2">',
      '{"body":"{\\"password\\":\\"hunter2\\"}"}',
      "%7B%22password%22%3A%22hunter2%22%7D",
      '"secret": {\n "value": "hunter2"\n}',
      '"passwords": ["hunter2","hunter3"]',
    ];
    // Every shape the redactor missed in the review, a screenful away from what any check matches.
    const far = `${SECRETS.join("\n")}\n${"filler line\n".repeat(60)}`;
    handler = weak(far, `\n${"filler line\n".repeat(60)}${SECRETS.join("\n")}`, {
      "content-security-policy": "script-src 'nonce-hunter2nonce'",
    });
    await run();
    const stored = await findings(s);
    expect(stored.map((f) => f.check_id)).toEqual(ALL_SIX);
    expect(stored[0]?.evidence.headers["content-security-policy"]).toBe("[present]");
    for (const finding of stored) {
      expect(finding.evidence.excerpt.length).toBeLessThanOrEqual(200);
      expect(Object.keys(finding.evidence).sort()).toEqual([
        "excerpt",
        "headers",
        "location",
        "method",
        "status",
        "target",
        "truncated",
      ]);
    }
    // Nothing the product keeps of this Campaign holds the secrets: Findings, the request log, the audit log.
    const kept = JSON.stringify([stored, await requests(s), await audited(s), await read(s)]);
    expect(kept).not.toMatch(/hunter/);
    expect(stored.find((f) => f.check_id === "RW-03")?.evidence.excerpt).toContain('"reports"');
    expect(stored.find((f) => f.check_id === "RW-02")?.evidence.excerpt).toContain("at handler (/srv/app/orders.js");
  }, 30_000);

  it("F3: a `content-encoding: br` body with no NUL is inconclusive, not 'ran, nothing reported'", async () => {
    const s = await seed();
    // What a compressed body looks like to a text pattern: bytes, none of them NUL.
    handler = weak("", "", { "content-encoding": "br" }, (body) =>
      Buffer.from(Uint8Array.from(Buffer.from(body), (byte) => (byte % 127) + 1)),
    );
    await run();
    const campaign = await read(s);
    expect(campaign).toMatchObject({
      status: "completed",
      checks: { ran: 2, reported: 2, inconclusive: 4, skipped: 0 },
      findings_dropped: 0,
    });
    expect((await findings(s)).map((f) => f.check_id)).toEqual(["RW-01", "RW-06"]);
  }, 30_000);

  it("F3: bytes OR-ed with 0x80 under `charset=ibm037` are inconclusive", async () => {
    const s = await seed();
    handler = weak("", "", { "content-type": "text/plain; charset=ibm037" }, (body) =>
      Buffer.from(Uint8Array.from(Buffer.from(body), (byte) => byte | 0x80)),
    );
    await run();
    const campaign = await read(s);
    const stored = (await findings(s)).map((f) => f.check_id);
    expect(campaign).toMatchObject({
      status: "completed",
      checks: { ran: 2, reported: 2, inconclusive: 4, skipped: 0 },
    });
    expect(stored).toEqual(["RW-01", "RW-06"]);
    expect((await audited(s)).at(-1)?.summary).toContain(
      "4 were inconclusive (4 responses could not be read as text or in full)",
    );
  }, 30_000);

  it("F4: a kill committed while the start checks run — the ownership request is never sent", async () => {
    const s = await seed();
    let engineRuns = 0;
    // The switch is committed right after the runner's first read of the Campaign (the start checks' facts).
    const db = hooked({
      async afterTx(count) {
        if (count === 1) await api.db.tx("none", (q) => setKillSwitch(q, true, now(), "review3"));
      },
    });
    try {
      await run(async () => void engineRuns++, db);
    } finally {
      await api.db.tx("none", (q) => setKillSwitch(q, false, now(), "review3 over"));
    }
    expect(hits).toEqual([]);
    expect(engineRuns).toBe(0);
    expect(await read(s)).toMatchObject({ status: "stopped", end_reason: "operator_kill", requests_sent: 0 });
  }, 30_000);

  it("F4: a suspension committed while the start checks run — the ownership request is never sent", async () => {
    const s = await seed();
    const db = hooked({
      async afterTx(count) {
        if (count === 1) await api.db.tx("none", (q) => setSuspension(q, s.organizationId, true, now(), "review3"));
      },
    });
    await run(async () => {}, db);
    expect(hits).toEqual([]);
    expect(await read(s)).toMatchObject({ status: "stopped", end_reason: "organization_suspended" });
  }, 30_000);

  it("F4: the owner's stop committed while the start checks run — the ownership request is never sent", async () => {
    const s = await seed();
    const db = hooked({
      async afterTx(count) {
        if (count === 1) {
          await api.db.tx({ organizationId: s.organizationId }, (q) =>
            requestStop(q, s.campaignId, { keyId: KEY, reason: "wrong target", at: now() }),
          );
        }
      },
    });
    await run(async () => {}, db);
    expect(hits).toEqual([]);
    expect(await read(s)).toMatchObject({ status: "stopped", end_reason: "owner_stop", requests_sent: 0 });
  }, 30_000);

  it("F4: a kill committed after the ownership answer and before the claim — the Campaign never starts", async () => {
    const s = await seed();
    let engineRuns = 0;
    let settled = false;
    const db = hooked({
      onQuery(sql) {
        if (/UPDATE campaign_requests/.test(sql)) settled = true;
      },
      async afterTx() {
        // Right after the ownership request's row is settled: the next thing the runner does is the claim.
        if (settled) {
          settled = false;
          await api.db.tx("none", (q) => setKillSwitch(q, true, now(), "review3"));
        }
      },
    });
    try {
      await run(async () => void engineRuns++, db);
    } finally {
      await api.db.tx("none", (q) => setKillSwitch(q, false, now(), "review3 over"));
    }
    expect(hits).toEqual([`GET ${VERIFICATION_FILE_PATH}`]);
    expect(engineRuns).toBe(0);
    const campaign = await read(s);
    expect(campaign).toMatchObject({ status: "stopped", end_reason: "operator_kill", started_at: null });
    expect((await audited(s)).map((entry) => entry.action)).not.toContain("campaign.start");
  }, 30_000);

  it("F4: the review's race — 3 ms on every transaction, the kill at any moment of a start: nothing goes on past it", async () => {
    // As the operator's route does: the switch is committed, then the runner is told. With every transaction slowed
    // down, the start checks, the ownership request and the claim are spread out, and the kill lands between them.
    const slow = hooked({ onQuery: () => undefined, afterTx: () => undefined });
    const delayed = new Proxy(slow, {
      get(target, property) {
        if (property === "tx") {
          return async (scope: unknown, fn: (q: unknown) => unknown) => {
            await sleep(3);
            return (target.tx as (s: unknown, f: (q: unknown) => unknown) => unknown)(scope, fn);
          };
        }
        const value = Reflect.get(target, property);
        return typeof value === "function" ? value.bind(target) : value;
      },
    }) as Db;
    const late: string[] = [];
    const outcomes: string[] = [];
    for (let round = 0; round < 14; round++) {
      const s = await seed();
      hits = [];
      const arrivals: number[] = [];
      handler = (req, res) => {
        arrivals.push(performance.now());
        const token = tokens.get(String(req.headers["x-airverse-campaign"]));
        if (req.url === VERIFICATION_FILE_PATH) return void res.end(`${token}\n`);
        res.end('{"reports":[]}');
      };
      const started = runner(delayed, async (options) => {
        for (let i = 0; i < 20; i++) {
          const exchange = (await options.request({ method: "GET", path: `/p${i}` })) as CampaignExchange;
          if (!exchange.ok && "refused" in exchange && exchange.fatal) return;
        }
      });
      await started.start();
      await sleep(round * 4);
      await api.db.tx("none", (q) => setKillSwitch(q, true, now(), "review3 race"));
      const committed = performance.now();
      const stopping = started.operatorStop({
        reason: "operator_kill",
        requestId: randomUUID(),
        operatorReason: "review3 race",
      });
      await stopping;
      await started.idle();
      await started.stop();
      await sleep(30);
      await api.db.tx("none", (q) => setKillSwitch(q, false, now(), "review3 race over"));
      const campaign = await read(s);
      outcomes.push(`${campaign?.status} ${campaign?.end_reason}`);
      // A request written to its socket just before the kill may still arrive; none is started after it.
      for (const at of arrivals)
        if (at > committed + 4) late.push(`round ${round}: +${(at - committed).toFixed(1)} ms`);
    }
    expect(late).toEqual([]);
    // Whatever the moment: stopped by the operator — or, when the kill came after the last check, completed before it.
    expect(outcomes.filter((outcome) => outcome !== "stopped operator_kill")).toEqual([]);
  }, 60_000);

  it("F4: the operator's stop aborts every Campaign running here before it awaits anything", async () => {
    const s = await seed();
    let engineSignal: AbortSignal | undefined;
    const started = runner(api.db, async (options) => {
      engineSignal = options.signal;
      await new Promise<void>((resolve) => options.signal?.addEventListener("abort", () => resolve(), { once: true }));
      throw new Error("stopped");
    });
    await started.start();
    await waitFor(() => engineSignal !== undefined);
    const stopping = started.operatorStop({
      reason: "operator_kill",
      requestId: randomUUID(),
      operatorReason: "review3",
    });
    // Synchronously: nothing was awaited between the call and the abort.
    expect(engineSignal?.aborted).toBe(true);
    expect(engineSignal?.reason).toBe("operator_kill");
    expect(await stopping).toBe(1);
    await started.stop();
    expect(await read(s)).toMatchObject({ status: "stopped", end_reason: "operator_kill" });
  }, 30_000);

  it("F4: a suspension aborts that Organization's Campaign at once, and no other's", async () => {
    const mine = await seed();
    const signals = new Map<string, AbortSignal>();
    const order: string[] = [];
    const started = runner(api.db, async (options) => {
      await options.request({ method: "GET", path: "/" });
      order.push("engine");
      if (options.signal !== undefined) signals.set(String(order.length), options.signal);
      await new Promise<void>((resolve) => options.signal?.addEventListener("abort", () => resolve(), { once: true }));
      // As the worker host does when its Campaign is stopped.
      throw new Error("stopped");
    });
    await started.start();
    await waitFor(() => signals.size === 1);
    const signal = [...signals.values()][0];
    const other = started.operatorStop({
      reason: "organization_suspended",
      organizationId: "org_ffffffffffffffffffffffff",
      requestId: randomUUID(),
      operatorReason: "review3",
    });
    expect(signal?.aborted).toBe(false);
    expect(await other).toBe(0);
    const stopping = started.operatorStop({
      reason: "organization_suspended",
      organizationId: mine.organizationId,
      requestId: randomUUID(),
      operatorReason: "review3",
    });
    expect(signal?.aborted).toBe(true);
    expect(await stopping).toBe(1);
    await started.stop();
    expect(await read(mine)).toMatchObject({ status: "stopped", end_reason: "organization_suspended" });
  }, 30_000);

  it("unconfirmed in the review: the owner's stop of a request in flight whose row cannot be settled ends as stopped", async () => {
    const s = await seed();
    const held: ServerResponse[] = [];
    handler = (req, res) => {
      const token = tokens.get(String(req.headers["x-airverse-campaign"]));
      if (req.url === VERIFICATION_FILE_PATH) return void res.end(`${token}\n`);
      held.push(res);
    };
    let failing = false;
    const db = hooked({
      onQuery(sql) {
        if (failing && /UPDATE campaign_requests/.test(sql)) throw new Error("could not write: disk full");
      },
    });
    const started = runner(db, async (options) => {
      await options.request({ method: "GET", path: "/api/admin/reports" });
    });
    await started.start();
    await waitFor(() => held.length === 1);
    failing = true;
    await api.db.tx({ organizationId: s.organizationId }, (q) =>
      requestStop(q, s.campaignId, { keyId: KEY, reason: "stop", at: now() }),
    );
    await started.abort(s.campaignId, "owner_stop");
    failing = false;
    await started.stop();
    for (const res of held) res.destroy();
    expect(await read(s)).toMatchObject({ status: "stopped", end_reason: "owner_stop" });
    // Its row stays `sending`: it was sent, and its result could not be recorded.
    expect((await requests(s)).map((row) => row.outcome)).toEqual(["sent", "sending"]);
  }, 30_000);
});
