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
import { findCampaign, insertCampaign, listCampaignFindings, listCampaignRequests } from "../src/stores/campaigns.ts";
import { insertVersion } from "../src/stores/rules-of-engagement.ts";
import { insertTarget, recordCheck } from "../src/stores/targets.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 15a, independent safety review: the runner against a real local TLS target (loopback, test CA) when a write
// fails (M1, L1), at shutdown (L5), and for two names on one address. The engine is a function here.

const fixture = (name: string) => readFileSync(new URL(`./fixtures/prove-tls/${name}`, import.meta.url), "utf8");
const HOST = "shop.acme-shop.io";
const T0 = Date.parse("2026-11-16T10:00:00.000Z");
const KEY = "key_0123456789abcdef01234567";
const now = () => new Date(T0);
const silent = { info() {}, warn() {} };

describe("review 15a: the runner", () => {
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

  /** The database as it is when some statements cannot be written (a full disk): every read works. */
  function failingDb(failing: RegExp): { db: Db; failures: () => number } {
    let failures = 0;
    const db = new Proxy(api.db, {
      get(target, property) {
        if (property === "tx") {
          return (scope: unknown, fn: (q: unknown) => unknown) =>
            (target.tx as (s: unknown, f: (q: unknown) => unknown) => unknown)(scope, (q) =>
              fn(
                new Proxy(q as object, {
                  get(inner, name) {
                    if (name === "query") {
                      return (sql: string, params?: unknown[]) => {
                        if (failing.test(sql)) {
                          failures++;
                          return Promise.reject(new Error("could not extend file: No space left on device"));
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
    return { db, failures: () => failures };
  }

  const resolver: Resolver = { txt: async () => [], addresses: async () => ["127.0.0.1"] };
  const runner = (db: Db, engine: CampaignEngineRunner, minSpacingMs = 15) =>
    createCampaignRunner({
      db,
      enabled: true,
      resolver,
      authorize: createAuthorize({ db, now }),
      now,
      logger: silent,
      engine,
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

  it("M1: a claim that cannot be written is not retried: one request reached the target, and the Campaign failed", async () => {
    const s = await seed();
    let engineRuns = 0;
    const { db, failures } = failingDb(/UPDATE campaigns SET status = 'running'/);
    const started = runner(db, async () => void engineRuns++);
    await started.start();
    await sleep(1500);
    await started.stop();
    expect(hits.map((hit) => hit.line)).toEqual([`GET ${VERIFICATION_FILE_PATH}`]);
    expect(failures()).toBe(1);
    expect(engineRuns).toBe(0);
    expect(await read(s)).toMatchObject({
      status: "failed",
      end_reason: "engine_error",
      requests_sent: 1,
      started_at: null,
    });
    // The one request is in the log, and the audit entry says what was sent.
    const log = await api.db.tx({ organizationId: s.organizationId }, (q) => listCampaignRequests(q, s.campaignId));
    expect(log).toMatchObject([
      { seq: 1, method: "GET", target: VERIFICATION_FILE_PATH, outcome: "sent", status: 200 },
    ]);
    const entries = await audited(s);
    expect(entries.map((entry) => entry.action)).toEqual(["campaign.refuse"]);
    expect(entries[0]?.summary).toContain("The ownership check was requested; no probe was sent.");
  });

  it("M1: when its end cannot be written either, the Campaign stays queued and parked until a restart", async () => {
    const s = await seed();
    let engineRuns = 0;
    const { db, failures } = failingDb(/UPDATE campaigns SET status = /);
    const stuck = runner(db, async () => void engineRuns++);
    await stuck.start();
    await sleep(1200);
    // Waking it again and again does not make it try again.
    for (let i = 0; i < 20; i++) stuck.wake();
    await sleep(300);
    await stuck.stop();
    expect(hits).toHaveLength(1);
    expect(failures()).toBe(2);
    expect(await read(s)).toMatchObject({ status: "queued", end_reason: null });
    expect(engineRuns).toBe(0);

    // After a restart (a new process, a database that writes again) every start check runs again and it runs.
    const fresh = runner(api.db, async () => void engineRuns++);
    await fresh.start();
    await fresh.idle();
    await fresh.stop();
    expect(engineRuns).toBe(1);
    expect(await read(s)).toMatchObject({ status: "completed", requests_sent: 2 });
    expect(hits.map((hit) => hit.line)).toEqual(Array(2).fill(`GET ${VERIFICATION_FILE_PATH}`));
  });

  it("M1: start-check requests to one host are spaced like any other, whichever Campaign makes them", async () => {
    const first = await seed();
    const second = await seed();
    const started = runner(api.db, async () => {}, 800);
    await started.start();
    await started.idle();
    await started.stop();
    expect((await read(first))?.status).toBe("completed");
    expect((await read(second))?.status).toBe("completed");
    expect(hits).toHaveLength(2);
    // Measured where the requests arrive, so with some slack for a busy machine: without the spacing they would be
    // a few milliseconds apart.
    expect((hits[1]?.at ?? 0) - (hits[0]?.at ?? 0)).toBeGreaterThanOrEqual(500);
  });

  it("L3: Rules that exclude the verification path refuse the Campaign, and the file is not fetched", async () => {
    const s = await seed(HOST, ["/.well-known"]);
    const started = runner(api.db, async () => {});
    await started.start();
    await started.idle();
    await started.stop();
    expect(await read(s)).toMatchObject({
      status: "refused",
      end_reason: "verification_path_excluded",
      requests_sent: 0,
    });
    expect(hits).toEqual([]);
    expect((await audited(s))[0]?.summary).toContain("Nothing was sent.");
  });

  it("L1: a Finding that cannot be stored is counted, and the Campaign ends as failed", async () => {
    const s = await seed();
    const { db } = failingDb(/INSERT INTO campaign_findings/);
    const engine: CampaignEngineRunner = async (options) => {
      const exchange = (await options.request({ method: "GET", path: "/api/admin/reports" })) as CampaignExchange;
      const seq = exchange.ok ? exchange.seq : 0;
      const finding = {
        check_id: "RW-03",
        path: "/api/admin/reports",
        title: "Admin data",
        severity: "high",
        seq,
        at: 0,
      };
      await options.onFinding(finding);
      options.onCheck({ id: "RW-03", result: "reported" });
    };
    const started = runner(db, engine);
    await started.start();
    await started.idle();
    await started.stop();
    expect(await read(s)).toMatchObject({
      status: "failed",
      end_reason: "engine_error",
      findings_dropped: 1,
      checks: { ran: 1, reported: 1 },
    });
    expect(await api.db.tx({ organizationId: s.organizationId }, (q) => listCampaignFindings(q, s.campaignId))).toEqual(
      [],
    );
    expect((await audited(s)).at(-1)?.summary).toContain("1 Finding could not be stored");
  });

  it("L5: a Campaign caught in its start checks at shutdown stays queued, with no end written", async () => {
    const s = await seed();
    // The ownership file does not answer until the test lets it.
    const held: ServerResponse[] = [];
    handler = (_req, res) => void held.push(res);
    let engineRuns = 0;
    const started = runner(api.db, async () => void engineRuns++);
    await started.start();
    await waitFor(() => hits.length === 1);
    await started.stop();
    for (const res of held) res.destroy();
    expect(await read(s)).toMatchObject({ status: "queued", end_reason: null, started_at: null });
    expect(await audited(s)).toEqual([]);
    expect(engineRuns).toBe(0);
    // The next start takes it again.
    handler = null;
    const again = runner(api.db, async () => void engineRuns++);
    await again.start();
    await again.idle();
    await again.stop();
    expect((await read(s))?.status).toBe("completed");
    expect(engineRuns).toBe(1);
  });

  it("two names on one address never run at once", async () => {
    const first = await seed(HOST);
    let release: () => void = () => {};
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    let engineRuns = 0;
    const started = runner(api.db, async () => {
      engineRuns++;
      await blocked;
    });
    await started.start();
    await waitFor(async () => (await read(first))?.status === "running");
    const second = await seed("other.acme-shop.io");
    started.wake();
    await sleep(400);
    // The second name resolves to the same address: it waits, and nothing was asked of the server in its name.
    expect(await read(second)).toMatchObject({ status: "queued" });
    expect(hits.map((hit) => hit.host)).toEqual([HOST]);
    release();
    await started.idle();
    await started.stop();
    expect((await read(first))?.status).toBe("completed");
    // Its turn came afterwards. (The fixture certificate is for the first name only, so its ownership check fails.)
    expect(await read(second)).toMatchObject({ status: "refused", end_reason: "target_not_verified" });
    expect(engineRuns).toBe(1);
  });
});
