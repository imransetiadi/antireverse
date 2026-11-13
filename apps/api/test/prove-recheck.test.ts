import { TargetResponseSchema, VerifyTargetResponseSchema } from "@antireverse/protocol";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import type { ProveNetwork } from "../src/prove/deps.ts";
import { createRecheckJob, RECHECK_DEFAULTS } from "../src/prove/recheck.ts";
import type { Fetcher, FetchOutcome, Resolver } from "../src/prove/verify.ts";
import { findTarget, recordCheck } from "../src/stores/targets.ts";
import { bearer, captureLogger, createOrganization, json, makeTestApi, type TestApi } from "./helpers.ts";

// The daily re-check (slice 14): every target whose last successful ownership check is more than 24 hours old is
// checked again; success moves verified_at, failure marks it lapsed with the reason. Stand-in DNS and file, a test
// clock and a test timer: no network, no waiting.

const T0 = Date.parse("2026-11-16T10:00:00.000Z");
const HOUR = 3_600_000;
const DAY = 24 * HOUR;
let clock = T0;
const now = () => new Date(clock);

const txt = new Map<string, string[][] | Error>();
let fileFor: (host: string) => Promise<FetchOutcome> = async () => ({ ok: false, reason: "status" });

const resolver: Resolver = {
  async txt(name) {
    const records = txt.get(name);
    if (records === undefined) throw Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" });
    if (records instanceof Error) throw records;
    return records;
  },
  addresses: async () => [],
};
const fetcher: Fetcher = (host) => fileFor(host);
const network: ProveNetwork = { resolver, fetcher };

let api: TestApi;
let orgA: { id: string; admin: string };
let orgB: { id: string; admin: string };

async function organization(name: string) {
  const created = await createOrganization(api, name);
  return { id: created.organization.id, admin: created.admin_key.key };
}

async function verifiedTarget(org: { admin: string }, host: string) {
  const res = await api.app.request("/v1/targets", json({ host }, bearer(org.admin)));
  const { target, verification } = TargetResponseSchema.parse(await res.json());
  txt.set(verification.dns_name, [[verification.dns_value]]);
  const verified = await api.app.request(`/v1/targets/${target.id}/verify`, {
    method: "POST",
    headers: bearer(org.admin),
  });
  const body = VerifyTargetResponseSchema.parse(await verified.json());
  expect(body.target.status).toBe("verified");
  return { ...body.target, dnsName: verification.dns_name, token: verification.file_content };
}

const read = async (orgId: string, id: string) =>
  (await api.db.tx({ organizationId: orgId }, (q) => findTarget(q, id)))?.target;

beforeAll(async () => {
  api = await makeTestApi({ now, prove: network });
  orgA = await organization("A");
  orgB = await organization("B");
});

afterAll(async () => {
  await api.close();
});

beforeEach(() => {
  clock = T0;
  fileFor = async () => ({ ok: false, reason: "status" });
});

describe("re-check job", () => {
  it("checks nothing that was verified less than 24 hours ago", async () => {
    const org = await organization("Young");
    const target = await verifiedTarget(org, "young.acme-shop.io");
    clock = T0 + DAY - 1;
    const job = createRecheckJob({ db: api.db, network, now });
    const counts = await job.runOnce();
    expect(await read(org.id, target.id)).toEqual(expect.objectContaining({ verified_at: target.verified_at }));
    expect(counts.verified + counts.lapsed).toBe(0);
  });

  it("moves verified_at forward on success and marks a failure lapsed with the reason, across Organizations", async () => {
    const kept = await verifiedTarget(orgA, "kept.acme-shop.io");
    const lost = await verifiedTarget(orgB, "lost.acme-shop.io");
    txt.delete(lost.dnsName);
    fileFor = async () => ({ ok: false, reason: "address_not_public" });
    clock = T0 + DAY + 60_000;
    const logger = captureLogger();
    const job = createRecheckJob({ db: api.db, network, now, logger });
    const counts = await job.runOnce();
    expect(counts).toMatchObject({ verified: expect.any(Number), lapsed: expect.any(Number), failed: 0 });
    const at = new Date(clock).toISOString();
    expect(await read(orgA.id, kept.id)).toMatchObject({
      status: "verified",
      method: "dns",
      verified_at: at,
      last_checked_at: at,
      lapsed_reason: null,
    });
    expect(await read(orgB.id, lost.id)).toMatchObject({
      status: "lapsed",
      verified_at: lost.verified_at,
      last_checked_at: at,
      lapsed_reason: "DNS: no_record; file: not_reachable",
    });
    // Which internal check refused the host is kept in counts only (review F4).
    expect(counts).toMatchObject({ notPublic: 1, unresolved: 0 });
    // Nothing in the log names a host or a token.
    for (const line of logger.lines) {
      expect(line).not.toContain("acme-shop.io");
      expect(line).not.toContain(kept.token);
    }

    // A lapsed target is not authorised; the job checks it again daily, and it stays lapsed while the check fails.
    const authorize = await api.app.request(
      "/v1/prove/authorize",
      json({ host: "lost.acme-shop.io", path: "/", intensity: "passive", at }, bearer(orgB.admin)),
    );
    expect(await authorize.json()).toEqual({ allowed: false, reason: "target_not_verified" });
    clock += DAY - 1;
    await job.runOnce();
    expect(await read(orgB.id, lost.id)).toMatchObject({ status: "lapsed", last_checked_at: at });
    clock += 1;
    await job.runOnce();
    expect(await read(orgB.id, lost.id)).toMatchObject({
      status: "lapsed",
      verified_at: lost.verified_at,
      last_checked_at: new Date(clock).toISOString(),
      lapsed_reason: "DNS: no_record; file: not_reachable",
    });
  });

  it("re-checks a lapsed target daily and verifies it again on its own once ownership is proven", async () => {
    const org = await organization("Recover");
    const target = await verifiedTarget(org, "recover.acme-shop.io");
    const record = txt.get(target.dnsName);
    txt.delete(target.dnsName);
    clock = T0 + DAY;
    const job = createRecheckJob({ db: api.db, network, now });
    await job.runOnce();
    expect(await read(org.id, target.id)).toMatchObject({ status: "lapsed" });
    if (record !== undefined) txt.set(target.dnsName, record);
    clock = T0 + 2 * DAY - 1;
    await job.runOnce();
    expect(await read(org.id, target.id)).toMatchObject({ status: "lapsed" });
    clock = T0 + 2 * DAY;
    await job.runOnce();
    const at = new Date(clock).toISOString();
    expect(await read(org.id, target.id)).toMatchObject({
      status: "verified",
      method: "dns",
      verified_at: at,
      last_checked_at: at,
      lapsed_reason: null,
    });
  });

  it("does not lapse a target when only our own resolver failed: retries each run, lapses after 3 in a row", async () => {
    const org = await organization("Outage");
    const target = await verifiedTarget(org, "outage.acme-shop.io");
    const record = txt.get(target.dnsName);
    const outage = () => {
      txt.set(target.dnsName, Object.assign(new Error("queryTxt ESERVFAIL"), { code: "ESERVFAIL" }));
      fileFor = async () => ({ ok: false, reason: "resolve_failed" });
    };
    const job = createRecheckJob({ db: api.db, network, now });
    outage();
    // Two failures of ours, then a success: the count starts again.
    for (const hours of [24, 25]) {
      clock = T0 + hours * HOUR;
      await job.runOnce();
      expect(await read(org.id, target.id)).toMatchObject({
        status: "verified",
        verified_at: target.verified_at,
        last_checked_at: new Date(clock).toISOString(),
      });
    }
    if (record !== undefined) txt.set(target.dnsName, record);
    clock = T0 + 26 * HOUR;
    await job.runOnce();
    const recovered = await read(org.id, target.id);
    expect(recovered).toMatchObject({ status: "verified", verified_at: new Date(clock).toISOString() });

    outage();
    for (const hours of [50, 51]) {
      clock = T0 + hours * HOUR;
      await job.runOnce();
      expect(await read(org.id, target.id)).toMatchObject({
        status: "verified",
        verified_at: recovered?.verified_at,
      });
    }
    clock = T0 + 52 * HOUR;
    await job.runOnce();
    expect(await read(org.id, target.id)).toMatchObject({
      status: "lapsed",
      verified_at: recovered?.verified_at,
      lapsed_reason: "DNS: lookup_failed; file: not_reachable",
    });
  });

  it("lapses at once when the customer's side answered (lookup failed but the file was reached)", async () => {
    const org = await organization("Answered");
    const target = await verifiedTarget(org, "answered.acme-shop.io");
    txt.set(target.dnsName, Object.assign(new Error("queryTxt ESERVFAIL"), { code: "ESERVFAIL" }));
    fileFor = async () => ({ ok: false, reason: "status" });
    clock = T0 + DAY;
    await createRecheckJob({ db: api.db, network, now }).runOnce();
    expect(await read(org.id, target.id)).toMatchObject({
      status: "lapsed",
      lapsed_reason: "DNS: lookup_failed; file: status",
    });
  });

  it("verifies by the file when the DNS record is gone but the file holds the token", async () => {
    const org = await organization("File");
    const target = await verifiedTarget(org, "file.acme-shop.io");
    txt.delete(target.dnsName);
    fileFor = async () => ({ ok: true, body: target.token });
    clock = T0 + 25 * HOUR;
    await createRecheckJob({ db: api.db, network, now }).runOnce();
    expect(await read(org.id, target.id)).toMatchObject({ status: "verified", method: "file" });
  });

  it("runs at most `concurrency` checks at once", async () => {
    const org = await organization("Many");
    const targets = [];
    for (let index = 0; index < 6; index++) {
      const target = await verifiedTarget(org, `many${index}.acme-shop.io`);
      txt.delete(target.dnsName);
      targets.push(target);
    }
    let inFlight = 0;
    let most = 0;
    fileFor = async () => {
      inFlight++;
      most = Math.max(most, inFlight);
      await new Promise((resolve) => setTimeout(resolve, 15));
      inFlight--;
      return { ok: false, reason: "timeout" };
    };
    clock = T0 + 30 * DAY;
    await createRecheckJob({ db: api.db, network, now, concurrency: 2 }).runOnce();
    expect(most).toBe(2);
    for (const target of targets) expect((await read(org.id, target.id))?.status).toBe("lapsed");
  });

  it("never overwrites a check recorded meanwhile (a manual verify during the re-check)", async () => {
    const org = await organization("Race");
    const target = await verifiedTarget(org, "race.acme-shop.io");
    txt.delete(target.dnsName);
    const manualAt = new Date(T0 + DAY + 30_000);
    fileFor = async () => {
      await api.db.tx({ organizationId: org.id }, (q) =>
        recordCheck(q, target.id, { verified: true, method: "file" }, manualAt),
      );
      return { ok: false, reason: "timeout" };
    };
    clock = T0 + DAY + 60_000;
    await createRecheckJob({ db: api.db, network, now }).runOnce();
    expect(await read(org.id, target.id)).toMatchObject({
      status: "verified",
      method: "file",
      verified_at: manualAt.toISOString(),
    });
  });

  it("schedules itself: first run after a jitter, then every interval plus jitter, until stopped", async () => {
    const timers: { fn: () => void; ms: number; cleared: boolean }[] = [];
    const job = createRecheckJob({
      db: api.db,
      network,
      now,
      intervalMs: 1_000,
      jitterMs: 100,
      random: () => 0.5,
      setTimer: (fn, ms) => {
        const timer = { fn, ms, cleared: false };
        timers.push(timer);
        return timer;
      },
      clearTimer: (handle) => {
        (handle as { cleared: boolean }).cleared = true;
      },
    });
    const stop = job.start();
    expect(timers.map((t) => t.ms)).toEqual([50]);
    timers[0]?.fn();
    await job.flush();
    expect(timers.map((t) => t.ms)).toEqual([50, 1_050]);
    stop();
    expect(timers[1]?.cleared).toBe(true);
    timers[1]?.fn();
    await job.flush();
    expect(timers).toHaveLength(2);
  });

  it("has a daily rhythm by default: hourly runs with up to 5 minutes of jitter, 4 checks at once", () => {
    expect(RECHECK_DEFAULTS).toEqual({ intervalMs: HOUR, jitterMs: 5 * 60_000, concurrency: 4, batchMax: 200 });
  });
});
