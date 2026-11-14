import { verifyWebhookSignature } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type OwnedDb, openDb } from "../src/db/db.ts";
import type { AlertFetch, AlertRequestInit } from "../src/notify/notifier.ts";
import { HISTOGRAM_SIZE, type SloBucket } from "../src/slo/evaluate.ts";
import { createSloService, SLO_JOB_DEFAULTS } from "../src/slo/service.ts";
import { readOpsSettings } from "../src/slo/settings.ts";
import { addSloBuckets, readSloBuckets } from "../src/slo/store.ts";
import { captureLogger } from "./helpers.ts";

// Slice 18d: the SLO job — evaluated every minute, burn alerts logged (counts only) and sent to the operator webhook,
// signed with AR_OPS_WEBHOOK_SECRET like alert-channel webhooks — and the operator settings.

const MINUTE = 60_000;
const SECRET = "whsec_".padEnd(48, "s3");
const URL_ = "https://ops.example.test/hooks/slo";

let db: OwnedDb;
beforeAll(async () => {
  db = await openDb();
});
afterAll(async () => {
  await db.close();
});

async function reset(): Promise<void> {
  await db.owner(async (q) => {
    await q.query("DELETE FROM slo_minutes");
    await q.query("DELETE FROM slo_alerts");
  });
}

function bucket(minute: number, good: number, total: number): SloBucket {
  return { minute, slo: "SLO-01", variant: "all", good, total, histogram: new Array(HISTOGRAM_SIZE).fill(0) };
}

describe("readOpsSettings", () => {
  it("is off without AR_OPS_TOKEN, and refuses a short or spaced token naming the variable only", () => {
    expect(readOpsSettings({})).toEqual({ token: null, webhook: null });
    expect(readOpsSettings({ AR_OPS_TOKEN: "" })).toEqual({ token: null, webhook: null });
    const token = "t".repeat(32);
    expect(readOpsSettings({ AR_OPS_TOKEN: token }).token).toBe(token);
    for (const bad of ["t".repeat(31), `${"t".repeat(32)} x`, "é".repeat(40)]) {
      let message = "";
      try {
        readOpsSettings({ AR_OPS_TOKEN: bad });
      } catch (error) {
        message = (error as Error).message;
      }
      expect(message).toMatch(/AR_OPS_TOKEN must be at least 32/);
      expect(message).not.toContain(bad);
    }
  });

  it("reads the webhook URL and its optional secret, and refuses a bad URL, a short secret or a secret alone", () => {
    expect(readOpsSettings({ AR_OPS_WEBHOOK_URL: URL_ }).webhook).toEqual({ url: URL_, secret: null });
    expect(readOpsSettings({ AR_OPS_WEBHOOK_URL: URL_, AR_OPS_WEBHOOK_SECRET: SECRET }).webhook).toEqual({
      url: URL_,
      secret: SECRET,
    });
    expect(() => readOpsSettings({ AR_OPS_WEBHOOK_URL: "ftp://x.test/" })).toThrow(/AR_OPS_WEBHOOK_URL/);
    expect(() => readOpsSettings({ AR_OPS_WEBHOOK_URL: "https://u:p@x.test/" })).toThrow(/AR_OPS_WEBHOOK_URL/);
    expect(() => readOpsSettings({ AR_OPS_WEBHOOK_URL: URL_, AR_OPS_WEBHOOK_SECRET: "short" })).toThrow(
      /AR_OPS_WEBHOOK_SECRET/,
    );
    expect(() => readOpsSettings({ AR_OPS_WEBHOOK_SECRET: SECRET })).toThrow(/AR_OPS_WEBHOOK_URL/);
  });
});

describe("SLO job", () => {
  it("fires once when the 1 h and 5 m burns cross 14.4x, resolves once, logs counts only and posts signed alerts", async () => {
    await reset();
    const start = Date.parse("2026-11-14T08:00:00.000Z");
    let clock = start;
    const sent: { url: string; init: AlertRequestInit }[] = [];
    const fetch: AlertFetch = async (url, init) => {
      sent.push({ url, init });
      return { status: 204, body: null };
    };
    const logger = captureLogger();
    const service = createSloService({
      db,
      now: () => new Date(clock),
      logger,
      webhook: { url: URL_, secret: SECRET },
      fetch,
      resolve: async () => [{ address: "10.0.0.7", family: 4 }],
    });
    const fired: string[] = [];
    // 60 healthy minutes, 10 at 2 % bad, 30 healthy: evaluated at the end of each minute, as the timer does.
    for (let m = 0; m < 100; m++) {
      const minute = start + m * MINUTE;
      const bad = m >= 60 && m < 70 ? 20 : 0;
      await db.owner((q) => addSloBuckets(q, [bucket(minute, 1000 - bad, 1000)]));
      clock = minute + 59_000;
      for (const t of await service.runOnce()) {
        if (t.slo === "SLO-01" && t.rule.id === "fast") fired.push(`${m}:${t.state}`);
      }
    }
    await service.flush();
    expect(fired).toEqual(["64:firing", "74:resolved"]);

    const fast = sent
      .map((s) => ({ s, body: JSON.parse(s.init.body) }))
      .filter(({ body }) => body.slo === "SLO-01" && body.rule === "fast");
    expect(fast.map(({ body }) => body.state)).toEqual(["firing", "resolved"]);
    const first = fast[0];
    expect(first?.s.url).toBe(URL_);
    expect(first?.body).toMatchObject({
      type: "slo.alert",
      state: "firing",
      slo: "SLO-01",
      name: "Attestation",
      rule: "fast",
      severity: "page",
      threshold: 14.4,
      long_window: "1h",
      short_window: "5m",
      runbook: "RB-03",
      at: new Date(start + 64 * MINUTE + 59_000).toISOString(),
    });
    expect(first?.body.burn["1h"]).toBeCloseTo(100 / 60_000 / 0.0001, 6);
    const signature = first?.s.init.headers["ar-signature"] ?? "";
    expect(
      verifyWebhookSignature(
        SECRET,
        signature,
        first?.s.init.body ?? "",
        Math.floor((start + 64 * MINUTE + 59_000) / 1000),
      ),
    ).toBe(true);

    const lines = logger.lines.filter((line) => line.startsWith("slo alert"));
    expect(lines).toContain(
      "slo alert firing slo=SLO-01 rule=fast severity=page runbook=RB-03 burn_long=16.67 burn_short=200",
    );
    expect(lines).toContain(
      "slo alert resolved slo=SLO-01 rule=fast severity=page runbook=RB-03 burn_long=33.33 burn_short=0",
    );
    expect(logger.lines.some((line) => line.startsWith("slo webhook") && line.includes("outcome=delivered"))).toBe(
      true,
    );
    // Never the URL or the secret.
    expect(logger.lines.join("\n")).not.toMatch(/example\.test|whsec/);
  });

  it("sends nothing without a webhook, and logs a failed delivery by its status only", async () => {
    await reset();
    const at = Date.parse("2026-11-14T12:00:30.000Z");
    await db.owner((q) => addSloBuckets(q, [bucket(Math.floor(at / MINUTE) * MINUTE, 0, 10)]));
    const quiet = createSloService({ db, now: () => new Date(at), logger: captureLogger() });
    expect((await quiet.runOnce()).length).toBe(3);
    // A fresh episode for the next service (the quiet one persisted its firing rules).
    await db.owner((q) => q.query("DELETE FROM slo_alerts"));

    const logger = captureLogger();
    let attempts = 0;
    const failing = createSloService({
      db,
      now: () => new Date(at),
      logger,
      webhook: { url: URL_, secret: null },
      fetch: async (_url, init) => {
        attempts++;
        expect(init.headers["ar-signature"]).toBeUndefined();
        return { status: 503, body: null };
      },
      resolve: async () => [{ address: "10.0.0.7", family: 4 }],
      sleep: async () => {},
    });
    await failing.runOnce();
    await failing.flush();
    // 3 rules fired, each tried 3 times.
    expect(attempts).toBe(9);
    expect(
      logger.lines.filter((line) => line.startsWith("slo webhook") && line.includes("outcome=failed status=503")),
    ).toHaveLength(3);
  });

  it("sweeps minutes older than 35 days on its run, and flushes the recorder on flush", async () => {
    await reset();
    const at = Date.parse("2026-11-14T12:00:30.000Z");
    const old = Math.floor((at - 36 * 86_400_000) / MINUTE) * MINUTE;
    await db.owner((q) => addSloBuckets(q, [bucket(old, 1, 1)]));
    const service = createSloService({ db, now: () => new Date(at), logger: captureLogger() });
    service.recorder.record("SLO-02", true, 5);
    await service.runOnce();
    const minutes = (await db.owner((q) => readSloBuckets(q))).map((b) => b.slo);
    expect(minutes).toEqual(["SLO-02"]);
    service.recorder.record("SLO-02", true, 5);
    await service.flush();
    expect((await db.owner((q) => readSloBuckets(q)))[0]?.total).toBe(2);
  });

  it("runs every minute on its timer, and stops", async () => {
    const timers: { fn: () => void; ms: number }[] = [];
    let cleared = 0;
    const service = createSloService({
      db,
      logger: captureLogger(),
      setTimer: (fn, ms) => {
        timers.push({ fn, ms });
        return timers.length;
      },
      clearTimer: () => {
        cleared++;
      },
    });
    expect(SLO_JOB_DEFAULTS.everyMs).toBe(60_000);
    const stop = service.start();
    expect(timers.map((t) => t.ms)).toEqual([60_000]);
    timers[0]?.fn();
    await service.flush();
    expect(timers.map((t) => t.ms)).toEqual([60_000, 60_000]);
    stop();
    expect(cleared).toBe(1);
  });
});

describe("review fixes", () => {
  const T = Date.parse("2026-11-14T15:00:30.000Z");
  const minuteAt = (ms: number) => Math.floor(ms / MINUTE) * MINUTE;
  const okFetch =
    (sent: string[]): AlertFetch =>
    async (_url, init) => {
      sent.push(init.body);
      return { status: 204, body: null };
    };
  const resolveLocal = async () => [{ address: "10.0.0.7", family: 4 }];

  it("M2: keeps firing states across a restart: a burn that still holds does not fire again, an ended one resolves", async () => {
    await reset();
    let clock = T;
    await db.owner((q) => addSloBuckets(q, [bucket(minuteAt(clock), 500, 1000)]));
    const sentA: string[] = [];
    const a = createSloService({
      db,
      now: () => new Date(clock),
      logger: captureLogger(),
      webhook: { url: URL_, secret: null },
      fetch: okFetch(sentA),
      resolve: resolveLocal,
    });
    expect((await a.runOnce()).map((t) => t.rule.id)).toEqual(["fast", "slow", "ticket"]);
    await a.flush();
    const fired = JSON.parse(sentA[0] ?? "{}");
    expect(fired.episode).toBe(`SLO-01/fast/${new Date(T).toISOString()}`);

    // The process restarts. One minute later the burn still holds: nothing fires again.
    clock = T + MINUTE;
    await db.owner((q) => addSloBuckets(q, [bucket(minuteAt(clock), 500, 1000)]));
    const sentB: string[] = [];
    const b = createSloService({
      db,
      now: () => new Date(clock),
      logger: captureLogger(),
      webhook: { url: URL_, secret: null },
      fetch: okFetch(sentB),
      resolve: resolveLocal,
    });
    expect(await b.runOnce()).toEqual([]);
    expect((await b.report()).slos.find((s) => s.id === "SLO-01")?.alerts[0]).toEqual({
      rule: "fast",
      severity: "page",
      state: "firing",
      since: new Date(T).toISOString(),
    });

    // Recovery: five clean minutes. The fast page resolves, with the episode id of its firing.
    for (let m = 2; m <= 6; m++)
      await db.owner((q) => addSloBuckets(q, [bucket(minuteAt(T + m * MINUTE), 1000, 1000)]));
    clock = T + 6 * MINUTE;
    const resolved = (await b.runOnce()).filter((t) => t.slo === "SLO-01");
    expect(resolved.map((t) => `${t.rule.id}:${t.state}`)).toEqual(["fast:resolved"]);
    await b.flush();
    expect(sentB.map((body) => JSON.parse(body))).toMatchObject([
      { state: "resolved", rule: "fast", episode: `SLO-01/fast/${new Date(T).toISOString()}` },
    ]);
    const stored = await db.owner((q) => q.query<{ rule: string }>("SELECT rule FROM slo_alerts ORDER BY rule"));
    expect(stored.rows.map((row) => row.rule)).toEqual(["slow", "ticket"]);
  });

  it("L2: flushes the recorder first on close, and waits at most 2 s for an unreachable webhook", async () => {
    await reset();
    await db.owner((q) => addSloBuckets(q, [bucket(minuteAt(T), 0, 10)]));
    const service = createSloService({
      db,
      now: () => new Date(T),
      logger: captureLogger(),
      webhook: { url: URL_, secret: null },
      // Hangs until aborted.
      fetch: (_url, init) =>
        new Promise((_resolve, reject) => init.signal.addEventListener("abort", () => reject(new Error("aborted")))),
      resolve: resolveLocal,
    });
    expect((await service.runOnce()).length).toBe(3);
    service.recorder.record("SLO-02", true, 5);
    const started = Date.now();
    await service.flush();
    expect(Date.now() - started).toBeLessThan(2_000);
    expect((await db.owner((q) => readSloBuckets(q))).some((b) => b.slo === "SLO-02")).toBe(true);
  });

  it("serves reads from a 30-day aggregate at most 15 s old", async () => {
    await reset();
    let clock = T;
    const service = createSloService({ db, now: () => new Date(clock), logger: captureLogger() });
    service.recorder.record("SLO-02", true, 5);
    const total = async () => (await service.report()).slos.find((s) => s.id === "SLO-02")?.total;
    expect(await total()).toBe(1);
    service.recorder.record("SLO-02", true, 5);
    clock = T + 10_000;
    expect(await total()).toBe(1);
    expect(await service.metrics()).toContain('airverse_slo_total{slo="SLO-02"} 1\n');
    clock = T + 16_000;
    expect(await total()).toBe(2);
    // The minute's evaluation always reads afresh.
    service.recorder.record("SLO-02", true, 5);
    await service.runOnce();
    expect(await total()).toBe(3);
  });
});
