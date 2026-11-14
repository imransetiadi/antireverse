import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type OwnedDb, openDb } from "../src/db/db.ts";
import { aggregate, HISTOGRAM_SIZE, type SloBucket } from "../src/slo/evaluate.ts";
import { createSloRecorder } from "../src/slo/recorder.ts";
import { readSloAggregates, readSloBuckets, sweepSloMinutes } from "../src/slo/store.ts";
import { GLOBAL_TABLES } from "./data-seed.ts";

// Slice 18d: the in-memory SLI recorder, its per-minute flush to the owner-only table `slo_minutes` (migration 0037),
// its restart safety, the 35-day sweep, and the SQL aggregation that must equal the pure one.

const MINUTE = 60_000;
const T0 = Date.parse("2026-11-14T10:00:00.000Z");

let db: OwnedDb;
let clock = T0;
const now = () => new Date(clock);

beforeAll(async () => {
  db = await openDb();
});
afterAll(async () => {
  await db.close();
});

async function rows(): Promise<SloBucket[]> {
  return db.owner((q) => readSloBuckets(q));
}

async function clear(): Promise<void> {
  await db.owner((q) => q.query("DELETE FROM slo_minutes"));
}

describe("slo_minutes", () => {
  it("has no tenant identifier, is a named global table, and the request role cannot touch it", async () => {
    const columns = await db.owner(async (q) => {
      const { rows } = await q.query<{ column_name: string }>(
        "SELECT column_name FROM information_schema.columns WHERE table_name = 'slo_minutes' ORDER BY ordinal_position",
      );
      return rows.map((row) => row.column_name);
    });
    expect(columns).toEqual(["minute", "slo", "variant", "good", "total", "histogram"]);
    for (const table of ["slo_minutes", "slo_alerts", "slo_flushes"]) {
      expect(GLOBAL_TABLES).toHaveProperty(table);
      await expect(
        db.tx("none", (q) => q.query(`SELECT * FROM ${table}`)),
        table,
      ).rejects.toThrow(/permission denied/);
    }
    await expect(db.tx("none", (q) => q.query("SELECT * FROM slo_minutes"))).rejects.toThrow(/permission denied/);
    await expect(
      db.tx("none", (q) =>
        q.query(
          "INSERT INTO slo_minutes (minute, slo, variant, good, total, histogram) VALUES (now(), 'SLO-01', 'all', 0, 0, '{}')",
        ),
      ),
    ).rejects.toThrow(/permission denied/);
  });

  it("refuses a histogram of the wrong size, good above total, and an unknown SLO", async () => {
    const insert = (slo: string, good: number, total: number, size: number) =>
      db.owner((q) =>
        q.query(
          "INSERT INTO slo_minutes (minute, slo, variant, good, total, histogram) VALUES (date_trunc('minute', now()), $1, 'all', $2, $3, $4)",
          [slo, good, total, new Array(size).fill(0)],
        ),
      );
    // The migration pins 23 buckets: the bounds of the protocol plus the overflow bucket.
    expect(HISTOGRAM_SIZE).toBe(23);
    await expect(insert("SLO-01", 0, 0, HISTOGRAM_SIZE)).resolves.toBeDefined();
    await expect(insert("SLO-01", 0, 0, HISTOGRAM_SIZE - 1)).rejects.toThrow(/check/i);
    await expect(insert("SLO-01", 2, 1, HISTOGRAM_SIZE)).rejects.toThrow(/check/i);
    await expect(insert("SLO-99", 0, 0, HISTOGRAM_SIZE)).rejects.toThrow(/check/i);
  });
});

describe("recorder", () => {
  it("holds counts per SLO, variant and minute in memory, and writes nothing until it flushes", async () => {
    await clear();
    clock = T0 + 5_000;
    const recorder = createSloRecorder({ db, now });
    recorder.record("SLO-01", true, 30);
    recorder.record("SLO-01", false, 400);
    recorder.record("SLO-07", true, 120, "read");
    clock = T0 + MINUTE + 1;
    recorder.record("SLO-01", true, 30);
    expect(recorder.pending()).toBe(3);
    expect(await rows()).toEqual([]);
    await recorder.flush();
    expect(recorder.pending()).toBe(0);
    const stored = await rows();
    const h = (entries: [number, number][]) => {
      const out = new Array<number>(HISTOGRAM_SIZE).fill(0);
      for (const [i, n] of entries) out[i] = n;
      return out;
    };
    // 30 ms: the bound 50 (index 3); 400 ms: 500 (index 10); 120 ms: 120 (index 6).
    expect(stored).toEqual([
      {
        minute: T0,
        slo: "SLO-01",
        variant: "all",
        good: 1,
        total: 2,
        histogram: h([
          [3, 1],
          [10, 1],
        ]),
      },
      { minute: T0, slo: "SLO-07", variant: "read", good: 1, total: 1, histogram: h([[6, 1]]) },
      { minute: T0 + MINUTE, slo: "SLO-01", variant: "all", good: 1, total: 1, histogram: h([[3, 1]]) },
    ]);
  });

  it("adds a later flush of the same minute to the stored row, so a restart loses nothing it flushed on close", async () => {
    await clear();
    clock = T0 + 10_000;
    const first = createSloRecorder({ db, now });
    first.record("SLO-02", true, 20);
    first.record("SLO-02", false, 20);
    await first.flush(); // the close of the first process
    const second = createSloRecorder({ db, now });
    second.record("SLO-02", true, 20);
    await second.flush();
    const [row] = await rows();
    expect(row).toMatchObject({ minute: T0, slo: "SLO-02", good: 2, total: 3 });
    expect(row?.histogram[2]).toBe(3);
  });

  it("keeps what a failed flush held, and writes it with the next one", async () => {
    await clear();
    clock = T0;
    let fail = true;
    const flaky: OwnedDb = { ...db, owner: (fn) => (fail ? Promise.reject(new Error("down")) : db.owner(fn)) };
    const recorder = createSloRecorder({ db: flaky, now });
    recorder.record("SLO-03", true, 1);
    await expect(recorder.flush()).rejects.toThrow("down");
    expect(recorder.pending()).toBe(1);
    recorder.record("SLO-03", false, 1);
    fail = false;
    await recorder.flush();
    const [row] = await rows();
    expect(row).toMatchObject({ slo: "SLO-03", good: 1, total: 2 });
  });

  it("does not count a batch twice when its flush failed after the commit (an ambiguous failure)", async () => {
    await clear();
    clock = T0;
    let failAfterCommit = true;
    const ambiguous: OwnedDb = {
      ...db,
      owner: async (fn) => {
        const result = await db.owner(fn);
        if (failAfterCommit) {
          failAfterCommit = false;
          throw new Error("connection lost after commit");
        }
        return result;
      },
    };
    const recorder = createSloRecorder({ db: ambiguous, now });
    recorder.record("SLO-03", true, 1);
    recorder.record("SLO-03", true, 1);
    await expect(recorder.flush()).rejects.toThrow("after commit");
    recorder.record("SLO-03", false, 1);
    await recorder.flush();
    const [row] = await rows();
    expect(row).toMatchObject({ slo: "SLO-03", good: 2, total: 3 });
  });

  it("ignores a negative or non-finite latency as 0 ms rather than throwing on the hot path", async () => {
    await clear();
    const recorder = createSloRecorder({ db, now });
    expect(() => recorder.record("SLO-01", true, Number.NaN)).not.toThrow();
    expect(() => recorder.record("SLO-01", true, -5)).not.toThrow();
    await recorder.flush();
    const [row] = await rows();
    expect(row?.histogram[0]).toBe(2);
  });
});

describe("store", () => {
  it("sweeps minutes older than 35 days and keeps the rest", async () => {
    await clear();
    clock = T0;
    const recorder = createSloRecorder({ db, now });
    clock = T0 - 35 * 86_400_000 - MINUTE;
    recorder.record("SLO-04", true, 1);
    clock = T0 - 35 * 86_400_000 + MINUTE;
    recorder.record("SLO-04", true, 1);
    await recorder.flush();
    const removed = await db.owner((q) => sweepSloMinutes(q, new Date(T0)));
    expect(removed).toBe(1);
    expect((await rows()).map((row) => row.minute)).toEqual([T0 - 35 * 86_400_000 + MINUTE]);
  });

  it("aggregates in SQL exactly as the pure function does", async () => {
    await clear();
    const recorder = createSloRecorder({ db, now });
    const minutesAgo = [0, 3, 4, 5, 20, 29, 30, 59, 60, 300, 359, 360, 4319, 4320, 43199, 43200, 50000];
    let n = 1;
    for (const ago of minutesAgo) {
      clock = T0 - ago * MINUTE + 7_000;
      for (let i = 0; i < n; i++) recorder.record("SLO-07", i % 3 !== 0, i * 37, i % 2 === 0 ? "read" : "write");
      recorder.record("SLO-01", ago % 2 === 0, ago);
      n = (n % 5) + 1;
    }
    await recorder.flush();
    const at = T0 + 30_000;
    const fromSql = await db.owner((q) => readSloAggregates(q, at));
    const fromPure = aggregate(await rows(), at);
    expect(fromSql).toEqual(fromPure);
    expect(fromSql.get("SLO-07")?.windows["5m"].total).toBeGreaterThan(0);
  });
});
