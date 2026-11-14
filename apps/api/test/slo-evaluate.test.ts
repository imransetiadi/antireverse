import {
  SLO_ALERT_MIN_EVENTS,
  SLO_CATALOG,
  SLO_LATENCY_BOUNDS_MS,
  type SloId,
  SloStatusSchema,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import {
  aggregate,
  createAlertMachine,
  evaluateSlo,
  percentileOf,
  ruleHolds,
  type SloBucket,
  signalOf,
} from "../src/slo/evaluate.ts";

// Slice 18d: the pure evaluation — per-minute buckets to 30-day attainment, error budget left, burn rates per window
// and latency percentiles — and the alert state machine, on synthetic buckets.

const MINUTE = 60_000;
const NOW = Date.parse("2026-11-14T10:00:30.000Z");
const CURRENT = Math.floor(NOW / MINUTE) * MINUTE;
const HISTOGRAM_SIZE = SLO_LATENCY_BOUNDS_MS.length + 1;

const def = (id: SloId) => {
  const found = SLO_CATALOG.find((slo) => slo.id === id);
  if (found === undefined) throw new Error(id);
  return found;
};

/** A histogram with `n` events in the bucket whose bound is `ms` (or the overflow bucket for null). */
function histogram(entries: [number | null, number][] = []): number[] {
  const out = new Array<number>(HISTOGRAM_SIZE).fill(0);
  for (const [ms, n] of entries) {
    const index = ms === null ? HISTOGRAM_SIZE - 1 : SLO_LATENCY_BOUNDS_MS.indexOf(ms as never);
    if (index < 0) throw new Error(`no bound ${ms}`);
    out[index] = (out[index] ?? 0) + n;
  }
  return out;
}

function bucket(
  minutesAgo: number,
  good: number,
  total: number,
  slo: SloId = "SLO-02",
  extra: Partial<SloBucket> = {},
) {
  return {
    minute: CURRENT - minutesAgo * MINUTE,
    slo,
    variant: "all",
    good,
    total,
    histogram: histogram(),
    ...extra,
  } satisfies SloBucket;
}

describe("aggregate", () => {
  it("sums each window over its last whole minutes, the current minute included", () => {
    const buckets = [
      bucket(0, 1, 1),
      bucket(4, 2, 2), // the 5th minute back: in 5m
      bucket(5, 4, 4), // the 6th: out of 5m, in 30m
      bucket(29, 8, 8),
      bucket(30, 16, 16), // out of 30m, in 1h
      bucket(59, 32, 32),
      bucket(60, 64, 64), // out of 1h, in 6h
      bucket(359, 128, 128),
      bucket(360, 256, 256), // out of 6h, in 3d
      bucket(3 * 1440 - 1, 512, 512),
      bucket(3 * 1440, 1024, 1024), // out of 3d, in 30d
      bucket(30 * 1440 - 1, 2048, 2048),
      bucket(30 * 1440, 4096, 4096), // out of every window
      bucket(-1, 8192, 8192), // a minute in the future (clock skew): ignored
    ];
    const sums = aggregate(buckets, NOW).get("SLO-02")?.windows;
    expect(sums).toEqual({
      "5m": { good: 3, total: 3 },
      "30m": { good: 15, total: 15 },
      "1h": { good: 63, total: 63 },
      "6h": { good: 255, total: 255 },
      "3d": { good: 1023, total: 1023 },
      "30d": { good: 4095, total: 4095 },
    });
  });

  it("adds histograms per variant over 30 days", () => {
    const agg = aggregate(
      [
        bucket(1, 1, 1, "SLO-07", { variant: "read", histogram: histogram([[50, 3]]) }),
        bucket(2, 1, 1, "SLO-07", {
          variant: "read",
          histogram: histogram([
            [50, 1],
            [200, 1],
          ]),
        }),
        bucket(2, 1, 1, "SLO-07", { variant: "write", histogram: histogram([[500, 2]]) }),
      ],
      NOW,
    ).get("SLO-07");
    expect(agg?.histograms.read).toEqual(
      histogram([
        [50, 4],
        [200, 1],
      ]),
    );
    expect(agg?.histograms.write).toEqual(histogram([[500, 2]]));
    expect(agg?.windows["30d"]).toEqual({ good: 3, total: 3 });
  });
});

describe("evaluateSlo", () => {
  it("states 30-day attainment, the budget left and the burn per window exactly", () => {
    // SLO-02, 99.95 %: over 30 days 10,000 batches, 9,990 good: attainment 0.999, burn 2, budget -1.
    // The last 5 minutes: 1,000 batches, 999 good: burn 2 (0.001 / 0.0005).
    const buckets = [bucket(0, 999, 1000), bucket(100, 8991, 9000)];
    const status = evaluateSlo(def("SLO-02"), aggregate(buckets, NOW).get("SLO-02"));
    expect(status.good).toBe(9990);
    expect(status.total).toBe(10_000);
    expect(status.attainment).toBeCloseTo(0.999, 12);
    expect(status.budget_remaining).toBeCloseTo(-1, 9);
    expect(status.burn["5m"]).toBeCloseTo(2, 9);
    expect(status.burn["30m"]).toBeCloseTo(2, 9);
    expect(status.burn["1h"]).toBeCloseTo(2, 9);
    // 6 h: 10,000 batches, 10 bad.
    expect(status.burn["6h"]).toBeCloseTo(2, 9);
    expect(status.burn["3d"]).toBeCloseTo(2, 9);
    expect(SloStatusSchema.omit({ alerts: true }).parse(status)).toEqual(status);
  });

  it("gives nulls without events, and a whole budget never touched", () => {
    const status = evaluateSlo(def("SLO-03"), undefined);
    expect(status).toMatchObject({ good: 0, total: 0, attainment: null, budget_remaining: null, latency: [] });
    expect(Object.values(status.burn)).toEqual([null, null, null, null, null]);
    const healthy = evaluateSlo(def("SLO-03"), aggregate([bucket(0, 10, 10, "SLO-03")], NOW).get("SLO-03"));
    expect(healthy).toMatchObject({ attainment: 1, budget_remaining: 1 });
    expect(healthy.burn["5m"]).toBe(0);
  });

  it("states an unmeasured SLO with zeros and its reason", () => {
    const status = evaluateSlo(def("SLO-06"), undefined);
    expect(status).toMatchObject({ measured: false, total: 0, latency: [] });
    expect(status.not_measured_reason).toMatch(/probe/);
  });

  it("judges the latency percentiles against their targets", () => {
    // SLO-01: p95 ≤ 50, p99 ≤ 120. 100 requests: 95 at ≤ 50 ms, 4 at ≤ 120 ms, 1 above the last bound.
    const agg = aggregate(
      [
        bucket(0, 99, 100, "SLO-01", {
          histogram: histogram([
            [25, 95],
            [120, 4],
            [null, 1],
          ]),
        }),
      ],
      NOW,
    ).get("SLO-01");
    expect(evaluateSlo(def("SLO-01"), agg).latency).toEqual([
      { variant: "all", percentile: 95, target_ms: 50, observed_ms: 25, met: true },
      { variant: "all", percentile: 99, target_ms: 120, observed_ms: 120, met: true },
    ]);
    expect(
      percentileOf(
        histogram([
          [25, 95],
          [120, 4],
          [null, 1],
        ]),
        100,
      ),
    ).toBeNull();
    expect(
      percentileOf(
        histogram([
          [25, 90],
          [300, 10],
        ]),
        95,
      ),
    ).toBe(300);
    expect(percentileOf(histogram(), 95)).toBeNull();
  });
});

describe("alert state machine", () => {
  it("holds a rule only when both windows burn at the threshold", () => {
    const fast = { id: "fast", severity: "page", threshold: 14.4, long_window: "1h", short_window: "5m" } as const;
    const burn = (long: number | null, short: number | null) => ({
      "5m": short,
      "30m": null,
      "1h": long,
      "6h": null,
      "3d": null,
    });
    expect(ruleHolds(fast, burn(14.4, 14.4))).toBe(true);
    expect(ruleHolds(fast, burn(14.4, 14.3))).toBe(false);
    expect(ruleHolds(fast, burn(14.3, 100))).toBe(false);
    expect(ruleHolds(fast, burn(null, 100))).toBe(false);
  });

  it("fires once when synthetic buckets cross 14.4x and resolves once when they recover", () => {
    // SLO-01 (99.99 %, budget rate 0.0001): 1,000 requests a minute. 60 healthy minutes, then 10 minutes with 2 %
    // bad (burn 200 per minute), then 30 healthy minutes. Evaluated every minute, as the job does.
    const machine = createAlertMachine();
    const buckets: SloBucket[] = [];
    const transitions: { minute: number; rule: string; state: string }[] = [];
    const start = CURRENT - 200 * MINUTE;
    for (let m = 0; m < 100; m++) {
      const minute = start + m * MINUTE;
      const bad = m >= 60 && m < 70 ? 20 : 0;
      buckets.push({ minute, slo: "SLO-01", variant: "all", good: 1000 - bad, total: 1000, histogram: histogram() });
      const at = minute + 59_000;
      const signal = signalOf(def("SLO-01"), aggregate(buckets, at).get("SLO-01"));
      for (const t of machine.update("SLO-01", signal, new Date(at))) {
        transitions.push({ minute: m, rule: t.rule.id, state: t.state });
      }
    }
    const fast = transitions.filter((t) => t.rule === "fast");
    // 1 h burn after k bad minutes: 20k / 60,000 / 0.0001 = 3.33k: at least 14.4 from k = 5 (the 65th minute).
    // The 5 m window is clean again 5 minutes after the last bad one (minute 74).
    expect(fast).toEqual([
      { minute: 64, rule: "fast", state: "firing" },
      { minute: 74, rule: "fast", state: "resolved" },
    ]);
    // Every rule fires at most once per episode.
    for (const rule of ["fast", "slow", "ticket"]) {
      expect(transitions.filter((t) => t.rule === rule && t.state === "firing").length, rule).toBeLessThanOrEqual(1);
    }
    expect(machine.states("SLO-01").find((s) => s.rule === "fast")).toEqual({
      rule: "fast",
      severity: "page",
      state: "ok",
      since: null,
    });
  });

  it("reports the episode's start while firing", () => {
    const machine = createAlertMachine();
    const at = new Date(NOW);
    const burning = {
      burn: { "5m": 20, "30m": 20, "1h": 20, "6h": 20, "3d": 20 },
      totals: { "5m": 100, "30m": 100, "1h": 100, "6h": 100, "3d": 100 },
    };
    expect(machine.update("SLO-02", burning, at).map((t) => t.rule.id)).toEqual(["fast", "slow", "ticket"]);
    expect(machine.update("SLO-02", burning, new Date(NOW + MINUTE))).toEqual([]);
    expect(machine.states("SLO-02")[0]).toEqual({
      rule: "fast",
      severity: "page",
      state: "firing",
      since: at.toISOString(),
    });
  });
});

describe("alert state machine on sparse SLOs (review M1)", () => {
  /** Evaluates SLO-10 every minute over `minutes`, with `badAt(m)` one bad T1 run in minute m; fast transitions. */
  function sparse(minutes: number, badAt: (m: number) => boolean, goodAt: (m: number) => boolean = () => false) {
    const machine = createAlertMachine();
    const buckets: SloBucket[] = [];
    const out: string[] = [];
    const start = CURRENT - 300 * MINUTE;
    for (let m = 0; m < minutes; m++) {
      const minute = start + m * MINUTE;
      if (badAt(m)) buckets.push({ minute, slo: "SLO-10", variant: "all", good: 0, total: 1, histogram: histogram() });
      if (goodAt(m)) buckets.push({ minute, slo: "SLO-10", variant: "all", good: 1, total: 1, histogram: histogram() });
      const at = minute + 59_000;
      for (const t of machine.update(
        "SLO-10",
        signalOf(def("SLO-10"), aggregate(buckets, at).get("SLO-10")),
        new Date(at),
      )) {
        if (t.rule.id === "fast") out.push(`${m}:${t.state}`);
      }
    }
    return out;
  }

  it("needs a minimum number of events in the long window: one bad Prove run of one does not page", () => {
    expect(SLO_ALERT_MIN_EVENTS).toBe(3);
    expect(sparse(30, (m) => m === 0)).toEqual([]);
    expect(sparse(30, (m) => m === 0 || m === 10)).toEqual([]);
  });

  it("fires exactly once for one bad run every 20 minutes over 120 minutes: an empty 5 m window keeps the state", () => {
    expect(sparse(120, (m) => m % 20 === 0)).toEqual(["40:firing"]);
  });

  it("resolves on evidence: good events in the confirmation window, or the long window below the threshold", () => {
    // Three bad runs fire at minute 20; good runs every minute from 30 on make the 5 m window clean at once.
    expect(
      sparse(
        40,
        (m) => m === 0 || m === 10 || m === 20,
        (m) => m >= 30,
      ),
    ).toEqual(["20:firing", "30:resolved"]);
  });
});
