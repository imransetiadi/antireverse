import type { SloId } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { createProber, type ProberOptions, type ProbeTransport } from "../src/probe/runner.ts";
import { captureLogger } from "./helpers.ts";

// Slice 18g: the probe runner over a scripted transport, a manual monotonic clock and manual timers. No sleeps: the
// injected `sleep` moves the clock. One cycle = the marked block's enforcement (SLO-06), then the marked Event's
// appearance (SLO-04).

interface Script {
  /** Milliseconds after the publish at which the Shield starts refusing the path; null: never. */
  enforcedAfterMs?: number | null;
  /** Milliseconds after the refusal at which the Event becomes readable; null: never. */
  visibleAfterMs?: number | null;
  publish?: () => Promise<void>;
  /** The status of a request the Shield's decision says it would refuse. Default 403. */
  status?: () => number;
  connect?: () => Promise<void>;
}

function harness(script: Script = {}, overrides: Partial<ProberOptions> = {}) {
  let clock = 1_000;
  const samples: { slo: SloId; good: boolean; ms: number }[] = [];
  const calls: string[] = [];
  const paths: string[] = [];
  const timers: { fn: () => void; ms: number; cleared: boolean }[] = [];
  const logger = captureLogger();
  let connects = 0;
  let closed = 0;
  let publishedAt: number | null = null;
  let refusedAt: number | null = null;
  const transport: ProbeTransport = {
    async publishBlock(path) {
      calls.push("publish");
      paths.push(path);
      await script.publish?.();
      publishedAt = clock;
      refusedAt = null;
    },
    blocks(path) {
      expect(path).toBe(paths.at(-1));
      const after = script.enforcedAfterMs === undefined ? 300 : script.enforcedAfterMs;
      return after !== null && publishedAt !== null && clock - publishedAt >= after;
    },
    async request(path) {
      calls.push("request");
      expect(path).toBe(paths.at(-1));
      const status = script.status?.() ?? 403;
      if (status === 403) refusedAt ??= clock;
      return status;
    },
    async eventVisible(route) {
      calls.push("event");
      expect(route).toBe(paths.at(-1));
      const after = script.visibleAfterMs === undefined ? 500 : script.visibleAfterMs;
      return after !== null && refusedAt !== null && clock - refusedAt >= after;
    },
    async close() {
      closed++;
    },
  };
  const prober = createProber({
    connect: async () => {
      connects++;
      await script.connect?.();
      return transport;
    },
    slo: { record: (slo, good, ms) => samples.push({ slo, good, ms }) },
    logger,
    now: () => new Date(Date.UTC(2026, 10, 20, 8, 0, 0) + clock),
    monotonic: () => clock,
    sleep: async (ms) => {
      clock += ms;
    },
    setTimer: (fn, ms) => {
      const timer = { fn, ms, cleared: false };
      timers.push(timer);
      return timer;
    },
    clearTimer: (handle) => {
      (handle as { cleared: boolean }).cleared = true;
    },
    ...overrides,
  });
  return {
    prober,
    samples,
    calls,
    paths,
    timers,
    logger,
    script,
    connects: () => connects,
    closed: () => closed,
    advance: (ms: number) => {
      clock += ms;
    },
  };
}

describe("one probe cycle", () => {
  it("publishes a marked block on a fresh nonce path, times its enforcement and then the Event's appearance", async () => {
    const h = harness();
    const run = await h.prober.runOnce();
    expect(h.paths).toHaveLength(1);
    expect(h.paths[0]).toMatch(/^\/airverse-probe\/[0-9a-f]{24}$/);
    expect(run).toEqual({
      enforcement: { outcome: "good", ms: 300 },
      freshness: { outcome: "good", ms: 500 },
    });
    expect(h.samples).toEqual([
      { slo: "SLO-06", good: true, ms: 300 },
      { slo: "SLO-04", good: true, ms: 500 },
    ]);
    // The real request is sent only once the Shield's own decision refuses the path: one Event a cycle.
    expect(h.calls.filter((call) => call === "request")).toHaveLength(1);
    expect(h.calls.indexOf("publish")).toBeLessThan(h.calls.indexOf("request"));
    expect(h.calls.indexOf("request")).toBeLessThan(h.calls.indexOf("event"));
    expect(h.prober.status()).toEqual({
      interval_s: 60,
      runs: 1,
      failures: 0,
      consecutive_failures: 0,
      setup_failures: 0,
      last_run_at: "2026-11-20T08:00:01.800Z",
      enforcement: { outcome: "good", ms: 300 },
      freshness: { outcome: "good", ms: 500 },
    });
    expect(h.logger.lines).toEqual([]);

    await h.prober.runOnce();
    expect(h.paths[1]).toMatch(/^\/airverse-probe\/[0-9a-f]{24}$/);
    expect(h.paths[1]).not.toBe(h.paths[0]);
    expect(h.connects()).toBe(1);
  });

  it("starts with an empty status", () => {
    expect(harness().prober.status()).toEqual({
      interval_s: 60,
      runs: 0,
      failures: 0,
      consecutive_failures: 0,
      setup_failures: 0,
      last_run_at: null,
      enforcement: null,
      freshness: null,
    });
  });

  it("counts enforcement at exactly 30 s as good and anything later as bad (late), still timing the Event", async () => {
    const onTime = harness({ enforcedAfterMs: 30_000 });
    expect((await onTime.prober.runOnce())?.enforcement).toEqual({ outcome: "good", ms: 30_000 });
    expect(onTime.samples[0]).toEqual({ slo: "SLO-06", good: true, ms: 30_000 });

    const late = harness({ enforcedAfterMs: 30_100 });
    const run = await late.prober.runOnce();
    expect(run).toEqual({ enforcement: { outcome: "late", ms: 30_100 }, freshness: { outcome: "good", ms: 500 } });
    expect(late.samples).toEqual([
      { slo: "SLO-06", good: false, ms: 30_100 },
      { slo: "SLO-04", good: true, ms: 500 },
    ]);
    expect(late.logger.lines).toEqual(["probe failed leg=enforcement outcome=late ms=30100"]);
    expect(late.prober.status()).toMatchObject({ runs: 1, failures: 1, consecutive_failures: 1 });
  });

  // A leg that is given up is recorded just past its bound, so that the latency histogram never shows it as having
  // met the p99 target it missed.
  it("gives up at 60 s: a bad SLO-06 sample, and the Event leg is skipped, not counted", async () => {
    const h = harness({ enforcedAfterMs: null });
    const run = await h.prober.runOnce();
    expect(run).toEqual({
      enforcement: { outcome: "timeout", ms: 60_000 },
      freshness: { outcome: "skipped", ms: null },
    });
    expect(h.samples).toEqual([{ slo: "SLO-06", good: false, ms: 60_001 }]);
    expect(h.calls).not.toContain("request");
    expect(h.calls).not.toContain("event");
    expect(h.logger.lines).toEqual([
      "probe failed leg=enforcement outcome=timeout ms=60000",
      "probe skipped leg=freshness reason=block_not_enforced",
    ]);
  });

  it("does not take the Shield's decision for enforcement: the request itself must be refused", async () => {
    let answers = 0;
    const h = harness({ enforcedAfterMs: 0, status: () => (++answers < 4 ? 204 : 403) });
    const run = await h.prober.runOnce();
    expect(run?.enforcement).toEqual({ outcome: "good", ms: 300 });
    expect(h.calls.filter((call) => call === "request")).toHaveLength(4);
  });

  it("keeps waiting when a request through the Shield fails, and says so only if the leg then fails", async () => {
    let attempts = 0;
    const h = harness({
      enforcedAfterMs: 0,
      status: () => {
        if (++attempts === 1) throw new Error("ECONNRESET with ark_prod_secret");
        return 403;
      },
    });
    expect((await h.prober.runOnce())?.enforcement).toEqual({ outcome: "good", ms: 100 });
    expect(h.logger.lines).toEqual([]);
  });

  it("records a refused publish as a bad SLO-06 sample at the timeout bound, without asking the Shield", async () => {
    const h = harness({
      publish: async () => {
        throw new Error("publish refused: 500 ark_prod_secret");
      },
    });
    const run = await h.prober.runOnce();
    expect(run).toEqual({ enforcement: { outcome: "failed", ms: null }, freshness: { outcome: "skipped", ms: null } });
    expect(h.samples).toEqual([{ slo: "SLO-06", good: false, ms: 60_001 }]);
    expect(h.calls).toEqual(["publish"]);
    expect(h.logger.lines).toEqual([
      "probe failed leg=enforcement outcome=failed reason=publish error=Error",
      "probe skipped leg=freshness reason=block_not_enforced",
    ]);
    // Never the error's text: it may hold anything.
    expect(h.logger.lines.join("\n")).not.toContain("ark_prod");
  });

  it("counts an Event readable after more than 5 s as bad (late), and gives up at 30 s", async () => {
    const late = harness({ visibleAfterMs: 5_250 });
    expect((await late.prober.runOnce())?.freshness).toEqual({ outcome: "late", ms: 5_250 });
    expect(late.samples[1]).toEqual({ slo: "SLO-04", good: false, ms: 5_250 });
    expect(late.logger.lines).toEqual(["probe failed leg=freshness outcome=late ms=5250"]);

    const edge = harness({ visibleAfterMs: 5_000 });
    expect((await edge.prober.runOnce())?.freshness).toEqual({ outcome: "good", ms: 5_000 });

    const never = harness({ visibleAfterMs: null });
    expect((await never.prober.runOnce())?.freshness).toEqual({ outcome: "timeout", ms: 30_000 });
    expect(never.samples).toEqual([
      { slo: "SLO-06", good: true, ms: 300 },
      { slo: "SLO-04", good: false, ms: 30_001 },
    ]);
    expect(never.logger.lines).toEqual(["probe failed leg=freshness outcome=timeout ms=30000"]);
  });

  it("records a failed set-up as a failed run without an SLI sample, and sets up again at the next cycle", async () => {
    let fail = true;
    const h = harness({
      connect: async () => {
        if (fail) throw new TypeError("no database");
      },
    });
    expect(await h.prober.runOnce()).toEqual({
      enforcement: { outcome: "failed", ms: null },
      freshness: { outcome: "skipped", ms: null },
    });
    expect(h.samples).toEqual([]);
    expect(h.logger.lines).toEqual([
      "probe failed leg=enforcement outcome=failed reason=setup error=TypeError setup_failures=1 counted=no",
      "probe skipped leg=freshness reason=block_not_enforced",
    ]);
    expect(h.prober.status()).toMatchObject({ runs: 1, failures: 1, consecutive_failures: 1 });
    fail = false;
    expect((await h.prober.runOnce())?.enforcement.outcome).toBe("good");
    expect(h.connects()).toBe(2);
    expect(h.prober.status()).toMatchObject({ runs: 2, failures: 1, consecutive_failures: 0 });
    expect(h.logger.lines.at(-1)).toBe("probe recovered after=1");
  });
});

describe("the probe schedule", () => {
  it("runs the first cycle after the start delay and the next one a minute after the last began", async () => {
    const h = harness();
    h.prober.start();
    expect(h.timers.map((timer) => timer.ms)).toEqual([5_000]);
    h.timers[0]?.fn();
    await h.prober.idle();
    expect(h.samples).toHaveLength(2);
    // The cycle took 800 ms of the minute.
    expect(h.timers.map((timer) => timer.ms)).toEqual([5_000, 59_200]);
  });

  it("never overlaps: nothing is scheduled while a cycle runs, and a cycle longer than the interval is followed after a pause", async () => {
    const gate = Promise.withResolvers<void>();
    const h = harness({ publish: () => gate.promise });
    h.prober.start();
    h.timers[0]?.fn();
    // A second call while the cycle is in flight joins it instead of starting another.
    const [first, second] = [h.prober.runOnce(), h.prober.runOnce()];
    expect(h.timers).toHaveLength(1);
    h.advance(90_000);
    gate.resolve();
    expect(await first).toBe(await second);
    await h.prober.idle();
    expect(h.calls.filter((call) => call === "publish")).toHaveLength(1);
    expect(h.timers.map((timer) => timer.ms)).toEqual([5_000, 1_000]);
  });

  it("stops cleanly: the timer is cleared, a cycle in flight records nothing, the transport is closed", async () => {
    const gate = Promise.withResolvers<void>();
    const h = harness({ publish: () => gate.promise });
    h.prober.start();
    h.timers[0]?.fn();
    const stopping = h.prober.stop();
    gate.resolve();
    await stopping;
    expect(h.samples).toEqual([]);
    expect(h.logger.lines).toEqual([]);
    expect(h.prober.status()).toMatchObject({ runs: 0, failures: 0 });
    expect(h.closed()).toBe(1);
    expect(h.timers).toHaveLength(1);
    // Stopped for good.
    expect(await h.prober.runOnce()).toBeNull();
    h.prober.start();
    expect(h.timers).toHaveLength(1);
  });

  it("clears a waiting timer on stop and closes nothing that was never opened", async () => {
    const h = harness();
    h.prober.start();
    await h.prober.stop();
    expect(h.timers[0]?.cleared).toBe(true);
    expect(h.closed()).toBe(0);
    expect(h.connects()).toBe(0);
  });

  it("is cut by stop while it waits for the block, without a sample", async () => {
    const h = harness({ enforcedAfterMs: null });
    let sleeps = 0;
    const cut = createProberWithStopAfter(h, () => ++sleeps === 5);
    expect(await cut.runOnce()).toBeNull();
    expect(h.samples).toEqual([]);
  });
});

/** A prober on `h`'s transport whose injected sleep stops it once `when` answers true. */
function createProberWithStopAfter(h: ReturnType<typeof harness>, when: () => boolean) {
  let clock = 0;
  const prober = createProber({
    connect: async () => ({
      publishBlock: async () => {},
      blocks: () => false,
      request: async () => 204,
      eventVisible: async () => false,
      close: async () => {},
    }),
    slo: { record: (slo, good, ms) => h.samples.push({ slo, good, ms }) },
    logger: h.logger,
    monotonic: () => clock,
    sleep: async (ms) => {
      clock += ms;
      if (when()) void prober.stop();
    },
    setTimer: () => 0,
    clearTimer: () => {},
  });
  return prober;
}
