import { randomBytes } from "node:crypto";
import { PROBE_BOUNDS, PROBE_PATH_PREFIX, type ProbeLeg, type ProbeStatus } from "@antireverse/protocol";
import { consoleLogger, type Logger } from "../log.ts";
import type { SloSink } from "../slo/recorder.ts";

// Slice 18g: the synthetic probes of OPERATION §7, as one cycle a minute.
//
// 1. Enforcement (SLO-06, PB-15). The cycle publishes the marked block — a Policy whose one enforced block Rule is on
//    the literal path `/airverse-probe/<fresh nonce>` — and waits for the probe's Shield to refuse that path. It watches
//    the Shield's own decision (`blocks`, no request, no Event) and confirms with a real request through the Shield's
//    middleware; the time is taken when that request is answered 403. Good within 30 s; bad when later, when given up
//    at 60 s, or when the publish itself failed.
// 2. Freshness (SLO-04, PB-13). The refused request's Event carries the Rule's path as its route: the marked Event. The
//    cycle waits for it to be readable through the Events route, timed from the 403. Good within 5 s; bad when later
//    or given up at 30 s. When the block was not enforced there is no marked Event: the leg is skipped and is not a
//    sample (Jev: a leg that was not exercised is never counted).
//
// The runner knows nothing of HTTP, keys or the database: it drives a `ProbeTransport` (`transport.ts` is the real
// one). Times are from a monotonic clock. One cycle at a time: the next is scheduled when the one before has ended.
// Every failure is a warning (leg, outcome, a reason code, milliseconds, the class of an error — never its text) and
// shows in `status()`. A cycle cut by `stop()` records nothing: stopping is not a failure.
//
// After the independent review: both samples of a cycle are recorded together when it has ended (F4); the bookkeeping
// of a run cannot reject it (F5); and a prober that cannot be set up counts as failing from its fourth failed cycle
// in a row (D-117) — a single failed set-up still records nothing.

/** What a cycle needs of the outside. Every method may reject; `blocks` must not throw. */
export interface ProbeTransport {
  /** Publishes the marked block: the probe App's Policy with one enforced block Rule on `path`. Rejects when refused. */
  publishBlock(path: string, signal: AbortSignal): Promise<void>;
  /** The probe Shield's own decision over the bundle it has applied: true when it would refuse `path`. */
  blocks(path: string): boolean;
  /** One real request for `path` through the Shield; its status. */
  request(path: string, signal: AbortSignal): Promise<number>;
  /** True when an Event with this route is readable through the Events route. */
  eventVisible(route: string, signal: AbortSignal): Promise<boolean>;
  close(): Promise<void>;
}

export const PROBE_JOB_DEFAULTS = Object.freeze({
  /** Between the starts of two cycles: every minute (OPERATION §7). */
  everyMs: 60_000,
  /** The wait before the first cycle, and the least pause after a cycle that overran the interval. */
  startDelayMs: 5_000,
  minPauseMs: 1_000,
  /** Between two looks at the Shield's decision, and between two reads of the Events route. */
  enforcePollMs: 100,
  eventPollMs: 250,
});

export interface ProberOptions {
  /** Sets the probe up (its Organization, keys, Shield and loopback server). Called again after a failure. */
  connect: (signal: AbortSignal) => Promise<ProbeTransport>;
  slo: SloSink;
  logger?: Logger | undefined;
  now?: (() => Date) | undefined;
  /** A millisecond clock that never goes back. Default: `performance.now`. */
  monotonic?: (() => number) | undefined;
  /** Resolves after `ms`, or at once when `signal` aborts. */
  sleep?: ((ms: number, signal: AbortSignal) => Promise<void>) | undefined;
  everyMs?: number | undefined;
  startDelayMs?: number | undefined;
  enforcePollMs?: number | undefined;
  eventPollMs?: number | undefined;
  /** Default: `setTimeout`, unref'd. */
  setTimer?: ((fn: () => void, ms: number) => unknown) | undefined;
  clearTimer?: ((handle: unknown) => void) | undefined;
}

/** What one cycle found. */
export interface ProbeRun {
  enforcement: ProbeLeg;
  freshness: ProbeLeg;
}

export interface Prober {
  /** Schedules the cycles. Does nothing after `stop()`. */
  start(): void;
  /** One cycle now, or the one in flight. Null when it was cut by `stop()`, or after it. Never rejects. */
  runOnce(): Promise<ProbeRun | null>;
  /** Resolves when no cycle is in flight. */
  idle(): Promise<void>;
  status(): ProbeStatus;
  /** Clears the timer, cuts the cycle in flight (it records nothing) and closes the transport. */
  stop(): Promise<void>;
}

const defaultSetTimer = (fn: () => void, ms: number): unknown => {
  const timer = setTimeout(fn, ms);
  timer.unref?.();
  return timer;
};
const defaultClearTimer = (handle: unknown): void => clearTimeout(handle as ReturnType<typeof setTimeout>);
const defaultSleep = (ms: number, signal: AbortSignal): Promise<void> =>
  new Promise((resolve) => {
    if (signal.aborted) return resolve();
    const done = () => {
      clearTimeout(timer);
      signal.removeEventListener("abort", done);
      resolve();
    };
    const timer = setTimeout(done, ms);
    timer.unref?.();
    signal.addEventListener("abort", done, { once: true });
  });

/**
 * The latency a leg that was given up (or could not be run) is recorded with: just past its bound, so that the
 * histogram's percentile never shows a given-up probe as having met the target it missed.
 */
const beyond = (boundMs: number): number => boundMs + 1;
/** Set-up failures in a row that record nothing; each further one is a bad SLO-06 sample (D-117). */
export const PROBE_SETUP_GRACE = 3;
/** One SLI sample of a cycle, recorded when the cycle has ended. */
interface Sample {
  slo: "SLO-04" | "SLO-06";
  good: boolean;
  ms: number;
}
const SKIPPED: ProbeLeg = Object.freeze({ outcome: "skipped", ms: null });
const errorName = (error: unknown): string => {
  const name = (error as { name?: unknown } | null)?.name;
  return typeof name === "string" && /^[A-Za-z]{1,40}$/.test(name) ? name : "Error";
};

export function createProber(options: ProberOptions): Prober {
  const { slo } = options;
  const logger = options.logger ?? consoleLogger;
  const now = options.now ?? (() => new Date());
  const monotonic = options.monotonic ?? (() => performance.now());
  const sleep = options.sleep ?? defaultSleep;
  const everyMs = options.everyMs ?? PROBE_JOB_DEFAULTS.everyMs;
  const startDelayMs = options.startDelayMs ?? PROBE_JOB_DEFAULTS.startDelayMs;
  const enforcePollMs = options.enforcePollMs ?? PROBE_JOB_DEFAULTS.enforcePollMs;
  const eventPollMs = options.eventPollMs ?? PROBE_JOB_DEFAULTS.eventPollMs;
  const setTimer = options.setTimer ?? defaultSetTimer;
  const clearTimer = options.clearTimer ?? defaultClearTimer;

  const stopping = new AbortController();
  const { signal } = stopping;
  let transport: ProbeTransport | undefined;
  let running: Promise<ProbeRun | null> | undefined;
  let handle: unknown;
  let started = false;
  const state: ProbeStatus = {
    interval_s: everyMs / 1_000,
    runs: 0,
    failures: 0,
    consecutive_failures: 0,
    setup_failures: 0,
    last_run_at: null,
    enforcement: null,
    freshness: null,
  };

  /** What one cycle found: its legs, the SLI samples to record and the warnings to log. */
  interface Outcome {
    run: ProbeRun;
    samples: Sample[];
    warnings: string[];
    /** True when the probe could not be set up. */
    setup?: boolean;
  }

  /**
   * The legs of one cycle; null when cut by `stop()`. It records nothing itself: the samples are recorded by `run`
   * once the cycle has ended, so a cycle that is cut leaves no sample at all (review F4).
   */
  async function cycle(): Promise<Outcome | null> {
    const failed = (reason: string, error: unknown, samples: Sample[], note = ""): Outcome => ({
      run: { enforcement: { outcome: "failed", ms: null }, freshness: SKIPPED },
      samples,
      warnings: [
        `probe failed leg=enforcement outcome=failed reason=${reason} error=${errorName(error)}${note}`,
        "probe skipped leg=freshness reason=block_not_enforced",
      ],
    });
    /** A bad SLO-06 sample, recorded past the bound where the probe gives up. */
    const gaveUp: Sample = { slo: "SLO-06", good: false, ms: beyond(PROBE_BOUNDS.enforceTimeoutMs) };

    let probe: ProbeTransport;
    try {
      transport ??= await options.connect(signal);
      probe = transport;
    } catch (error) {
      if (signal.aborted) return null;
      // Could not be set up. Once or twice or three times in a row, nothing of the path was exercised and there is no
      // sample: the next cycle tries again. From the fourth failure in a row a prober that cannot run counts as
      // failing (D-117): each further cycle is a bad SLO-06 sample, so the existing burn rules page.
      const failures = state.setup_failures + 1;
      const counted = failures > PROBE_SETUP_GRACE;
      return {
        ...failed(
          "setup",
          error,
          counted ? [gaveUp] : [],
          ` setup_failures=${failures} counted=${counted ? "bad" : "no"}`,
        ),
        setup: true,
      };
    }
    if (signal.aborted) return null;

    const path = `${PROBE_PATH_PREFIX}${randomBytes(12).toString("hex")}`;
    const published = monotonic();
    try {
      await probe.publishBlock(path, signal);
    } catch (error) {
      if (signal.aborted) return null;
      // The action could not be applied at all: a bad sample.
      return failed("publish", error, [gaveUp]);
    }

    // Leg 1: until a request for the marked path is refused.
    let enforcement: ProbeLeg | undefined;
    let refused = 0;
    while (enforcement === undefined) {
      if (signal.aborted) return null;
      if (probe.blocks(path)) {
        let status: number | undefined;
        try {
          status = await probe.request(path, signal);
        } catch {
          status = undefined; // asked again at the next look; a leg that never succeeds ends as a timeout
        }
        if (signal.aborted) return null;
        if (status === 403) {
          refused = monotonic();
          const ms = refused - published;
          enforcement = { outcome: ms <= PROBE_BOUNDS.enforceGoodMs ? "good" : "late", ms };
          break;
        }
      }
      const waited = monotonic() - published;
      if (waited >= PROBE_BOUNDS.enforceTimeoutMs) enforcement = { outcome: "timeout", ms: waited };
      else await sleep(enforcePollMs, signal);
    }
    if (signal.aborted) return null;
    const warnings: string[] = [];
    const samples: Sample[] = [
      enforcement.outcome === "timeout"
        ? gaveUp
        : { slo: "SLO-06", good: enforcement.outcome === "good", ms: enforcement.ms ?? 0 },
    ];
    if (enforcement.outcome !== "good") {
      warnings.push(
        `probe failed leg=enforcement outcome=${enforcement.outcome} ms=${Math.round(enforcement.ms ?? 0)}`,
      );
    }
    if (enforcement.outcome === "timeout") {
      warnings.push("probe skipped leg=freshness reason=block_not_enforced");
      return { run: { enforcement, freshness: SKIPPED }, samples, warnings };
    }

    // Leg 2: until the refused request's Event is readable.
    let freshness: ProbeLeg | undefined;
    while (freshness === undefined) {
      if (signal.aborted) return null;
      let visible = false;
      try {
        visible = await probe.eventVisible(path, signal);
      } catch {
        visible = false; // read again; a read route that stays down ends the leg as a timeout
      }
      if (signal.aborted) return null;
      const ms = monotonic() - refused;
      if (visible) freshness = { outcome: ms <= PROBE_BOUNDS.freshGoodMs ? "good" : "late", ms };
      else if (ms >= PROBE_BOUNDS.freshTimeoutMs) freshness = { outcome: "timeout", ms };
      else await sleep(eventPollMs, signal);
    }
    if (signal.aborted) return null;
    samples.push({
      slo: "SLO-04",
      good: freshness.outcome === "good",
      ms: freshness.outcome === "timeout" ? beyond(PROBE_BOUNDS.freshTimeoutMs) : (freshness.ms ?? 0),
    });
    if (freshness.outcome !== "good") {
      warnings.push(`probe failed leg=freshness outcome=${freshness.outcome} ms=${Math.round(freshness.ms ?? 0)}`);
    }
    return { run: { enforcement, freshness }, samples, warnings };
  }

  /** A step of the bookkeeping that must not take the others with it (review F5): a sink, a clock or a logger that throws. */
  const contained = (step: () => void): void => {
    try {
      step();
    } catch {
      // nothing to tell anybody with: the status below still has the run
    }
  };

  /** One cycle and its bookkeeping. Never rejects. */
  async function run(): Promise<ProbeRun | null> {
    let result: Outcome | null;
    try {
      result = await cycle();
    } catch (error) {
      // Nothing above is meant to throw; if something does, it is a failed run like any other.
      result = signal.aborted
        ? null
        : {
            run: { enforcement: { outcome: "failed", ms: null }, freshness: SKIPPED },
            samples: [],
            warnings: [`probe failed leg=enforcement outcome=failed reason=internal error=${errorName(error)}`],
          };
    }
    if (result === null || signal.aborted) return null;
    const { run: found, samples, warnings } = result;
    const ok = found.enforcement.outcome === "good" && found.freshness.outcome === "good";
    const before = state.consecutive_failures;
    // The status first: plain assignments, so the run is counted whatever fails after it.
    state.runs++;
    if (!ok) state.failures++;
    state.consecutive_failures = ok ? 0 : before + 1;
    state.setup_failures = result.setup === true ? state.setup_failures + 1 : 0;
    state.enforcement = found.enforcement;
    state.freshness = found.freshness;
    state.last_run_at = null;
    contained(() => {
      state.last_run_at = now().toISOString();
    });
    for (const sample of samples) contained(() => slo.record(sample.slo, sample.good, sample.ms));
    for (const line of warnings) contained(() => logger.warn(line));
    if (ok && before > 0) contained(() => logger.info(`probe recovered after=${before}`));
    return found;
  }

  function runOnce(): Promise<ProbeRun | null> {
    if (signal.aborted) return Promise.resolve(null);
    running ??= run().finally(() => {
      running = undefined;
    });
    return running;
  }

  function arm(ms: number): void {
    if (signal.aborted) return;
    handle = setTimer(() => {
      handle = undefined;
      if (signal.aborted) return;
      const began = monotonic();
      // The next cycle is scheduled only here, when this one has ended: cycles never overlap. `run` never rejects;
      // the catch is there so that, if it ever did, the schedule would go on and nothing would be left unhandled.
      void runOnce()
        .catch(() => null)
        .finally(() => arm(Math.max(everyMs - (monotonic() - began), PROBE_JOB_DEFAULTS.minPauseMs)));
    }, ms);
  }

  return {
    start() {
      if (started || signal.aborted) return;
      started = true;
      arm(startDelayMs);
    },
    runOnce,
    async idle() {
      while (running !== undefined) await running.catch(() => {});
    },
    status: () => ({ ...state }),
    async stop() {
      stopping.abort();
      if (handle !== undefined) clearTimer(handle);
      handle = undefined;
      while (running !== undefined) await running.catch(() => {});
      const open = transport;
      transport = undefined;
      await open?.close().catch(() => {});
    },
  };
}
