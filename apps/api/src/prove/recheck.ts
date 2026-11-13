import { TARGET_LIMITS } from "@antireverse/protocol";
import type { Db } from "../db/db.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import { type CheckGuard, findTarget, listDueTargets, recordCheck, recordRecheckMiss } from "../stores/targets.ts";
import { type ProveNetwork, runCheck } from "./deps.ts";

// The daily re-check of Verified Targets (slice 14): every verified target whose last successful ownership check is
// more than 24 hours old, and every lapsed target last checked more than 24 hours ago, is checked again (DNS first,
// then the file). Success makes it verified with `verified_at` = now. A failure marks it lapsed with the reason, except
// a failure on our side only (our DNS lookup failed and the file's host did not resolve, so the customer's side never
// answered): a verified target then stays verified and is retried at the next run, and lapses after
// `RECHECK_MISSES_MAX` such failures in a row. `authorize` still refuses once the last success is 26 hours old, so
// that grace never widens what may be tested. The job runs in process on a timer — first after a jitter, then every interval plus a
// jitter — with a bounded number of checks at once. Each check runs outside any transaction; its outcome is recorded
// only if the target was not checked meanwhile. Log lines carry counts and error kinds only, never a host or token.

export const RECHECK_DEFAULTS = Object.freeze({
  /** Between runs. A target due at 24 h is checked by 25 h 5 min, inside the 26 h `authorize` accepts. */
  intervalMs: 3_600_000,
  /** Added to each wait, uniformly at random, so that processes started together do not run together. */
  jitterMs: 5 * 60_000,
  /** Checks at once. */
  concurrency: 4,
  /** Targets taken per run; the rest wait for the next run. */
  batchMax: 200,
});

/** Failures on our side only, in a row, after which a verified target lapses anyway. */
export const RECHECK_MISSES_MAX = 3;

export interface RecheckCounts {
  /** Due targets found. */
  due: number;
  verified: number;
  lapsed: number;
  /** Failed on our side only: kept verified, retried at the next run. */
  deferred: number;
  /** Failed checks whose file host did not resolve (reported per target as `not_reachable`). */
  unresolved: number;
  /** Failed checks whose file host resolved to an address that is not public (reported as `not_reachable`). */
  notPublic: number;
  /** No longer due or changed meanwhile: nothing recorded. */
  skipped: number;
  /** An error of ours (database): nothing recorded, logged by kind. */
  failed: number;
}

export interface RecheckOptions {
  db: Db;
  network: ProveNetwork;
  now?: (() => Date) | undefined;
  logger?: Logger | undefined;
  intervalMs?: number;
  jitterMs?: number;
  concurrency?: number;
  batchMax?: number;
  /** In [0, 1). Default `Math.random`. */
  random?: () => number;
  /** Default: `setTimeout`, unref'd so that the timer never keeps the process alive. */
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
}

export interface RecheckJob {
  /** Schedules the runs; returns `stop`, which cancels the next run (a run in progress finishes; see `flush`). */
  start(): () => void;
  /** One run now: checks the due targets and records the outcomes. Never rejects. */
  runOnce(): Promise<RecheckCounts>;
  /** Resolves when the run in progress, if any, has finished. */
  flush(): Promise<void>;
}

const defaultSetTimer = (fn: () => void, ms: number): unknown => {
  const timer = setTimeout(fn, ms);
  timer.unref?.();
  return timer;
};
const defaultClearTimer = (handle: unknown): void => clearTimeout(handle as ReturnType<typeof setTimeout>);

export function createRecheckJob(options: RecheckOptions): RecheckJob {
  const { db, network } = options;
  const now = options.now ?? (() => new Date());
  const logger = redacting(options.logger ?? consoleLogger);
  const intervalMs = options.intervalMs ?? RECHECK_DEFAULTS.intervalMs;
  const jitterMs = options.jitterMs ?? RECHECK_DEFAULTS.jitterMs;
  const concurrency = Math.max(1, options.concurrency ?? RECHECK_DEFAULTS.concurrency);
  const batchMax = options.batchMax ?? RECHECK_DEFAULTS.batchMax;
  const random = options.random ?? Math.random;
  const setTimer = options.setTimer ?? defaultSetTimer;
  const clearTimer = options.clearTimer ?? defaultClearTimer;

  let running: Promise<RecheckCounts> | undefined;

  async function checkOne(organizationId: string, targetId: string, cutoff: Date, counts: RecheckCounts) {
    try {
      const found = await db.tx({ organizationId }, (q) => findTarget(q, targetId));
      const status = found?.target.status;
      // Due: verified with the last success at or before the cutoff, or lapsed with the last check at or before it.
      const since = status === "verified" ? found?.target.verified_at : found?.target.last_checked_at;
      if (found === null || (status !== "verified" && status !== "lapsed") || since == null) {
        counts.skipped++;
        return;
      }
      if (Date.parse(since) > cutoff.getTime()) {
        counts.skipped++;
        return;
      }
      const guard: CheckGuard = { status, lastCheckedAt: found.target.last_checked_at };
      const { outcome, result, fileFailure } = await runCheck(network, found.target.host, found.token, now());
      const at = new Date(result.checked_at);
      if (fileFailure === "resolve_failed") counts.unresolved++;
      if (fileFailure === "address_not_public") counts.notPublic++;
      const oursOnly = !result.verified && result.dns === "lookup_failed" && fileFailure === "resolve_failed";
      const recorded = await db.tx({ organizationId }, async (q) => {
        if (oursOnly && status === "verified") {
          const kept = await recordRecheckMiss(q, targetId, at, guard, RECHECK_MISSES_MAX);
          if (kept !== null) return "deferred" as const;
        }
        return recordCheck(q, targetId, outcome, at, { guard });
      });
      if (recorded === "deferred") counts.deferred++;
      else if (recorded === null) counts.skipped++;
      else if (recorded.status === "verified") counts.verified++;
      else counts.lapsed++;
    } catch (error) {
      counts.failed++;
      logger.warn(`prove recheck error ${(error as Error)?.name ?? "Error"}`);
    }
  }

  async function run(): Promise<RecheckCounts> {
    const counts: RecheckCounts = {
      due: 0,
      verified: 0,
      lapsed: 0,
      deferred: 0,
      unresolved: 0,
      notPublic: 0,
      skipped: 0,
      failed: 0,
    };
    const cutoff = new Date(now().getTime() - TARGET_LIMITS.recheckIntervalS * 1000);
    let due: { organizationId: string; targetId: string }[];
    try {
      due = await db.tx("none", (q) => listDueTargets(q, cutoff, batchMax));
    } catch (error) {
      counts.failed++;
      logger.warn(`prove recheck error ${(error as Error)?.name ?? "Error"}`);
      return counts;
    }
    counts.due = due.length;
    let next = 0;
    const worker = async (): Promise<void> => {
      while (next < due.length) {
        const item = due[next++];
        if (item !== undefined) await checkOne(item.organizationId, item.targetId, cutoff, counts);
      }
    };
    await Promise.all(Array.from({ length: Math.min(concurrency, due.length) }, worker));
    if (counts.due > 0) {
      logger.info(
        `prove recheck due=${counts.due} verified=${counts.verified} lapsed=${counts.lapsed} deferred=${counts.deferred} unresolved=${counts.unresolved} not_public=${counts.notPublic} skipped=${counts.skipped} failed=${counts.failed}`,
      );
    }
    return counts;
  }

  function runOnce(): Promise<RecheckCounts> {
    // One run at a time: a run that outlasts the interval is not started twice.
    running ??= run().finally(() => {
      running = undefined;
    });
    return running;
  }

  return {
    start() {
      let stopped = false;
      let handle: unknown;
      const schedule = (base: number) => {
        if (stopped) return;
        handle = setTimer(
          () => {
            if (stopped) return;
            void runOnce().finally(() => schedule(intervalMs));
          },
          base + Math.floor(random() * jitterMs),
        );
      };
      schedule(0);
      return () => {
        stopped = true;
        clearTimer(handle);
      };
    },
    runOnce,
    async flush() {
      while (running !== undefined) await running.catch(() => {});
    },
  };
}
