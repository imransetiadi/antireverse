import { deletionReportSignedText, type SignedDeletionReport } from "@antireverse/protocol";
import type { OwnedDb } from "../db/db.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import type { Signer } from "../signer.ts";
import { dueDeletions, purgeOrganization, recordPurgeFailure, storeDeletionReport } from "../stores/deletions.ts";

// The daily purge (slice 18b): every Organization whose deletion is pending past its `purge_after` is purged by the
// owner-only `organization_purge` (migration 0033) — every row in every tenant table, the audit chain included — and
// its deletion report (rows per table, times) is signed with the audit key and stored with the tombstone, all in one
// owner transaction per Organization. A failed purge is recorded and retried after an hour, behind the others. A run
// that finds nothing due changes nothing, so runs are idempotent. Runs in
// process on a timer: first `firstRunMs` after the start, then every `everyMs`. Log lines carry counts and error kinds
// only, never a name.

export const PURGE_DEFAULTS = Object.freeze({
  /** Between runs: daily. */
  everyMs: 86_400_000,
  /** The first run after the start. */
  firstRunMs: 60_000,
  /** Organizations purged per run; the rest wait for the next run. */
  batchMax: 20,
});

export interface PurgeCounts {
  /** Due deletions found. */
  due: number;
  purged: number;
  /** An error of ours (database): that Organization is left as it was and retried at the next run. */
  failed: number;
}

export interface PurgeOptions {
  /** The owner's database: the purge function is the owner's only. */
  db: OwnedDb;
  /** The audit key: signs the deletion reports. */
  signer: Signer;
  now?: (() => Date) | undefined;
  logger?: Logger | undefined;
  /**
   * Told each Organization purged, after its transaction committed: the in-process state that still holds it (the
   * Detector's windows, the Clone Beacon's caches and limits) forgets it. Never throws into the job.
   */
  onPurged?: ((organizationId: string) => void) | undefined;
  everyMs?: number;
  firstRunMs?: number;
  batchMax?: number;
  /** Default: `setTimeout`, unref'd so that the timer never keeps the process alive. */
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
}

export interface PurgeJob {
  /** Schedules the runs; returns `stop`, which cancels the next run (a run in progress finishes; see `flush`). */
  start(): () => void;
  /** One run now. Never rejects. */
  runOnce(): Promise<PurgeCounts>;
  /** Resolves when the run in progress, if any, has finished. */
  flush(): Promise<void>;
}

const defaultSetTimer = (fn: () => void, ms: number): unknown => {
  const timer = setTimeout(fn, ms);
  timer.unref?.();
  return timer;
};
const defaultClearTimer = (handle: unknown): void => clearTimeout(handle as ReturnType<typeof setTimeout>);

export function createPurgeJob(options: PurgeOptions): PurgeJob {
  const { db, signer } = options;
  const now = options.now ?? (() => new Date());
  const logger = redacting(options.logger ?? consoleLogger);
  const everyMs = options.everyMs ?? PURGE_DEFAULTS.everyMs;
  const firstRunMs = options.firstRunMs ?? PURGE_DEFAULTS.firstRunMs;
  const batchMax = options.batchMax ?? PURGE_DEFAULTS.batchMax;
  const setTimer = options.setTimer ?? defaultSetTimer;
  const clearTimer = options.clearTimer ?? defaultClearTimer;

  let running: Promise<PurgeCounts> | undefined;

  async function run(): Promise<PurgeCounts> {
    const counts: PurgeCounts = { due: 0, purged: 0, failed: 0 };
    const at = now();
    let due: Awaited<ReturnType<typeof dueDeletions>>;
    try {
      due = await db.owner((q) => dueDeletions(q, at, batchMax));
    } catch (error) {
      counts.failed++;
      logger.warn(`organization purge error ${(error as Error)?.name ?? "Error"}`);
      return counts;
    }
    counts.due = due.length;
    for (const deletion of due) {
      try {
        await db.owner(async (q) => {
          const report = await purgeOrganization(q, deletion, at);
          const signed: SignedDeletionReport = {
            report,
            key_id: signer.keyId,
            signature: signer.sign(new TextEncoder().encode(deletionReportSignedText(report))),
          };
          await storeDeletionReport(q, signed);
        });
        counts.purged++;
      } catch (error) {
        counts.failed++;
        logger.warn(`organization purge error ${(error as Error)?.name ?? "Error"}`);
        // Recorded, so that the next runs take the others first and retry this one after an hour.
        await db
          .owner((q) => recordPurgeFailure(q, deletion.id, at))
          .catch((recordError: unknown) => {
            logger.warn(`organization purge error ${(recordError as Error)?.name ?? "Error"}`);
          });
        continue;
      }
      try {
        options.onPurged?.(deletion.organizationId);
      } catch (error) {
        logger.warn(`organization purge eviction error ${(error as Error)?.name ?? "Error"}`);
      }
    }
    if (counts.due > 0) {
      logger.info(`organization purge due=${counts.due} purged=${counts.purged} failed=${counts.failed}`);
    }
    return counts;
  }

  function runOnce(): Promise<PurgeCounts> {
    // One run at a time.
    running ??= run().finally(() => {
      running = undefined;
    });
    return running;
  }

  return {
    start() {
      let stopped = false;
      let handle: unknown;
      const schedule = (ms: number) => {
        if (stopped) return;
        handle = setTimer(() => {
          if (stopped) return;
          void runOnce().finally(() => schedule(everyMs));
        }, ms);
      };
      schedule(firstRunMs);
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
