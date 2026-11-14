import { randomUUID } from "node:crypto";
import type { SloId, SloVariant } from "@antireverse/protocol";
import type { OwnedDb } from "../db/db.ts";
import { bucketIndex, HISTOGRAM_SIZE, minuteOf, type SloBucket } from "./evaluate.ts";
import { addSloBuckets } from "./store.ts";

// Slice 18d: the SLI recorder. On the hot path it only counts in memory (one map lookup and three increments per
// event, no I/O); `flush` adds what it holds to `slo_minutes` in one owner transaction. The SLO job flushes it every
// minute, and `startApi`'s close flushes it last, so a restart loses nothing but a crash's last minute. Nothing it
// holds names a tenant.

/** What the feeds see: record one SLI event. Never throws. */
export interface SloSink {
  /** `good` as judged by the feed; `ms` the event's latency (for the histogram); `variant` SLO-07's read or write. */
  record(slo: SloId, good: boolean, ms: number, variant?: SloVariant): void;
}

export interface SloRecorder extends SloSink {
  /**
   * Adds what is held to `slo_minutes`. A failed write keeps the batch, with its id, for the next flush (and rejects);
   * a batch that committed despite the error is not added twice. One at a time.
   */
  flush(): Promise<void>;
  /** Buckets held in memory, not yet flushed. */
  pending(): number;
}

export function createSloRecorder(options: { db: OwnedDb; now?: (() => Date) | undefined }): SloRecorder {
  const { db } = options;
  const now = options.now ?? (() => new Date());
  let held = new Map<string, SloBucket>();
  /**
   * Batches whose write failed, each with its id: written again as they were, so that a batch that did commit (an
   * ambiguous failure) is recognised by its id and adds nothing.
   */
  const retry: { id: string; buckets: SloBucket[] }[] = [];
  let flushing: Promise<void> = Promise.resolve();

  async function write(): Promise<void> {
    if (held.size > 0) {
      retry.push({ id: randomUUID(), buckets: [...held.values()] });
      held = new Map();
    }
    while (retry.length > 0) {
      const batch = retry[0] as { id: string; buckets: SloBucket[] };
      await db.owner((q) => addSloBuckets(q, batch.buckets, { id: batch.id, at: now() }));
      retry.shift();
    }
  }

  return {
    record(slo, good, ms, variant = "all") {
      const minute = minuteOf(now().getTime());
      const key = `${minute}|${slo}|${variant}`;
      let bucket = held.get(key);
      if (bucket === undefined) {
        bucket = { minute, slo, variant, good: 0, total: 0, histogram: new Array<number>(HISTOGRAM_SIZE).fill(0) };
        held.set(key, bucket);
      }
      bucket.total++;
      if (good) bucket.good++;
      const index = bucketIndex(Number.isFinite(ms) && ms > 0 ? ms : 0);
      bucket.histogram[index] = (bucket.histogram[index] ?? 0) + 1;
    },
    flush() {
      const next = flushing.then(write, write);
      flushing = next.catch(() => {});
      return next;
    },
    pending: () => held.size + retry.reduce((n, batch) => n + batch.buckets.length, 0),
  };
}
