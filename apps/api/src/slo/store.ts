import { SLO_RETENTION_DAYS, SLO_WINDOWS, type SloId, type SloVariant } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";
import {
  type AlertTransition,
  type FiringState,
  HISTOGRAM_SIZE,
  type SloAggregate,
  type SloBucket,
  type WindowName,
  windowStarts,
} from "./evaluate.ts";

// Slice 18d: the owner-only table `slo_minutes` (migration 0037). Every function runs inside `db.owner`.

/**
 * Adds the buckets to their stored minutes (a minute flushed twice adds up). With `flushId`, a batch whose id was
 * already written adds nothing (a retry after an ambiguous failure); returns false then.
 */
export async function addSloBuckets(
  q: Queryable,
  buckets: readonly SloBucket[],
  flush?: { id: string; at: Date },
): Promise<boolean> {
  if (flush !== undefined) {
    const { rows } = await q.query(
      "INSERT INTO slo_flushes (id, at) VALUES ($1, $2::timestamptz) ON CONFLICT (id) DO NOTHING RETURNING id",
      [flush.id, flush.at.toISOString()],
    );
    if (rows.length === 0) return false;
  }
  if (buckets.length === 0) return true;
  await q.query(
    `INSERT INTO slo_minutes AS s (minute, slo, variant, good, total, histogram)
     SELECT to_timestamp(b.minute / 1000.0), b.slo, b.variant, b.good, b.total,
            ARRAY(SELECT jsonb_array_elements_text(b.histogram)::bigint)
     FROM jsonb_to_recordset($1::jsonb) AS b(minute bigint, slo text, variant text, good bigint, total bigint, histogram jsonb)
     ON CONFLICT (minute, slo, variant) DO UPDATE SET
       good = s.good + excluded.good,
       total = s.total + excluded.total,
       histogram = ARRAY(SELECT x + y FROM unnest(s.histogram, excluded.histogram) AS h(x, y))`,
    [JSON.stringify(buckets)],
  );
  return true;
}

/** Every stored bucket, in (minute, slo, variant) order: for tests and small reads. */
export async function readSloBuckets(q: Queryable): Promise<SloBucket[]> {
  const { rows } = await q.query<{
    minute: Date;
    slo: SloId;
    variant: SloVariant;
    good: string | number;
    total: string | number;
    histogram: (string | number)[];
  }>("SELECT minute, slo, variant, good, total, histogram FROM slo_minutes ORDER BY minute, slo, variant");
  return rows.map((row) => ({
    minute: row.minute.getTime(),
    slo: row.slo,
    variant: row.variant,
    good: Number(row.good),
    total: Number(row.total),
    histogram: row.histogram.map(Number),
  }));
}

/** Removes the minutes older than `SLO_RETENTION_DAYS` before `at`. Returns how many rows went. */
export async function sweepSloMinutes(q: Queryable, at: Date): Promise<number> {
  const { rows } = await q.query<{ n: number }>(
    `WITH gone AS (DELETE FROM slo_minutes WHERE minute < $1::timestamptz - make_interval(days => $2::int) RETURNING 1)
     SELECT count(*)::int AS n FROM gone`,
    [at.toISOString(), SLO_RETENTION_DAYS],
  );
  await q.query("DELETE FROM slo_flushes WHERE at < $1::timestamptz - interval '1 day'", [at.toISOString()]);
  return rows[0]?.n ?? 0;
}

/** The burn rules firing when the process last wrote them. */
export async function readSloAlerts(q: Queryable): Promise<FiringState[]> {
  const { rows } = await q.query<{ slo: SloId; rule: FiringState["rule"]; since: Date }>(
    "SELECT slo, rule, since FROM slo_alerts ORDER BY slo, rule",
  );
  return rows.map((row) => ({ slo: row.slo, rule: row.rule, since: row.since }));
}

/** Writes what fired (with its episode's start) and removes what resolved. */
export async function saveSloAlertTransitions(q: Queryable, transitions: readonly AlertTransition[]): Promise<void> {
  for (const t of transitions) {
    if (t.state === "firing") {
      await q.query(
        "INSERT INTO slo_alerts (slo, rule, since) VALUES ($1, $2, $3::timestamptz) ON CONFLICT (slo, rule) DO UPDATE SET since = excluded.since",
        [t.slo, t.rule.id, t.since.toISOString()],
      );
    } else {
      await q.query("DELETE FROM slo_alerts WHERE slo = $1 AND rule = $2", [t.slo, t.rule.id]);
    }
  }
}

const WINDOW_NAMES = Object.keys(SLO_WINDOWS) as WindowName[];

/**
 * `aggregate(readSloBuckets(q), now)`, computed in SQL: the window sums per SLO and the 30-day histograms per SLO and
 * variant, without reading every minute into the process.
 */
export async function readSloAggregates(q: Queryable, now: number): Promise<Map<SloId, SloAggregate>> {
  const starts = windowStarts(now);
  const current = new Date(Math.floor(now / 60_000) * 60_000).toISOString();
  const params: unknown[] = [current, ...WINDOW_NAMES.map((name) => new Date(starts[name]).toISOString())];
  const sums = WINDOW_NAMES.map(
    (name, i) =>
      `COALESCE(sum(good) FILTER (WHERE minute >= $${i + 2}::timestamptz), 0)::bigint AS "good_${name}",
       COALESCE(sum(total) FILTER (WHERE minute >= $${i + 2}::timestamptz), 0)::bigint AS "total_${name}"`,
  ).join(",\n");
  const month = `$${WINDOW_NAMES.indexOf("30d") + 2}::timestamptz`;
  const windows = await q.query<Record<string, string | number> & { slo: SloId }>(
    `SELECT slo, ${sums} FROM slo_minutes WHERE minute <= $1::timestamptz AND minute >= ${month} GROUP BY slo`,
    params,
  );
  const histograms = await q.query<{ slo: SloId; variant: SloVariant; histogram: (string | number)[] }>(
    `SELECT slo, variant, array_agg(n ORDER BY i) AS histogram FROM (
       SELECT s.slo, s.variant, h.i, sum(h.n)::bigint AS n
       FROM slo_minutes s, unnest(s.histogram) WITH ORDINALITY AS h(n, i)
       WHERE s.minute <= $1::timestamptz AND s.minute >= $2::timestamptz
       GROUP BY s.slo, s.variant, h.i
     ) t GROUP BY slo, variant`,
    [current, new Date(starts["30d"]).toISOString()],
  );
  const out = new Map<SloId, SloAggregate>();
  for (const row of windows.rows) {
    const agg: SloAggregate = {
      windows: Object.fromEntries(
        WINDOW_NAMES.map((name) => [name, { good: Number(row[`good_${name}`]), total: Number(row[`total_${name}`]) }]),
      ) as SloAggregate["windows"],
      histograms: {},
    };
    out.set(row.slo, agg);
  }
  for (const row of histograms.rows) {
    const agg = out.get(row.slo);
    if (agg === undefined) continue;
    const histogram = row.histogram.map(Number);
    if (histogram.length !== HISTOGRAM_SIZE) continue;
    agg.histograms[row.variant] = histogram;
  }
  return out;
}
