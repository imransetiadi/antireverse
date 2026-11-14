import {
  type EventRetentionDays,
  type OrganizationRetention,
  RETENTION_FIXED_DAYS,
  type RetentionRun,
} from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

// Retention (slice 18c, migration 0035). The request side reads and changes the transaction's own Organization's
// Event retention (row-level security) and reads its runs; the job's side runs the owner-only sweep and records runs.

/** Rows removed per Organization id, per table. */
export type SweepCounts = Record<string, Record<string, number>>;

/** The transaction's own Organization's retention, or null when it is not visible. */
export async function organizationRetention(
  q: Queryable,
  organizationId: string,
): Promise<OrganizationRetention | null> {
  const { rows } = await q.query<{ event_retention_days: EventRetentionDays }>(
    "SELECT event_retention_days FROM organizations WHERE id = $1",
    [organizationId],
  );
  const row = rows[0];
  return row === undefined ? null : { event_retention_days: row.event_retention_days, ...RETENTION_FIXED_DAYS };
}

/**
 * The transaction's own Organization's retention, its row locked until the transaction ends: what a change reads, so
 * that the reason check and the audit's before → after use the value it replaces. Null when it is not visible.
 */
export async function lockedRetention(q: Queryable, organizationId: string): Promise<OrganizationRetention | null> {
  const { rows } = await q.query<{ event_retention_days: EventRetentionDays }>(
    "SELECT event_retention_days FROM organizations WHERE id = $1 FOR UPDATE",
    [organizationId],
  );
  const row = rows[0];
  return row === undefined ? null : { event_retention_days: row.event_retention_days, ...RETENTION_FIXED_DAYS };
}

/** Sets the transaction's own Organization's Event retention; false when the Organization is not visible. */
export async function setEventRetention(
  q: Queryable,
  organizationId: string,
  days: EventRetentionDays,
): Promise<boolean> {
  const { rows } = await q.query<{ id: string }>(
    "UPDATE organizations SET event_retention_days = $2 WHERE id = $1 RETURNING id",
    [organizationId, days],
  );
  return rows.length > 0;
}

/** The transaction's own Organization's most recent retention run, or null. */
export async function lastRetentionRun(q: Queryable): Promise<RetentionRun | null> {
  const { rows } = await q.query<{ ran_at: Date; complete: boolean; counts: Record<string, number | string> }>(
    "SELECT ran_at, complete, counts FROM retention_runs ORDER BY ran_at DESC, seq DESC LIMIT 1",
  );
  const row = rows[0];
  if (row === undefined) return null;
  return {
    ran_at: row.ran_at.toISOString(),
    complete: row.complete,
    counts: Object.fromEntries(Object.entries(row.counts).map(([table, n]) => [table, Number(n)])),
  };
}

// --- The owner's side: the retention job ----------------------------------------------------------------------

export interface SweepCall {
  rows: SweepCounts;
  /** Some Organization used its whole share in some step: it may have more. */
  saturated: boolean;
  /** Organizations served by this call (at most `batch`), and Organizations the sweep covers. */
  window: number;
  organizations: number;
  /** This call alone does not show that nothing is left (saturated, or the window did not hold everyone). */
  more: boolean;
}

/**
 * One call of `retention_sweep`: a window of at most `batch` Organizations from where the last call stopped, each
 * step deleting at most `batch` rows shared equally over them. Owner transaction.
 */
export async function sweepRetention(q: Queryable, at: Date, batch: number): Promise<SweepCall> {
  const { rows } = await q.query<{
    result: {
      rows: Record<string, Record<string, number | string>>;
      saturated: boolean;
      window: number;
      organizations: number;
    };
  }>("SELECT retention_sweep($1, $2) AS result", [at.toISOString(), batch]);
  const result = rows[0]?.result;
  if (result === undefined) throw new Error("The retention sweep answered nothing.");
  const counts: SweepCounts = {};
  for (const [organizationId, tables] of Object.entries(result.rows)) {
    counts[organizationId] = Object.fromEntries(Object.entries(tables).map(([table, n]) => [table, Number(n)]));
  }
  const saturated = result.saturated === true;
  const window = Number(result.window);
  const organizations = Number(result.organizations);
  return { rows: counts, saturated, window, organizations, more: saturated || window < organizations };
}

/** Expires the protected artifacts past their keep date; answers the artifacts removed per Organization. Owner. */
export async function expireArtifactsByOrganization(q: Queryable, at: Date): Promise<Record<string, number>> {
  const { rows } = await q.query<{ organization_id: string; removed: number }>(
    "SELECT organization_id, removed FROM assessment_artifacts_expire_by_organization($1)",
    [at.toISOString()],
  );
  return Object.fromEntries(rows.map((row) => [row.organization_id, Number(row.removed)]));
}

/**
 * Records a run: one row per Organization the sweep covered (those whose deletion is not pending), with its counts,
 * keeping the 30 most recent per Organization. Owner transaction. Answers the rows written.
 */
export async function recordRetentionRun(
  q: Queryable,
  at: Date,
  counts: SweepCounts,
  complete: boolean,
): Promise<number> {
  const { rows } = await q.query<{ n: number }>("SELECT retention_record($1, $2, $3) AS n", [
    at.toISOString(),
    JSON.stringify(counts),
    complete,
  ]);
  return rows[0]?.n ?? 0;
}
