import type { DeletionReport, OrganizationDeletion, SignedDeletionReport } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

// Organization deletions (slice 18b, migration 0033). The request role reaches the table only through definer
// functions bound to the transaction's Organization; the purge job reads and writes it as the owner.

/** The owner's table of deletion requests and tombstones: not tenant data, never exported, never purged. */
export const DELETION_TABLE = "organization_deletions";

interface DeletionRow {
  id: string;
  organization_id: string;
  requested_at: Date;
  purge_after: Date;
  cancelled_at: Date | null;
  purged_at: Date | null;
}

function toDeletion(row: DeletionRow): OrganizationDeletion {
  return {
    id: row.id,
    organization_id: row.organization_id,
    status: row.purged_at !== null ? "purged" : row.cancelled_at !== null ? "cancelled" : "pending",
    requested_at: row.requested_at.toISOString(),
    purge_after: row.purge_after.toISOString(),
    cancelled_at: row.cancelled_at?.toISOString() ?? null,
    purged_at: row.purged_at?.toISOString() ?? null,
  };
}

/** The transaction's Organization's pending deletion, or null. */
export async function pendingDeletion(q: Queryable): Promise<OrganizationDeletion | null> {
  const { rows } = await q.query<DeletionRow>("SELECT * FROM organization_deletion_pending()");
  const row = rows[0];
  return row === undefined ? null : toDeletion(row);
}

/** Records a deletion request of the transaction's Organization. A second pending one throws (SQL state 23505). */
export async function insertDeletion(
  q: Queryable,
  input: { id: string; requestedBy: string; reason: string; at: Date; purgeAfter: Date },
): Promise<OrganizationDeletion> {
  const { rows } = await q.query<DeletionRow>("SELECT * FROM organization_deletion_request($1, $2, $3, $4, $5)", [
    input.id,
    input.requestedBy,
    input.reason,
    input.at.toISOString(),
    input.purgeAfter.toISOString(),
  ]);
  const row = rows[0];
  if (row === undefined) throw new Error("The deletion request was not stored.");
  return toDeletion(row);
}

/** Cancels the transaction's Organization's pending deletion; null when there is none. */
export async function cancelDeletion(q: Queryable, at: Date): Promise<OrganizationDeletion | null> {
  const { rows } = await q.query<DeletionRow>("SELECT * FROM organization_deletion_cancel($1)", [at.toISOString()]);
  const row = rows[0];
  return row === undefined ? null : toDeletion(row);
}

/** The signed report of a purged deletion; null for an unknown, pending or cancelled one. Needs no tenant. */
export async function deletionReport(q: Queryable, id: string): Promise<SignedDeletionReport | null> {
  const { rows } = await q.query<{ report: DeletionReport; report_signature: string; report_key_id: string }>(
    "SELECT * FROM organization_deletion_report($1)",
    [id],
  );
  const row = rows[0];
  return row === undefined ? null : { report: row.report, key_id: row.report_key_id, signature: row.report_signature };
}

// --- The owner's side: the purge job --------------------------------------------------------------------------

export interface DueDeletion {
  id: string;
  organizationId: string;
}

/** How long a deletion whose purge failed waits before it is tried again. */
export const PURGE_RETRY_AFTER_MS = 3_600_000;

/**
 * Pending deletions whose `purge_after` has passed, oldest first; one whose purge failed less than
 * `PURGE_RETRY_AFTER_MS` ago is skipped, and those that failed before come after those that never did, so that
 * failing deletions never hold the others back. Owner transaction.
 */
export async function dueDeletions(q: Queryable, at: Date, limit: number): Promise<DueDeletion[]> {
  const { rows } = await q.query<{ id: string; organization_id: string }>(
    `SELECT id, organization_id FROM organization_deletions
     WHERE cancelled_at IS NULL AND purged_at IS NULL AND purge_after <= $1
       AND (last_failed_at IS NULL OR last_failed_at <= $1::timestamptz - make_interval(secs => $3 / 1000.0))
     ORDER BY last_failed_at NULLS FIRST, purge_after, id LIMIT $2`,
    [at.toISOString(), limit, PURGE_RETRY_AFTER_MS],
  );
  return rows.map((row) => ({ id: row.id, organizationId: row.organization_id }));
}

/**
 * Purges the Organization of a due deletion (`organization_purge`) and answers the report. Owner transaction; the
 * caller signs the report and stores it with `storeDeletionReport` in the same transaction.
 */
export async function purgeOrganization(q: Queryable, due: DueDeletion, at: Date): Promise<DeletionReport> {
  const purged = await q.query<{ result: { deletion_id: string; rows: Record<string, number> } }>(
    "SELECT organization_purge($1, $2) AS result",
    [due.organizationId, at.toISOString()],
  );
  const result = purged.rows[0]?.result;
  if (result === undefined || result.deletion_id !== due.id) throw new Error("The purge purged another deletion.");
  const { rows } = await q.query<{ requested_at: Date; purge_after: Date; purged_at: Date }>(
    "SELECT requested_at, purge_after, purged_at FROM organization_deletions WHERE id = $1",
    [due.id],
  );
  const times = rows[0];
  if (times === undefined) throw new Error("The deletion vanished during its purge.");
  const counts = Object.fromEntries(Object.entries(result.rows).map(([table, n]) => [table, Number(n)]));
  return {
    deletion_id: due.id,
    organization_id: due.organizationId,
    requested_at: times.requested_at.toISOString(),
    purge_after: times.purge_after.toISOString(),
    purged_at: times.purged_at.toISOString(),
    rows: counts,
    total_rows: Object.values(counts).reduce((sum, n) => sum + n, 0),
  };
}

/** Records a failed purge of a deletion: one more attempt, failed at `at`. Owner transaction. */
export async function recordPurgeFailure(q: Queryable, id: string, at: Date): Promise<void> {
  await q.query(
    "UPDATE organization_deletions SET purge_attempts = purge_attempts + 1, last_failed_at = $2 WHERE id = $1",
    [id, at.toISOString()],
  );
}

/** Stores the signed report of a purged deletion. Owner transaction. */
export async function storeDeletionReport(q: Queryable, signed: SignedDeletionReport): Promise<void> {
  await q.query(
    "UPDATE organization_deletions SET report = $2, report_signature = $3, report_key_id = $4 WHERE id = $1",
    [signed.report.deletion_id, JSON.stringify(signed.report), signed.signature, signed.key_id],
  );
}
