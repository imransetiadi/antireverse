import { TARGET_LIMITS, type Target, type TargetStatus, type VerificationMethod } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

// Verified Targets of the transaction's Organization (slice 14). The token is read only by `findTarget` (the
// single-target response and the ownership check); every other read leaves it out.

interface TargetRow {
  id: string;
  host: string;
  status: TargetStatus;
  method: VerificationMethod | null;
  verified_at: Date | null;
  last_checked_at: Date | null;
  lapsed_reason: string | null;
  created_at: Date;
}

const COLUMNS = "id, host, status, method, verified_at, last_checked_at, lapsed_reason, created_at";

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());

function toTarget(row: TargetRow): Target {
  return {
    id: row.id,
    host: row.host,
    status: row.status,
    method: row.method,
    verified_at: iso(row.verified_at),
    last_checked_at: iso(row.last_checked_at),
    lapsed_reason: row.lapsed_reason,
    created_at: row.created_at.toISOString(),
  };
}

/** Every target of the Organization, oldest first (at most `targetsPerOrganization`, which is all). */
export async function listTargets(q: Queryable): Promise<Target[]> {
  const { rows } = await q.query<TargetRow>(`SELECT ${COLUMNS} FROM targets ORDER BY created_at, id LIMIT $1`, [
    TARGET_LIMITS.targetsPerOrganization,
  ]);
  return rows.map(toTarget);
}

/** One target and its token, or null. `forUpdate` locks the row until the transaction ends. */
export async function findTarget(
  q: Queryable,
  id: string,
  options: { forUpdate?: boolean } = {},
): Promise<{ target: Target; token: string } | null> {
  const { rows } = await q.query<TargetRow & { token: string }>(
    `SELECT ${COLUMNS}, token FROM targets WHERE id = $1${options.forUpdate === true ? " FOR UPDATE" : ""}`,
    [id],
  );
  const row = rows[0];
  return row === undefined ? null : { target: toTarget(row), token: row.token };
}

export async function countTargets(q: Queryable): Promise<number> {
  const { rows } = await q.query<{ n: number }>("SELECT count(*)::int AS n FROM targets");
  return rows[0]?.n ?? 0;
}

export async function hostTaken(q: Queryable, host: string): Promise<boolean> {
  const { rows } = await q.query("SELECT 1 FROM targets WHERE host = $1", [host]);
  return rows.length > 0;
}

/** Stores a new pending target. A host already taken raises a unique violation (23505). */
export async function insertTarget(
  q: Queryable,
  input: { organizationId: string; id: string; host: string; token: string; createdAt: Date },
): Promise<Target> {
  const { rows } = await q.query<TargetRow>(
    `INSERT INTO targets (organization_id, id, host, token, status, created_at)
     VALUES ($1, $2, $3, $4, 'pending', $5::timestamptz)
     RETURNING ${COLUMNS}`,
    [input.organizationId, input.id, input.host, input.token, input.createdAt.toISOString()],
  );
  const row = rows[0];
  if (row === undefined) throw new Error("The target was not stored.");
  return toTarget(row);
}

export async function deleteTarget(q: Queryable, id: string): Promise<boolean> {
  const { rows } = await q.query("DELETE FROM targets WHERE id = $1 RETURNING id", [id]);
  return rows.length === 1;
}

const WINDOW_MS = 3_600_000;

/** The `verify_limits` subject of the Organization as a whole. */
const ORGANIZATION = "*";

/**
 * Counts one manual verification attempt of `host` (review F2): at most `verifyAttemptsPerHour` per host of the
 * Organization — kept across deleting and adding the host again — and `verifyAttemptsPerOrganizationPerHour` for the
 * Organization, each in a fixed one-hour window that starts at its first attempt. A refused attempt counts nowhere;
 * `retryAfterS` is when every exhausted window ends.
 */
export async function takeVerifyAttempt(
  q: Queryable,
  input: { organizationId: string; host: string; at: Date },
): Promise<{ allowed: true } | { allowed: false; retryAfterS: number }> {
  const { organizationId, host, at } = input;
  const ms = at.getTime();
  // Windows that ended are dropped, so the table holds at most the hosts tried within the last hour.
  await q.query("DELETE FROM verify_limits WHERE window_start <= $1::timestamptz", [
    new Date(ms - WINDOW_MS).toISOString(),
  ]);
  await q.query(
    `INSERT INTO verify_limits (organization_id, subject, window_start, attempts)
     VALUES ($1, $2, $4::timestamptz, 0), ($1, $3, $4::timestamptz, 0)
     ON CONFLICT (organization_id, subject) DO NOTHING`,
    [organizationId, ORGANIZATION, host, at.toISOString()],
  );
  const { rows } = await q.query<{ subject: string; window_start: Date; attempts: number }>(
    "SELECT subject, window_start, attempts FROM verify_limits WHERE subject IN ($1, $2) ORDER BY subject FOR UPDATE",
    [ORGANIZATION, host],
  );
  const windows = rows.map((row) => {
    const start = row.window_start.getTime();
    // A window that ended (or lies ahead of a clock that moved back) starts again now.
    const current = ms - start < WINDOW_MS && ms >= start;
    return {
      subject: row.subject,
      start: current ? start : ms,
      attempts: current ? row.attempts : 0,
      limit:
        row.subject === ORGANIZATION
          ? TARGET_LIMITS.verifyAttemptsPerOrganizationPerHour
          : TARGET_LIMITS.verifyAttemptsPerHour,
    };
  });
  const exhausted = windows.filter((window) => window.attempts >= window.limit);
  if (exhausted.length > 0) {
    const until = Math.max(...exhausted.map((window) => window.start + WINDOW_MS));
    return { allowed: false, retryAfterS: Math.max(1, Math.ceil((until - ms) / 1000)) };
  }
  for (const window of windows) {
    await q.query("UPDATE verify_limits SET window_start = $2::timestamptz, attempts = $3 WHERE subject = $1", [
      window.subject,
      new Date(window.start).toISOString(),
      window.attempts + 1,
    ]);
  }
  return { allowed: true };
}

/** What one ownership check found. */
export type CheckOutcome = { verified: true; method: VerificationMethod } | { verified: false; reason: string };

/**
 * What a check saw when it started: a record is written only while the target still has this `last_checked_at`
 * (and, for the re-check job, this status), so a check recorded in between is never overwritten by an older one
 * (review F3).
 */
export interface CheckGuard {
  status?: "verified" | "lapsed";
  lastCheckedAt: string | null;
}

function guardSql(guard: CheckGuard | undefined, first: number): { sql: string; params: unknown[] } {
  if (guard === undefined) return { sql: "", params: [] };
  const checked = ` AND last_checked_at IS NOT DISTINCT FROM $${first}::timestamptz`;
  if (guard.status === undefined) return { sql: checked, params: [guard.lastCheckedAt] };
  return { sql: `${checked} AND status = $${first + 1}`, params: [guard.lastCheckedAt, guard.status] };
}

/**
 * Records a check made at `at`. Passed: verified with the method, `verified_at` and `last_checked_at` = `at`, no
 * reason. Failed: a pending target stays pending; a verified or lapsed one is (or stays) lapsed with the reason;
 * `verified_at` keeps the last successful check. Either way the count of re-check misses starts again. With
 * `guard` (the re-check job), nothing is written unless the target is unchanged since it was read.
 * Null when the target is gone or (with `guard`) changed meanwhile.
 */
export async function recordCheck(
  q: Queryable,
  id: string,
  outcome: CheckOutcome,
  at: Date,
  options: { guard?: CheckGuard } = {},
): Promise<Target | null> {
  const guard = guardSql(options.guard, 4);
  if (outcome.verified) {
    const { rows } = await q.query<TargetRow>(
      `UPDATE targets SET status = 'verified', method = $2, verified_at = $3::timestamptz,
         last_checked_at = $3::timestamptz, lapsed_reason = NULL, recheck_misses = 0
       WHERE id = $1${guard.sql}
       RETURNING ${COLUMNS}`,
      [id, outcome.method, at.toISOString(), ...guard.params],
    );
    return rows[0] === undefined ? null : toTarget(rows[0]);
  }
  const reason = outcome.reason.slice(0, TARGET_LIMITS.lapsedReasonMax);
  const { rows } = await q.query<TargetRow>(
    `UPDATE targets SET
       status = CASE WHEN status = 'pending' THEN 'pending' ELSE 'lapsed' END,
       lapsed_reason = CASE WHEN status = 'pending' THEN NULL ELSE $2 END,
       last_checked_at = $3::timestamptz,
       recheck_misses = 0
     WHERE id = $1${guard.sql}
     RETURNING ${COLUMNS}`,
    [id, reason, at.toISOString(), ...guard.params],
  );
  return rows[0] === undefined ? null : toTarget(rows[0]);
}

/**
 * Counts a re-check of a verified target that failed on our side only and keeps it verified (`last_checked_at` =
 * `at`) while fewer than `missesMax` such failures came in a row. Null when the target changed since it was read or
 * this miss reaches `missesMax`: the caller then records the failure with `recordCheck`, which lapses it.
 */
export async function recordRecheckMiss(
  q: Queryable,
  id: string,
  at: Date,
  guard: CheckGuard,
  missesMax: number,
): Promise<Target | null> {
  const where = guardSql(guard, 4);
  const { rows } = await q.query<TargetRow>(
    `UPDATE targets SET recheck_misses = recheck_misses + 1, last_checked_at = $2::timestamptz
     WHERE id = $1 AND status = 'verified' AND recheck_misses + 1 < $3${where.sql}
     RETURNING ${COLUMNS}`,
    [id, at.toISOString(), missesMax, ...where.params],
  );
  return rows[0] === undefined ? null : toTarget(rows[0]);
}

/**
 * The targets due for a re-check, across Organizations, ids only: verified ones whose last successful check is at or
 * before `cutoff`, and lapsed ones whose last check of any kind is.
 */
export async function listDueTargets(
  q: Queryable,
  cutoff: Date,
  limit: number,
): Promise<{ organizationId: string; targetId: string }[]> {
  const { rows } = await q.query<{ organization_id: string; target_id: string }>(
    "SELECT organization_id, target_id FROM prove_due_targets($1::timestamptz, $2)",
    [cutoff.toISOString(), limit],
  );
  return rows.map((row) => ({ organizationId: row.organization_id, targetId: row.target_id }));
}
