import {
  type BundleBlock,
  CONTAINMENT_LIMITS,
  type Containment,
  type ContainmentStatus,
  type ContainmentTarget,
  type Environment,
} from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

interface ContainmentRow {
  id: string;
  app_id: string;
  environment: Environment;
  incident_id: string | null;
  target_kind: "actor" | "prefix";
  ip_hash: string | null;
  ip_prefix: string | null;
  created_at: Date;
  expires_at: Date;
  created_by: string;
  lifted_at: Date | null;
  lifted_by: string | null;
}

/**
 * Blocks one list answers: `GET /v1/containments` and an Incident's detail. The active blocks of one App
 * Environment (at most `CONTAINMENT_LIMITS.activePerAppEnv`) always fit.
 */
export const CONTAINMENTS_LISTED = 200;

const COLUMNS =
  "id, app_id, environment, incident_id, target_kind, ip_hash, ip_prefix, created_at, expires_at, created_by, lifted_at, lifted_by";

/** Which blocks: those of one App Environment of the transaction's Organization. */
export interface ContainmentScope {
  organizationId: string;
  appId: string;
  environment: Environment;
}

/** `lifted` once lifted; else `active` until `expires_at` (exclusive) on the clock, `expired` from then on. */
function statusOf(row: ContainmentRow, at: Date): ContainmentStatus {
  if (row.lifted_at !== null) return "lifted";
  return row.expires_at.getTime() > at.getTime() ? "active" : "expired";
}

function targetOf(row: ContainmentRow): ContainmentTarget {
  // Guaranteed by the table's check: exactly the member of its kind is set.
  return row.target_kind === "actor"
    ? { kind: "actor", ip_hash: row.ip_hash ?? "" }
    : { kind: "prefix", ip_prefix: row.ip_prefix ?? "" };
}

function toContainment(row: ContainmentRow, at: Date): Containment {
  return {
    id: row.id,
    app_id: row.app_id,
    environment: row.environment,
    incident_id: row.incident_id,
    target: targetOf(row),
    created_at: row.created_at.toISOString(),
    expires_at: row.expires_at.toISOString(),
    created_by: row.created_by,
    lifted_at: row.lifted_at?.toISOString() ?? null,
    lifted_by: row.lifted_by,
    status: statusOf(row, at),
  };
}

/** The SQL condition of a status at the time in parameter `at` (e.g. "$2"). Constant text. */
function statusSql(status: ContainmentStatus, at: `$${number}`): string {
  if (status === "lifted") return "lifted_at IS NOT NULL";
  return status === "active"
    ? `(lifted_at IS NULL AND expires_at > ${at}::timestamptz)`
    : `(lifted_at IS NULL AND expires_at <= ${at}::timestamptz)`;
}

export interface NewContainment extends ContainmentScope {
  id: string;
  incidentId: string | null;
  target: ContainmentTarget;
  createdAt: Date;
  expiresAt: Date;
  /** The id of the admin key that creates it. */
  createdBy: string;
}

/** Stores a new block. The caller checked the rules (Incident, target, allowlist, limit). */
export async function insertContainment(q: Queryable, input: NewContainment): Promise<Containment> {
  const { rows } = await q.query<ContainmentRow>(
    `INSERT INTO containments (organization_id, id, app_id, environment, incident_id, target_kind, ip_hash, ip_prefix,
       created_at, expires_at, created_by)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9::timestamptz, $10::timestamptz, $11)
     RETURNING ${COLUMNS}`,
    [
      input.organizationId,
      input.id,
      input.appId,
      input.environment,
      input.incidentId,
      input.target.kind,
      input.target.kind === "actor" ? input.target.ip_hash : null,
      input.target.kind === "prefix" ? input.target.ip_prefix : null,
      input.createdAt.toISOString(),
      input.expiresAt.toISOString(),
      input.createdBy,
    ],
  );
  const row = rows[0];
  if (row === undefined) throw new Error("The Containment was not stored.");
  return toContainment(row, input.createdAt);
}

/** The active block of the App Environment with exactly this target, or null. */
export async function findActiveContainment(
  q: Queryable,
  scope: ContainmentScope,
  target: ContainmentTarget,
  at: Date,
): Promise<Containment | null> {
  const { rows } = await q.query<ContainmentRow>(
    `SELECT ${COLUMNS} FROM containments
     WHERE organization_id = $1 AND app_id = $2 AND environment = $3 AND ${statusSql("active", "$4")}
       AND target_kind = $5 AND ip_hash IS NOT DISTINCT FROM $6::text AND ip_prefix IS NOT DISTINCT FROM $7::text
     ORDER BY created_at, id
     LIMIT 1`,
    [
      scope.organizationId,
      scope.appId,
      scope.environment,
      at.toISOString(),
      target.kind,
      target.kind === "actor" ? target.ip_hash : null,
      target.kind === "prefix" ? target.ip_prefix : null,
    ],
  );
  return rows[0] === undefined ? null : toContainment(rows[0], at);
}

/** How many blocks of the App Environment are active at `at`. */
export async function countActiveContainments(q: Queryable, scope: ContainmentScope, at: Date): Promise<number> {
  const { rows } = await q.query<{ n: number }>(
    `SELECT count(*)::int AS n FROM containments
     WHERE organization_id = $1 AND app_id = $2 AND environment = $3 AND ${statusSql("active", "$4")}`,
    [scope.organizationId, scope.appId, scope.environment, at.toISOString()],
  );
  return rows[0]?.n ?? 0;
}

/** One block of the transaction's Organization, or null. With `lock`, the row stays locked until commit. */
export async function findContainment(q: Queryable, id: string, at: Date, lock = false): Promise<Containment | null> {
  const { rows } = await q.query<ContainmentRow>(
    `SELECT ${COLUMNS} FROM containments WHERE id = $1${lock ? " FOR UPDATE" : ""}`,
    [id],
  );
  return rows[0] === undefined ? null : toContainment(rows[0], at);
}

/** Lifts a block that is active at `at`, recording the admin key and the time; null when it is not active. */
export async function liftContainment(q: Queryable, id: string, keyId: string, at: Date): Promise<Containment | null> {
  const { rows } = await q.query<ContainmentRow>(
    `UPDATE containments SET lifted_at = $2::timestamptz, lifted_by = $3
     WHERE id = $1 AND ${statusSql("active", "$2")}
     RETURNING ${COLUMNS}`,
    [id, at.toISOString(), keyId],
  );
  return rows[0] === undefined ? null : toContainment(rows[0], at);
}

/** The blocks of the transaction's Organization, newest first (by `created_at`, then id), optionally filtered. */
export async function listContainments(
  q: Queryable,
  filter: { appId?: string; environment?: Environment; status?: ContainmentStatus; limit: number },
  at: Date,
): Promise<Containment[]> {
  const { rows } = await q.query<ContainmentRow>(
    `SELECT ${COLUMNS} FROM containments
     WHERE ($1::text IS NULL OR app_id = $1::text) AND ($2::text IS NULL OR environment = $2::text)
       AND ${filter.status === undefined ? "TRUE" : statusSql(filter.status, "$3")}
       -- Typed in every variant: a parameter no condition mentions has no type, and the statement fails.
       AND $3::timestamptz IS NOT NULL
     ORDER BY created_at DESC, id DESC
     LIMIT $4`,
    [filter.appId ?? null, filter.environment ?? null, at.toISOString(), filter.limit],
  );
  return rows.map((row) => toContainment(row, at));
}

/** The blocks created from one Incident, newest first, at most `limit`. */
export async function listIncidentContainments(
  q: Queryable,
  incidentId: string,
  at: Date,
  limit: number,
): Promise<Containment[]> {
  const { rows } = await q.query<ContainmentRow>(
    `SELECT ${COLUMNS} FROM containments WHERE incident_id = $1 ORDER BY created_at DESC, id DESC LIMIT $2`,
    [incidentId, limit],
  );
  return rows.map((row) => toContainment(row, at));
}

/**
 * The blocks of an App Environment active at `at`, as the Policy Bundle carries them: oldest first (by
 * `created_at`, then id), at most `CONTAINMENT_LIMITS.activePerAppEnv`.
 */
export async function activeBlocks(q: Queryable, scope: ContainmentScope, at: Date): Promise<BundleBlock[]> {
  const { rows } = await q.query<ContainmentRow>(
    `SELECT ${COLUMNS} FROM containments
     WHERE organization_id = $1 AND app_id = $2 AND environment = $3 AND ${statusSql("active", "$4")}
     ORDER BY created_at, id
     LIMIT $5`,
    [scope.organizationId, scope.appId, scope.environment, at.toISOString(), CONTAINMENT_LIMITS.activePerAppEnv],
  );
  return rows.map((row) => {
    const expires_at = row.expires_at.toISOString();
    return row.target_kind === "actor"
      ? { id: row.id, kind: "actor", ip_hash: row.ip_hash ?? "", expires_at }
      : { id: row.id, kind: "prefix", ip_prefix: row.ip_prefix ?? "", expires_at };
  });
}
