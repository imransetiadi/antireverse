import {
  AUDIT_GENESIS_HASH,
  type AuditAction,
  type AuditActorKind,
  type AuditEntry,
  type AuditTargetKind,
} from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

// Reading the audit log (slice 18a). Writing is `audit` in src/audit.ts, inside the change's transaction.

interface EntryRow {
  id: string;
  organization_id: string;
  seq: string | number;
  at: Date;
  actor_kind: AuditActorKind;
  actor_key_id: string | null;
  action: string;
  app_id: string | null;
  target_kind: string;
  target_id: string;
  reason: string | null;
  summary: string;
  request_id: string;
  prev_hash: string;
  hash: string;
}

const COLUMNS = `id, organization_id, seq, at, actor_kind, actor_key_id, action, app_id, target_kind, target_id, reason,
  summary, request_id::text AS request_id, prev_hash, hash`;

/** A stored row as the protocol's entry. Optional members that are null are left out (the hash covers no null). */
function toEntry(row: EntryRow): AuditEntry {
  return {
    id: row.id,
    organization_id: row.organization_id,
    seq: Number(row.seq),
    at: row.at.toISOString(),
    actor: row.actor_key_id === null ? { kind: row.actor_kind } : { kind: row.actor_kind, key_id: row.actor_key_id },
    action: row.action as AuditAction,
    ...(row.app_id === null ? {} : { app_id: row.app_id }),
    target: { kind: row.target_kind as AuditTargetKind, id: row.target_id },
    ...(row.reason === null ? {} : { reason: row.reason }),
    summary: row.summary,
    request_id: row.request_id,
    prev_hash: row.prev_hash,
    hash: row.hash,
  };
}

export interface AuditFilter {
  action?: AuditAction | undefined;
  appId?: string | undefined;
  targetId?: string | undefined;
  /** Inclusive. */
  from?: Date | undefined;
  /** Exclusive. */
  to?: Date | undefined;
  /** Entries with a lower `seq` only. */
  beforeSeq?: number | undefined;
  limit: number;
}

/** The transaction's Organization's entries, newest first. */
export async function listAuditEntries(q: Queryable, filter: AuditFilter): Promise<AuditEntry[]> {
  const conditions: string[] = [];
  const params: unknown[] = [];
  const add = (column: string, operator: string, value: unknown) => {
    params.push(value);
    conditions.push(`${column} ${operator} $${params.length}`);
  };
  if (filter.action !== undefined) add("action", "=", filter.action);
  if (filter.appId !== undefined) add("app_id", "=", filter.appId);
  if (filter.targetId !== undefined) add("target_id", "=", filter.targetId);
  if (filter.from !== undefined) add("at", ">=", filter.from);
  if (filter.to !== undefined) add("at", "<", filter.to);
  if (filter.beforeSeq !== undefined) add("seq", "<", filter.beforeSeq);
  params.push(filter.limit);
  const where = conditions.length === 0 ? "" : `WHERE ${conditions.join(" AND ")}`;
  const { rows } = await q.query<EntryRow>(
    `SELECT ${COLUMNS} FROM audit_entries ${where} ORDER BY seq DESC LIMIT $${params.length}`,
    params,
  );
  return rows.map(toEntry);
}

/**
 * Up to `limit` entries with a `seq` above `afterSeq` (and at most `upToSeq` when given), oldest first: one page of the
 * export and of verification.
 */
export async function auditEntriesAfter(
  q: Queryable,
  afterSeq: number,
  limit: number,
  upToSeq?: number,
): Promise<AuditEntry[]> {
  const { rows } = await q.query<EntryRow>(
    `SELECT ${COLUMNS} FROM audit_entries WHERE seq > $1 AND ($3::bigint IS NULL OR seq <= $3::bigint)
     ORDER BY seq LIMIT $2`,
    [afterSeq, limit, upToSeq ?? null],
  );
  return rows.map(toEntry);
}

/** How many entries have a `seq` above `afterSeq`. */
export async function countAuditEntriesAfter(q: Queryable, afterSeq: number): Promise<number> {
  const { rows } = await q.query<{ n: number }>("SELECT count(*)::int AS n FROM audit_entries WHERE seq > $1", [
    afterSeq,
  ]);
  return rows[0]?.n ?? 0;
}

/** The chain head of the transaction's Organization: `seq` 0 and the genesis hash when it has none. */
export async function auditHead(q: Queryable): Promise<{ seq: number; hash: string }> {
  const { rows } = await q.query<{ seq: string | number; hash: string }>("SELECT seq, hash FROM audit_heads");
  const row = rows[0];
  return row === undefined ? { seq: 0, hash: AUDIT_GENESIS_HASH } : { seq: Number(row.seq), hash: row.hash };
}
