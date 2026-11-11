import { type AllowlistEntry, CONTAINMENT_LIMITS } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

interface EntryRow {
  id: string;
  cidr: string;
  note: string;
  created_at: Date;
  created_by: string;
}

const COLUMNS = "id, cidr, note, created_at, created_by";

function toEntry(row: EntryRow): AllowlistEntry {
  return {
    id: row.id,
    cidr: row.cidr,
    note: row.note,
    created_at: row.created_at.toISOString(),
    created_by: row.created_by,
  };
}

/**
 * The allowlist of the transaction's Organization, oldest first (by `created_at`, then id): at most
 * `CONTAINMENT_LIMITS.allowlistMax` entries, which is all of them.
 */
export async function listAllowlist(q: Queryable): Promise<AllowlistEntry[]> {
  const { rows } = await q.query<EntryRow>(
    `SELECT ${COLUMNS} FROM allowlist_entries ORDER BY created_at, id LIMIT $1`,
    [CONTAINMENT_LIMITS.allowlistMax],
  );
  return rows.map(toEntry);
}

export async function countAllowlist(q: Queryable): Promise<number> {
  const { rows } = await q.query<{ n: number }>("SELECT count(*)::int AS n FROM allowlist_entries");
  return rows[0]?.n ?? 0;
}

/** Whether the Organization's allowlist holds exactly this (canonical) CIDR. */
export async function allowlistHas(q: Queryable, cidr: string): Promise<boolean> {
  const { rows } = await q.query("SELECT 1 FROM allowlist_entries WHERE cidr = $1", [cidr]);
  return rows.length > 0;
}

/**
 * Stores an entry. `cidr` must be canonical. A CIDR already on the Organization's allowlist raises a unique
 * violation (SQL state 23505); the caller checks first and turns a concurrent duplicate into a 409.
 */
export async function insertAllowlistEntry(
  q: Queryable,
  input: { organizationId: string; id: string; cidr: string; note: string; createdAt: Date; createdBy: string },
): Promise<AllowlistEntry> {
  const { rows } = await q.query<EntryRow>(
    `INSERT INTO allowlist_entries (organization_id, id, cidr, note, created_at, created_by)
     VALUES ($1, $2, $3, $4, $5::timestamptz, $6)
     RETURNING ${COLUMNS}`,
    [input.organizationId, input.id, input.cidr, input.note, input.createdAt.toISOString(), input.createdBy],
  );
  const row = rows[0];
  if (row === undefined) throw new Error("The allowlist entry was not stored.");
  return toEntry(row);
}

/** Removes an entry of the transaction's Organization. False when there is none with this id. */
export async function deleteAllowlistEntry(q: Queryable, id: string): Promise<boolean> {
  const { rows } = await q.query("DELETE FROM allowlist_entries WHERE id = $1 RETURNING id", [id]);
  return rows.length === 1;
}

/** The CIDRs of the transaction's Organization, as the Policy Bundle carries them: in `listAllowlist` order. */
export async function allowlistCidrs(q: Queryable): Promise<string[]> {
  return (await listAllowlist(q)).map((entry) => entry.cidr);
}
