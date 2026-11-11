import type { App } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

interface AppRow {
  id: string;
  name: string;
  created_at: Date;
}

const COLUMNS = "id, name, created_at";

function toApp(row: AppRow): App {
  return { id: row.id, name: row.name, created_at: row.created_at.toISOString() };
}

export async function insertApp(
  q: Queryable,
  input: { id: string; organizationId: string; name: string },
): Promise<App> {
  const { rows } = await q.query<AppRow>(
    `INSERT INTO apps (id, organization_id, name) VALUES ($1, $2, $3) RETURNING ${COLUMNS}`,
    [input.id, input.organizationId, input.name],
  );
  const row = rows[0];
  if (row === undefined) throw new Error("The App was not stored.");
  return toApp(row);
}

/**
 * The Apps of the transaction's Organization, newest first. Ordered by the generated `seq` column, which
 * counts up on every insert: it gives the true creation order even when two Apps share a millisecond, where
 * `created_at` alone would tie and fall back to the random id. `seq` is internal and never leaves the store.
 */
export async function listApps(q: Queryable): Promise<App[]> {
  const { rows } = await q.query<AppRow>(`SELECT ${COLUMNS} FROM apps ORDER BY seq DESC`);
  return rows.map(toApp);
}

/** One App of the transaction's Organization, or null. Another Organization's App is null as well. */
export async function findApp(q: Queryable, id: string): Promise<App | null> {
  const { rows } = await q.query<AppRow>(`SELECT ${COLUMNS} FROM apps WHERE id = $1`, [id]);
  return rows[0] === undefined ? null : toApp(rows[0]);
}

/**
 * Locks one App of the transaction's Organization until the transaction ends, so that whoever publishes
 * a Policy for it waits for the publisher before. False when the Organization has no such App.
 * (`NO KEY`: rows that refer to the App, such as a new key, can still be inserted meanwhile.)
 */
export async function lockApp(q: Queryable, id: string): Promise<boolean> {
  const { rows } = await q.query("SELECT id FROM apps WHERE id = $1 FOR NO KEY UPDATE", [id]);
  return rows.length === 1;
}
