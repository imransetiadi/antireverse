import type { Queryable } from "../db/db.ts";

/** The epoch of this database: 32 lowercase hex characters, fixed by the migration `0003_epoch.sql`. */
export async function databaseEpoch(q: Queryable): Promise<string> {
  const { rows } = await q.query<{ epoch: string }>("SELECT epoch FROM database_epoch");
  const row = rows[0];
  if (row === undefined) throw new Error("The database has no epoch.");
  return row.epoch;
}
