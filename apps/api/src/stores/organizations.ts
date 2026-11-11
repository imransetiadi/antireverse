import type { Organization } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

interface OrganizationRow {
  id: string;
  name: string;
  created_at: Date;
}

const COLUMNS = "id, name, created_at";

function toOrganization(row: OrganizationRow): Organization {
  return { id: row.id, name: row.name, created_at: row.created_at.toISOString() };
}

/** Inserts an Organization. The transaction's tenant must already be the new identifier. */
export async function insertOrganization(q: Queryable, input: { id: string; name: string }): Promise<Organization> {
  const { rows } = await q.query<OrganizationRow>(
    `INSERT INTO organizations (id, name) VALUES ($1, $2) RETURNING ${COLUMNS}`,
    [input.id, input.name],
  );
  const row = rows[0];
  if (row === undefined) throw new Error("The Organization was not stored.");
  return toOrganization(row);
}

/** The transaction's own Organization, or null. Row-level security hides every other one. */
export async function findOrganization(q: Queryable, id: string): Promise<Organization | null> {
  const { rows } = await q.query<OrganizationRow>(`SELECT ${COLUMNS} FROM organizations WHERE id = $1`, [id]);
  return rows[0] === undefined ? null : toOrganization(rows[0]);
}
