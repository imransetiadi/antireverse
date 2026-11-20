import type { Queryable } from "../db/db.ts";

// Slice 18g: the owner-only registry `system_organizations` (migration 0043). Every function runs inside `db.owner`.

export type SystemOrganizationKind = "probe";

export interface SystemOrganization {
  organizationId: string;
  appId: string;
}

/** The registered Organization and App of a kind, or null. */
export async function readSystemOrganization(
  q: Queryable,
  kind: SystemOrganizationKind,
): Promise<SystemOrganization | null> {
  const { rows } = await q.query<{ org_id: string; app_id: string }>(
    "SELECT org_id, app_id FROM system_organizations WHERE kind = $1",
    [kind],
  );
  const row = rows[0];
  return row === undefined ? null : { organizationId: row.org_id, appId: row.app_id };
}

/**
 * Registers the identifiers of a kind unless one is registered already, and answers the registered ones: of two
 * callers, both get the same row.
 */
export async function registerSystemOrganization(
  q: Queryable,
  kind: SystemOrganizationKind,
  candidate: SystemOrganization,
  at: Date,
): Promise<SystemOrganization> {
  await q.query(
    `INSERT INTO system_organizations (kind, org_id, app_id, created_at) VALUES ($1, $2, $3, $4::timestamptz)
     ON CONFLICT (kind) DO NOTHING`,
    [kind, candidate.organizationId, candidate.appId, at.toISOString()],
  );
  const registered = await readSystemOrganization(q, kind);
  if (registered === null) throw new Error("The system Organization was not registered.");
  return registered;
}

/** The id of every Organization the API itself owns (not a tenant). */
export async function listSystemOrganizationIds(q: Queryable): Promise<string[]> {
  const { rows } = await q.query<{ org_id: string }>("SELECT org_id FROM system_organizations ORDER BY org_id");
  return rows.map((row) => row.org_id);
}

/**
 * The system Organizations, held in memory (review F2, D-116): asked on every request and every Event, so it is a set
 * lookup and never a database read. `startApi` fills it from the registry at start and adds the probe's Organization
 * as soon as it is provisioned, before the probe sends its first request.
 */
export interface SystemOrganizations {
  has(organizationId: string): boolean;
  add(organizationId: string): void;
}

export function createSystemOrganizations(initial: readonly string[] = []): SystemOrganizations {
  const ids = new Set(initial);
  return { has: (organizationId) => ids.has(organizationId), add: (organizationId) => void ids.add(organizationId) };
}
