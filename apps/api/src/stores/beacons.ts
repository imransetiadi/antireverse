import type { Environment, ManifestBeacon } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

/** The Build a beacon token names, and what a report is judged against. */
export interface BeaconBuild {
  organizationId: string;
  appId: string;
  environment: Environment;
  buildId: string;
  /** The allowed origins, canonical. */
  origins: string[];
}

/**
 * Stores the beacon of a Build in the Build's own transaction. A token registered before for the same App raises
 * a unique violation (SQL state 23505); the route turns that into a 409 and the Build rolls back.
 */
export async function insertBeacon(
  q: Queryable,
  input: {
    organizationId: string;
    appId: string;
    environment: Environment;
    buildId: string;
    beacon: ManifestBeacon;
    createdAt: Date;
  },
): Promise<void> {
  await q.query(
    `INSERT INTO build_beacons (organization_id, app_id, build_id, environment, token, origins, created_at)
     VALUES ($1::text, $2::text, $3::text, $4::text, $5::text, $6::text[], $7::timestamptz)`,
    [
      input.organizationId,
      input.appId,
      input.buildId,
      input.environment,
      input.beacon.token,
      input.beacon.origins,
      input.createdAt.toISOString(),
    ],
  );
}

interface LookupRow {
  organization_id: string;
  build_id: string;
  app_id: string;
  environment: Environment;
  origins: string[];
}

/**
 * The Build a beacon token names within an App, or null (tokens are unique per App). Needs no tenant
 * (`beacon_lookup_token` is the one definer function of the table, like `auth_lookup_key`): every write that
 * follows runs in the returned Organization's scope. The token is a value from a public request: never log it.
 */
export async function findBeaconBuild(q: Queryable, appId: string, token: string): Promise<BeaconBuild | null> {
  const { rows } = await q.query<LookupRow>("SELECT * FROM beacon_lookup_token($1::text, $2::text)", [appId, token]);
  const row = rows[0];
  if (row === undefined) return null;
  return {
    organizationId: row.organization_id,
    appId: row.app_id,
    environment: row.environment,
    buildId: row.build_id,
    origins: row.origins,
  };
}
