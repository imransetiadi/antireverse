import type { Build, BuildManifest } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

/** Which Builds: those of an App of the transaction's Organization. */
export interface BuildTarget {
  organizationId: string;
  appId: string;
}

interface BuildRow {
  manifest: BuildManifest;
  registered_at: Date;
}

const OF_TARGET = "organization_id = $1::text AND app_id = $2::text";

/**
 * The Manifest is stored whole; the denormalised columns are only for keys and ordering. Its Canaries are
 * returned as id and kind: a decoy value goes into the Policy Bundle only, never into an admin response. Its
 * Clone Beacon is returned as its origins only: responses stay minimal, the token is never returned.
 */
function toBuild(row: BuildRow): Build {
  const { canaries, beacon, ...manifest } = row.manifest;
  return {
    ...manifest,
    ...(canaries === undefined ? {} : { canaries: canaries.map(({ id, kind }) => ({ id, kind })) }),
    ...(beacon === undefined ? {} : { beacon: { origins: beacon.origins } }),
    registered_at: row.registered_at.toISOString(),
  };
}

/**
 * Stores a Manifest as a Build and returns it with the time the API stamped. A second registration of the
 * same `(organization, app, build)` raises a primary-key conflict (SQL state 23505); the route turns that
 * into a 409. The columns beside `manifest` are drawn from it, for the primary key and for ordering.
 */
export async function insertBuild(
  q: Queryable,
  input: { organizationId: string; manifest: BuildManifest; registeredAt: Date },
): Promise<Build> {
  const m = input.manifest;
  const { rows } = await q.query<BuildRow>(
    `INSERT INTO builds (organization_id, app_id, build_id, environment, version, profile, manifest, registered_at)
     VALUES ($1::text, $2::text, $3::text, $4::text, $5::text, $6::text, $7::jsonb, $8::timestamptz)
     RETURNING manifest, registered_at`,
    [
      input.organizationId,
      m.app_id,
      m.build_id,
      m.environment,
      m.version,
      m.profile,
      JSON.stringify(m),
      input.registeredAt.toISOString(),
    ],
  );
  const row = rows[0];
  if (row === undefined) throw new Error("The Build was not stored.");
  return toBuild(row);
}

/** The newest `limit` Builds of the App, newest first: by `registered_at`, then Build id, both descending. */
export async function listBuilds(q: Queryable, target: BuildTarget, limit: number): Promise<Build[]> {
  const { rows } = await q.query<BuildRow>(
    `SELECT manifest, registered_at FROM builds
     WHERE ${OF_TARGET}
     ORDER BY registered_at DESC, build_id DESC
     LIMIT $3`,
    [target.organizationId, target.appId, limit],
  );
  return rows.map(toBuild);
}

/** One Build of the App, or null. Another Organization's or App's Build is null as well. */
export async function findBuild(q: Queryable, target: BuildTarget, buildId: string): Promise<Build | null> {
  const { rows } = await q.query<BuildRow>(
    `SELECT manifest, registered_at FROM builds WHERE ${OF_TARGET} AND build_id = $3::text`,
    [target.organizationId, target.appId, buildId],
  );
  return rows[0] === undefined ? null : toBuild(rows[0]);
}
