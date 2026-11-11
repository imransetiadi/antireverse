import { CANARY_LIMITS, type Canary, type Environment } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

/** Which Canaries: those of one App Environment of the transaction's Organization. */
export interface CanaryTarget {
  organizationId: string;
  appId: string;
  environment: Environment;
}

/**
 * Stores the Canaries of a Build, in Manifest order, in the Build's own transaction. An id the Organization
 * registered before raises a primary-key conflict (SQL state 23505); the route turns that into a 409.
 */
export async function insertCanaries(
  q: Queryable,
  input: CanaryTarget & { buildId: string; canaries: readonly Canary[]; createdAt: Date },
): Promise<void> {
  if (input.canaries.length === 0) return;
  // One statement: the Manifest's order is the array index.
  await q.query(
    `INSERT INTO canaries (organization_id, id, app_id, environment, build_id, position, kind, value, created_at)
     SELECT $1::text, c.id, $2::text, $3::text, $4::text, (c.ord - 1)::int, c.kind, c.value, $5::timestamptz
     FROM unnest($6::text[], $7::text[], $8::text[]) WITH ORDINALITY AS c(id, kind, value, ord)`,
    [
      input.organizationId,
      input.appId,
      input.environment,
      input.buildId,
      input.createdAt.toISOString(),
      input.canaries.map((canary) => canary.id),
      input.canaries.map((canary) => canary.kind),
      input.canaries.map((canary) => canary.value),
    ],
  );
}

/**
 * The active Canaries of an App Environment, as the Policy Bundle carries them: those of its most recent
 * `CANARY_LIMITS.buildsInBundle` Builds, newest Build first (by `registered_at`, then Build id, as the Build
 * list), in Manifest order within a Build, at most `CANARY_LIMITS.perBundle`.
 */
export async function activeCanaries(q: Queryable, target: CanaryTarget): Promise<Canary[]> {
  const { rows } = await q.query<Canary>(
    `WITH recent AS (
       SELECT build_id, registered_at FROM builds
       WHERE organization_id = $1::text AND app_id = $2::text AND environment = $3::text
       ORDER BY registered_at DESC, build_id DESC
       LIMIT $4
     )
     SELECT c.id, c.kind, c.value FROM canaries c JOIN recent r ON c.build_id = r.build_id
     WHERE c.organization_id = $1::text AND c.app_id = $2::text AND c.environment = $3::text
     ORDER BY r.registered_at DESC, r.build_id DESC, c.position
     LIMIT $5`,
    [target.organizationId, target.appId, target.environment, CANARY_LIMITS.buildsInBundle, CANARY_LIMITS.perBundle],
  );
  return rows.map((row) => ({ id: row.id, kind: row.kind, value: row.value }) as Canary);
}

/**
 * The Build a Canary of this App Environment was planted in, or null: an unknown id, and another
 * Organization's, App's or Environment's Canary, are all null alike. Never the value.
 */
export async function findCanaryBuild(q: Queryable, target: CanaryTarget, canaryId: string): Promise<string | null> {
  const { rows } = await q.query<{ build_id: string }>(
    `SELECT build_id FROM canaries
     WHERE organization_id = $1::text AND app_id = $2::text AND environment = $3::text AND id = $4::text`,
    [target.organizationId, target.appId, target.environment, canaryId],
  );
  return rows[0]?.build_id ?? null;
}
