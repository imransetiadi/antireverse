import { type BuildManifest, type Environment, INTEGRITY_LIMITS } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

// Tamper detection (slice 21a, migration 0038): what the integrity recorder reads and writes beside the Detection
// itself. The lookup needs no tenant (a definer function, like `findBeaconBuild`); everything else runs in a
// transaction of the Organization the lookup returned.

/** One file of a Build's integrity marker: its path and its registered SHA-256 (lowercase hex). */
export interface IntegrityFile {
  path: string;
  sha256: string;
}

/** The Build an integrity report names, and what the report is judged against. */
export interface IntegrityBuild {
  organizationId: string;
  appId: string;
  environment: Environment;
  buildId: string;
  /** The marker's files, in the marker's order: a report names one by its index. Empty: the Build has no marker. */
  files: IntegrityFile[];
  /** Whether a fully matching report armed the Build (`builds.integrity_first_match_at`). */
  armed: boolean;
}

interface LookupRow {
  organization_id: string;
  build_id: string | null;
  environment: Environment | null;
  files: string[] | null;
  digests: Record<string, string> | null;
  first_match_at: Date | null;
}

/**
 * The marker's files with their registered digests, in the marker's order. A marker path without an artifact cannot
 * be registered (the request schema refuses it); if one is ever stored, the Build is treated as having no marker
 * rather than judged against a missing digest.
 */
function markerFiles(files: readonly string[], digestOf: (path: string) => string | undefined): IntegrityFile[] {
  const out: IntegrityFile[] = [];
  for (const path of files) {
    const sha256 = digestOf(path);
    if (typeof sha256 !== "string") return [];
    out.push({ path, sha256 });
  }
  return out;
}

/** What a registered Manifest gives the recorder without any read: the Build as a report is judged against it. */
export function integrityBuildOf(organizationId: string, manifest: BuildManifest): IntegrityBuild {
  const digests = new Map(manifest.artifacts.map((artifact) => [artifact.path, artifact.sha256]));
  return {
    organizationId,
    appId: manifest.app_id,
    environment: manifest.environment,
    buildId: manifest.build_id,
    files: markerFiles(manifest.integrity?.files ?? [], (path) => digests.get(path)),
    armed: false,
  };
}

/** How many of an App's newest Builds one lookup answers beside the named one (`integrity_lookup_builds`). */
export const LOOKUP_RECENT_BUILDS = 20;

/**
 * One lookup for a report of `appId` naming `buildId`: the App's Organization (null: no such App) and, of that App,
 * the named Build when it exists and its newest `LOOKUP_RECENT_BUILDS` Builds. A Build of any other App or
 * Organization is simply not among them. The Build id is a value from a public request: never log it unless it is
 * among the Builds found.
 */
export async function findIntegrityBuilds(
  q: Queryable,
  appId: string,
  buildId: string,
): Promise<{ organizationId: string | null; builds: IntegrityBuild[] }> {
  const { rows } = await q.query<LookupRow>("SELECT * FROM integrity_lookup_builds($1::text, $2::text)", [
    appId,
    buildId,
  ]);
  const builds: IntegrityBuild[] = [];
  for (const row of rows) {
    if (row.build_id === null || row.environment === null) continue;
    const digests = row.digests ?? {};
    builds.push({
      organizationId: row.organization_id,
      appId,
      environment: row.environment,
      buildId: row.build_id,
      files: markerFiles(row.files ?? [], (path) => digests[path]),
      armed: row.first_match_at !== null,
    });
  }
  return { organizationId: rows[0]?.organization_id ?? null, builds };
}

/**
 * Arms a Build: stamps `integrity_first_match_at` unless it is set. `armed` when this call armed it, `already` when
 * it was armed before, `gone` when the Build is no longer there (its Organization was purged). Run in a transaction
 * of the Build's Organization.
 */
export async function armBuild(
  q: Queryable,
  build: Pick<IntegrityBuild, "organizationId" | "appId" | "buildId">,
  at: Date,
): Promise<"armed" | "already" | "gone"> {
  const { rows } = await q.query<{ updated: number; present: boolean }>(
    `WITH armed AS (
       UPDATE builds SET integrity_first_match_at = $4::timestamptz
       WHERE organization_id = $1::text AND app_id = $2::text AND build_id = $3::text
         AND integrity_first_match_at IS NULL
       RETURNING build_id
     )
     SELECT (SELECT count(*)::int FROM armed) AS updated,
       EXISTS (SELECT 1 FROM builds
               WHERE organization_id = $1::text AND app_id = $2::text AND build_id = $3::text) AS present`,
    [build.organizationId, build.appId, build.buildId, at.toISOString()],
  );
  const row = rows[0];
  if (row !== undefined && row.updated > 0) return "armed";
  return row?.present === true ? "already" : "gone";
}

/** Builds one load of the recent hashes reads at most, newest first: the bound of the 30-day part of "recent". */
export const RECENT_BUILDS_SCAN_MAX = 200;

/** Path → the registered SHA-256 (hex) of that path in the recent Builds of one App Environment. */
export type RecentHashes = Map<string, Set<string>>;

/**
 * The registered digests of `paths` in the recent Builds of an App Environment, whatever those Builds' own markers
 * list: what tells a stale file (a page of one deploy loading a file of another) from a tampered one. Recent: among
 * the last `INTEGRITY_LIMITS.recentBuilds` Builds registered, or registered within `INTEGRITY_LIMITS.recentDays`
 * days of `at`; at most the newest `RECENT_BUILDS_SCAN_MAX` are read. This reads Manifests: the recorder calls it
 * once per App Environment and keeps the answer, never once per report.
 */
export async function loadRecentHashes(
  q: Queryable,
  build: Pick<IntegrityBuild, "organizationId" | "appId" | "environment">,
  paths: readonly string[],
  at: Date,
): Promise<RecentHashes> {
  const hashes: RecentHashes = new Map();
  if (paths.length === 0) return hashes;
  const { rows } = await q.query<{ path: string; sha256: string }>(
    `WITH recent AS (
       SELECT b.manifest
       FROM (
         SELECT manifest, registered_at, row_number() OVER (ORDER BY registered_at DESC, build_id DESC) AS n
         FROM builds
         WHERE organization_id = $1::text AND app_id = $2::text AND environment = $3::text
         ORDER BY registered_at DESC, build_id DESC
         LIMIT ${RECENT_BUILDS_SCAN_MAX}
       ) AS b
       WHERE b.n <= ${INTEGRITY_LIMITS.recentBuilds}
          OR b.registered_at >= $4::timestamptz - interval '${INTEGRITY_LIMITS.recentDays} days'
     )
     SELECT DISTINCT a->>'path' AS path, a->>'sha256' AS sha256
     FROM recent r, jsonb_array_elements(r.manifest->'artifacts') AS a
     WHERE a->>'path' = ANY ($5::text[])`,
    [build.organizationId, build.appId, build.environment, at.toISOString(), [...paths]],
  );
  for (const row of rows) {
    const known = hashes.get(row.path);
    if (known === undefined) hashes.set(row.path, new Set([row.sha256]));
    else known.add(row.sha256);
  }
  return hashes;
}

/**
 * Whether an observed hash may be recorded for the Build at `at`, decided where it is durable: inside the transaction
 * that then writes the Detection, after locking the Build's row, so that writers of one Build take turns and the
 * answer holds across API processes and restarts.
 * - `repeat`: a Detection of the same Build, file and hash was recorded within the last `windowS` seconds (the rule's
 *   window): one per window.
 * - `cap`: `INTEGRITY_LIMITS.hashesPerDay` distinct `(path, hash)` pairs were recorded for the Build in the 24 hours
 *   before, over all its Incidents (open or resolved), and this pair is not one of them.
 * - `ok` otherwise.
 */
export async function admitObservation(
  q: Queryable,
  build: Pick<IntegrityBuild, "organizationId" | "appId" | "buildId">,
  observed: IntegrityFile,
  at: Date,
  windowS: number,
): Promise<"ok" | "repeat" | "cap"> {
  await q.query(
    "SELECT 1 FROM builds WHERE organization_id = $1::text AND app_id = $2::text AND build_id = $3::text FOR UPDATE",
    [build.organizationId, build.appId, build.buildId],
  );
  const { rows } = await q.query<{ pairs: number; seen: boolean; repeat: boolean }>(
    `SELECT count(*)::int AS pairs,
       COALESCE(bool_or(p.artifact_path = $5::text AND p.observed_sha256 = $6::text), false) AS seen,
       COALESCE(bool_or(p.artifact_path = $5::text AND p.observed_sha256 = $6::text
         AND p.latest > $4::timestamptz - make_interval(secs => $7::int)), false) AS repeat
     FROM (
       SELECT d.artifact_path, d.observed_sha256, max(d.detected_at) AS latest
       FROM incidents i JOIN detections d ON d.organization_id = i.organization_id AND d.incident_id = i.id
       WHERE i.organization_id = $1::text AND i.app_id = $2::text AND i.rule = 'tampered-build'
         AND i.build_id = $3::text AND d.artifact_path IS NOT NULL
         AND d.detected_at > $4::timestamptz - interval '24 hours'
       GROUP BY d.artifact_path, d.observed_sha256
     ) AS p`,
    [build.organizationId, build.appId, build.buildId, at.toISOString(), observed.path, observed.sha256, windowS],
  );
  const row = rows[0];
  if (row === undefined) return "ok";
  if (row.repeat) return "repeat";
  return row.seen || row.pairs < INTEGRITY_LIMITS.hashesPerDay ? "ok" : "cap";
}

/**
 * Marks the Build's open or acknowledged `tampered-build` Incident, if there is one, as capped: a cap dropped a
 * distinct observed hash. Set once per Incident; an Incident already marked stays as it is.
 */
export async function markCapped(
  q: Queryable,
  build: Pick<IntegrityBuild, "organizationId" | "appId" | "buildId">,
  at: Date,
): Promise<void> {
  await q.query(
    `UPDATE incidents SET capped_at = $4::timestamptz
     WHERE organization_id = $1::text AND app_id = $2::text AND rule = 'tampered-build' AND build_id = $3::text
       AND status IN ('open', 'acknowledged') AND capped_at IS NULL`,
    [build.organizationId, build.appId, build.buildId, at.toISOString()],
  );
}
