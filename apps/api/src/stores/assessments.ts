import { randomBytes } from "node:crypto";
import {
  ASSESSMENT_LIMITS,
  type Assessment,
  type AssessmentCall,
  type AssessmentCallTotals,
  type AssessmentStatus,
  type AssessmentTier,
  type Canary,
  type Environment,
  type InconclusiveCode,
  type ObjectiveResult,
  type ScopeStatement,
} from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";
import type { BuildTarget } from "./builds.ts";

// The Reverse Assessment store (slice 12a, 0026_assessments.sql): uploaded artifacts and their files, Assessments, and
// the identifiers-only queue functions the runner uses before a tenant is known.

const RETENTION_MS = ASSESSMENT_LIMITS.retentionDays * 86_400_000;

/** An artifact id. Internal only: never part of a response. */
export function newArtifactId(): string {
  return `art_${randomBytes(12).toString("hex")}`;
}

export interface ArtifactFileInput {
  path: string;
  sha256: string;
  content: Uint8Array;
}

/** Stores an uploaded artifact whose files passed Proof of Ownership, kept until `createdAt` plus 30 days. */
export async function insertArtifact(
  q: Queryable,
  input: BuildTarget & { id: string; buildId: string; files: readonly ArtifactFileInput[]; createdAt: Date },
): Promise<void> {
  const bytes = input.files.reduce((sum, file) => sum + file.content.byteLength, 0);
  await q.query(
    `INSERT INTO artifacts (organization_id, id, app_id, build_id, files, bytes, created_at, kept_until)
     VALUES ($1::text, $2::text, $3::text, $4::text, $5::int, $6::bigint, $7::timestamptz, $8::timestamptz)`,
    [
      input.organizationId,
      input.id,
      input.appId,
      input.buildId,
      input.files.length,
      bytes,
      input.createdAt.toISOString(),
      new Date(input.createdAt.getTime() + RETENTION_MS).toISOString(),
    ],
  );
  // One statement per file: a file may be up to 25 MB, and one statement holds every parameter in memory at once.
  for (const file of input.files) {
    await q.query(
      `INSERT INTO artifact_files (organization_id, artifact_id, path, sha256, content)
       VALUES ($1::text, $2::text, $3::text, $4::text, $5::bytea)`,
      [input.organizationId, input.id, file.path, file.sha256, file.content],
    );
  }
}

/**
 * The Build's most recent artifact still kept at `now`, locked until the transaction ends (`FOR UPDATE`, with
 * `kept_until` re-checked in the same statement). Call it in the transaction that inserts the Assessment: the expiry
 * skips locked rows, and after the commit the queued Assessment holds the artifact.
 */
export const LATEST_KEPT_ARTIFACT_SQL = `SELECT id FROM artifacts
     WHERE organization_id = $1::text AND app_id = $2::text AND build_id = $3::text AND kept_until > $4::timestamptz
     ORDER BY created_at DESC, id DESC LIMIT 1
     FOR UPDATE`;

export async function latestKeptArtifact(
  q: Queryable,
  target: BuildTarget,
  buildId: string,
  now: Date,
): Promise<string | null> {
  const { rows } = await q.query<{ id: string }>(LATEST_KEPT_ARTIFACT_SQL, [
    target.organizationId,
    target.appId,
    buildId,
    now.toISOString(),
  ]);
  return rows[0]?.id ?? null;
}

/** An artifact's files, path → bytes. Empty when it was deleted. */
export async function artifactFiles(q: Queryable, artifactId: string): Promise<Map<string, Uint8Array>> {
  const { rows } = await q.query<{ path: string; content: Uint8Array }>(
    "SELECT path, content FROM artifact_files WHERE artifact_id = $1::text ORDER BY path",
    [artifactId],
  );
  return new Map(rows.map((row) => [row.path, row.content]));
}

interface AssessmentRow {
  id: string;
  app_id: string;
  build_id: string;
  environment: Environment;
  tier: AssessmentTier;
  status: AssessmentStatus;
  results: ObjectiveResult[];
  rrs: number | null;
  renormalised: boolean;
  inconclusive_reason: string | null;
  inconclusive_code: InconclusiveCode | null;
  scope: ScopeStatement;
  failure_reason: string | null;
  created_at: Date;
  started_at: Date | null;
  finished_at: Date | null;
  artifact_kept_until: Date | null;
}

const SELECT_ASSESSMENT = `
  SELECT a.id, a.app_id, a.build_id, a.environment, a.tier, a.status, a.results, a.rrs, a.renormalised,
         a.inconclusive_reason, a.inconclusive_code, a.scope, a.failure_reason, a.created_at, a.started_at,
         a.finished_at, ar.kept_until AS artifact_kept_until
  FROM assessments a
  LEFT JOIN artifacts ar ON ar.organization_id = a.organization_id AND ar.id = a.artifact_id`;

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());

function toAssessment(row: AssessmentRow): Assessment {
  return {
    id: row.id,
    build_id: row.build_id,
    app_id: row.app_id,
    environment: row.environment,
    tier: row.tier,
    status: row.status,
    results: row.results,
    rrs: row.rrs,
    inconclusive_reason: row.inconclusive_reason,
    inconclusive_code: row.inconclusive_code,
    renormalised: row.renormalised,
    scope: row.scope,
    created_at: row.created_at.toISOString(),
    started_at: iso(row.started_at),
    finished_at: iso(row.finished_at),
    failure_reason: row.failure_reason,
    artifact_kept_until: iso(row.artifact_kept_until),
  };
}

/** Queues an Assessment of a Build on an artifact and returns it. */
export async function insertAssessment(
  q: Queryable,
  input: BuildTarget & {
    id: string;
    buildId: string;
    environment: Environment;
    tier: AssessmentTier;
    scope: ScopeStatement;
    artifactId: string;
    createdAt: Date;
  },
): Promise<Assessment> {
  await q.query(
    `INSERT INTO assessments (organization_id, id, app_id, build_id, environment, tier, status, scope, artifact_id,
       created_at)
     VALUES ($1::text, $2::text, $3::text, $4::text, $5::text, $6::text, 'queued', $7::jsonb, $8::text, $9::timestamptz)`,
    [
      input.organizationId,
      input.id,
      input.appId,
      input.buildId,
      input.environment,
      input.tier,
      JSON.stringify(input.scope),
      input.artifactId,
      input.createdAt.toISOString(),
    ],
  );
  const found = await findAssessment(q, input.id);
  if (found === null) throw new Error("The Assessment was not stored.");
  return found;
}

/** The newest `limit` Assessments of a Build, newest first (by creation, then id, both descending). */
export async function listAssessments(
  q: Queryable,
  target: BuildTarget,
  buildId: string,
  limit: number,
): Promise<Assessment[]> {
  const { rows } = await q.query<AssessmentRow>(
    `${SELECT_ASSESSMENT}
     WHERE a.organization_id = $1::text AND a.app_id = $2::text AND a.build_id = $3::text
     ORDER BY a.created_at DESC, a.id DESC LIMIT $4`,
    [target.organizationId, target.appId, buildId, limit],
  );
  return rows.map(toAssessment);
}

/** One Assessment of the transaction's Organization, or null (another Organization's is null as well). */
export async function findAssessment(q: Queryable, id: string): Promise<Assessment | null> {
  const { rows } = await q.query<AssessmentRow>(`${SELECT_ASSESSMENT} WHERE a.id = $1::text`, [id]);
  return rows[0] === undefined ? null : toAssessment(rows[0]);
}

/**
 * One Assessment with its stored calls and their totals (detail only; the list never carries them), or null.
 */
export async function findAssessmentDetail(
  q: Queryable,
  id: string,
): Promise<{ assessment: Assessment; log: StoredCalls | null } | null> {
  const { rows } = await q.query<
    AssessmentRow & { calls: AssessmentCall[] | null; call_totals: AssessmentCallTotals | null }
  >(`${SELECT_ASSESSMENT.replace("a.finished_at,", "a.finished_at, a.calls, a.call_totals,")} WHERE a.id = $1::text`, [
    id,
  ]);
  const row = rows[0];
  if (row === undefined) return null;
  const log = row.calls === null || row.call_totals === null ? null : { calls: row.calls, totals: row.call_totals };
  return { assessment: toAssessment(row), log };
}

/** Identifiers of queued and running Assessments across Organizations, oldest first (the runner, without a tenant). */
export async function assessmentQueue(
  q: Queryable,
  limit: number,
): Promise<{ organizationId: string; assessmentId: string; status: "queued" | "running" }[]> {
  const { rows } = await q.query<{ organization_id: string; assessment_id: string; status: "queued" | "running" }>(
    "SELECT organization_id, assessment_id, status FROM assessment_queue($1::int)",
    [limit],
  );
  return rows.map((row) => ({
    organizationId: row.organization_id,
    assessmentId: row.assessment_id,
    status: row.status,
  }));
}

/** What a claimed run needs: the Assessment's Build and tier, and the artifact it works on. */
export interface ClaimedRun {
  id: string;
  appId: string;
  buildId: string;
  tier: AssessmentTier;
  artifactId: string | null;
  /** When the Assessment was created (queued): the start of SLO-10's clock. */
  createdAt: Date;
}

/**
 * Starts a queued Assessment unless another Assessment of the Organization is running: running, `started_at` set.
 * Null when it is no longer queued or the Organization has a running one.
 */
export async function claimAssessment(q: Queryable, id: string, startedAt: Date): Promise<ClaimedRun | null> {
  const { rows } = await q.query<{
    id: string;
    app_id: string;
    build_id: string;
    tier: AssessmentTier;
    artifact_id: string | null;
    created_at: Date;
  }>(
    `UPDATE assessments SET status = 'running', started_at = GREATEST($2::timestamptz, created_at)
     WHERE id = $1::text AND status = 'queued'
       AND NOT EXISTS (SELECT 1 FROM assessments r WHERE r.organization_id = assessments.organization_id
                       AND r.status = 'running')
     RETURNING id, app_id, build_id, tier, artifact_id, created_at`,
    [id, startedAt.toISOString()],
  );
  const row = rows[0];
  return row === undefined
    ? null
    : {
        id: row.id,
        appId: row.app_id,
        buildId: row.build_id,
        tier: row.tier,
        artifactId: row.artifact_id,
        createdAt: row.created_at,
      };
}

/** The Build's planted Canaries, in Manifest order, with their decoy values: verifier input only. */
export async function buildCanaries(q: Queryable, target: BuildTarget, buildId: string): Promise<Canary[]> {
  const { rows } = await q.query<Canary>(
    `SELECT id, kind, value FROM canaries
     WHERE organization_id = $1::text AND app_id = $2::text AND build_id = $3::text ORDER BY position`,
    [target.organizationId, target.appId, buildId],
  );
  return rows.map((row) => ({ id: row.id, kind: row.kind, value: row.value }) as Canary);
}

/** The referenced calls of a run and the totals of its whole call log (fork 5). */
export interface StoredCalls {
  calls: readonly AssessmentCall[];
  totals: AssessmentCallTotals;
}

export type Finish = (
  | {
      status: "scored";
      results: readonly ObjectiveResult[];
      rrs: number;
      renormalised: boolean;
      scope: ScopeStatement;
    }
  | {
      status: "inconclusive";
      results: readonly ObjectiveResult[];
      reason: string;
      code: InconclusiveCode;
      scope: ScopeStatement;
    }
  | { status: "failed"; results: readonly ObjectiveResult[]; reason: string }
) & { log?: StoredCalls | null };

/**
 * Records how a running Assessment ended and moves its artifact's retention to the finish plus 30 days. False when it
 * was no longer running (interrupted meanwhile): nothing is written.
 */
export async function finishAssessment(q: Queryable, id: string, finish: Finish, finishedAt: Date): Promise<boolean> {
  const scored = finish.status === "scored" ? finish : null;
  const inconclusive = finish.status === "inconclusive" ? finish : null;
  const { rows } = await q.query<{ organization_id: string; artifact_id: string | null; finished_at: Date }>(
    `UPDATE assessments SET status = $2::text, results = $3::jsonb, rrs = $4::int, renormalised = $5::boolean,
       inconclusive_reason = $6::text, inconclusive_code = $7::text, scope = COALESCE($8::jsonb, scope),
       failure_reason = $9::text, finished_at = GREATEST($10::timestamptz, started_at),
       calls = $11::jsonb, call_totals = $12::jsonb
     WHERE id = $1::text AND status = 'running'
     RETURNING organization_id, artifact_id, finished_at`,
    [
      id,
      finish.status,
      JSON.stringify(finish.results),
      scored?.rrs ?? null,
      scored?.renormalised ?? false,
      inconclusive?.reason ?? null,
      inconclusive?.code ?? null,
      finish.status === "failed" ? null : JSON.stringify(finish.scope),
      finish.status === "failed" ? finish.reason : null,
      finishedAt.toISOString(),
      finish.log == null ? null : JSON.stringify(finish.log.calls),
      finish.log == null ? null : JSON.stringify(finish.log.totals),
    ],
  );
  const row = rows[0];
  if (row === undefined) return false;
  if (row.artifact_id !== null) {
    await q.query(
      `UPDATE artifacts SET kept_until = GREATEST(kept_until, $2::timestamptz + interval '30 days')
       WHERE id = $1::text`,
      [row.artifact_id, row.finished_at.toISOString()],
    );
  }
  return true;
}

/** On start: every running Assessment (of any Organization) becomes failed with `reason`. Returns how many. */
export async function interruptRunning(q: Queryable, at: Date, reason: string): Promise<number> {
  const { rows } = await q.query<{ n: number }>("SELECT assessments_interrupt($1::timestamptz, $2::text) AS n", [
    at.toISOString(),
    reason,
  ]);
  return rows[0]?.n ?? 0;
}

/** Deletes every artifact whose retention passed and that no queued or running Assessment uses. Returns how many. */
export async function expireArtifacts(q: Queryable, now: Date): Promise<number> {
  const { rows } = await q.query<{ n: number }>("SELECT assessment_artifacts_expire($1::timestamptz) AS n", [
    now.toISOString(),
  ]);
  return rows[0]?.n ?? 0;
}
