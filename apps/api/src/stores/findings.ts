import {
  type Environment,
  EXPOSURE_LIMITS,
  FINDING_SEVERITIES,
  type Finding,
  type FindingSeverity,
  type FindingSource,
  type FindingStatus,
  type FindingsSummary,
} from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

interface FindingRow {
  id: string;
  app_id: string;
  environment: Environment;
  source: FindingSource;
  build_id: string | null;
  package: string;
  version: string;
  dev: boolean;
  advisory_id: string;
  aliases: string[];
  summary: string;
  severity: FindingSeverity;
  fixed_versions: string[];
  status: FindingStatus;
  ignore_reason: string | null;
  ignore_until: Date | null;
  ignore_by: string | null;
  first_seen: Date;
  last_seen: Date;
}

// Aliases and summary are the advisory's, as last synced; everything else is the Finding's own.
const FINDING_SELECT = `SELECT f.id, f.app_id, f.environment, f.source, f.build_id, f.package, f.version, f.dev,
    f.advisory_id, a.aliases, a.summary, f.severity, f.fixed_versions, f.status, f.ignore_reason, f.ignore_until,
    f.ignore_by, f.first_seen, f.last_seen
  FROM findings f JOIN advisories a ON a.id = f.advisory_id`;

function toFinding(row: FindingRow): Finding {
  return {
    id: row.id,
    app_id: row.app_id,
    environment: row.environment,
    source: row.source,
    build_id: row.build_id,
    package: row.package,
    version: row.version,
    dev: row.dev,
    advisory_id: row.advisory_id,
    aliases: row.aliases,
    summary: row.summary,
    severity: row.severity,
    fixed_versions: row.fixed_versions,
    status: row.status,
    ignore:
      row.status === "ignored" && row.ignore_reason !== null && row.ignore_until !== null && row.ignore_by !== null
        ? { reason: row.ignore_reason, until: row.ignore_until.toISOString(), by: row.ignore_by }
        : null,
    first_seen: row.first_seen.toISOString(),
    last_seen: row.last_seen.toISOString(),
  };
}

/** Ignored Findings whose expiry has passed are open again. Run before every read of the transaction's Findings. */
export async function reviveExpired(q: Queryable, at: Date): Promise<void> {
  await q.query(
    `UPDATE findings SET status = 'open', ignore_reason = NULL, ignore_until = NULL, ignore_by = NULL,
       updated_at = $1::timestamptz
     WHERE status = 'ignored' AND ignore_until <= $1::timestamptz`,
    [at.toISOString()],
  );
}

export interface FindingFilter {
  appId?: string | undefined;
  environment?: Environment | undefined;
  status?: FindingStatus | undefined;
  severity?: FindingSeverity | undefined;
  source?: FindingSource | undefined;
  /** Build Findings of this Build only. */
  buildId?: string | undefined;
  /** The advisory's id or any of its aliases, exactly. */
  advisoryId?: string | undefined;
  limit: number;
}

/** The Findings of the transaction's Organization, newest first (by `last_seen`, then id), optionally filtered. */
export async function listFindings(q: Queryable, filter: FindingFilter): Promise<Finding[]> {
  const { rows } = await q.query<FindingRow>(
    `${FINDING_SELECT}
     WHERE ($1::text IS NULL OR f.app_id = $1::text) AND ($2::text IS NULL OR f.environment = $2::text)
       AND ($3::text IS NULL OR f.status = $3::text) AND ($4::text IS NULL OR f.severity = $4::text)
       AND ($5::text IS NULL OR f.source = $5::text)
       AND ($6::text IS NULL OR (f.source = 'build' AND f.build_id = $6::text))
       AND ($8::text IS NULL OR f.advisory_id = $8::text OR $8::text = ANY(a.aliases))
     ORDER BY f.last_seen DESC, f.id DESC
     LIMIT $7`,
    [
      filter.appId ?? null,
      filter.environment ?? null,
      filter.status ?? null,
      filter.severity ?? null,
      filter.source ?? null,
      filter.buildId ?? null,
      filter.limit,
      filter.advisoryId ?? null,
    ],
  );
  return rows.map(toFinding);
}

/** One Finding of the transaction's Organization, or null. With `lock`, the row stays locked until commit. */
export async function findFinding(q: Queryable, id: string, lock = false): Promise<Finding | null> {
  const { rows } = await q.query<FindingRow>(`${FINDING_SELECT} WHERE f.id = $1${lock ? " FOR UPDATE OF f" : ""}`, [
    id,
  ]);
  return rows[0] === undefined ? null : toFinding(rows[0]);
}

/** Sets a Finding ignored with its reason, expiry and admin key. The caller checked the transition. */
export async function ignoreFinding(
  q: Queryable,
  id: string,
  ignore: { reason: string; until: Date; by: string },
  at: Date,
): Promise<void> {
  await q.query(
    `UPDATE findings SET status = 'ignored', ignore_reason = $2, ignore_until = $3::timestamptz, ignore_by = $4,
       updated_at = $5::timestamptz
     WHERE id = $1`,
    [id, ignore.reason, ignore.until.toISOString(), ignore.by, at.toISOString()],
  );
}

/** Sets an ignored Finding open again. The caller checked the transition. */
export async function reopenFinding(q: Queryable, id: string, at: Date): Promise<void> {
  await q.query(
    `UPDATE findings SET status = 'open', ignore_reason = NULL, ignore_until = NULL, ignore_by = NULL,
       updated_at = $2::timestamptz
     WHERE id = $1`,
    [id, at.toISOString()],
  );
}

const RANK = Object.fromEntries(FINDING_SEVERITIES.map((severity, index) => [severity, index])) as Record<
  FindingSeverity,
  number
>;

/**
 * The open build Findings of one Build, as the registration's summary: counts per severity and at most
 * `EXPOSURE_LIMITS.summaryItemsMax` items, most severe first, then by advisory, package and version.
 */
export async function buildFindingsSummary(q: Queryable, appId: string, buildId: string): Promise<FindingsSummary> {
  const { rows } = await q.query<{
    advisory_id: string;
    package: string;
    version: string;
    severity: FindingSeverity;
    fixed_versions: string[];
  }>(
    `SELECT advisory_id, package, version, severity, fixed_versions FROM findings
     WHERE app_id = $1 AND source = 'build' AND build_id = $2 AND status = 'open'`,
    [appId, buildId],
  );
  const open = { critical: 0, high: 0, medium: 0, low: 0, unknown: 0 };
  for (const row of rows) open[row.severity]++;
  const byText = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
  const items = rows
    .sort(
      (a, b) =>
        RANK[a.severity] - RANK[b.severity] ||
        byText(a.advisory_id, b.advisory_id) ||
        byText(a.package, b.package) ||
        byText(a.version, b.version),
    )
    .slice(0, EXPOSURE_LIMITS.summaryItemsMax)
    .map((row) => ({
      advisory: row.advisory_id,
      package: row.package,
      version: row.version,
      severity: row.severity,
      fixed: row.fixed_versions,
    }));
  return { open, items };
}
