import type { Intensity, RulesOfEngagementContent, RulesOfEngagementVersion, Weekday } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

// Signed Rules of Engagement versions of the transaction's Organization (slice 14). Immutable: the request role can
// insert and read only. The highest version number is current.

interface VersionRow {
  id: string;
  scope: string[];
  exclusions: string[];
  intensity: Intensity;
  window_days: Weekday[];
  window_from: string;
  window_to: string;
  contacts: string[];
  signed_by: string;
  signed_at: Date;
  content_sha256: string;
}

const COLUMNS =
  "id, scope, exclusions, intensity, window_days, window_from, window_to, contacts, signed_by, signed_at, content_sha256";

function toVersion(row: VersionRow): RulesOfEngagementVersion {
  return {
    id: row.id,
    scope: row.scope,
    exclusions: row.exclusions,
    intensity: row.intensity,
    window: { days: row.window_days, from: row.window_from, to: row.window_to },
    contacts: row.contacts,
    signed_by: row.signed_by,
    signed_at: row.signed_at.toISOString(),
    content_sha256: row.content_sha256,
  };
}

/** Every version, newest first. */
export async function listVersions(q: Queryable): Promise<RulesOfEngagementVersion[]> {
  const { rows } = await q.query<VersionRow>(`SELECT ${COLUMNS} FROM rules_of_engagement ORDER BY version DESC`);
  return rows.map(toVersion);
}

/** The newest version, or null before the first is signed. */
export async function currentVersion(q: Queryable): Promise<RulesOfEngagementVersion | null> {
  const { rows } = await q.query<VersionRow>(
    `SELECT ${COLUMNS} FROM rules_of_engagement ORDER BY version DESC LIMIT 1`,
  );
  return rows[0] === undefined ? null : toVersion(rows[0]);
}

/**
 * Stores a signed version as the Organization's next version number. The caller holds the Organization lock, so
 * numbers never collide; a collision still raises a unique violation rather than replacing anything.
 */
export async function insertVersion(
  q: Queryable,
  input: {
    organizationId: string;
    id: string;
    content: RulesOfEngagementContent;
    signedBy: string;
    signedAt: Date;
    contentSha256: string;
  },
): Promise<RulesOfEngagementVersion> {
  const { content } = input;
  const { rows } = await q.query<VersionRow>(
    `INSERT INTO rules_of_engagement (organization_id, id, version, scope, exclusions, intensity, window_days,
       window_from, window_to, contacts, signed_by, signed_at, content_sha256)
     SELECT $1, $2, COALESCE(MAX(version), 0) + 1, $3, $4, $5, $6, $7, $8, $9, $10, $11::timestamptz, $12
     FROM rules_of_engagement
     RETURNING ${COLUMNS}`,
    [
      input.organizationId,
      input.id,
      content.scope,
      content.exclusions,
      content.intensity,
      content.window.days,
      content.window.from,
      content.window.to,
      content.contacts,
      input.signedBy,
      input.signedAt.toISOString(),
      input.contentSha256,
    ],
  );
  const row = rows[0];
  if (row === undefined) throw new Error("The Rules of Engagement version was not stored.");
  return toVersion(row);
}
