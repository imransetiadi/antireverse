import type { Advisory, FindingSeverity } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

interface AdvisoryRow {
  id: string;
  aliases: string[];
  summary: string;
  severity: FindingSeverity;
  ghsa_severity: "LOW" | "MODERATE" | "HIGH" | "CRITICAL" | null;
  cvss: Advisory["severity"];
  affected: Advisory["affected"];
  published: Date;
  modified: Date;
  withdrawn: Date | null;
}

/** An advisory as stored, with the severity computed when it was synced. */
export interface StoredAdvisory {
  advisory: Advisory;
  severity: FindingSeverity;
}

const ADVISORY_COLUMNS =
  "a.id, a.aliases, a.summary, a.severity, a.ghsa_severity, a.cvss, a.affected, a.published, a.modified, a.withdrawn";

function toAdvisory(row: AdvisoryRow): StoredAdvisory {
  const advisory: Advisory = {
    id: row.id,
    aliases: row.aliases,
    summary: row.summary,
    severity: row.cvss,
    ...(row.ghsa_severity === null ? {} : { database_specific: { severity: row.ghsa_severity } }),
    affected: row.affected,
    published: row.published.toISOString(),
    modified: row.modified.toISOString(),
    ...(row.withdrawn === null ? {} : { withdrawn: row.withdrawn.toISOString() }),
  };
  return { advisory, severity: row.severity };
}

/** The advisories that name any of the npm package `names` and are not withdrawn, by id. */
export async function advisoriesForPackages(q: Queryable, names: readonly string[]): Promise<StoredAdvisory[]> {
  if (names.length === 0) return [];
  const { rows } = await q.query<AdvisoryRow>(
    `SELECT ${ADVISORY_COLUMNS} FROM advisories a
     WHERE a.withdrawn IS NULL
       AND a.id IN (SELECT p.advisory_id FROM advisory_packages p WHERE p.package = ANY($1::text[]))
     ORDER BY a.id`,
    [names],
  );
  return rows.map(toAdvisory);
}

/** One advisory, or null. */
export async function findAdvisory(q: Queryable, id: string): Promise<StoredAdvisory | null> {
  const { rows } = await q.query<AdvisoryRow>(`SELECT ${ADVISORY_COLUMNS} FROM advisories a WHERE a.id = $1`, [id]);
  return rows[0] === undefined ? null : toAdvisory(rows[0]);
}
