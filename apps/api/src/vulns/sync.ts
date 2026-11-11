import { type Advisory, severityOf } from "@antireverse/protocol";
import type { OwnedDb } from "../db/db.ts";
import type { SourceStats, VulnerabilitySource } from "./source.ts";

export interface SyncCounts {
  /** Advisories the source yielded (valid ones). */
  received: number;
  inserted: number;
  updated: number;
  unchanged: number;
  /** Entries the source refused (not JSON, or not an advisory); 0 when the source does not count. */
  invalid: number;
}

/** The npm package names an advisory names, each once. Other ecosystems' entries are kept but never indexed. */
function npmPackages(advisory: Advisory): string[] {
  return [...new Set(advisory.affected.filter((a) => a.package.ecosystem === "npm").map((a) => a.package.name))];
}

/**
 * Stores every advisory of `source` in the global advisories table, through the definer function
 * `advisory_upsert` (the request role cannot write the table itself). All or nothing (plan A7, M3): the whole
 * source is read and validated first — an archive the zip reader refuses stores nothing — then every advisory is
 * stored in one transaction. An advisory whose `modified` and `withdrawn` are unchanged is left as it is. Returns
 * counts only.
 */
export async function syncAdvisories(
  db: OwnedDb,
  source: VulnerabilitySource & { stats?: SourceStats },
): Promise<SyncCounts> {
  const counts: SyncCounts = { received: 0, inserted: 0, updated: 0, unchanged: 0, invalid: 0 };
  const all: Advisory[] = [];
  for await (const advisory of source.advisories()) all.push(advisory);
  counts.received = all.length;
  counts.invalid = source.stats?.invalid ?? 0;
  if (all.length === 0) return counts;
  // As the owner: the request role may not execute `advisory_upsert`.
  await db.owner(async (q) => {
    for (const advisory of all) {
      const { rows } = await q.query<{ outcome: "inserted" | "updated" | "unchanged" }>(
        `SELECT advisory_upsert($1::text, $2::text[], $3::text, $4::text, $5::text, $6::jsonb, $7::jsonb,
           $8::timestamptz, $9::timestamptz, $10::timestamptz, $11::text[]) AS outcome`,
        [
          advisory.id,
          advisory.aliases,
          advisory.summary,
          severityOf(advisory),
          advisory.database_specific?.severity ?? null,
          JSON.stringify(advisory.severity),
          JSON.stringify(advisory.affected),
          advisory.published,
          advisory.modified,
          advisory.withdrawn ?? null,
          npmPackages(advisory),
        ],
      );
      const outcome = rows[0]?.outcome;
      if (outcome === undefined) throw new Error("The advisory was not stored.");
      counts[outcome]++;
    }
  });
  return counts;
}
