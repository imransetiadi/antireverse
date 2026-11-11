import { readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { type Advisory, AdvisorySchema } from "@antireverse/protocol";
import { readZip, ZIP_LIMITS, ZipError, type ZipLimits } from "./zip.ts";

/**
 * Where advisories come from (SDD §12A). Replaceable: the OSV archive in production, a fixture in tests. A
 * source only ever receives nothing and yields public advisories: no customer data goes to it.
 */
export interface VulnerabilitySource {
  advisories(): AsyncIterable<Advisory>;
}

/** What a source saw: entries read, advisories valid, entries refused by the schema or JSON, entries skipped. */
export interface SourceStats {
  entries: number;
  valid: number;
  invalid: number;
  skipped: number;
}

/** The synthetic advisories the API's tests use. */
export const FIXTURE_ADVISORIES_FILE = fileURLToPath(new URL("../../test/fixtures/advisories.json", import.meta.url));

/** A source over a list of OSV records (already parsed): each is validated, the invalid ones counted and skipped. */
export function fixtureSource(records: readonly unknown[]): VulnerabilitySource & { stats: SourceStats } {
  const stats: SourceStats = { entries: 0, valid: 0, invalid: 0, skipped: 0 };
  return {
    stats,
    async *advisories() {
      for (const record of records) {
        stats.entries++;
        const parsed = AdvisorySchema.safeParse(record);
        if (!parsed.success) {
          stats.invalid++;
          continue;
        }
        stats.valid++;
        yield parsed.data;
      }
    },
  };
}

/** A fixture source over a JSON file holding an array of OSV records (a development fixture, or the tests'). */
export function fixtureSourceFromFile(path: string): VulnerabilitySource & { stats: SourceStats } {
  const records: unknown = JSON.parse(readFileSync(path, "utf8"));
  if (!Array.isArray(records)) throw new TypeError("The fixture file must hold a JSON array of advisories.");
  return fixtureSource(records);
}

/**
 * The OSV ecosystem archive (`npm/all.zip`) at a local path: one OSV record per `*.json` entry. The file is
 * bounded before it is read; the archive is read by the in-house reader (`readZip`), which refuses a malicious
 * archive as a whole. An entry that is not JSON, or not an advisory, is counted and skipped.
 */
export function osvZipSource(
  path: string,
  limits: Partial<ZipLimits> = {},
): VulnerabilitySource & { stats: SourceStats } {
  const stats: SourceStats = { entries: 0, valid: 0, invalid: 0, skipped: 0 };
  const archiveBytesMax = limits.archiveBytesMax ?? ZIP_LIMITS.archiveBytesMax;
  return {
    stats,
    async *advisories() {
      if (statSync(path).size > archiveBytesMax) throw new ZipError("The archive is larger than the limit.");
      for (const entry of readZip(readFileSync(path), limits)) {
        stats.entries++;
        if (!entry.name.endsWith(".json")) {
          stats.skipped++;
          continue;
        }
        let record: unknown;
        try {
          record = JSON.parse(entry.data.toString("utf8"));
        } catch {
          stats.invalid++;
          continue;
        }
        const parsed = AdvisorySchema.safeParse(record);
        if (!parsed.success) {
          stats.invalid++;
          continue;
        }
        stats.valid++;
        yield parsed.data;
      }
    },
  };
}
