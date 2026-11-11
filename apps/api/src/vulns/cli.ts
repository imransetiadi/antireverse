// `npm run vulns:sync -w @antireverse/api [-- --file <zip> | --fixture <json>]`
// Imports npm advisories into the API's database, then matches every Organization's latest inventories again and
// opens the Incidents of newly opened Critical or High Findings.
//   (no option)       downloads the OSV archive (npm/all.zip) to a temporary file, reads it, deletes it
//   --file <zip>      reads an OSV archive already on disk (no network)
//   --fixture <json>  reads a JSON array of OSV records (a development fixture; no network)
// Environment: AR_DATA_DIR (default apps/api/.data/pg). The data directory has one owner at a time: stop the API
// first. AR_CONSOLE_URL and AR_ALLOW_PRIVATE_ALERT_URLS as for the server (alerts of the re-match).
// Logs counts only: never a package name, a version or an advisory.
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { readConfig } from "../config.ts";
import { openDb } from "../db/db.ts";
import { rematchAll } from "../exposure/match.ts";
import { consoleLogger } from "../log.ts";
import { createNotifier, DEFAULT_CONSOLE_URL } from "../notify/notifier.ts";
import { downloadToFile, OSV_NPM_ARCHIVE_URL } from "./download.ts";
import { fixtureSourceFromFile, osvZipSource, type SourceStats, type VulnerabilitySource } from "./source.ts";
import { syncAdvisories } from "./sync.ts";

const USAGE = "usage: npm run vulns:sync -w @antireverse/api [-- --file <osv npm zip> | --fixture <advisories json>]";

function parseArgs(argv: string[]): { file?: string; fixture?: string } {
  const out: { file?: string; fixture?: string } = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = argv[i];
    const value = argv[i + 1];
    if ((arg === "--file" || arg === "--fixture") && value !== undefined && !value.startsWith("--")) {
      out[arg === "--file" ? "file" : "fixture"] = value;
      i++;
    } else {
      throw new Error(USAGE);
    }
  }
  if (out.file !== undefined && out.fixture !== undefined) throw new Error(USAGE);
  return out;
}

async function main(): Promise<void> {
  const args = parseArgs(process.argv.slice(2));
  // A downloaded archive lives in its own new directory, removed whatever happens.
  const temporary =
    args.file === undefined && args.fixture === undefined ? mkdtempSync(join(tmpdir(), "ar-osv-")) : undefined;
  try {
    await sync(args, temporary);
  } finally {
    if (temporary !== undefined) rmSync(temporary, { recursive: true, force: true });
  }
}

async function sync(args: { file?: string; fixture?: string }, temporary: string | undefined): Promise<void> {
  const log = consoleLogger;
  let source: VulnerabilitySource & { stats: SourceStats };
  if (args.fixture !== undefined) {
    source = fixtureSourceFromFile(args.fixture);
  } else {
    let file = args.file;
    if (file === undefined) {
      if (temporary === undefined) throw new Error(USAGE);
      file = join(temporary, "npm-all.zip");
      log.info("vulns:sync downloading the OSV npm archive");
      const bytes = await downloadToFile(OSV_NPM_ARCHIVE_URL, file);
      log.info(`vulns:sync downloaded bytes=${bytes}`);
    }
    source = osvZipSource(file);
  }

  const config = readConfig(process.env);
  const db = await openDb({ dataDir: config.dataDir });
  const notifier = createNotifier({
    db,
    allowPrivate: process.env.AR_ALLOW_PRIVATE_ALERT_URLS === "1",
    consoleUrl: process.env.AR_CONSOLE_URL || DEFAULT_CONSOLE_URL,
    logger: log,
  });
  try {
    const counts = await syncAdvisories(db, source);
    log.info(
      `vulns:sync advisories received=${counts.received} inserted=${counts.inserted} updated=${counts.updated} unchanged=${counts.unchanged} invalid=${counts.invalid} skipped=${source.stats.skipped}`,
    );
    // Logs its own counts.
    await rematchAll({ db, notifier, logger: log });
  } finally {
    await notifier.drain();
    await db.close();
  }
}

main().catch((error: unknown) => {
  // One line, no stack, no data: the message is ours (usage, limits, the archive's problem), never a record's text.
  const message =
    error instanceof SyntaxError ? "the fixture is not valid JSON" : error instanceof Error ? error.message : "error";
  consoleLogger.warn(`vulns:sync failed: ${message}`);
  process.exit(1);
});
