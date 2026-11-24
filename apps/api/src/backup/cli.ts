// `npm run data:backup -- --to <dir>` and `npm run data:restore -- --from <dir> --data-dir <dir> [--force]` (slice 18h).
// Stop the API first: both refuse while a live process holds the data directory. Output: the directory about to be
// acted on, then names and counts, never the content of a file; refusals, failures and warnings go to the error
// stream. Exit 0 done, 1 refused or failed, 2 usage.
import { realpathSync } from "node:fs";
import { isAbsolute, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { DEFAULT_DATA_DIR } from "../config.ts";
import { backupDataDir, restoreDataDir } from "./backup.ts";

const USAGE = `npm run data:backup -- --to <directory> [--data-dir <directory>]
npm run data:restore -- --from <directory> --data-dir <directory> [--force] [--drop-keys]

Backs up, or restores, the API's data directory together with the key files beside it (the Policy signing key, the
attestation keys, the audit key, the mail hash key and the usage salts). Stop the API first: both commands refuse
while a process holds the data directory.

  --to <directory>        Where the backup is written: a directory that does not exist yet.
  --from <directory>      The backup to restore. It is verified against its manifest before anything is touched.
  --data-dir <directory>  The data directory. backup: default AR_DATA_DIR, else apps/api/.data/pg.
                          restore: required, here or as AR_DATA_DIR; it never falls back to the default directory.
                          A relative AR_DATA_DIR is refused: the API reads it from wherever it was started.
  --force                 restore only: replace an existing data directory and key files with the backup's state.
                          Everything written since the backup is lost. Only a data directory is ever replaced.
  --drop-keys             restore only: also remove key files that exist now and are not in the backup.

A backup holds private keys: keep it where the data directory itself may be kept. Nothing of a key is printed.
Exit: 0 done · 1 refused or failed · 2 usage.`;

export interface CliIo {
  env: Record<string, string | undefined>;
  /** Relative paths typed on the command line are read from here. */
  cwd: string;
  /** The data directory of an API started without AR_DATA_DIR. */
  defaultDataDir: string;
  print(line: string): void;
  /** Refusals, failures, usage errors and warnings. */
  error(line: string): void;
}

const megabytes = (bytes: number): string => `${(bytes / 1_048_576).toFixed(1)} MB`;
const names = (list: readonly string[]): string => (list.length === 0 ? "none" : list.join(", "));

/** Runs one command and returns the exit code. */
export function runBackupCli(argv: readonly string[], io: CliIo): number {
  if (argv.includes("--help") || argv.includes("-h")) {
    io.print(USAGE);
    return 0;
  }
  const [command, ...rest] = argv;
  const values: Record<string, string> = {};
  const flags = new Set<string>();
  const usage = (message: string): number => {
    io.error(`${message}\n\n${USAGE}`);
    return 2;
  };
  if (command !== "backup" && command !== "restore") return usage("Expected the command backup or restore.");
  const place = command === "backup" ? "--to" : "--from";
  for (let i = 0; i < rest.length; i++) {
    const arg = rest[i] as string;
    if ((arg === "--force" || arg === "--drop-keys") && command === "restore") flags.add(arg);
    else if (arg === place || arg === "--data-dir") {
      const value = rest[++i];
      if (value === undefined || value.startsWith("--")) return usage(`${arg} needs a directory.`);
      values[arg] = value;
    } else return usage(`Unknown option ${arg} for ${command}.`);
  }
  const where = values[place];
  if (where === undefined) return usage(`${command} needs ${place} <directory>.`);

  // Which directory: what the operator typed, else what the API is told, else (backup only) the API's default.
  let dataDir: string;
  const typed = values["--data-dir"];
  const fromEnvironment = io.env.AR_DATA_DIR || undefined;
  if (typed !== undefined) dataDir = resolve(io.cwd, typed);
  else if (fromEnvironment !== undefined) {
    if (!isAbsolute(fromEnvironment)) {
      return usage(
        "AR_DATA_DIR is a relative path: the API reads it from the directory it is started in, which this command " +
          "cannot know. Name the directory with --data-dir.",
      );
    }
    dataDir = resolve(fromEnvironment);
  } else if (command === "backup") dataDir = io.defaultDataDir;
  else {
    return usage(
      "restore needs --data-dir <directory> (or AR_DATA_DIR): it never falls back to the default data directory.",
    );
  }
  const target = resolve(io.cwd, where);
  io.print(`Data directory: ${dataDir}`);
  const warn = (pid: number | null): void => {
    if (pid === null) return;
    io.error(
      `Warning: a lock left by process ${pid}, which no longer runs, was found: the API did not stop cleanly. ` +
        (command === "backup"
          ? "The backup is a copy of a directory that was not shut down cleanly; PostgreSQL recovers it when it is next opened."
          : "The lock was replaced."),
    );
  };
  try {
    if (command === "backup") {
      const result = backupDataDir({ dataDir, to: target });
      warn(result.staleLock);
      io.print(`Backed up to ${target}: ${result.files} files, ${megabytes(result.bytes)}.`);
      io.print(`Key files in the backup: ${names(result.keys)}.`);
    } else {
      const result = restoreDataDir({
        from: target,
        dataDir,
        force: flags.has("--force"),
        dropKeys: flags.has("--drop-keys"),
      });
      warn(result.staleLock);
      io.print(
        `Restored ${target}: ${result.files} files, ${megabytes(result.bytes)}` +
          `${result.replaced ? "; what was there was replaced" : ""}.`,
      );
      io.print(`Key files restored: ${names(result.keys)}.`);
      io.print(`Key files removed: ${names(result.removedKeys)}.`);
    }
    return 0;
  } catch (error) {
    io.error(`${command} failed: ${error instanceof Error ? error.message : String(error)}`);
    return 1;
  }
}

/** True when this file is the script being run. Real paths: a checkout reached through a link is still this file. */
function isMain(): boolean {
  try {
    return (
      process.argv[1] !== undefined && realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url))
    );
  } catch {
    return false;
  }
}

if (isMain()) {
  process.exitCode = runBackupCli(process.argv.slice(2), {
    env: process.env,
    // npm runs a script from the package root; INIT_CWD is where the operator typed the command.
    cwd: process.env.INIT_CWD || process.cwd(),
    defaultDataDir: DEFAULT_DATA_DIR,
    print: (line) => process.stdout.write(`${line}\n`),
    error: (line) => process.stderr.write(`${line}\n`),
  });
}
