// Slice 18h: a cold backup of the API's data, and its restore — what "rollback" can mean today (D-121).
//
// The data is the PGlite data directory plus the secret files beside it (key-files.ts): the database is of little use
// without the keys that signed what it holds. Both are plain files, so a backup is a copy — taken while no process has
// the directory open (the pid lock says so, and the tool holds it while it works) — with a manifest of every file's
// size and SHA-256. A restore verifies the whole backup against its manifest before it touches anything, then swaps
// the directory and the key files by renames, and renames them back if a step fails.
//
// What a restore may replace is narrow on purpose (review H1): a data directory (it has a PG_VERSION file), an empty
// directory, or nothing. `force` never widens that. What it moves aside is deleted only once the swap is complete or
// completely undone (H2); leftovers of an earlier run are never deleted (L2).
//
// Nothing here prints or returns the content of a file: only names, counts and sizes.
import { createHash, randomBytes } from "node:crypto";
import {
  chmodSync,
  cpSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  type Stats,
  writeFileSync,
} from "node:fs";
import { basename, dirname, join, resolve, sep } from "node:path";
import { acquireDataDirLock } from "../db/lock.ts";
import { KEY_FILES } from "../key-files.ts";

export const MANIFEST_FILE = "manifest.json";
/** Inside a backup: the data directory, and the key files that lay beside it. */
const DATA = "pg";
const KEYS = "keys";
/** Beside a data directory while a restore works: the copy about to go in, and what it moved aside. */
const STAGED = ".restoring-";
const REPLACED = ".replaced-";

interface ManifestFile {
  /** Relative to the backup, with `/`: `pg/…` or `keys/<name>`. */
  path: string;
  bytes: number;
  sha256: string;
}

interface Manifest {
  format: 1;
  created_at: string;
  files: ManifestFile[];
  /** Every directory under `pg/`, relative to the backup: PostgreSQL needs its empty ones too. */
  directories: string[];
}

export interface BackupResult {
  files: number;
  bytes: number;
  /** The names of the key files in the backup (never their content). */
  keys: string[];
  /**
   * The process id in a lock that was found and whose process no longer runs: the API did not stop cleanly. The work
   * went on (PostgreSQL recovers such a directory when it is next opened); the caller should say so.
   */
  staleLock: number | null;
}

export interface RestoreResult extends BackupResult {
  /** The names of the live key files that the backup does not have and that were removed (`dropKeys`). */
  removedKeys: string[];
  /** True when a data directory or key file was there and was replaced. */
  replaced: boolean;
}

export class BackupError extends Error {}

const digest = (file: string): string => createHash("sha256").update(readFileSync(file)).digest("hex");
const unique = (): string => `${process.pid}-${randomBytes(4).toString("hex")}`;

function stat(path: string): Stats | null {
  try {
    return lstatSync(path);
  } catch {
    return null;
  }
}

/**
 * The path with every symbolic link in it resolved, also when its last parts do not exist yet: two names of one place
 * compare equal (review L3).
 */
function real(path: string): string {
  const absolute = resolve(path);
  const missing: string[] = [];
  let existing = absolute;
  while (stat(existing) === null && dirname(existing) !== existing) {
    missing.unshift(basename(existing));
    existing = dirname(existing);
  }
  return join(realpathSync(existing), ...missing);
}

const inside = (child: string, parent: string): boolean => child === parent || child.startsWith(parent + sep);

/** The regular files and the directories under `dir`, relative to it with `/`. Anything else (a link, a socket) is refused. */
function walk(dir: string, prefix = ""): { files: string[]; directories: string[] } {
  const files: string[] = [];
  const directories: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true }).sort((a, b) => (a.name < b.name ? -1 : 1))) {
    const relative = prefix === "" ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) {
      directories.push(relative);
      const below = walk(join(dir, entry.name), relative);
      files.push(...below.files);
      directories.push(...below.directories);
    } else if (entry.isFile()) files.push(relative);
    else throw new BackupError(`${relative} is neither a file nor a directory; it cannot be part of a backup.`);
  }
  return { files, directories };
}

/** A directory (not a link to one) with a PG_VERSION file in it. */
function isDataDir(dir: string): boolean {
  return stat(dir)?.isDirectory() === true && stat(join(dir, "PG_VERSION"))?.isFile() === true;
}

/** The process id written in the lock of `dataDir`, when there is a lock file. */
function lockHolder(dataDir: string): number | null {
  try {
    const pid = Number.parseInt(readFileSync(`${dataDir}.lock`, "utf8").trim(), 10);
    return Number.isInteger(pid) && pid > 0 ? pid : null;
  } catch {
    return null;
  }
}

/**
 * Takes the lock of each name of the data directory (a live holder of any refuses), and answers how to release them
 * and the holder of a lock that was there but dead.
 */
function lockAll(names: readonly string[]): { release: () => void; stale: number | null } {
  const releases: (() => void)[] = [];
  let stale: number | null = null;
  try {
    for (const name of new Set(names)) {
      const holder = lockHolder(name);
      releases.push(acquireDataDirLock(name));
      stale ??= holder;
    }
  } catch (error) {
    for (const release of releases) release();
    throw error;
  }
  return {
    release: () => {
      for (const release of releases) release();
    },
    stale,
  };
}

/**
 * Copies `dataDir` and the key files beside it to the new directory `to`. Refuses while a live process holds the data
 * directory, when `to` exists or lies inside the data directory, and when `dataDir` is not a data directory. An
 * interrupted backup leaves a `<to>.partial-…` directory, never a `to` that looks complete.
 *
 * `dataDir` may be a symbolic link to the data directory (the API may have been started on either name): its files are
 * copied, not the link, the key files are the ones beside the name given, and both names are locked.
 */
export function backupDataDir(options: { dataDir: string; to: string; now?: () => Date }): BackupResult {
  const named = resolve(options.dataDir);
  if (stat(named) === null) throw new BackupError(`${named} is not a data directory (it does not exist).`);
  const dataDir = realpathSync(named);
  if (!isDataDir(dataDir)) throw new BackupError(`${named} is not a data directory (no PG_VERSION file in it).`);
  const to = real(options.to);
  if (inside(to, dataDir)) throw new BackupError("The backup cannot be written inside the data directory.");
  if (stat(to) !== null) throw new BackupError(`${to} already exists; a backup is written to a new directory.`);
  // The name given with its parents resolved (one lock file, whatever the way to it), and the directory itself.
  const lock = lockAll([join(realpathSync(dirname(named)), basename(named)), dataDir]);
  const partial = `${to}.partial-${unique()}`;
  try {
    mkdirSync(join(partial, KEYS), { recursive: true, mode: 0o700 });
    chmodSync(partial, 0o700);
    chmodSync(join(partial, KEYS), 0o700);
    cpSync(dataDir, join(partial, DATA), { recursive: true });
    const keys: string[] = [];
    for (const name of KEY_FILES) {
      const source = join(dirname(named), name);
      const found = stat(source);
      if (found === null) continue;
      if (!found.isFile()) throw new BackupError(`${source} is not a regular file; it cannot be backed up.`);
      writeFileSync(join(partial, KEYS, name), readFileSync(source), { mode: 0o600 });
      keys.push(name);
    }
    const tree = walk(join(partial, DATA));
    const paths = [...tree.files.map((file) => `${DATA}/${file}`), ...keys.map((name) => `${KEYS}/${name}`)];
    const files = paths.map((path) => {
      const file = join(partial, path);
      return { path, bytes: lstatSync(file).size, sha256: digest(file) };
    });
    const manifest: Manifest = {
      format: 1,
      created_at: (options.now?.() ?? new Date()).toISOString(),
      files,
      directories: tree.directories.map((directory) => `${DATA}/${directory}`),
    };
    writeFileSync(join(partial, MANIFEST_FILE), `${JSON.stringify(manifest, null, 2)}\n`, { mode: 0o600 });
    renameSync(partial, to);
    return {
      files: files.length,
      bytes: files.reduce((sum, file) => sum + file.bytes, 0),
      keys,
      staleLock: lock.stale,
    };
  } catch (error) {
    // Made by this call, under a name no earlier run can have used.
    rmSync(partial, { recursive: true, force: true });
    throw error;
  } finally {
    lock.release();
  }
}

function readManifest(from: string): Manifest {
  let parsed: unknown;
  try {
    if (!lstatSync(join(from, MANIFEST_FILE)).isFile()) throw new Error("not a file");
    parsed = JSON.parse(readFileSync(join(from, MANIFEST_FILE), "utf8"));
  } catch {
    throw new BackupError(`${from} is not a backup: it has no readable ${MANIFEST_FILE}.`);
  }
  const m = parsed as Partial<Manifest>;
  const pathOk = (path: unknown): path is string =>
    typeof path === "string" &&
    !path.split("/").some((part) => part === "" || part === "." || part === "..") &&
    !path.includes("\\") &&
    (path.startsWith(`${DATA}/`) || KEY_FILES.some((name) => path === `${KEYS}/${name}`));
  const ok =
    m.format === 1 &&
    Array.isArray(m.files) &&
    Array.isArray(m.directories) &&
    m.files.every(
      (file) =>
        pathOk(file?.path) &&
        Number.isSafeInteger(file.bytes) &&
        file.bytes >= 0 &&
        typeof file.sha256 === "string" &&
        /^[0-9a-f]{64}$/.test(file.sha256),
    ) &&
    m.directories.every((directory) => pathOk(directory) && directory.startsWith(`${DATA}/`));
  if (!ok) throw new BackupError(`The backup's ${MANIFEST_FILE} is not a manifest this version reads.`);
  return m as Manifest;
}

/**
 * Every problem of a backup against its manifest: a damaged, missing or unlisted file, a missing directory, and
 * anything in it that is not a plain file or directory (review M2: a link in a backup would be copied as a link).
 */
function verifyBackup(from: string, manifest: Manifest): void {
  const problems: string[] = [];
  const parts: string[] = [];
  if (stat(join(from, DATA))?.isDirectory() === true) parts.push(DATA);
  else problems.push(`${DATA} is not a directory of the backup`);
  const keysDirectory = stat(join(from, KEYS));
  if (keysDirectory?.isDirectory() === true) parts.push(KEYS);
  else if (keysDirectory !== null) problems.push(`${KEYS} is not a directory of the backup`);
  for (const file of manifest.files) {
    const found = stat(join(from, file.path));
    if (found === null || !found.isFile()) problems.push(`${file.path} is missing`);
    else if (found.size !== file.bytes || digest(join(from, file.path)) !== file.sha256) {
      problems.push(`${file.path} has changed`);
    }
  }
  for (const directory of manifest.directories) {
    if (stat(join(from, directory))?.isDirectory() !== true) problems.push(`the directory ${directory} is missing`);
  }
  const listed = new Set(manifest.files.map((file) => file.path));
  for (const part of parts) {
    try {
      for (const file of walk(join(from, part)).files) {
        if (!listed.has(`${part}/${file}`)) problems.push(`${part}/${file} is not in the manifest`);
      }
    } catch (error) {
      problems.push(error instanceof Error ? error.message : String(error));
    }
  }
  if (!listed.has(`${DATA}/PG_VERSION`)) problems.push("the manifest lists no data directory");
  if (problems.length > 0) {
    const shown = problems.slice(0, 5).join("; ");
    const more = problems.length > 5 ? `; and ${problems.length - 5} more` : "";
    throw new BackupError(`The backup at ${from} is damaged or incomplete: ${shown}${more}. Nothing was restored.`);
  }
}

/**
 * Puts the backup `from` in place as `dataDir` with its key files beside it. Before anything is touched: the backup is
 * verified; `dataDir` must be absent, an empty directory or a data directory, and never a symbolic link; no leftover
 * of an earlier restore may lie beside it; no live process may hold it.
 *
 * `force`: replace a data directory and key files that are there with the backup's state. `dropKeys`: also remove live
 * key files the backup does not have (without it such a restore is refused, review L1). Neither lets a restore replace
 * anything that is not a data directory.
 */
export function restoreDataDir(options: {
  from: string;
  dataDir: string;
  force?: boolean;
  dropKeys?: boolean;
  /** Tests: in place of `fs.renameSync`, to make the swap fail half-way. */
  rename?: (from: string, to: string) => void;
}): RestoreResult {
  const named = resolve(options.dataDir);
  const rename = options.rename ?? renameSync;
  const target = stat(named);
  if (target?.isSymbolicLink() === true) {
    throw new BackupError(
      `${named} is a symbolic link. A restore would replace the link and leave the directory it points to behind: ` +
        "name the real directory with --data-dir. Nothing was changed.",
    );
  }
  // The parents resolved, so that two names of one place compare equal; the last part is not a link (checked above).
  const dataDir = real(named);
  const beside = dirname(dataDir);
  const empty = target?.isDirectory() === true && readdirSync(dataDir).length === 0;
  if (target !== null && !empty && !isDataDir(dataDir)) {
    throw new BackupError(
      `${dataDir} exists and is not a data directory (it has no PG_VERSION file). A restore only ever replaces a data ` +
        "directory; --force does not change that. Nothing was changed.",
    );
  }
  const from = real(options.from);
  if (inside(from, dataDir)) throw new BackupError("A backup inside the data directory cannot be restored over it.");
  if (inside(dataDir, from)) throw new BackupError("The data directory cannot lie inside the backup.");
  const manifest = readManifest(from);
  verifyBackup(from, manifest);

  const leftovers = (stat(beside)?.isDirectory() === true ? readdirSync(beside) : []).filter(
    (name) => name.startsWith(basename(dataDir) + STAGED) || name.startsWith(basename(dataDir) + REPLACED),
  );
  if (leftovers.length > 0) {
    throw new BackupError(
      `Leftovers of an earlier restore lie beside the data directory: ${leftovers.map((name) => join(beside, name)).join(", ")}. ` +
        `A directory named …${REPLACED}… may hold the only copy of the data and key files from before that restore. ` +
        "Look at them, move or remove them, then run the restore again. Nothing was changed.",
    );
  }
  const keys = KEY_FILES.filter((name) => manifest.files.some((file) => file.path === `${KEYS}/${name}`));
  const liveKeys = KEY_FILES.filter((name) => stat(join(beside, name)) !== null);
  const present = (target !== null && !empty) || liveKeys.length > 0;
  if (present && options.force !== true) {
    throw new BackupError(
      `${dataDir} or a key file beside it exists. Restoring replaces them with the backup's state: ` +
        "pass --force to do that. Nothing was changed.",
    );
  }
  const removedKeys = liveKeys.filter((name) => !keys.includes(name));
  if (removedKeys.length > 0 && options.dropKeys !== true) {
    throw new BackupError(
      `The backup has no ${removedKeys.join(", ")}, and ${removedKeys.length === 1 ? "that file exists" : "those files exist"} beside ${dataDir}. ` +
        "Restoring the backup's state would remove them: pass --drop-keys to do that. Nothing was changed.",
    );
  }

  const lock = lockAll([dataDir]);
  const id = unique();
  const staged = `${dataDir}${STAGED}${id}`;
  const replaced = `${dataDir}${REPLACED}${id}`;
  // What was moved aside is deleted only when nothing of the old state is in it any more, or it is no longer needed.
  let keepReplaced = false;
  try {
    mkdirSync(join(staged, KEYS), { recursive: true, mode: 0o700 });
    mkdirSync(join(replaced, KEYS), { recursive: true, mode: 0o700 });
    cpSync(join(from, DATA), join(staged, DATA), { recursive: true });
    for (const name of keys) {
      writeFileSync(join(staged, KEYS, name), readFileSync(join(from, KEYS, name)), { mode: 0o600 });
    }
    // The swap: renames on one file system, each undone in reverse order if a later one fails.
    const moves: [string, string][] = [];
    if (target !== null) moves.push([dataDir, join(replaced, DATA)]);
    moves.push([join(staged, DATA), dataDir]);
    for (const name of KEY_FILES) {
      const live = join(beside, name);
      if (liveKeys.includes(name)) moves.push([live, join(replaced, KEYS, name)]);
      if (keys.includes(name)) moves.push([join(staged, KEYS, name), live]);
    }
    const done: [string, string][] = [];
    try {
      for (const move of moves) {
        rename(move[0], move[1]);
        done.push(move);
      }
    } catch (error) {
      const failure = error instanceof Error ? error.message : String(error);
      try {
        for (const [source, moved] of [...done].reverse()) renameSync(moved, source);
      } catch (undoError) {
        keepReplaced = true;
        const undo = undoError instanceof Error ? undoError.message : String(undoError);
        throw new BackupError(
          `The restore failed (${failure}) and could not be undone (${undo}). The data directory and key files from ` +
            `before the restore are kept in ${replaced} (the directory as ${DATA}, the key files under ${KEYS}): ` +
            `nothing in it was deleted. Put them back by hand — ${join(replaced, DATA)} to ${dataDir}, each file of ` +
            `${join(replaced, KEYS)} to ${beside} — then move ${replaced} away before the next restore.`,
        );
      }
      throw error;
    }
    return {
      files: manifest.files.length,
      bytes: manifest.files.reduce((sum, file) => sum + file.bytes, 0),
      keys,
      removedKeys,
      replaced: present,
      staleLock: lock.stale,
    };
  } finally {
    // The staged copy is a copy of the backup. Both names were made by this call and no earlier run can have used them.
    rmSync(staged, { recursive: true, force: true });
    if (!keepReplaced) rmSync(replaced, { recursive: true, force: true });
    lock.release();
  }
}
