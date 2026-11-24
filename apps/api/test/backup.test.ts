import { spawnSync } from "node:child_process";
import {
  existsSync,
  lstatSync,
  mkdirSync,
  mkdtempSync,
  readdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  statSync,
  symlinkSync,
  writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { backupDataDir, MANIFEST_FILE, restoreDataDir } from "../src/backup/backup.ts";
import { runBackupCli } from "../src/backup/cli.ts";
import { KEY_FILES } from "../src/key-files.ts";

// Slice 18h: the cold backup and restore of the data directory and the key files beside it. These tests use a
// stand-in directory (a PG_VERSION file and a few others); the rollback rehearsal runs the same code on a real one.

const SECRET = "c2VjcmV0LWtleS1tYXRlcmlhbC1uZXZlci1wcmludGVk";

let root: string;
let dataDir: string;
let to: string;

function tree(dir: string, base = dir): Record<string, string> {
  const out: Record<string, string> = {};
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) Object.assign(out, tree(path, base));
    else out[path.slice(base.length + 1)] = readFileSync(path, "hex");
  }
  return out;
}

/** The data directory and what lies beside it that belongs to it. */
function installation(): { pg: Record<string, string>; keys: Record<string, string | null> } {
  return {
    pg: tree(dataDir),
    keys: Object.fromEntries(
      KEY_FILES.map((name) => [name, existsSync(join(root, name)) ? readFileSync(join(root, name), "utf8") : null]),
    ),
  };
}

beforeEach(() => {
  // The real path: the tool reports real paths, and the temporary directory may itself be reached through a link.
  root = realpathSync(mkdtempSync(join(tmpdir(), "ar-api-backup-")));
  dataDir = join(root, "pg");
  to = join(root, "backups", "first");
  mkdirSync(join(dataDir, "base", "1"), { recursive: true });
  writeFileSync(join(dataDir, "PG_VERSION"), "17\n");
  writeFileSync(join(dataDir, "base", "1", "1234"), Buffer.from([0, 1, 2, 3, 255]));
  writeFileSync(join(dataDir, "postmaster.opts"), "");
  for (const name of KEY_FILES.slice(0, 3)) {
    writeFileSync(join(root, name), JSON.stringify({ name, private_key: SECRET }), { mode: 0o600 });
  }
});

afterEach(() => {
  rmSync(root, { recursive: true, force: true });
});

describe("backupDataDir", () => {
  it("copies the data directory and the key files beside it, with a manifest of sizes and digests", () => {
    const result = backupDataDir({ dataDir, to });
    expect(result).toEqual({ files: 6, bytes: expect.any(Number), keys: KEY_FILES.slice(0, 3), staleLock: null });
    expect(tree(join(to, "pg"))).toEqual(tree(dataDir));
    for (const name of KEY_FILES.slice(0, 3)) {
      expect(readFileSync(join(to, "keys", name), "utf8")).toBe(readFileSync(join(root, name), "utf8"));
      expect(statSync(join(to, "keys", name)).mode & 0o777).toBe(0o600);
    }
    expect(statSync(to).mode & 0o777).toBe(0o700);
    const manifest = JSON.parse(readFileSync(join(to, MANIFEST_FILE), "utf8"));
    expect(manifest.format).toBe(1);
    expect(manifest.files.map((f: { path: string }) => f.path).sort()).toEqual(
      [
        "pg/PG_VERSION",
        "pg/base/1/1234",
        "pg/postmaster.opts",
        ...KEY_FILES.slice(0, 3).map((name) => `keys/${name}`),
      ].sort(),
    );
    expect(readFileSync(join(to, MANIFEST_FILE), "utf8")).not.toContain(SECRET);
    // The lock it held while copying is released, and is not part of the backup.
    expect(existsSync(`${dataDir}.lock`)).toBe(false);
  });

  it("refuses while a live process holds the data directory, and writes nothing", () => {
    writeFileSync(`${dataDir}.lock`, `${process.pid}\n`);
    expect(() => backupDataDir({ dataDir, to })).toThrow(/in use by process/);
    expect(existsSync(to)).toBe(false);
  });

  it("refuses a destination that exists, and a directory that is not a data directory", () => {
    mkdirSync(to, { recursive: true });
    writeFileSync(join(to, "note.txt"), "mine");
    expect(() => backupDataDir({ dataDir, to })).toThrow(/already exists/);
    expect(readdirSync(to)).toEqual(["note.txt"]);
    expect(() => backupDataDir({ dataDir: join(root, "backups"), to: join(root, "other") })).toThrow(
      /not a data directory/,
    );
    expect(() => backupDataDir({ dataDir: join(root, "missing"), to: join(root, "other") })).toThrow(
      /not a data directory/,
    );
    expect(existsSync(join(root, "other"))).toBe(false);
  });

  it("refuses a destination inside the data directory", () => {
    expect(() => backupDataDir({ dataDir, to: join(dataDir, "backup") })).toThrow(/inside the data directory/);
  });

  // Review L3: the same place under another name is the same place.
  it("refuses a destination that reaches into the data directory through a symbolic link", () => {
    symlinkSync(dataDir, join(root, "shortcut"), "dir");
    expect(() => backupDataDir({ dataDir, to: join(root, "shortcut", "backup") })).toThrow(/inside the data directory/);
    expect(readdirSync(dataDir).sort()).toEqual(["PG_VERSION", "base", "postmaster.opts"]);
  });

  it("backs up a data directory named through a symbolic link: its files, not the link, under both locks", () => {
    const link = join(root, "linked", "pg");
    mkdirSync(join(root, "linked"));
    symlinkSync(dataDir, link, "dir");
    writeFileSync(join(root, "linked", KEY_FILES[0] as string), "{}", { mode: 0o600 });
    // An API started on the real name holds the real name's lock.
    writeFileSync(`${dataDir}.lock`, `${process.pid}\n`);
    expect(() => backupDataDir({ dataDir: link, to })).toThrow(/in use by process/);
    rmSync(`${dataDir}.lock`);
    expect(backupDataDir({ dataDir: link, to }).keys).toEqual([KEY_FILES[0]]);
    expect(lstatSync(join(to, "pg")).isDirectory()).toBe(true);
    expect(tree(join(to, "pg"))).toEqual(tree(dataDir));
    expect(existsSync(`${link}.lock`) || existsSync(`${dataDir}.lock`)).toBe(false);
  });

  // Review L7: a lock whose process is gone means the API did not stop cleanly. The backup goes on, and says so.
  it("reports a lock left by a process that no longer runs", () => {
    const dead = spawnSync(process.execPath, ["-e", ""]).pid as number;
    writeFileSync(`${dataDir}.lock`, `${dead}\n`);
    expect(backupDataDir({ dataDir, to }).staleLock).toBe(dead);
  });

  // Review L2: what an earlier, killed backup left is never deleted, whatever its name.
  it("leaves the partial directory of an earlier run alone", () => {
    const earlier = `${to}.partial-${process.pid}`;
    mkdirSync(earlier, { recursive: true });
    writeFileSync(join(earlier, "note"), "kept");
    backupDataDir({ dataDir, to });
    expect(readFileSync(join(earlier, "note"), "utf8")).toBe("kept");
  });
});

describe("restoreDataDir", () => {
  it("restores into an empty place exactly what was backed up", () => {
    const before = installation();
    backupDataDir({ dataDir, to });
    const elsewhere = join(root, "elsewhere", "pg");
    const result = restoreDataDir({ from: to, dataDir: elsewhere });
    expect(result).toEqual({
      files: 6,
      bytes: expect.any(Number),
      keys: KEY_FILES.slice(0, 3),
      removedKeys: [],
      replaced: false,
      staleLock: null,
    });
    expect(tree(elsewhere)).toEqual(before.pg);
    for (const name of KEY_FILES.slice(0, 3)) {
      expect(readFileSync(join(root, "elsewhere", name), "utf8")).toBe(before.keys[name]);
      expect(statSync(join(root, "elsewhere", name)).mode & 0o777).toBe(0o600);
    }
    expect(existsSync(`${elsewhere}.lock`)).toBe(false);
  });

  it("refuses to overwrite a data directory or a key file without force, and changes nothing", () => {
    backupDataDir({ dataDir, to });
    writeFileSync(join(dataDir, "base", "1", "1234"), "newer");
    const live = installation();
    expect(() => restoreDataDir({ from: to, dataDir })).toThrow(/--force/);
    expect(installation()).toEqual(live);
    // A key file alone is enough to refuse: restoring would replace the key.
    rmSync(dataDir, { recursive: true });
    expect(() => restoreDataDir({ from: to, dataDir })).toThrow(/--force/);
    expect(existsSync(dataDir)).toBe(false);
  });

  it("with force, puts back the backed-up state: later files and later keys are gone", () => {
    const before = installation();
    backupDataDir({ dataDir, to });
    writeFileSync(join(dataDir, "base", "1", "1234"), "newer");
    writeFileSync(join(dataDir, "base", "1", "9999"), "written after the backup");
    writeFileSync(join(root, KEY_FILES[0] as string), JSON.stringify({ private_key: "another key" }));
    writeFileSync(join(root, KEY_FILES[4] as string), JSON.stringify({ salts: "made after the backup" }));
    const live = installation();
    // Review L1: a live key file the backup does not have is not removed by --force alone.
    expect(() => restoreDataDir({ from: to, dataDir, force: true })).toThrow(/--drop-keys/);
    expect(() => restoreDataDir({ from: to, dataDir, force: true })).toThrow(KEY_FILES[4] as string);
    expect(installation()).toEqual(live);
    const result = restoreDataDir({ from: to, dataDir, force: true, dropKeys: true });
    expect(result.replaced).toBe(true);
    expect(result.keys).toEqual(KEY_FILES.slice(0, 3));
    expect(result.removedKeys).toEqual([KEY_FILES[4]]);
    expect(installation()).toEqual(before);
    // Nothing of the swap is left beside the data directory.
    expect(readdirSync(root).sort()).toEqual(["backups", "pg", ...KEY_FILES.slice(0, 3)].sort());
  });

  it.each([
    ["a changed file", () => writeFileSync(join(to, "pg", "base", "1", "1234"), Buffer.from([0, 1, 2, 3, 254]))],
    ["a missing file", () => rmSync(join(to, "pg", "PG_VERSION"))],
    ["a changed key file", () => writeFileSync(join(to, "keys", KEY_FILES[0] as string), "{}")],
    ["a file the manifest does not list", () => writeFileSync(join(to, "pg", "base", "1", "extra"), "x")],
    ["no manifest", () => rmSync(join(to, MANIFEST_FILE))],
    ["a manifest that is not one", () => writeFileSync(join(to, MANIFEST_FILE), '{"format":2}')],
    [
      "a manifest that points outside the backup",
      () => {
        const file = join(to, MANIFEST_FILE);
        const manifest = JSON.parse(readFileSync(file, "utf8"));
        manifest.files[0].path = "../../outside";
        writeFileSync(file, JSON.stringify(manifest));
      },
    ],
  ])("refuses a damaged backup (%s) before it touches anything, even with force", (_name, damage) => {
    backupDataDir({ dataDir, to });
    damage();
    const live = installation();
    expect(() => restoreDataDir({ from: to, dataDir, force: true })).toThrow(/backup/i);
    expect(installation()).toEqual(live);
    expect(readdirSync(root).sort()).toEqual(["backups", "pg", ...KEY_FILES.slice(0, 3)].sort());
  });

  it("refuses while a live process holds the data directory", () => {
    backupDataDir({ dataDir, to });
    writeFileSync(`${dataDir}.lock`, `${process.pid}\n`);
    const live = installation();
    expect(() => restoreDataDir({ from: to, dataDir, force: true })).toThrow(/in use by process/);
    expect(installation()).toEqual(live);
  });

  it("puts the old state back when the swap fails half-way", () => {
    backupDataDir({ dataDir, to });
    writeFileSync(join(dataDir, "base", "1", "1234"), "newer");
    writeFileSync(join(root, KEY_FILES[0] as string), JSON.stringify({ private_key: "another key" }));
    const live = installation();
    for (const failAt of [1, 2, 3, 4, 5]) {
      let calls = 0;
      const rename = (source: string, target: string) => {
        if (++calls === failAt) throw new Error("rename failed");
        renameSync(source, target);
      };
      expect(() => restoreDataDir({ from: to, dataDir, force: true, rename })).toThrow("rename failed");
      expect(installation(), `failing at rename ${failAt}`).toEqual(live);
      expect(readdirSync(root).sort()).toEqual(["backups", "pg", ...KEY_FILES.slice(0, 3)].sort());
    }
  });

  // Review H2: when putting the old state back fails too, the only copy of the old data must survive.
  it("keeps the old data, and says where, when the swap fails and cannot be undone", () => {
    backupDataDir({ dataDir, to });
    writeFileSync(join(dataDir, "base", "1", "1234"), "the only copy of the newer data");
    const old = tree(dataDir);
    let calls = 0;
    const rename = (source: string, target: string) => {
      calls += 1;
      // Step 1 moves the old directory aside. Step 2 leaves something in its place and fails: step 1 cannot be undone.
      if (calls === 2) {
        mkdirSync(join(target, "half"), { recursive: true });
        writeFileSync(join(target, "half", "file"), "x");
        throw new Error("rename failed");
      }
      renameSync(source, target);
    };
    let message = "";
    try {
      restoreDataDir({ from: to, dataDir, force: true, rename });
    } catch (error) {
      message = (error as Error).message;
    }
    expect(message).toMatch(/could not be undone/);
    const kept = readdirSync(root).filter((name) => name.startsWith("pg.replaced-"));
    expect(kept).toHaveLength(1);
    expect(message).toContain(join(root, kept[0] as string));
    expect(tree(join(root, kept[0] as string, "pg"))).toEqual(old);
  });

  // Review L2: what an earlier, killed restore left may be the only copy of the data from before it.
  it("refuses while leftovers of an earlier restore lie beside the data directory, and deletes none of them", () => {
    const before = installation();
    backupDataDir({ dataDir, to });
    const dead = spawnSync(process.execPath, ["-e", ""]).pid;
    // What a killed restore can leave: the old directory moved aside, nothing in its place, a lock of a dead process.
    mkdirSync(`${dataDir}.replaced-${process.pid}`);
    renameSync(dataDir, join(`${dataDir}.replaced-${process.pid}`, "pg"));
    mkdirSync(`${dataDir}.restoring-${dead}`);
    writeFileSync(`${dataDir}.lock`, `${dead}\n`);
    for (const force of [false, true]) {
      expect(() => restoreDataDir({ from: to, dataDir, force })).toThrow(/earlier restore/);
      expect(() => restoreDataDir({ from: to, dataDir, force })).toThrow(`pg.replaced-${process.pid}`);
    }
    expect(tree(join(`${dataDir}.replaced-${process.pid}`, "pg"))).toEqual(before.pg);
    expect(existsSync(`${dataDir}.restoring-${dead}`)).toBe(true);
    // The operator looks at them and moves them away; then the restore runs.
    mkdirSync(join(root, "aside"));
    renameSync(`${dataDir}.replaced-${process.pid}`, join(root, "aside", "replaced"));
    renameSync(`${dataDir}.restoring-${dead}`, join(root, "aside", "restoring"));
    expect(restoreDataDir({ from: to, dataDir, force: true }).staleLock).toBe(dead);
    expect(installation()).toEqual(before);
  });

  // Review H1: --force replaces a data directory, never anything else.
  it.each([
    ["a directory that is not a data directory", () => join(root, "work")],
    ["the directory that holds the data directory", () => root],
    ["a file", () => join(root, "work", "src", "thesis.txt")],
  ])("refuses to restore over %s, also with force", (_name, target) => {
    mkdirSync(join(root, "work", "src"), { recursive: true });
    writeFileSync(join(root, "work", "src", "thesis.txt"), "years of work");
    backupDataDir({ dataDir, to });
    const everything = tree(root);
    for (const force of [false, true]) {
      expect(() => restoreDataDir({ from: to, dataDir: target(), force, dropKeys: true })).toThrow(
        /not a data directory/,
      );
    }
    expect(tree(root)).toEqual(everything);
  });

  it("restores into an empty directory, which is not something to protect", () => {
    backupDataDir({ dataDir, to });
    const empty = join(root, "fresh", "pg");
    mkdirSync(empty, { recursive: true });
    expect(restoreDataDir({ from: to, dataDir: empty }).replaced).toBe(false);
    expect(tree(empty)).toEqual(tree(dataDir));
  });

  // Review L3: a data directory that is a link would be replaced by a directory, and the real one orphaned.
  it("refuses a data directory that is a symbolic link", () => {
    backupDataDir({ dataDir, to });
    const link = join(root, "linked", "pg");
    mkdirSync(join(root, "linked"));
    symlinkSync(dataDir, link, "dir");
    expect(() => restoreDataDir({ from: to, dataDir: link, force: true })).toThrow(/symbolic link/);
    expect(lstatSync(link).isSymbolicLink()).toBe(true);
    expect(tree(dataDir)).toEqual(tree(join(to, "pg")));
  });

  // Review M2: a link inside a backup would be copied as a link, and the live data directory would become one.
  it.each([
    [
      "its data directory is a symbolic link",
      () => {
        renameSync(join(to, "pg"), join(root, "elsewhere-pg"));
        symlinkSync(join(root, "elsewhere-pg"), join(to, "pg"), "dir");
      },
    ],
    [
      "its key directory is a symbolic link",
      () => {
        renameSync(join(to, "keys"), join(root, "elsewhere-keys"));
        symlinkSync(join(root, "elsewhere-keys"), join(to, "keys"), "dir");
      },
    ],
    [
      "a file in it is a symbolic link",
      () => {
        renameSync(join(to, "pg", "PG_VERSION"), join(root, "elsewhere-version"));
        symlinkSync(join(root, "elsewhere-version"), join(to, "pg", "PG_VERSION"), "file");
      },
    ],
    [
      "its manifest is a symbolic link",
      () => {
        renameSync(join(to, MANIFEST_FILE), join(root, "elsewhere-manifest"));
        symlinkSync(join(root, "elsewhere-manifest"), join(to, MANIFEST_FILE), "file");
      },
    ],
  ])("refuses a backup when %s, even with force", (_name, damage) => {
    backupDataDir({ dataDir, to });
    damage();
    const live = installation();
    expect(() => restoreDataDir({ from: to, dataDir, force: true })).toThrow(/backup/i);
    expect(installation()).toEqual(live);
    expect(lstatSync(dataDir).isDirectory()).toBe(true);
  });

  // Review L1: a backup without key files is a backup of a directory that never had any. It removes none by accident.
  it("a backup without key files restores over live keys only with --drop-keys, and says which it removed", () => {
    const bare = join(root, "bare", "pg");
    mkdirSync(bare, { recursive: true });
    writeFileSync(join(bare, "PG_VERSION"), "17\n");
    backupDataDir({ dataDir: bare, to });
    expect(existsSync(join(to, "keys"))).toBe(true);
    const live = installation();
    expect(() => restoreDataDir({ from: to, dataDir, force: true })).toThrow(/--drop-keys/);
    expect(installation()).toEqual(live);
    const result = restoreDataDir({ from: to, dataDir, force: true, dropKeys: true });
    expect(result).toMatchObject({ keys: [], removedKeys: KEY_FILES.slice(0, 3) });
    expect(installation().keys).toEqual(Object.fromEntries(KEY_FILES.map((name) => [name, null])));
  });
});

describe("the command line", () => {
  const run = (argv: string[], env: Record<string, string> = {}) => {
    const out: string[] = [];
    const err: string[] = [];
    const code = runBackupCli(argv, {
      env,
      cwd: root,
      // Never the developer's own data directory: a command that falls back to the default lands here.
      defaultDataDir: join(root, "default", "pg"),
      print: (line) => out.push(line),
      error: (line) => err.push(line),
    });
    return { code, text: out.join("\n"), errors: err.join("\n") };
  };

  it("backs up and restores, printing names and counts and never a key", () => {
    const before = installation();
    const backup = run(["backup", "--to", "backups/first"], { AR_DATA_DIR: dataDir });
    expect(backup.code).toBe(0);
    expect(backup.text).toMatch(/6 files/);
    // The directory it is about to act on comes first.
    expect(backup.text.split("\n")[0]).toBe(`Data directory: ${dataDir}`);
    for (const name of KEY_FILES.slice(0, 3)) expect(backup.text).toContain(name);
    expect(backup.text).not.toContain(SECRET);
    expect(backup.errors).toBe("");

    writeFileSync(join(dataDir, "base", "1", "1234"), "newer");
    const refused = run(["restore", "--from", "backups/first", "--data-dir", dataDir]);
    expect(refused.code).toBe(1);
    // Review L7: a refusal is an error, on the error stream.
    expect(refused.errors).toMatch(/--force/);
    expect(refused.text).toBe(`Data directory: ${dataDir}`);
    expect(refused.errors).not.toContain(SECRET);

    const restored = run(["restore", "--from", "backups/first", "--data-dir", dataDir, "--force"]);
    expect(restored.code).toBe(0);
    expect(restored.text).toMatch(new RegExp(`Key files restored: ${KEY_FILES.slice(0, 3).join(", ")}\\.`));
    expect(restored.text).toMatch(/Key files removed: none\./);
    expect(restored.text).not.toContain(SECRET);
    expect(installation()).toEqual(before);
  });

  it("--drop-keys: says which live key files it removed", () => {
    run(["backup", "--to", "backups/first", "--data-dir", dataDir]);
    writeFileSync(join(root, KEY_FILES[4] as string), "{}");
    const refused = run(["restore", "--from", "backups/first", "--data-dir", dataDir, "--force"]);
    expect(refused.code).toBe(1);
    expect(refused.errors).toMatch(/--drop-keys/);
    const done = run(["restore", "--from", "backups/first", "--data-dir", dataDir, "--force", "--drop-keys"]);
    expect(done.code).toBe(0);
    expect(done.text).toMatch(new RegExp(`Key files removed: ${KEY_FILES[4]}\\.`));
  });

  it("warns about a lock left by a process that no longer runs, and still backs up", () => {
    const dead = spawnSync(process.execPath, ["-e", ""]).pid;
    writeFileSync(`${dataDir}.lock`, `${dead}\n`);
    const backup = run(["backup", "--to", "backups/first", "--data-dir", dataDir]);
    expect(backup.code).toBe(0);
    expect(backup.errors).toMatch(new RegExp(`Warning: .*process ${dead}.*did not stop cleanly`));
  });

  // The API reads a relative AR_DATA_DIR from wherever it is started; the command cannot know where that was (D-126).
  it("refuses a relative AR_DATA_DIR instead of guessing which directory it names", () => {
    mkdirSync(join(root, "data"), { recursive: true });
    const backup = run(["backup", "--to", "backups/first"], { AR_DATA_DIR: "data/pg" });
    expect(backup.code).toBe(2);
    expect(backup.errors).toMatch(/AR_DATA_DIR is a relative path/);
    expect(backup.errors).toMatch(/--data-dir/);
    expect(existsSync(join(root, "backups"))).toBe(false);
    // --data-dir is what the operator typed, where they typed it: relative is fine there, and wins.
    renameSync(dataDir, join(root, "data", "pg"));
    const named = run(["backup", "--to", "backups/first", "--data-dir", "data/pg"], { AR_DATA_DIR: "elsewhere" });
    expect(named.code).toBe(0);
    expect(named.text.split("\n")[0]).toBe(`Data directory: ${join(root, "data", "pg")}`);
  });

  it("restore never falls back to the default data directory: it must be named", () => {
    run(["backup", "--to", "backups/first", "--data-dir", dataDir]);
    const restore = run(["restore", "--from", "backups/first", "--force"]);
    expect(restore.code).toBe(2);
    expect(restore.errors).toMatch(/restore needs --data-dir/);
    expect(restore.text).toBe("");
    expect(existsSync(join(root, "default"))).toBe(false);
    // backup may use the default: here it is not a data directory, and the refusal names it.
    const fallback = run(["backup", "--to", "backups/second"]);
    expect(fallback.code).toBe(1);
    expect(fallback.text).toBe(`Data directory: ${join(root, "default", "pg")}`);
    // Named by the environment is named.
    expect(run(["restore", "--from", "backups/first", "--force"], { AR_DATA_DIR: dataDir }).code).toBe(0);
  });

  it("explains itself, and refuses what it does not understand", () => {
    expect(run(["--help"]).code).toBe(0);
    expect(run(["--help"]).text).toMatch(/data:backup/);
    expect(run(["--help"]).text).toMatch(/--drop-keys/);
    expect(run([]).code).toBe(2);
    expect(run([]).errors).toMatch(/Expected the command backup or restore/);
    expect(run([]).text).toBe("");
    expect(run(["backup"]).code).toBe(2);
    expect(run(["restore", "--to", "x"]).code).toBe(2);
    expect(run(["backup", "--to", "x", "--force"]).code).toBe(2);
    expect(run(["backup", "--to", "x", "--drop-keys"]).code).toBe(2);
    expect(run(["erase", "--from", "x"]).code).toBe(2);
  });

  it("runs as a script, also when the checkout is reached through a symbolic link", () => {
    const repository = fileURLToPath(new URL("../../..", import.meta.url));
    const link = join(root, "checkout");
    symlinkSync(repository, link, "dir");
    const tsx = join(repository, "node_modules/tsx/dist/cli.mjs");
    for (const base of [repository, link]) {
      const child = spawnSync(process.execPath, [tsx, join(base, "apps/api/src/backup/cli.ts"), "erase"], {
        encoding: "utf8",
        env: { ...process.env, AR_DATA_DIR: dataDir },
      });
      // A script that did nothing would exit 0 and print nothing: the operator would believe a backup was made.
      expect(child.status, base === link ? "through the link" : "directly").toBe(2);
      expect(child.stderr).toMatch(/Expected the command backup or restore/);
      expect(child.stdout).toBe("");
    }
  });
});
