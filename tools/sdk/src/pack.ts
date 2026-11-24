// `npm pack` on the staging folders (slice 23). Every npm child of the SDK tooling runs with a cache and empty user
// and global configuration files inside the layout's work folder, a home directory there too, and without any
// npm_* variable of a surrounding `npm run`: the user's npm settings and cache are neither read nor written, and
// cannot change what is packed. Lifecycle scripts never run.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { exec } from "./exec.ts";
import { type Layout, prepareBuildDir } from "./safe.ts";
import type { StagedPackage } from "./stage.ts";

export interface PackedTarball {
  name: string;
  version: string;
  /** The file name inside the output folder. */
  file: string;
  path: string;
  size: number;
  sha256: string;
  /** npm's own integrity string (sha512). */
  integrity: string;
}

export const sha256File = (path: string): string => createHash("sha256").update(readFileSync(path)).digest("hex");

/** The environment of an isolated npm child. `registry`: where it may ask; without one it is offline. */
export function npmEnv(work: string, options: { registry?: string } = {}): NodeJS.ProcessEnv {
  const home = join(work, "npm-home");
  mkdirSync(join(work, "npm-cache"), { recursive: true });
  mkdirSync(home, { recursive: true });
  for (const file of ["npmrc-user", "npmrc-global"])
    if (!existsSync(join(work, file))) writeFileSync(join(work, file), "");
  const env: NodeJS.ProcessEnv = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (/^npm_/i.test(key) || key === "NODE_OPTIONS" || key === "INIT_CWD") continue;
    env[key] = value;
  }
  return {
    ...env,
    HOME: home,
    USERPROFILE: home,
    npm_config_cache: join(work, "npm-cache"),
    npm_config_userconfig: join(work, "npmrc-user"),
    npm_config_globalconfig: join(work, "npmrc-global"),
    npm_config_update_notifier: "false",
    npm_config_audit: "false",
    npm_config_fund: "false",
    npm_config_ignore_scripts: "true",
    ...(options.registry === undefined ? { npm_config_offline: "true" } : { npm_config_registry: options.registry }),
  };
}

interface NpmPackEntry {
  name: string;
  version: string;
  filename: string;
  integrity: string;
}

/** Packs folders with one `npm pack`; returns what npm wrote into `destination`. */
export async function npmPack(folders: readonly string[], destination: string, work: string): Promise<PackedTarball[]> {
  mkdirSync(destination, { recursive: true });
  const result = await exec(
    "npm",
    ["pack", "--json", "--ignore-scripts", "--pack-destination", destination, ...folders],
    {
      cwd: work,
      env: npmEnv(work),
    },
  );
  if (result.code !== 0) throw new Error(`npm pack failed (exit ${result.code}):\n${result.stderr}`);
  const entries = JSON.parse(result.stdout) as NpmPackEntry[];
  if (!Array.isArray(entries) || entries.length !== folders.length)
    throw new Error("npm pack did not report every folder");
  return entries.map((entry) => {
    // npm names the file of a scoped package scope-name-version.tgz, and reports it so (older npm: with a slash).
    const file = entry.filename.replace(/^@/, "").replace(/\//g, "-");
    const path = join(destination, file);
    return {
      name: entry.name,
      version: entry.version,
      file,
      path,
      size: statSync(path).size,
      sha256: sha256File(path),
      integrity: entry.integrity,
    };
  });
}

/** Packs the staged packages into the layout's output folder, which is emptied first. */
export async function packStaged(staged: readonly StagedPackage[], layout: Layout): Promise<PackedTarball[]> {
  prepareBuildDir(layout.out);
  const packed = await npmPack(
    staged.map((entry) => entry.dir),
    layout.out,
    layout.work,
  );
  for (const [index, entry] of staged.entries()) {
    const tarball = packed[index] as PackedTarball;
    if (tarball.name !== entry.pkg.name || tarball.version !== entry.version) {
      throw new Error(
        `npm packed ${tarball.name}@${tarball.version} where ${entry.pkg.name}@${entry.version} was staged`,
      );
    }
  }
  return packed;
}
