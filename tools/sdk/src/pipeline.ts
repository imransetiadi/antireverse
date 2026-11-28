// `npm run sdk:pack` as a function (slice 23): build, stage, check the dependency allowlist, pack, write a bill of
// materials per package, and sign a manifest of everything. Every folder comes from the layout. The allowlist is
// checked before anything is packed: a pack that fails it writes no tarball and signs nothing.
import { createHash } from "node:crypto";
import { readdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { join, relative, sep } from "node:path";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import type { GateKey } from "../../gate/src/sign.ts";
import { type Allowlist, checkAllowlist, installScripts, readAllowlist } from "./allowlist.ts";
import { buildAll, vendorDirOf } from "./build.ts";
import { type Closure, readLockfile, sdkClosures, vendoredDependencies } from "./closure.ts";
import { exec } from "./exec.ts";
import {
  artifactFile,
  MANIFEST_SCHEMA,
  MANIFEST_STATEMENT,
  RELEASE_STATEMENT,
  type SdkManifest,
  writeManifest,
} from "./manifest.ts";
import { npmEnv, type PackedTarball, packStaged } from "./pack.ts";
import { sdkPackage } from "./packages.ts";
import type { ReleaseInfo } from "./release.ts";
import type { Layout } from "./safe.ts";
import { sbomFileOf, sbomOf, serializeSbom } from "./sbom.ts";
import { type StagedPackage, stageAll } from "./stage.ts";

export interface PackResult {
  staged: StagedPackage[];
  tarballs: PackedTarball[];
  closures: Record<string, Closure>;
  manifest: SdkManifest;
  manifestPath: string;
}

/** The closures of the staged packages, with a check that the lockfile and the staged manifests agree. */
export function stagedClosures(staged: readonly StagedPackage[]): Record<string, Closure> {
  const lock = readLockfile();
  const extra = vendoredDependencies(lock);
  for (const entry of staged) {
    const locked = [
      ...Object.entries(lock.packages[`packages/${entry.pkg.short}`]?.dependencies ?? {}),
      ...entry.vendored.flatMap((name) =>
        Object.entries(lock.packages[`packages/${sdkPackage(name).short}`]?.dependencies ?? {}),
      ),
    ];
    const wanted = new Set(locked.map(([name, version]) => `${name}@${version}`));
    const got = new Set(Object.entries(entry.dependencies).map(([name, version]) => `${name}@${version}`));
    if (wanted.size !== got.size || [...wanted].some((id) => !got.has(id))) {
      throw new Error(
        `${entry.pkg.name}: package-lock.json does not match the package's dependencies; run npm install`,
      );
    }
  }
  return sdkClosures(lock, extra);
}

async function sourceState(): Promise<SdkManifest["source"]> {
  const head = await exec("git", ["rev-parse", "HEAD"], { cwd: REPO_ROOT });
  const status = await exec("git", ["status", "--porcelain"], { cwd: REPO_ROOT });
  const commit = head.code === 0 && /^[0-9a-f]{40}$/.test(head.stdout.trim()) ? head.stdout.trim() : null;
  return { commit, dirty: commit === null || status.code !== 0 ? null : status.stdout.trim() !== "" };
}

async function toolchain(work: string): Promise<SdkManifest["toolchain"]> {
  const npm = await exec("npm", ["--version"], { cwd: work, env: npmEnv(work) });
  const typescript = JSON.parse(readFileSync(join(REPO_ROOT, "node_modules/typescript/package.json"), "utf8")) as {
    version: string;
  };
  return { node: process.versions.node, npm: npm.stdout.trim(), typescript: typescript.version };
}

/** A digest of a folder's files: SHA-256 over each relative path and its bytes, in sorted order. */
function filesDigest(dir: string): string {
  const hash = createHash("sha256");
  const walk = (at: string): void => {
    for (const entry of readdirSync(at).sort()) {
      const path = join(at, entry);
      if (statSync(path).isDirectory()) walk(path);
      else {
        hash.update(`${relative(dir, path).split(sep).join("/")}\0`);
        hash.update(readFileSync(path));
        hash.update("\0");
      }
    }
  };
  walk(dir);
  return hash.digest("hex");
}

/**
 * Build, stage, check, pack, bills of materials, signed manifest. Without `release`: the ordinary pack — four
 * private tarballs into the layout's `out`. With `release` (what `releaseState` returned for a clean tree on
 * origin/main): the three publishable tarballs into the layout's `release` folder. It packs; it never publishes.
 */
export async function buildAndPack(
  layout: Layout,
  options: { key: GateKey; allowlist?: Allowlist; release?: ReleaseInfo },
): Promise<PackResult> {
  const { release } = options;
  const out = release === undefined ? layout.out : layout.release;
  await buildAll(layout);
  const staged = stageAll(layout, release);
  const closures = stagedClosures(staged);
  const problems = checkAllowlist(closures, options.allowlist ?? readAllowlist(), installScripts);
  if (problems.length > 0) throw new Error(`the dependency allowlist does not match:\n  ${problems.join("\n  ")}`);
  const tarballs = await packStaged(staged, layout, out);
  const digests = Object.fromEntries(tarballs.map((tarball) => [tarball.name, tarball.sha256]));
  const packages: SdkManifest["packages"] = [];
  for (const [index, entry] of staged.entries()) {
    const tarball = tarballs[index] as PackedTarball;
    const sbomFile = sbomFileOf(tarball.file);
    const vendored = entry.vendored.map((name) => {
      const dir = `dist/${vendorDirOf(sdkPackage(name))}`;
      // In a release the vendored package has no tarball of its own beside this one: its files are named instead.
      return name in digests ? { name, dir } : { name, dir, filesSha256: filesDigest(join(entry.dir, dir)) };
    });
    const sbom = sbomOf(entry.pkg.name, entry.version, closures[entry.pkg.name] as Closure, digests, vendored);
    writeFileSync(join(out, sbomFile), serializeSbom(sbom));
    packages.push({
      name: entry.pkg.name,
      version: entry.version,
      tarball: artifactFile(out, tarball.file),
      sbom: artifactFile(out, sbomFile),
      dependencies: entry.dependencies,
      vendored: entry.vendored,
    });
  }
  const manifest: SdkManifest = {
    schema: MANIFEST_SCHEMA,
    kind: release === undefined ? "local" : "release",
    ...(release === undefined ? {} : { repository: release.repository }),
    statement: release === undefined ? MANIFEST_STATEMENT : RELEASE_STATEMENT,
    created_at: new Date().toISOString(),
    source: release === undefined ? await sourceState() : { commit: release.commit, dirty: false },
    toolchain: await toolchain(layout.work),
    packages,
  };
  const manifestPath = writeManifest(out, manifest, options.key);
  return { staged, tarballs, closures, manifest, manifestPath };
}
