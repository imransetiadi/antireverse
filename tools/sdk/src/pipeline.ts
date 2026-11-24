// `npm run sdk:pack` as a function (slice 23): build, stage, check the dependency allowlist, pack, write a bill of
// materials per package, and sign a manifest of everything. Every folder comes from the layout. The allowlist is
// checked before anything is packed: a pack that fails it writes no tarball and signs nothing.
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { REPO_ROOT } from "../../gate/src/paths.ts";
import type { GateKey } from "../../gate/src/sign.ts";
import { type Allowlist, checkAllowlist, installScripts, readAllowlist } from "./allowlist.ts";
import { buildAll, vendorDirOf } from "./build.ts";
import { type Closure, readLockfile, sdkClosures, vendoredDependencies } from "./closure.ts";
import { exec } from "./exec.ts";
import { artifactFile, MANIFEST_SCHEMA, MANIFEST_STATEMENT, type SdkManifest, writeManifest } from "./manifest.ts";
import { npmEnv, type PackedTarball, packStaged } from "./pack.ts";
import { sdkPackage } from "./packages.ts";
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

export async function buildAndPack(
  layout: Layout,
  options: { key: GateKey; allowlist?: Allowlist },
): Promise<PackResult> {
  await buildAll(layout);
  const staged = stageAll(layout);
  const closures = stagedClosures(staged);
  const problems = checkAllowlist(closures, options.allowlist ?? readAllowlist(), installScripts);
  if (problems.length > 0) throw new Error(`the dependency allowlist does not match:\n  ${problems.join("\n  ")}`);
  const tarballs = await packStaged(staged, layout);
  const digests = Object.fromEntries(tarballs.map((tarball) => [tarball.name, tarball.sha256]));
  const packages: SdkManifest["packages"] = [];
  for (const [index, entry] of staged.entries()) {
    const tarball = tarballs[index] as PackedTarball;
    const sbomFile = sbomFileOf(tarball.file);
    const vendored = entry.vendored.map((name) => ({ name, dir: `dist/${vendorDirOf(sdkPackage(name))}` }));
    const sbom = sbomOf(entry.pkg.name, entry.version, closures[entry.pkg.name] as Closure, digests, vendored);
    writeFileSync(join(layout.out, sbomFile), serializeSbom(sbom));
    packages.push({
      name: entry.pkg.name,
      version: entry.version,
      tarball: artifactFile(layout.out, tarball.file),
      sbom: artifactFile(layout.out, sbomFile),
      dependencies: entry.dependencies,
      vendored: entry.vendored,
    });
  }
  const manifest: SdkManifest = {
    schema: MANIFEST_SCHEMA,
    statement: MANIFEST_STATEMENT,
    created_at: new Date().toISOString(),
    source: await sourceState(),
    toolchain: await toolchain(layout.work),
    packages,
  };
  const manifestPath = writeManifest(layout.out, manifest, options.key);
  return { staged, tarballs, closures, manifest, manifestPath };
}
