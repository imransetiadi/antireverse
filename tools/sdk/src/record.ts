// The record of a release that is kept in the repository (releases/<version>/): the signed manifest and the bills
// of materials of a release folder, without the tarballs — those are on the registry — and, beside them,
// integrity.json: the sha512 of each tarball in npm's form, which is what `npm view <name>@<version> dist.integrity`
// reports. The manifest's signature covers the tarballs' SHA-256; integrity.json is derived from the same bytes when
// the record is written and is NOT signed: it is there so that anyone can compare a published package with the
// record without the tarball. Checking a record reads only; with `online` it asks a registry, read-only.
import { createHash } from "node:crypto";
import { copyFileSync, existsSync, lstatSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { verifyReport } from "../../gate/src/sign.ts";
import { MANIFEST_FILE, MANIFEST_MAX_BYTES, type SdkManifest } from "./manifest.ts";
import { ask } from "./publish.ts";

export const INTEGRITY_FILE = "integrity.json";

interface IntegrityList {
  about: string;
  derived: true;
  signed: false;
  /** name@version → sha512 integrity of the tarball. */
  packages: Record<string, string>;
}

export interface RecordResult {
  ok: boolean;
  problems: string[];
  fingerprint: string | null;
  commit: string | null;
  packages: Array<{ name: string; version: string; sha256: string; integrity: string | null; registry: string }>;
  asked: boolean;
}

/** Writes the record of a release folder into `dir` (which must not exist yet): everything but the tarballs. */
export function writeRecord(releaseDir: string, dir: string): void {
  if (existsSync(dir)) throw new Error(`${dir} exists already: a record is written once`);
  const manifest = JSON.parse(readFileSync(join(releaseDir, MANIFEST_FILE), "utf8")) as SdkManifest;
  if (manifest.kind !== "release") throw new Error(`${releaseDir} is not a release folder`);
  mkdirSync(dir, { recursive: true });
  copyFileSync(join(releaseDir, MANIFEST_FILE), join(dir, MANIFEST_FILE));
  const packages: Record<string, string> = {};
  for (const entry of manifest.packages) {
    copyFileSync(join(releaseDir, entry.sbom.file), join(dir, entry.sbom.file));
    const bytes = readFileSync(join(releaseDir, entry.tarball.file));
    if (createHash("sha256").update(bytes).digest("hex") !== entry.tarball.sha256) {
      throw new Error(`${entry.tarball.file} is not the file the manifest lists`);
    }
    packages[`${entry.name}@${entry.version}`] = `sha512-${createHash("sha512").update(bytes).digest("base64")}`;
  }
  const list: IntegrityList = {
    about:
      "The sha512 of each released tarball, in the form `npm view <name>@<version> dist.integrity` reports. Derived from the same files as the SHA-256 digests in sdk-manifest.json when this record was written. The manifest is signed; this file is not.",
    derived: true,
    signed: false,
    packages,
  };
  writeFileSync(join(dir, INTEGRITY_FILE), `${JSON.stringify(list, null, 2)}\n`);
}

/** Checks a release record. `expect`: the signer's fingerprint, when the caller has one to compare with. */
export async function recordCheck(
  dir: string,
  options: { expect?: string; online?: { registry: string; work: string } } = {},
): Promise<RecordResult> {
  const result: RecordResult = { ok: false, problems: [], fingerprint: null, commit: null, packages: [], asked: false };
  const fail = (problem: string): RecordResult => {
    result.problems.push(problem);
    return result;
  };
  const path = join(dir, MANIFEST_FILE);
  if (!existsSync(path)) return fail(`${MANIFEST_FILE}: missing`);
  if (!lstatSync(path).isFile() || lstatSync(path).size > MANIFEST_MAX_BYTES)
    return fail(`${MANIFEST_FILE}: not a regular file of a manifest's size`);
  let manifest: SdkManifest;
  try {
    manifest = JSON.parse(readFileSync(path, "utf8")) as SdkManifest;
  } catch {
    return fail(`${MANIFEST_FILE}: not JSON`);
  }
  const signature = verifyReport(manifest);
  if (!signature.ok) return fail(`${MANIFEST_FILE}: ${signature.reason}`);
  result.fingerprint = signature.fingerprint;
  if (manifest.kind !== "release" || !Array.isArray(manifest.packages))
    return fail(`${MANIFEST_FILE}: not a release manifest`);
  if (options.expect !== undefined && options.expect !== signature.fingerprint) {
    result.problems.push(`the record is signed by ${signature.fingerprint}, not by the expected ${options.expect}`);
  }
  result.commit = manifest.source?.commit ?? null;
  let list: Partial<IntegrityList> = {};
  try {
    list = JSON.parse(readFileSync(join(dir, INTEGRITY_FILE), "utf8")) as Partial<IntegrityList>;
  } catch {
    result.problems.push(`${INTEGRITY_FILE}: missing or not JSON`);
  }
  const listed = list.packages !== null && typeof list.packages === "object" ? list.packages : {};
  const wanted = manifest.packages.map((entry) => `${entry.name}@${entry.version}`);
  if (JSON.stringify(Object.keys(listed).sort()) !== JSON.stringify([...wanted].sort())) {
    result.problems.push(`${INTEGRITY_FILE} does not list exactly the manifest's packages`);
  }
  const allowed = new Set([MANIFEST_FILE, INTEGRITY_FILE]);
  for (const entry of manifest.packages) {
    allowed.add(entry.sbom.file);
    const sbom = join(dir, entry.sbom.file);
    if (!existsSync(sbom) || !lstatSync(sbom).isFile()) result.problems.push(`${entry.sbom.file}: missing`);
    else {
      const bytes = readFileSync(sbom);
      if (bytes.length !== entry.sbom.size)
        result.problems.push(`${entry.sbom.file}: size ${bytes.length}, the manifest says ${entry.sbom.size}`);
      else if (createHash("sha256").update(bytes).digest("hex") !== entry.sbom.sha256)
        result.problems.push(`${entry.sbom.file}: SHA-256 does not match the manifest`);
    }
    const integrity = listed[`${entry.name}@${entry.version}`];
    result.packages.push({
      name: entry.name,
      version: entry.version,
      sha256: entry.tarball.sha256,
      integrity: typeof integrity === "string" && /^sha512-[A-Za-z0-9+/]+=*$/.test(integrity) ? integrity : null,
      registry: "not asked",
    });
  }
  // A record holds no tarball and nothing else: what is not the manifest, the list or a bill of materials is named.
  for (const name of readdirSync(dir).sort())
    if (!allowed.has(name)) result.problems.push(`${name}: not part of a release record`);
  if (result.problems.length > 0 || options.online === undefined) {
    result.ok = result.problems.length === 0;
    return result;
  }
  result.asked = true;
  for (const pkg of result.packages) {
    const answer = await ask(pkg.name, pkg.version, options.online);
    if (answer.state === "unreachable")
      return fail(
        `the registry could not be reached (${options.online.registry}: ${answer.detail}); nothing was compared`,
      );
    if (answer.state === "absent") {
      pkg.registry = "absent";
      result.problems.push(`${pkg.name}@${pkg.version} is not on the registry`);
    } else if (answer.state === "unlisted") {
      pkg.registry = "unlisted";
      result.problems.push(
        `${pkg.name}: the name is on the registry but ${pkg.version} is not listed (it may be staged and waiting for approval)`,
      );
    } else if (answer.integrity !== pkg.integrity) {
      pkg.registry = "different";
      result.problems.push(`${pkg.name}@${pkg.version}: the registry's integrity is not the record's`);
    } else pkg.registry = "same";
  }
  result.ok = result.problems.length === 0;
  return result;
}
