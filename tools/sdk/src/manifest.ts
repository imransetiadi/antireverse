// The signed manifest of a packed folder and its check (slice 23, D-139). The manifest lists every tarball and bill
// of materials with size and SHA-256 and is signed with the gate's local Ed25519 key (tools/gate/src/sign.ts; the
// key file lives outside the repository and is never printed).
//
// What a valid, trusted result proves: the files in the folder are the ones the holder of that key signed. It is a
// local signature. It is not provenance: nothing in it says which source, which machine or which pipeline produced
// the files, and anyone can sign a changed folder with a key of their own — which is why a signer is trusted only
// when it is the fingerprint the caller expects or, when the caller names none, the local gate key.
import { createHash } from "node:crypto";
import { existsSync, lstatSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { type GateKey, signReport, verifyReport } from "../../gate/src/sign.ts";
import { BUILD_MARKER, MARKER_TEXT } from "./safe.ts";

export const MANIFEST_FILE = "sdk-manifest.json";
export const MANIFEST_SCHEMA = "airverse.sdk-artifacts/1";
/** A manifest larger than this is not read: a real one is a few kilobytes. */
export const MANIFEST_MAX_BYTES = 1024 * 1024;
export const MANIFEST_STATEMENT =
  "Built and signed locally. The signature says that the holder of the signing key signed these files on their own machine; it is not provenance from a trusted builder. These packages are not published and this is not a release.";

export interface ArtifactFile {
  file: string;
  size: number;
  sha256: string;
}

export interface SdkManifest {
  schema: typeof MANIFEST_SCHEMA;
  statement: string;
  created_at: string;
  /** The commit the working tree was at, and whether it had uncommitted changes; null when git could not say. */
  source: { commit: string | null; dirty: boolean | null };
  toolchain: { node: string; npm: string; typescript: string };
  packages: Array<{
    name: string;
    version: string;
    tarball: ArtifactFile;
    sbom: ArtifactFile;
    dependencies: Record<string, string>;
    /** The SDK packages whose compiled files this tarball carries. */
    vendored: string[];
  }>;
}

export function artifactFile(dir: string, file: string): ArtifactFile {
  const bytes = readFileSync(join(dir, file));
  return { file, size: bytes.length, sha256: createHash("sha256").update(bytes).digest("hex") };
}

/** Signs the manifest and writes it into the folder. */
export function writeManifest(dir: string, manifest: SdkManifest, key: GateKey): string {
  const path = join(dir, MANIFEST_FILE);
  writeFileSync(path, `${JSON.stringify(signReport(manifest, key), null, 2)}\n`);
  return path;
}

export interface Verification {
  /** Every file matches, nothing is missing or extra, the signature verifies, and the signer is trusted. */
  ok: boolean;
  problems: string[];
  /** The signer's fingerprint, when the signature verifies. */
  fingerprint: string | null;
  /** The signer is the local gate key or the expected fingerprint. */
  trusted: boolean;
  packages: Array<{ name: string; version: string; file: string }>;
}

const PLAIN_NAME = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;

function isArtifactFile(value: unknown): value is ArtifactFile {
  const file = value as Partial<ArtifactFile> | null;
  return (
    file !== null &&
    typeof file === "object" &&
    typeof file.file === "string" &&
    typeof file.size === "number" &&
    typeof file.sha256 === "string"
  );
}

/**
 * Checks a packed folder against its manifest. `expect`: the fingerprint the caller was given by the signer — when
 * given, the only signer that is trusted. `localFingerprint`: the local gate key's, trusted when no `expect` is
 * given. Reads only; never creates a key.
 */
export function verifyArtifacts(
  dir: string,
  options: { localFingerprint?: string | null; expect?: string } = {},
): Verification {
  const fail = (problem: string): Verification => ({
    ok: false,
    problems: [problem],
    fingerprint: null,
    trusted: false,
    packages: [],
  });
  const path = join(dir, MANIFEST_FILE);
  if (!existsSync(path)) return fail(`${MANIFEST_FILE}: missing`);
  const stat = lstatSync(path);
  if (!stat.isFile()) return fail(`${MANIFEST_FILE}: not a regular file`);
  if (stat.size > MANIFEST_MAX_BYTES) return fail(`${MANIFEST_FILE}: larger than ${MANIFEST_MAX_BYTES} bytes`);
  let manifest: Partial<SdkManifest>;
  try {
    manifest = JSON.parse(readFileSync(path, "utf8")) as Partial<SdkManifest>;
  } catch {
    return fail(`${MANIFEST_FILE}: not JSON`);
  }
  if (manifest === null || typeof manifest !== "object" || Array.isArray(manifest))
    return fail(`${MANIFEST_FILE}: not a manifest`);
  const signature = verifyReport(manifest);
  if (!signature.ok) return fail(`${MANIFEST_FILE}: ${signature.reason}`);
  if (manifest.schema !== MANIFEST_SCHEMA) {
    return fail(`${MANIFEST_FILE}: not an SDK artifact manifest (schema ${String(manifest.schema)})`);
  }
  const problems: string[] = [];
  const listed = new Set<string>([MANIFEST_FILE]);
  const packages: Verification["packages"] = [];
  if (!Array.isArray(manifest.packages) || manifest.packages.length === 0)
    problems.push(`${MANIFEST_FILE}: lists no package`);
  for (const entry of Array.isArray(manifest.packages) ? manifest.packages : []) {
    if (
      typeof entry?.name !== "string" ||
      typeof entry.version !== "string" ||
      !isArtifactFile(entry.tarball) ||
      !isArtifactFile(entry.sbom)
    ) {
      problems.push(`${MANIFEST_FILE}: a package entry is malformed`);
      continue;
    }
    packages.push({ name: entry.name, version: entry.version, file: entry.tarball.file });
    for (const file of [entry.tarball, entry.sbom]) {
      if (!PLAIN_NAME.test(file.file) || file.file === MANIFEST_FILE) {
        problems.push(`${MANIFEST_FILE}: a file name that is not a plain name (${JSON.stringify(file.file)})`);
        continue;
      }
      if (listed.has(file.file)) {
        problems.push(`${MANIFEST_FILE}: ${file.file} is listed twice`);
        continue;
      }
      listed.add(file.file);
      const at = join(dir, file.file);
      let stat: ReturnType<typeof lstatSync>;
      try {
        stat = lstatSync(at);
      } catch {
        problems.push(`${file.file}: missing`);
        continue;
      }
      if (!stat.isFile()) {
        problems.push(`${file.file}: not a regular file`);
        continue;
      }
      if (stat.size !== file.size) {
        problems.push(`${file.file}: size ${stat.size}, the manifest says ${file.size}`);
        continue;
      }
      const sha256 = createHash("sha256").update(readFileSync(at)).digest("hex");
      if (sha256 !== file.sha256) problems.push(`${file.file}: SHA-256 does not match the manifest`);
    }
  }
  for (const name of readdirSync(dir).sort()) {
    if (listed.has(name)) continue;
    // The build marker of the folder is the one file that may be there unlisted, and only as the build wrote it.
    if (
      name === BUILD_MARKER &&
      lstatSync(join(dir, name)).isFile() &&
      readFileSync(join(dir, name), "utf8") === MARKER_TEXT
    )
      continue;
    problems.push(`${name}: not listed in the manifest`);
  }
  // With an expected fingerprint only that signer is trusted; the local key counts only when none was given.
  const trusted =
    options.expect !== undefined
      ? signature.fingerprint === options.expect
      : options.localFingerprint != null && signature.fingerprint === options.localFingerprint;
  return { ok: problems.length === 0 && trusted, problems, fingerprint: signature.fingerprint, trusted, packages };
}
