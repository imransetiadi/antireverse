// The owner's checks around publishing (slice 23b). Both only read: the folder, and the registry through
// `npm view`. Nothing here publishes, logs in or changes npm's configuration — the commands that do are printed
// for the owner to run with their own login and one-time code.
//   release-check    before: the folder verifies as a release folder signed by a trusted key; no name@version is on
//                    the registry yet; then the exact commands, one per line.
//   published-check  after: the registry's dist.integrity of each name@version is the local tarball's.
import { createHash } from "node:crypto";
import { mkdirSync, readFileSync } from "node:fs";
import { join } from "node:path";
import { gunzipSync } from "node:zlib";
import { exec } from "./exec.ts";
import { MANIFEST_FILE, type SdkManifest, verifyArtifacts } from "./manifest.ts";
import { npmEnv } from "./pack.ts";
import { RELEASED_PACKAGES } from "./packages.ts";
import { tarFile } from "./tar.ts";

export const NPM_REGISTRY = "https://registry.npmjs.org/";

export interface CheckOptions {
  /** Where to ask. The commands use the public registry; tests a loopback one. */
  registry: string;
  /** A folder for npm's cache and empty configuration files: the user's npm settings are not read. */
  work: string;
  localFingerprint?: string | null;
  expect?: string;
}

export interface CheckedTarball {
  name: string;
  version: string;
  file: string;
  path: string;
  size: number;
  sha256: string;
  /** npm's form: sha512, base64. What the registry reports as dist.integrity after a publish. */
  integrity: string;
  /** absent: not on the registry. same / different: there, with these or other bytes. unknown: not asked or no answer. */
  registry: "absent" | "same" | "different" | "unknown";
}

export interface CheckResult {
  ok: boolean;
  problems: string[];
  fingerprint: string | null;
  tarballs: CheckedTarball[];
  /** release-check only: what the owner runs, in order. Empty unless everything is in order. */
  commands: string[];
  /** Whether a registry was asked at all: not when the folder itself was refused. */
  asked: boolean;
}

/** A path as one word of a POSIX shell command: single quotes, so `$`, backticks, `!` and spaces are plain text. */
export function shellQuote(text: string): string {
  return `'${text.replaceAll("'", "'\\''")}'`;
}

/** The folder as a verified release folder, or the problems. Asks no registry. */
function releaseFolder(dir: string, options: CheckOptions): CheckResult {
  const verified = verifyArtifacts(dir, {
    localFingerprint: options.localFingerprint ?? null,
    ...(options.expect === undefined ? {} : { expect: options.expect }),
  });
  const result: CheckResult = {
    ok: false,
    problems: [...verified.problems],
    fingerprint: verified.fingerprint,
    tarballs: [],
    commands: [],
    asked: false,
  };
  if (verified.problems.length > 0) return result;
  if (!verified.trusted) {
    result.problems.push(
      `the signer ${verified.fingerprint} is not trusted: it is not the local gate key${options.expect === undefined ? "" : " or the fingerprint given with --expect"}`,
    );
    return result;
  }
  const manifest = JSON.parse(readFileSync(join(dir, MANIFEST_FILE), "utf8")) as SdkManifest;
  const names = manifest.packages.map((entry) => entry.name);
  const wanted = RELEASED_PACKAGES.map((pkg) => pkg.name);
  if (manifest.kind !== "release" || names.length !== wanted.length || wanted.some((name) => !names.includes(name))) {
    result.problems.push(
      `not a release folder: ${MANIFEST_FILE} is of kind ${JSON.stringify(manifest.kind ?? "local")} with ${names.join(", ")}; a release folder is written by \`npm run sdk:release\` and holds exactly ${wanted.join(", ")}`,
    );
    return result;
  }
  for (const entry of manifest.packages) {
    const path = join(dir, entry.tarball.file);
    const bytes = readFileSync(path);
    const packed = JSON.parse(tarFile(gunzipSync(bytes), "package/package.json").toString("utf8")) as Record<
      string,
      unknown
    >;
    if (packed.name !== entry.name || packed.version !== entry.version) {
      result.problems.push(
        `${entry.tarball.file} holds ${String(packed.name)}@${String(packed.version)}, the manifest says ${entry.name}@${entry.version}`,
      );
    }
    if ("private" in packed)
      result.problems.push(`${entry.tarball.file}: its package.json is private; it cannot be published`);
    result.tarballs.push({
      name: entry.name,
      version: entry.version,
      file: entry.tarball.file,
      path,
      size: bytes.length,
      sha256: createHash("sha256").update(bytes).digest("hex"),
      integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
      registry: "unknown",
    });
  }
  return result;
}

type Answer = { state: "absent" } | { state: "present"; integrity: string } | { state: "unreachable"; detail: string };

/** `npm view name@version dist.integrity`: read-only, with npm's own configuration left out. */
async function ask(name: string, version: string, options: CheckOptions): Promise<Answer> {
  mkdirSync(options.work, { recursive: true });
  const result = await exec(
    "npm",
    ["view", `${name}@${version}`, "dist.integrity", "--json", "--fetch-retries=0", "--fetch-timeout=20000"],
    { cwd: options.work, env: npmEnv(options.work, { registry: options.registry }), timeoutMs: 60_000 },
  );
  const output = `${result.stdout}\n${result.stderr}`;
  if (result.code === 0) {
    const text = result.stdout.trim();
    // An existing package without that version answers with nothing.
    if (text === "") return { state: "absent" };
    try {
      const integrity = JSON.parse(text) as unknown;
      if (typeof integrity === "string" && integrity.startsWith("sha512-")) return { state: "present", integrity };
    } catch {}
    return { state: "unreachable", detail: "the registry's answer could not be read" };
  }
  if (/E404|404 Not Found|is not in this registry/.test(output)) return { state: "absent" };
  const code = /\b(E[A-Z_]{3,}|ENOTFOUND|ECONNREFUSED|ETIMEDOUT)\b/.exec(output)?.[1] ?? `exit ${result.code}`;
  return { state: "unreachable", detail: code };
}

const UNREACHABLE = (registry: string, detail: string) =>
  `the registry could not be reached (${registry}: ${detail}); nothing was checked there. Go online and run this again`;

/** Before publishing: the folder is a trusted release folder and none of its versions exists on the registry. */
export async function releaseCheck(dir: string, options: CheckOptions): Promise<CheckResult> {
  const result = releaseFolder(dir, options);
  if (result.problems.length > 0) return result;
  result.asked = true;
  for (const tarball of result.tarballs) {
    const answer = await ask(tarball.name, tarball.version, options);
    if (answer.state === "unreachable") {
      result.problems.push(UNREACHABLE(options.registry, answer.detail));
      return result;
    }
    if (answer.state === "present") {
      tarball.registry = answer.integrity === tarball.integrity ? "same" : "different";
      result.problems.push(
        `${tarball.name}@${tarball.version} is already on the registry: that version can never be published again`,
      );
    } else tarball.registry = "absent";
  }
  if (result.problems.length > 0) return result;
  result.ok = true;
  result.commands = [
    "npm login",
    ...result.tarballs.map((tarball) => `npm publish ${shellQuote(tarball.path)} --access public`),
  ];
  return result;
}

/** After publishing: the registry has each version, with the bytes of the local tarball. */
export async function publishedCheck(dir: string, options: CheckOptions): Promise<CheckResult> {
  const result = releaseFolder(dir, options);
  if (result.problems.length > 0) return result;
  result.asked = true;
  for (const tarball of result.tarballs) {
    const answer = await ask(tarball.name, tarball.version, options);
    if (answer.state === "unreachable") {
      result.problems.push(UNREACHABLE(options.registry, answer.detail));
      return result;
    }
    if (answer.state === "absent") {
      tarball.registry = "absent";
      result.problems.push(`${tarball.name}@${tarball.version} is not on the registry`);
    } else if (answer.integrity !== tarball.integrity) {
      tarball.registry = "different";
      result.problems.push(
        `${tarball.name}@${tarball.version} on the registry has another integrity than the local tarball`,
      );
    } else tarball.registry = "same";
  }
  result.ok = result.problems.length === 0;
  return result;
}
