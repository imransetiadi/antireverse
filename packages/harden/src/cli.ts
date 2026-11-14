#!/usr/bin/env node
// The `antireverse` CLI. `antireverse harden <dir>` applies behaviour-preserving protection to a bundle the
// developer OWNS, prints a report, and — with `--register` — registers the Build Manifest with the API.
//
// Safety properties enforced here:
//   - The admin key is read ONLY from the named environment variable (`--key-env`), never from an argument,
//     and is never printed.
//   - Local-first: nothing but the Manifest (with the components, routes and logic beside it) leaves the machine, and only
//     when `--register` is passed; the protected output files leave it only with `--assess`.
//   - The run exits non-zero on any failure: a parse error, an equivalence failure, a budget that even
//     mangle-only cannot satisfy, Canaries (with the Clone Beacon, when on) that fit no file's budget, or a
//     register error.
//   - Clone Beacon (slice 10): `--origin` needs `--register`; origins are validated with the other --register
//     arguments, before any work (exit 2); the token is derived locally from the seed, App and version.
//   - Integrity marker (slice 21a): with --register one more statement is planted with the Canaries: the Build id and
//     up to 32 artifact paths under `globalThis[Symbol.for("ar.build")]`, identifiers only. It never fails a run: when
//     it does not fit the size budget it is planted with fewer files or not at all, and the report and the Manifest
//     (`integrity.files`) say so. `--no-integrity-marker` turns it off. It is not the `--integrity` self-check.
//   - Leak scan (slice 07): every input file is scanned before any transform. An unsuppressed finding exits
//     with code 3, writes nothing and registers nothing. A finding's value is never printed: only its rule,
//     path:line, mask and fingerprint. There is no flag to skip the scan.
//   - Component inventory (slice 19): the lockfile (`--lockfile`, default ./package-lock.json in the cwd) is read
//     before any work; a given-but-missing or unparseable lockfile, or one over 5,000 components, exits 2. Only
//     names, versions and the dev flag are sent, beside the Manifest, and only with --register; package names
//     are never printed (counts only), except the findings summary's items. `--fail-on <level>` needs
//     --register and exits 4 when the registered Build has open findings at or above the level.
//   - Route inventory (slice 12a): `--routes <file>` is read and validated before any work (exit 2, naming an entry
//     by position, never by value). The routes are sent beside the Manifest only with --register (the Manifest
//     carries their count and digest); they are never written into the output and never printed beyond a count.
//   - Logic file (slice 12b): `--logic <file>` (the designated protected functions with their hidden vectors, at most
//     1 MB) is read and validated before any work (exit 2, naming a place in the file, never a value). Like the routes
//     it is sent beside the Manifest only with --register (the Manifest carries `logic_count` and `logic_digest`); it
//     is never written into the output, never uploaded with --assess and never printed beyond a count.
//   - Reverse Assessment (slice 12a): `--assess <T1|T2|T3>` needs --register and is validated with it. The
//     protected output files (exactly the Manifest's artifacts) are uploaded only after a successful registration.
//     Output over the 25 MB / 1,000-file limits is registered and written as usual, and the upload is skipped (never
//     sent) with the reason. A skipped or failed upload exits 1 but the Build stays registered (and --out is written).
//   - CI gate (slice 13): `--min-rrs <0–100>` needs --assess and is validated with it (with `--wait` and `--on-no-score`,
//     which need --min-rrs), before any work. After the Assessment is queued the run polls it until it finishes or the
//     wait ends: exit 5 below the threshold, 6 with no score (unless `--on-no-score pass`). When the findings gate (4)
//     also fails, 4 wins and both gates are reported. `antireverse gate --assessment <asm_id>` does the same for an
//     Assessment queued by an earlier step. Only Objective names and results are printed — never evidence, never the key.
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, readdirSync, readFileSync, realpathSync, writeFileSync } from "node:fs";
import { dirname, join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type AssessmentTier,
  BEACON_LIMITS,
  type Canary,
  type Component,
  canonicalOrigin,
  ENVIRONMENTS,
  type Environment,
  type FindingsSummary,
  ID_PATTERNS,
  INTEGRITY_LIMITS,
  isLocalOrigin,
  type LogicFile,
  type ManifestBeacon,
  PROFILES,
  type Profile,
  TIER_IDS,
} from "@antireverse/protocol";
import {
  componentsDigest,
  deriveBeaconToken,
  logicDigest,
  newId,
  routesDigest,
  seedId,
} from "@antireverse/protocol/server";
import { type AssessmentFile, assessmentUploadProblem, consoleBuildUrl, requestAssessment } from "./assess.ts";
import { beaconEndpointUrl } from "./beacon.ts";
import type { PlantedMarker } from "./canaries.ts";
import { readComponents } from "./components.ts";
import { type BundleLeakScan, hardenBundle } from "./engine.ts";
import { checkEquivalence } from "./equivalence.ts";
import {
  defaultWaitSeconds,
  endpointHasCredentials,
  evaluateRrsGate,
  MIN_RRS_RANGE,
  ON_NO_SCORE,
  type OnNoScore,
  parseBoundedInt,
  type RrsGate,
  readAdminKey,
  rrsGateExit,
  rrsGateLines,
  rrsGateMessage,
  WAIT_RANGE,
  type WaitIo,
  waitForAssessment,
} from "./gate.ts";
import { DEFAULT_ALLOWLIST_PATH, type LeakFinding, loadAllowlist } from "./leaks/scan.ts";
import { readLogic } from "./logic.ts";
import { buildManifest } from "./manifest.ts";
import { applyIntegrity } from "./passes/integrity.ts";
import { registerBuild } from "./register.ts";
import { readRoutes } from "./routes.ts";

/** The I/O surface, injected so the CLI is testable without spawning a process. */
export interface CliIo {
  env: Record<string, string | undefined>;
  stdout: (s: string) => void;
  stderr: (s: string) => void;
  /** The working directory the default allowlist and `--leak-allow` resolve against. Default: process.cwd(). */
  cwd?: string;
  /** The fetch the RRS gate polls with (slice 13). Default: the global fetch, looked up at call time. */
  fetch?: typeof globalThis.fetch;
  /** The clock of the RRS gate's wait, in milliseconds. Default: Date.now. */
  now?: () => number;
  /** The RRS gate's backoff sleep. Default: a timer. */
  sleep?: (ms: number) => Promise<void>;
  /** The abort signal of one RRS gate poll. Default: AbortSignal.timeout. */
  timeout?: (ms: number) => AbortSignal;
}

/**
 * The wait loop's I/O from the CLI's, with the real fetch, clock, timer and timeout as defaults. Progress goes to
 * stderr only (every 60 s), so `--json` on stdout stays clean.
 */
function waitIo(io: CliIo, command: string, id: string): WaitIo {
  return {
    fetch: io.fetch ?? ((input, init) => globalThis.fetch(input, init)),
    // Monotonic: a wall-clock step (NTP, a VM resume) never stretches or cuts the wait.
    now: io.now ?? (() => performance.now()),
    sleep: io.sleep ?? ((ms) => new Promise((done) => setTimeout(done, ms))),
    timeout: io.timeout ?? ((ms) => AbortSignal.timeout(ms)),
    onProgress: (status, elapsed) =>
      io.stderr(`${command}: waiting for assessment ${id}: ${status ?? "no answer yet"}, ${elapsed} s elapsed\n`),
  };
}

/** Exit code of a run stopped by the leak scan (distinct from other failures). */
export const EXIT_LEAKS = 3;

/** Exit code of a registered Build whose open findings reach the `--fail-on` level (slice 19). */
export const EXIT_FINDINGS = 4;

export { EXIT_NO_SCORE, EXIT_RRS_BELOW } from "./gate.ts";

/** The `--fail-on` levels, lowest first. `unknown` severity is not a level and never counts towards one. */
const FAIL_ON_LEVELS = ["low", "medium", "high", "critical"] as const;
type FailOnLevel = (typeof FAIL_ON_LEVELS)[number];

/** The Console the `--assess` link points to when `AR_CONSOLE_URL` is not set (as the API's alert links). */
const DEFAULT_CONSOLE_URL = "http://127.0.0.1:3000";

/** The default lockfile, relative to the working directory. */
const DEFAULT_LOCKFILE = "package-lock.json";

const SOURCE_EXTENSIONS = [".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx"];
const SKIP_DIRS = new Set(["node_modules", "dist", ".git", ".next", "coverage", "build"]);
/** Directories the leak scan does not read: dependencies and version control are not part of the bundle. */
const SCAN_SKIP_DIRS = new Set(["node_modules", ".git"]);

const HELP = `antireverse harden <dir> — defensive build-time protection for a bundle you own.
antireverse gate — fail a CI step when a Build's Reverse Resistance Score is below your threshold.

Responsible use: Harden protects software you own and never changes its behaviour (the equivalence gate proves it); it is not for evading detection or protecting software you do not own.

Usage:
  antireverse harden <dir> --profile <light|balanced|maximum> [options]
  antireverse gate --assessment <asm_id> --min-rrs <0-100> --endpoint <url> --key-env <VAR> [--wait <s>] [--on-no-score <fail|pass>] [--json]

Options:
  --profile <p>        Protection profile (default: balanced). light = mangle; balanced/maximum = mangle + string encryption.
  --seed <n>           Integer seed for reproducible output (default: derived from the Build id).
  --map <file.json>    JSON map of "relative/path": "skip" to emit a file unchanged.
  --integrity          Wrap already-bundled (non-ESM) output in a tamper self-check. Refused on ESM input.
  --out <dir>          Write the protected files to <dir> (default: report only, nothing written).
  --test <command>     Run this command against the protected copy as the equivalence gate; a failure fails the run.
  --json               Print a machine-readable JSON report instead of the human one.
  --leak-allow <file>  Leak allowlist (default: ${DEFAULT_ALLOWLIST_PATH} in the working directory).

Leak scan: every file of <dir> is scanned for secrets, source maps and internal URLs before any transform.
A finding fails the run with exit code 3 (nothing written, nothing registered); accept a reviewed finding by
adding its fingerprint to the allowlist: { "version": 1, "allow": [{ "fingerprint": "<32 hex>", "reason": "…" }] }.

Canaries: each Build gets one decoy key and two decoy routes, planted in one protected file. They are watched
only when the Build is registered.

Clone Beacon (needs --register):
  --origin <origin>    An origin the bundle is served from, canonical scheme://host[:port] (http or https), not
                       local; repeat for up to ${BEACON_LIMITS.originsMax}. A copy of the bundle running on any other public origin
                       reports it once (navigator.sendBeacon to <endpoint>/v1/beacon). Planted with the Canaries.

Integrity marker (on with --register):
  --no-integrity-marker
                       Do not plant the integrity marker. By default a registered Build carries one statement, planted
                       with the Canaries, that names the Build id and up to ${INTEGRITY_LIMITS.filesMax} of its files (paths only, never a
                       hash) under globalThis[Symbol.for("ar.build")], so that Guard can report what a browser received
                       and the API can compare it with this Build. It never fails a run: when it does not fit the size
                       budget it is planted with fewer files, or not at all, and the report says so. Serve the files
                       byte-identical: a step that rewrites them after Harden (a minifier, an HTML rewriter, a CDN
                       that injects code) changes their hashes.

Register the Build (sends ONLY the Manifest — no source, no bundle, no seed — and, beside it, the lockfile's
components, the --routes inventory and the --logic file):
  --register --endpoint <url> --key-env <VAR> --app <appId> --environment <env> --build-version <v>
  The admin key is read only from the environment variable named by --key-env; it is never printed.

Component inventory (known-vulnerability findings):
  --lockfile <path>    npm lockfile to read (default: ./${DEFAULT_LOCKFILE}; when absent, inventory is skipped).
                       Only package names, versions and the dev flag are sent, and only with --register.
  --fail-on <level>    With --register: exit 4 when the Build has open findings at or above
                       <${FAIL_ON_LEVELS.join("|")}>, or when the API returns no findings summary;
                       each one is listed with its fix version. Unknown severity is reported, never counted.

Route inventory (Reverse Assessment, W1 Map):
  --routes <file>      JSON array of "METHOD /path" (":param" segments), at most 2,000. Sent beside the Manifest
                       with --register (the Manifest carries only their count and digest); never written to --out,
                       never printed beyond a count, never shown to the assessing agent.

Protected functions (Reverse Assessment, W3 Logic):
  --logic <file>       JSON { "functions": [{ "id", "description", "examples", "vectors" }] }: 1–5 functions, each
                       with up to 2 public examples and 10–200 hidden test vectors ({ "input": [args], "output" }),
                       at most 1 MB. Sent beside the Manifest with --register (the Manifest carries only their count
                       and digest); never written to --out, never printed beyond a count. The assessing agent sees
                       each function's id, description and examples, never the vectors.

Reverse Assessment (needs --register):
  --assess <${TIER_IDS.join("|")}>  After registration, upload the protected output files (at most 25 MB and 1,000 files)
                       and request an Assessment at that tier. Prints the Assessment id and the Console link
                       (AR_CONSOLE_URL, default ${DEFAULT_CONSOLE_URL}). Output over the limits is registered and written but not uploaded. A skipped or failed request exits 1;
                       the Build stays registered.

CI gate on the Reverse Resistance Score (needs --assess, or use antireverse gate for an earlier Assessment):
  --min-rrs <0-100>    Wait for the Assessment and exit 5 when its RRS is below this integer (at or above: exit 0).
                       Prints the score, the threshold, the status and the two weakest Objectives.
  --wait <s>           Seconds to wait for the Assessment to finish, 1–86,400 (default: the tier's seconds plus 300).
                       Polls GET /v1/assessments/:id with backoff 2 s doubling to 30 s until the wait ends, with a
                       last poll at its end; each poll is aborted after 15 s or the time left (at least 2 s), so a
                       run may exceed --wait by up to 2 s. Network errors, timeouts, 408, 429 and 5xx are retried
                       within the wait (a Retry-After on 429 or 503 is honoured, up to the end of the wait); any other
                       4xx, a different Assessment, or a request that can never be made stops with exit 1. The wait
                       follows a monotonic clock. A progress line goes to stderr every 60 s. --out is written before
                       the wait.
  --on-no-score <fail|pass>
                       No score — inconclusive, failed, or unfinished when the wait ends — exits 6 (fail, the
                       default), or passes with a warning and the gate reported as skipped (pass).
  antireverse gate --assessment <asm_id> --min-rrs <0-100> --endpoint <url> --key-env <VAR> does the same for an
  Assessment queued by an earlier step (with --wait, --on-no-score and --json as above).
  --json reports the gate (gate in antireverse gate, rrs_gate in harden): result passed | failed | no_score | skipped,
  rrs, threshold, status, reason and the weakest Objectives; in harden, result error with a reason when the gate
  could not be evaluated (exit 1). The key is never printed; --endpoint must not carry credentials.

Exit codes: 0 ok · 1 failure · 2 usage or input error · 3 leak scan · 4 findings at or above --fail-on ·
5 RRS below --min-rrs · 6 no score (inconclusive, failed, or the wait ended). When 4 and 5 or 6 both apply, 4 wins
and both gates are reported.
`;

interface Flags {
  profile: string;
  seed?: string | undefined;
  map?: string | undefined;
  integrity: boolean;
  out?: string | undefined;
  test?: string | undefined;
  json: boolean;
  leakAllow?: string | undefined;
  register: boolean;
  endpoint?: string | undefined;
  keyEnv?: string | undefined;
  app?: string | undefined;
  environment?: string | undefined;
  buildVersion?: string | undefined;
  /** `--origin` values in the order given; `undefined` marks an `--origin` with no value. */
  origins: Array<string | undefined>;
  /** `--no-integrity-marker`: the integrity marker is not planted (slice 21a). */
  noIntegrityMarker: boolean;
  /** `--lockfile`: absent = the default; `null` = the flag was given without a value. */
  lockfile?: string | null | undefined;
  /** `--fail-on`: absent = no gate; `null` = the flag was given without a value. */
  failOn?: string | null | undefined;
  /** `--routes`: absent = no inventory; `null` = the flag was given without a value. */
  routes?: string | null | undefined;
  /** `--logic`: absent = no protected functions; `null` = the flag was given without a value. */
  logic?: string | null | undefined;
  /** `--assess`: absent = no Assessment; `null` = the flag was given without a value. */
  assess?: string | null | undefined;
  /** `--min-rrs`: absent = no RRS gate; `null` = the flag was given without a value. */
  minRrs?: string | null | undefined;
  /** `--wait`: absent = the default; `null` = the flag was given without a value. */
  wait?: string | null | undefined;
  /** `--on-no-score`: absent = fail; `null` = the flag was given without a value. */
  onNoScore?: string | null | undefined;
}

function parseFlags(args: string[]): { dir: string | undefined; flags: Flags; unknown: string | undefined } {
  const flags: Flags = {
    profile: "balanced",
    integrity: false,
    json: false,
    register: false,
    origins: [],
    noIntegrityMarker: false,
  };
  let dir: string | undefined;
  /** The first unknown `--flag`: refused, so its value is never taken as the bundle folder. */
  let unknown: string | undefined;
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    switch (arg) {
      case "--profile":
        flags.profile = args[++i] ?? "";
        break;
      case "--seed":
        flags.seed = args[++i];
        break;
      case "--map":
        flags.map = args[++i];
        break;
      case "--integrity":
        flags.integrity = true;
        break;
      case "--out":
        flags.out = args[++i];
        break;
      case "--test":
        flags.test = args[++i];
        break;
      case "--json":
        flags.json = true;
        break;
      case "--leak-allow":
        flags.leakAllow = args[++i];
        break;
      case "--register":
        flags.register = true;
        break;
      case "--endpoint":
        flags.endpoint = args[++i];
        break;
      case "--key-env":
        flags.keyEnv = args[++i];
        break;
      case "--app":
        flags.app = args[++i];
        break;
      case "--environment":
        flags.environment = args[++i];
        break;
      case "--build-version":
        flags.buildVersion = args[++i];
        break;
      case "--origin":
        flags.origins.push(args[++i]);
        break;
      case "--no-integrity-marker":
        flags.noIntegrityMarker = true;
        break;
      case "--lockfile":
        flags.lockfile = args[++i] ?? null;
        break;
      case "--fail-on":
        flags.failOn = args[++i] ?? null;
        break;
      case "--routes":
        flags.routes = args[++i] ?? null;
        break;
      case "--logic":
        flags.logic = args[++i] ?? null;
        break;
      case "--assess":
        flags.assess = args[++i] ?? null;
        break;
      case "--min-rrs":
        flags.minRrs = args[++i] ?? null;
        break;
      case "--wait":
        flags.wait = args[++i] ?? null;
        break;
      case "--on-no-score":
        flags.onNoScore = args[++i] ?? null;
        break;
      default:
        if (arg?.startsWith("--")) unknown ??= arg;
        else if (arg && dir === undefined) dir = arg;
        break;
    }
  }
  return { dir, flags, unknown };
}

/** Reads every source file under `dir`, keyed by its path relative to `dir` (posix separators, sorted). */
function readSources(dir: string): Record<string, string> {
  const entries = readdirSync(dir, { recursive: true, withFileTypes: true });
  const files: Array<[string, string]> = [];
  for (const entry of entries) {
    if (!entry.isFile()) continue;
    if (!SOURCE_EXTENSIONS.some((ext) => entry.name.endsWith(ext))) continue;
    const full = join(entry.parentPath, entry.name);
    const rel = relative(dir, full).split(sep).join("/");
    // The skip list applies to directories INSIDE the bundle, so it is checked on the relative path: a bundle
    // that itself lives under e.g. /ci/build/app must still be read.
    if (
      rel
        .split("/")
        .slice(0, -1)
        .some((part) => SKIP_DIRS.has(part))
    )
      continue;
    files.push([rel, readFileSync(full, "utf8")]);
  }
  files.sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
  return Object.fromEntries(files);
}

interface BundleFiles {
  /** Every file name under `dir` (relative, posix, sorted), binary ones included. */
  fileNames: string[];
  /** The non-source files that are valid UTF-8 text: scanned, never transformed. */
  extraFiles: Array<{ path: string; text: string }>;
  /** What the scan could not read as UTF-8 (reported, by path). */
  coverage: ScanCoverage;
}

interface ScanCoverage {
  /** Files with a NUL byte that are not valid UTF-8 (binary): not scanned. */
  notScanned: string[];
  /** Files that are not valid UTF-8 but have no NUL byte: scanned decoded as latin1 (every rule is ASCII). */
  latin1: string[];
}

/** Reads every non-source file under `dir` for the leak scan (skipping only node_modules and .git). */
function readBundleFiles(dir: string, sources: Record<string, string>): BundleFiles {
  const decoder = new TextDecoder("utf-8", { fatal: true });
  const fileNames: string[] = [];
  const extraFiles: Array<{ path: string; text: string }> = [];
  const notScanned: string[] = [];
  const latin1: string[] = [];
  for (const entry of readdirSync(dir, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const full = join(entry.parentPath, entry.name);
    const rel = relative(dir, full).split(sep).join("/");
    if (rel.split("/").some((part) => SCAN_SKIP_DIRS.has(part))) continue;
    fileNames.push(rel);
    if (rel in sources) continue;
    const bytes = readFileSync(full);
    try {
      extraFiles.push({ path: rel, text: decoder.decode(bytes) });
    } catch {
      // Not UTF-8. A file with a NUL byte is treated as binary and skipped (but listed); anything else is
      // scanned decoded as latin1, which maps every byte to one character, so ASCII secrets are still found.
      if (bytes.includes(0)) {
        notScanned.push(rel);
      } else {
        extraFiles.push({ path: rel, text: bytes.toString("latin1") });
        latin1.push(rel);
      }
    }
  }
  const byPath = (a: string, b: string) => (a < b ? -1 : a > b ? 1 : 0);
  fileNames.sort(byPath);
  extraFiles.sort((a, b) => byPath(a.path, b.path));
  notScanned.sort(byPath);
  latin1.sort(byPath);
  return { fileNames, extraFiles, coverage: { notScanned, latin1 } };
}

/** A deterministic numeric seed derived from a Build id (used when `--seed` is not given). */
function seedFromBuildId(buildId: string): number {
  return createHash("sha256").update(buildId).digest().readUInt32BE(0);
}

export async function main(argv: string[], io: CliIo): Promise<number> {
  if (argv.length === 0 || argv.includes("--help") || argv.includes("-h")) {
    io.stdout(HELP);
    return 0;
  }
  if (argv[0] === "gate") return runGate(argv.slice(1), io);
  if (argv[0] !== "harden") {
    io.stderr(`unknown command: ${argv[0]}\n`);
    return 2;
  }

  const { dir, flags, unknown } = parseFlags(argv.slice(1));
  if (unknown !== undefined) {
    io.stderr(`harden: unknown option ${unknown}\n`);
    return 2;
  }
  if (!dir) {
    io.stderr("harden: a <dir> is required\n");
    return 2;
  }
  if (!(PROFILES as readonly string[]).includes(flags.profile)) {
    io.stderr(`harden: unknown profile "${flags.profile}" (expected ${PROFILES.join(", ")})\n`);
    return 2;
  }
  const profile = flags.profile as Profile;

  const buildId = newId("bld");
  const rawSeed = flags.seed !== undefined ? Number.parseInt(flags.seed, 10) : seedFromBuildId(buildId);
  if (!Number.isFinite(rawSeed)) {
    io.stderr(`harden: --seed must be an integer\n`);
    return 2;
  }
  // Normalised once (plan amendment A1): the PRNG and the Canaries use the same 32-bit seed.
  const seed = rawSeed >>> 0;

  // The --register arguments are validated before any scan or transform work, so a usage error (a missing
  // flag, an unset key variable, an unknown environment) is reported whatever the bundle holds.
  let registerKey: string | undefined;
  if (flags.register) {
    const missing = (["endpoint", "keyEnv", "app", "environment", "buildVersion"] as const).filter(
      (k) => flags[k] === undefined,
    );
    if (missing.length > 0) {
      io.stderr(`harden: --register needs --endpoint, --key-env, --app, --environment, --build-version\n`);
      return 2;
    }
    if (endpointHasCredentials(flags.endpoint as string)) {
      io.stderr("harden: --endpoint must not contain credentials (user:pass@); the key is read from --key-env\n");
      return 2;
    }
    const read = readAdminKey("harden", flags.keyEnv, io.env);
    if ("error" in read) {
      io.stderr(`${read.error}\n`);
      return 2;
    }
    registerKey = read.key;
    if (!(ENVIRONMENTS as readonly string[]).includes(flags.environment as string)) {
      io.stderr(`harden: unknown --environment "${flags.environment}" (expected ${ENVIRONMENTS.join(", ")})\n`);
      return 2;
    }
    if (!ID_PATTERNS.app.test(flags.app as string)) {
      io.stderr(`harden: --app must be an App id (app_<24 hex>)\n`);
      return 2;
    }
    if (/[\r\n]/.test(flags.buildVersion as string) || (flags.buildVersion as string).length === 0) {
      io.stderr(`harden: --build-version must be a non-empty single line\n`);
      return 2;
    }
  }

  // The findings gate (slice 19), validated with the --register arguments, before any work.
  let failOn: FailOnLevel | undefined;
  if (flags.failOn !== undefined) {
    if (!flags.register) {
      io.stderr("harden: --fail-on needs --register (findings come from the registered Build)\n");
      return 2;
    }
    if (flags.failOn === null || !(FAIL_ON_LEVELS as readonly string[]).includes(flags.failOn)) {
      io.stderr(`harden: --fail-on must be one of ${FAIL_ON_LEVELS.join(", ")}\n`);
      return 2;
    }
    failOn = flags.failOn as FailOnLevel;
  }

  // The Assessment tier (slice 12a), validated with the --register arguments, before any work.
  let assessTier: AssessmentTier | undefined;
  if (flags.assess !== undefined) {
    if (!flags.register) {
      io.stderr("harden: --assess needs --register (only a registered Build can be assessed)\n");
      return 2;
    }
    if (flags.assess === null || !(TIER_IDS as readonly string[]).includes(flags.assess)) {
      io.stderr(`harden: --assess must be one of ${TIER_IDS.join(", ")}\n`);
      return 2;
    }
    assessTier = flags.assess as AssessmentTier;
  }

  // The RRS gate (slice 13), validated with --assess, before any work.
  const rrsGateArgs = rrsGateFlagsProblem("harden", flags, assessTier !== undefined, "--assess");
  if ("error" in rrsGateArgs) {
    io.stderr(`${rrsGateArgs.error}\n`);
    return 2;
  }

  // The Clone Beacon's origins (slice 10), validated with the --register arguments, before any work.
  let beaconOrigins: string[] | undefined;
  if (flags.origins.length > 0) {
    const problem = originsProblem(flags);
    if (problem !== null) {
      io.stderr(`harden: ${problem}\n`);
      return 2;
    }
    beaconOrigins = flags.origins as string[];
  }

  // The allowlist is read next: a malformed or missing-but-given file fails before any scan or transform.
  const allowLoad = loadAllowlist({ cwd: io.cwd ?? process.cwd(), file: flags.leakAllow });
  if ("error" in allowLoad) {
    io.stderr(`harden: ${allowLoad.error}\n`);
    return 2;
  }

  // The component inventory (slice 19), read before any work: a given-but-missing or unparseable lockfile, or
  // one over the limit, is an input error (exit 2). A missing default lockfile only turns the inventory off.
  const cwd = io.cwd ?? process.cwd();
  let inventory: { components: Component[]; skipped: number } | null = null;
  /** Dependencies the lockfile listed when every one was skipped: then no list is sent at all (see below). */
  let allSkipped: number | null = null;
  if (flags.lockfile === null || flags.lockfile === "") {
    io.stderr("harden: --lockfile needs a path\n");
    return 2;
  }
  const lockfilePath = resolve(cwd, flags.lockfile ?? DEFAULT_LOCKFILE);
  if (flags.lockfile !== undefined || existsSync(lockfilePath)) {
    const read = readComponents(lockfilePath);
    if ("error" in read) {
      io.stderr(`harden: lockfile ${flags.lockfile ?? `./${DEFAULT_LOCKFILE}`} ${read.error}\n`);
      return 2;
    }
    // A lockfile that lists dependencies none of which could be read says nothing about what the Build ships. An
    // empty list would tell the API it ships nothing (and fix every older Finding), so the inventory is off for this
    // Build instead. Only a lockfile that truly lists no dependencies sends [].
    if (read.components.length === 0 && read.skipped > 0) allSkipped = read.skipped;
    else inventory = read;
  }

  // The route inventory (slice 12a), read before any work: an unreadable or invalid file is an input error (exit 2).
  // The message names an entry by position only — a route is never printed.
  let routes: string[] | null = null;
  if (flags.routes !== undefined) {
    if (flags.routes === null || flags.routes === "") {
      io.stderr("harden: --routes needs a path\n");
      return 2;
    }
    const read = readRoutes(resolve(cwd, flags.routes));
    if ("error" in read) {
      io.stderr(`harden: --routes ${flags.routes} ${read.error}\n`);
      return 2;
    }
    routes = read.routes;
  }

  // The logic file (slice 12b), read before any work like the routes: an unreadable, invalid or oversized file is an
  // input error (exit 2). The message names a place in the file only — a vector is never printed.
  let logic: LogicFile | null = null;
  if (flags.logic !== undefined) {
    if (flags.logic === null || flags.logic === "") {
      io.stderr("harden: --logic needs a path\n");
      return 2;
    }
    const read = readLogic(resolve(cwd, flags.logic));
    if ("error" in read) {
      io.stderr(`harden: --logic ${flags.logic} ${read.error}\n`);
      return 2;
    }
    logic = read.logic;
  }

  let sources: Record<string, string>;
  try {
    sources = readSources(dir);
  } catch (error) {
    io.stderr(`harden: cannot read ${dir} (${error instanceof Error ? error.message : String(error)})\n`);
    return 2;
  }
  if (Object.keys(sources).length === 0) {
    io.stderr(`harden: no source files found under ${dir}\n`);
    return 2;
  }

  let protectionMap: Record<string, "skip"> | undefined;
  if (flags.map) {
    try {
      const raw = JSON.parse(readFileSync(flags.map, "utf8")) as Record<string, string>;
      protectionMap = {};
      for (const [path, value] of Object.entries(raw)) {
        if (value !== "skip") {
          io.stderr(`harden: --map value for "${path}" must be "skip"\n`);
          return 2;
        }
        protectionMap[path] = "skip";
      }
    } catch (error) {
      io.stderr(`harden: cannot read --map file (${error instanceof Error ? error.message : String(error)})\n`);
      return 2;
    }
  }

  let bundleFiles: BundleFiles;
  try {
    bundleFiles = readBundleFiles(dir, sources);
  } catch (error) {
    io.stderr(`harden: cannot read ${dir} (${error instanceof Error ? error.message : String(error)})\n`);
    return 2;
  }

  const result = hardenBundle(
    { sources, extraFiles: bundleFiles.extraFiles, fileNames: bundleFiles.fileNames },
    {
      profile,
      seed,
      allow: allowLoad.allow,
      ...(protectionMap ? { protectionMap } : {}),
      // A registered Build's Canaries are scoped to its App and version (the API keys Canaries per Organization).
      ...(flags.register ? { canaryScope: { appId: flags.app as string, version: flags.buildVersion as string } } : {}),
      // The Clone Beacon token is derived from the normalised seed, App and version (only with --origin).
      ...(beaconOrigins
        ? {
            beacon: {
              appId: flags.app as string,
              token: deriveBeaconToken(seed, { appId: flags.app as string, version: flags.buildVersion as string }),
              origins: beaconOrigins,
              endpoint: flags.endpoint as string,
            },
          }
        : {}),
      // The integrity marker names the Build this run registers (slice 21a): only with --register.
      ...(flags.register && !flags.noIntegrityMarker ? { integrityMarker: { buildId } } : {}),
    },
  );

  // Leaks fail the run with exit code 3: nothing is written and nothing is registered.
  if (result.leakScan.status === "failed") {
    emitLeakFailure(io, {
      profile,
      seed,
      leakScan: result.leakScan,
      coverage: bundleFiles.coverage,
      json: flags.json,
    });
    io.stderr(
      `harden: leak scan found ${countFindings(result.leakScan.findings.length)}; nothing written or registered.\n`,
    );
    return EXIT_LEAKS;
  }

  // Parse errors fail the run: nothing is written and nothing is registered.
  const broken = result.files.filter((f) => f.error !== undefined);
  if (broken.length > 0) {
    for (const f of broken) io.stderr(`harden: ${f.path}: ${f.error}\n`);
    return 1;
  }

  // Canaries are never dropped silently: if no protected file can hold them within budget, the run fails.
  if (result.plantError !== undefined || result.plantedIn === null) {
    io.stderr(`${result.plantError ?? "harden: Canaries were not planted"}; nothing written or registered.\n`);
    return 1;
  }

  // Protected code per path (post-integrity if requested). The Canaries are already planted, so the integrity
  // wrapper hashes the planted code and its self-check passes.
  const codeByPath = new Map<string, string>(result.files.map((f) => [f.path, f.code]));
  let integrity = false;
  if (flags.integrity) {
    integrity = true;
    for (const f of result.files) {
      if (f.skipped) continue;
      try {
        codeByPath.set(f.path, applyIntegrity(f.code));
      } catch (error) {
        io.stderr(`harden: ${f.path}: ${error instanceof Error ? error.message : String(error)}\n`);
        return 1;
      }
    }
  }

  const protectedFiles = Object.fromEntries(codeByPath);

  // Equivalence gate (only when a test command is given in this slice).
  let equivalence: "passed" | "skipped" = "skipped";
  if (flags.test) {
    const check = await checkEquivalence({ dir, testCommand: flags.test, protectedFiles });
    if (!check.passed) {
      io.stderr(`harden: equivalence gate failed; nothing written or registered.\n${check.output}\n`);
      return 1;
    }
    equivalence = "passed";
  }

  const transform = { ...result.transform, integrity };

  // The Assessment's upload is exactly the Manifest's artifacts.
  const assessFiles: AssessmentFile[] = Object.entries(protectedFiles).map(([path, code]) => ({ path, code }));

  // Register (sends only the Manifest and, beside it, the components).
  let registered: { build_id: string } | { error: string } | undefined;
  let findings: FindingsSummary | null = null;
  if (flags.register) {
    const key = registerKey as string;
    const manifest = buildManifest({
      buildId,
      appId: flags.app as string,
      environment: flags.environment as Environment,
      version: flags.buildVersion as string,
      profile,
      seed,
      artifacts: assessFiles,
      originals: sources,
      transform,
      equivalence,
      leakScan: {
        status: result.leakScan.status === "suppressed" ? "suppressed" : "clean",
        suppressed: result.leakScan.suppressed,
      },
      canaries: result.canaries,
      ...(result.beacon ? { beacon: result.beacon } : {}),
      ...(inventory
        ? { components: { count: inventory.components.length, digest: componentsDigest(inventory.components) } }
        : {}),
      ...(routes ? { routes: { count: routes.length, digest: routesDigest(routes) } } : {}),
      ...(logic ? { logic: { count: logic.functions.length, digest: logicDigest(logic) } } : {}),
      ...(result.integrity ? { integrityFiles: result.integrity.files } : {}),
    });
    const reg = await registerBuild({
      endpoint: flags.endpoint as string,
      key,
      appId: flags.app as string,
      manifest,
      ...(inventory ? { components: inventory.components } : {}),
      ...(routes ? { routes } : {}),
      ...(logic ? { logic } : {}),
    });
    if ("error" in reg) {
      io.stderr(`harden: register failed: ${reg.error}\n`);
      return 1;
    }
    registered = { build_id: reg.build.build_id };
    findings = reg.findings ?? null;
  }

  // The Assessment (slice 12a), requested only after a successful registration. Output over the upload limits
  // (25 MB / 1,000 files) does not block hardening (Jev: register_then_refuse, 0.77): the Build is registered and
  // written as usual and the upload is skipped. Neither a skip nor a failure undoes the registration: the files are
  // still written and the run then exits 1.
  let assessment: AssessmentReport | undefined;
  const uploadProblem = assessTier ? assessmentUploadProblem(assessFiles) : null;
  if (assessTier && registered && "build_id" in registered && uploadProblem !== null) {
    assessment = { error: uploadProblem, skipped: true };
  } else if (assessTier && registered && "build_id" in registered) {
    const requested = await requestAssessment({
      endpoint: flags.endpoint as string,
      key: registerKey as string,
      appId: flags.app as string,
      buildId: registered.build_id,
      tier: assessTier,
      files: assessFiles,
    });
    assessment =
      "error" in requested
        ? { error: requested.error }
        : {
            id: requested.assessment.id,
            status: requested.assessment.status,
            tier: requested.assessment.tier,
            url: consoleBuildUrl(
              io.env.AR_CONSOLE_URL || DEFAULT_CONSOLE_URL,
              flags.app as string,
              registered.build_id,
            ),
          };
  }

  // Write the protected files only when an output directory is given, and only after a successful register
  // (review F5): a Build that failed to register leaves nothing behind that could be deployed unwatched. They are
  // written before the RRS gate waits (slice 13), so a CI job killed during a long wait still has its output.
  if (flags.out) {
    for (const [rel, code] of Object.entries(protectedFiles)) {
      const dest = join(flags.out, rel);
      mkdirSync(dirname(dest), { recursive: true });
      writeFileSync(dest, code, "utf8");
    }
  }

  // The RRS gate (slice 13): wait for the queued Assessment, then compare its score with --min-rrs. A gate that cannot
  // be evaluated — the Assessment was not queued, or a poll stopped the wait (a 4xx other than 408 or 429, a response
  // that is not this Assessment, a request that can never be made) — is reported as an error: exit 1.
  let rrsGate: RrsGate | RrsGateError | null = null;
  if (rrsGateArgs.minRrs !== undefined && assessment && "error" in assessment) {
    rrsGate = { result: "error", reason: `the Assessment was not queued: ${assessment.error}` };
  } else if (rrsGateArgs.minRrs !== undefined && assessment && "id" in assessment && assessTier) {
    const waited = await waitForAssessment(
      {
        endpoint: flags.endpoint as string,
        key: registerKey as string,
        id: assessment.id,
        waitSeconds: rrsGateArgs.waitSeconds ?? defaultWaitSeconds(assessTier),
      },
      waitIo(io, "harden", assessment.id),
    );
    if ("error" in waited) {
      rrsGate = { result: "error", reason: `cannot read the Assessment: ${waited.error}` };
    } else {
      rrsGate = evaluateRrsGate(waited, rrsGateArgs.minRrs, rrsGateArgs.onNoScore);
      const final = "finished" in waited ? waited.finished : waited.last;
      if (final) assessment.finalStatus = final.status;
    }
  }

  // The findings gate is decided after a successful register; the files are still written (the Build is
  // registered, so it is watched) and the run then exits 4.
  const gate = failOn ? evaluateGate(failOn, findings) : null;

  const fileReports = result.files.map((f) => ({
    path: f.path,
    bytes: Buffer.byteLength(protectedFiles[f.path] ?? f.code, "utf8"),
    renamed: f.renamed,
    strings_encrypted: f.stringsEncrypted,
    skipped: f.skipped,
    ...(f.mangleOnly ? { mangle_only: f.mangleOnly } : {}),
  }));

  emitReport(io, {
    profile,
    seed,
    equivalence,
    integrity,
    transform,
    files: fileReports,
    registered,
    flags,
    leakScan: result.leakScan,
    coverage: bundleFiles.coverage,
    canaries: result.canaries,
    plantedIn: result.plantedIn,
    beacon: result.beacon,
    marker: result.integrity,
    inventory,
    allSkipped,
    findings,
    gate,
    routes,
    logic,
    assessment,
    rrsGate,
  });
  if (assessment && "error" in assessment) {
    const buildId = (registered as { build_id: string }).build_id;
    const what = assessment.skipped ? "assessment skipped" : "assessment request failed";
    io.stderr(`harden: ${what}: ${assessment.error}; the Build stays registered (${buildId})\n`);
  }
  // A gate that was not evaluated because the poll stopped (the not-queued case was reported just above).
  if (rrsGate?.result === "error" && !(assessment && "error" in assessment)) {
    const buildId = (registered as { build_id: string }).build_id;
    io.stderr(`harden: ${rrsGate.reason}; the Build stays registered (${buildId})\n`);
  }
  // Every gate's verdict is printed before the exit code is chosen, so both gates are reported.
  let findingsFailed = false;
  // Fail closed (Jev: fail_closed_unknown_excluded, 0.94): a gate that could not be evaluated fails too.
  if (gate?.noSummary) {
    io.stderr(`harden: findings gate could not be evaluated: ${NO_SUMMARY}\n`);
    findingsFailed = true;
  } else if (gate && gate.count > 0) {
    io.stderr(`harden: findings gate failed: ${gateCount(gate)} at or above ${gate.level}\n`);
    findingsFailed = true;
  }
  const rrsMessage = rrsGate && rrsGate.result !== "error" ? rrsGateMessage(rrsGate, "harden") : null;
  if (rrsMessage !== null) io.stderr(`${rrsMessage}\n`);
  // The lowest non-zero gate code wins: 4 (findings) before 5 or 6 (RRS). An error is 1, as before slice 13.
  if (findingsFailed) return EXIT_FINDINGS;
  if (assessment && "error" in assessment) return 1;
  if (rrsGate?.result === "error") return 1;
  if (rrsGate) return rrsGateExit(rrsGate);
  return 0;
}

/** An RRS gate that could not be evaluated (exit 1). */
type RrsGateError = { result: "error"; reason: string };

/** The parsed RRS gate flags, or the usage error. `needs` names the flag --min-rrs requires. */
type RrsGateArgs = { minRrs?: number; waitSeconds?: number; onNoScore: OnNoScore } | { error: string };

function rrsGateFlagsProblem(
  command: string,
  flags: {
    minRrs?: string | null | undefined;
    wait?: string | null | undefined;
    onNoScore?: string | null | undefined;
  },
  hasSource: boolean,
  needs: string,
): RrsGateArgs {
  if (flags.minRrs === undefined) {
    if (flags.wait !== undefined) return { error: `${command}: --wait needs --min-rrs` };
    if (flags.onNoScore !== undefined) return { error: `${command}: --on-no-score needs --min-rrs` };
    return { onNoScore: "fail" };
  }
  if (!hasSource) return { error: `${command}: --min-rrs needs ${needs} (the score comes from the Assessment)` };
  const minRrs = parseBoundedInt(flags.minRrs, MIN_RRS_RANGE);
  if (minRrs === null) return { error: `${command}: --min-rrs must be an integer from 0 to 100` };
  let waitSeconds: number | undefined;
  if (flags.wait !== undefined) {
    const parsed = parseBoundedInt(flags.wait, WAIT_RANGE);
    if (parsed === null) return { error: `${command}: --wait must be an integer from 1 to 86,400 (seconds)` };
    waitSeconds = parsed;
  }
  if (flags.onNoScore !== undefined && !(ON_NO_SCORE as readonly (string | null)[]).includes(flags.onNoScore)) {
    return { error: `${command}: --on-no-score must be fail or pass` };
  }
  return {
    minRrs,
    ...(waitSeconds !== undefined ? { waitSeconds } : {}),
    onNoScore: (flags.onNoScore ?? "fail") as OnNoScore,
  };
}

/**
 * `antireverse gate --assessment <asm_id> --min-rrs <n> --endpoint <url> --key-env <VAR> [--wait <s>]
 * [--on-no-score fail|pass] [--json]`: the RRS gate for an Assessment queued by an earlier step. Every argument is
 * validated before any request (exit 2); the key is read only from the named variable and never printed.
 */
async function runGate(args: string[], io: CliIo): Promise<number> {
  const flags: {
    assessment?: string | null;
    minRrs?: string | null;
    endpoint?: string | null;
    keyEnv?: string | null;
    wait?: string | null;
    onNoScore?: string | null;
    json: boolean;
  } = { json: false };
  for (let i = 0; i < args.length; i++) {
    const arg = args[i];
    const value = () => args[++i] ?? null;
    switch (arg) {
      case "--assessment":
        flags.assessment = value();
        break;
      case "--min-rrs":
        flags.minRrs = value();
        break;
      case "--endpoint":
        flags.endpoint = value();
        break;
      case "--key-env":
        flags.keyEnv = value();
        break;
      case "--wait":
        flags.wait = value();
        break;
      case "--on-no-score":
        flags.onNoScore = value();
        break;
      case "--json":
        flags.json = true;
        break;
      default:
        io.stderr(`gate: unknown argument ${JSON.stringify(arg)}\n`);
        return 2;
    }
  }
  const missing = (
    [
      ["--assessment", flags.assessment],
      ["--min-rrs", flags.minRrs],
      ["--endpoint", flags.endpoint],
      ["--key-env", flags.keyEnv],
    ] as const
  )
    .filter(([, v]) => v === undefined)
    .map(([name]) => name);
  if (missing.length > 0) {
    io.stderr(`gate: missing ${missing.join(", ")} (needs --assessment, --min-rrs, --endpoint and --key-env)\n`);
    return 2;
  }
  if (typeof flags.assessment !== "string" || !ID_PATTERNS.asm.test(flags.assessment)) {
    io.stderr("gate: --assessment must be an Assessment id (asm_<24 hex>)\n");
    return 2;
  }
  const parsed = rrsGateFlagsProblem("gate", flags, true, "--assessment");
  if ("error" in parsed) {
    io.stderr(`${parsed.error}\n`);
    return 2;
  }
  const minRrs = parsed.minRrs as number;
  if (endpointHasCredentials(flags.endpoint ?? "")) {
    io.stderr("gate: --endpoint must not contain credentials (user:pass@); the key is read from --key-env\n");
    return 2;
  }
  let endpointOk = false;
  try {
    const url = new URL(flags.endpoint ?? "");
    endpointOk = url.protocol === "https:" || url.protocol === "http:";
  } catch {
    endpointOk = false;
  }
  if (!endpointOk) {
    io.stderr("gate: --endpoint must be an http(s) URL\n");
    return 2;
  }
  const read = readAdminKey("gate", flags.keyEnv, io.env);
  if ("error" in read) {
    io.stderr(`${read.error}\n`);
    return 2;
  }
  const key = read.key;

  const id = flags.assessment;
  const waited = await waitForAssessment(
    { endpoint: flags.endpoint as string, key, id, waitSeconds: parsed.waitSeconds },
    waitIo(io, "gate", id),
  );
  if ("error" in waited) {
    if (flags.json) io.stdout(`${JSON.stringify({ assessment: { id }, gate: null, error: waited.error }, null, 2)}\n`);
    io.stderr(`gate: cannot read the Assessment: ${waited.error}\n`);
    return 1;
  }
  const gate = evaluateRrsGate(waited, minRrs, parsed.onNoScore);
  const final = "finished" in waited ? waited.finished : waited.last;
  if (flags.json) {
    const report = {
      assessment: final
        ? { id, status: final.status, tier: final.tier, rrs: final.rrs }
        : { id, status: null, tier: null, rrs: null },
      gate,
    };
    io.stdout(`${JSON.stringify(report, null, 2)}\n`);
  } else {
    io.stdout(`${rrsGateLines(gate, id, final?.tier ?? null).join("\n")}\n`);
  }
  const message = rrsGateMessage(gate, "gate");
  if (message !== null) io.stderr(`${message}\n`);
  return rrsGateExit(gate);
}

/**
 * The Assessment as the report shows it: id, status, tier and the Console link; or why there is none — the request's
 * error, or (`skipped`) the upload limit the output exceeds, in which case nothing was sent.
 */
type AssessmentReport =
  | { id: string; status: string; tier: AssessmentTier; url: string; finalStatus?: string }
  | { error: string; skipped?: boolean };

interface GateResult {
  level: FailOnLevel;
  /** Open findings at or above the level, from the summary's counts (the items may be truncated). */
  count: number;
  /** The summary's items at or above the level. */
  failed: FindingsSummary["items"];
  /** Open findings of unknown severity: never counted towards a level, but reported. */
  unknown: number;
  /** The API returned no findings summary, so nothing could be checked: the gate fails closed. */
  noSummary: boolean;
}

const NO_SUMMARY = "the API returned no findings summary";

/** The gate as `--json` reports it, or null without --fail-on. */
function gateReport(gate: GateResult | null) {
  if (gate === null) return null;
  return {
    level: gate.level,
    evaluated: !gate.noSummary,
    passed: !gate.noSummary && gate.count === 0,
    count: gate.count,
    unknown_not_counted: gate.unknown,
  };
}

function gateCount(gate: GateResult): string {
  return `${gate.count} open finding${gate.count === 1 ? "" : "s"}`;
}

/** The `--fail-on` outcome: counts and items at or above `level` (`unknown` never counts). */
function evaluateGate(level: FailOnLevel, summary: FindingsSummary | null): GateResult {
  if (summary === null) return { level, count: 0, failed: [], unknown: 0, noSummary: true };
  const levels = FAIL_ON_LEVELS.slice(FAIL_ON_LEVELS.indexOf(level)) as readonly string[];
  const count = FAIL_ON_LEVELS.slice(FAIL_ON_LEVELS.indexOf(level)).reduce((n, l) => n + summary.open[l], 0);
  const items = summary.items.filter((item) => levels.includes(item.severity));
  return { level, count, failed: items, unknown: summary.open.unknown, noSummary: false };
}

/**
 * Why the `--origin` flags are unusable, or null. Each origin must be exactly canonical (the message shows the
 * canonical form when there is one), not local, listed once; 1..20 of them; and they need --register with an
 * http(s) --endpoint (the report URL is planted in the bundle). The other --register arguments are checked first.
 */
function originsProblem(flags: Flags): string | null {
  if (!flags.register) {
    return "--origin needs --register (a Clone Beacon nobody watches is pointless)";
  }
  if (flags.origins.length > BEACON_LIMITS.originsMax) {
    return `--origin may be given at most ${BEACON_LIMITS.originsMax} times (got ${flags.origins.length})`;
  }
  const seen = new Set<string>();
  for (const origin of flags.origins) {
    if (origin === undefined || origin === "") return "--origin needs a value (scheme://host[:port])";
    const canonical = canonicalOrigin(origin);
    if (canonical === null) {
      return `--origin ${JSON.stringify(origin)} is not an http(s) origin (scheme://host[:port], no path, query or credentials)`;
    }
    if (canonical !== origin) {
      return `--origin ${JSON.stringify(origin)} is not canonical; use ${JSON.stringify(canonical)}`;
    }
    if (isLocalOrigin(origin)) {
      return `--origin ${JSON.stringify(origin)} is a local origin (a local origin never reports); list only public origins`;
    }
    if (seen.has(origin)) return `--origin ${JSON.stringify(origin)} is given twice`;
    seen.add(origin);
  }
  try {
    beaconEndpointUrl(flags.endpoint as string);
  } catch (error) {
    return `--endpoint: ${error instanceof Error ? error.message.replace(/^harden: /, "") : String(error)}`;
  }
  return null;
}

function countFindings(n: number): string {
  return `${n} finding${n === 1 ? "" : "s"}`;
}

/**
 * The report's `leak_scan`: findings are masked (never a value); `not_scanned` lists binary files (NUL byte,
 * not UTF-8) that were skipped; `decoded_as_latin1` lists non-UTF-8 files that were scanned as latin1.
 */
function leakScanReport(leakScan: BundleLeakScan, coverage: ScanCoverage) {
  return {
    status: leakScan.status,
    findings: leakScan.findings.map((f: LeakFinding) => ({
      rule: f.rule,
      path: f.path,
      line: f.line,
      masked: f.masked,
      fingerprint: f.fingerprint,
    })),
    suppressed: leakScan.suppressed,
    not_scanned: coverage.notScanned,
    decoded_as_latin1: coverage.latin1,
  };
}

function leakScanLines(leakScan: BundleLeakScan, coverage: ScanCoverage): string[] {
  const lines: string[] = [];
  if (leakScan.status === "failed") {
    lines.push(`✗ leak scan: ${countFindings(leakScan.findings.length)}`);
    for (const f of leakScan.findings) lines.push(`  ${f.rule}  ${f.path}:${f.line}  ${f.masked}  ${f.fingerprint}`);
    lines.push(
      `  accept a reviewed finding by adding its fingerprint to ${DEFAULT_ALLOWLIST_PATH} (or --leak-allow <file>)`,
    );
  } else {
    lines.push(leakScan.suppressed > 0 ? `✓ leak scan clean (${leakScan.suppressed} suppressed)` : "✓ leak scan clean");
  }
  if (coverage.latin1.length > 0) {
    lines.push(`  decoded as latin1 (not UTF-8): ${coverage.latin1.join(", ")}`);
  }
  if (coverage.notScanned.length > 0) {
    lines.push(`  not scanned (binary, not UTF-8): ${coverage.notScanned.join(", ")}`);
  }
  return lines;
}

function emitLeakFailure(
  io: CliIo,
  input: { profile: Profile; seed: number; leakScan: BundleLeakScan; coverage: ScanCoverage; json: boolean },
): void {
  if (input.json) {
    const report = {
      profile: input.profile,
      seed_id: seedId(String(input.seed)),
      leak_scan: leakScanReport(input.leakScan, input.coverage),
    };
    io.stdout(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }
  io.stdout(`${[`harden: profile ${input.profile}`, ...leakScanLines(input.leakScan, input.coverage)].join("\n")}\n`);
}

interface FileReport {
  path: string;
  bytes: number;
  renamed: number;
  strings_encrypted: number;
  skipped: boolean;
  mangle_only?: string;
}

interface ReportInput {
  profile: Profile;
  seed: number;
  equivalence: "passed" | "skipped";
  integrity: boolean;
  transform: { mangled: number; strings_encrypted: number; files_mangle_only: number; integrity: boolean };
  files: FileReport[];
  registered?: { build_id: string } | { error: string } | undefined;
  flags: Flags;
  leakScan: BundleLeakScan;
  coverage: ScanCoverage;
  canaries: Canary[];
  plantedIn: string | null;
  beacon: ManifestBeacon | null;
  /** The planted integrity marker (slice 21a); null when none was asked for. */
  marker: PlantedMarker | null;
  inventory: { components: Component[]; skipped: number } | null;
  /** The dependencies a lockfile listed when every one was skipped (inventory off); null otherwise. */
  allSkipped: number | null;
  findings: FindingsSummary | null;
  gate: GateResult | null;
  /** The route inventory (never printed: only its count). */
  routes: string[] | null;
  /** The logic file (never printed: only its function count). */
  logic: LogicFile | null;
  assessment: AssessmentReport | undefined;
  /** The RRS gate (slice 13): null without --min-rrs; `{ error }` when the wait stopped with an error. */
  rrsGate: RrsGate | RrsGateError | null;
}

function emitReport(io: CliIo, input: ReportInput): void {
  if (input.flags.json) {
    const report = {
      profile: input.profile,
      seed_id: seedId(String(input.seed)),
      integrity: input.integrity,
      equivalence: input.equivalence,
      transform: input.transform,
      files: input.files,
      leak_scan: leakScanReport(input.leakScan, input.coverage),
      // Decoy values are not secrets: the developer may want to test with them.
      canaries: input.canaries,
      canaries_planted_in: input.plantedIn,
      // The token is in the public bundle anyway; it is reported so a deployment can be checked against it.
      ...(input.beacon ? { beacon: { ...input.beacon, planted_in: input.plantedIn } } : {}),
      // The files the marker lists, in its order (empty: it did not fit and was not planted), and how many
      // protected files it had to leave out.
      ...(input.marker
        ? {
            integrity_marker: {
              files: input.marker.files,
              planted_in: input.marker.files.length > 0 ? input.plantedIn : null,
              dropped: markerDropped(input.marker),
              // With --integrity the planted file is a string inside the self-check wrapper: Guard cannot find the
              // marker in the served bytes, so the Build is registered but not watched for tampering.
              ...(input.integrity && input.marker.files.length > 0 ? { watched: false } : {}),
            },
          }
        : {}),
      ...(input.registered ? { registered: input.registered } : {}),
      // Counts only: the component list itself is never printed.
      components: input.inventory
        ? { count: input.inventory.components.length, skipped: input.inventory.skipped }
        : input.allSkipped !== null
          ? { count: 0, skipped: input.allSkipped, sent: false }
          : null,
      findings: input.findings,
      gate: gateReport(input.gate),
      // Count only: the routes themselves are never printed.
      routes: input.routes ? { count: input.routes.length } : null,
      // Count only: the functions and their vectors are never printed.
      logic: input.logic ? { count: input.logic.functions.length } : null,
      ...(input.assessment
        ? {
            assessment:
              "error" in input.assessment
                ? { error: input.assessment.error }
                : { id: input.assessment.id, status: input.assessment.finalStatus ?? input.assessment.status },
          }
        : {}),
      ...(input.rrsGate ? { rrs_gate: input.rrsGate } : {}),
    };
    io.stdout(`${JSON.stringify(report, null, 2)}\n`);
    return;
  }

  const lines: string[] = [];
  lines.push(`harden: profile ${input.profile}, ${input.files.length} file(s)`);
  lines.push(`  mangled bindings: ${input.transform.mangled}`);
  lines.push(`  strings encrypted: ${input.transform.strings_encrypted}`);
  lines.push(`  files mangle-only (over size budget): ${input.transform.files_mangle_only}`);
  lines.push(`  integrity self-check: ${input.integrity ? "on" : "off"}`);
  lines.push(`  equivalence: ${input.equivalence}`);
  for (const f of input.files) {
    if (f.mangle_only) lines.push(`  - ${f.path}: ${f.mangle_only}`);
  }
  lines.push(...leakScanLines(input.leakScan, input.coverage));
  const watched = input.flags.register ? "" : " (not watched: pass --register)";
  lines.push(`✓ ${input.canaries.length} Canaries planted in ${input.plantedIn}${watched}`);
  for (const c of input.canaries) lines.push(`  - ${c.kind} ${c.id}`);
  if (input.beacon) {
    const n = input.beacon.origins.length;
    lines.push(`✓ Clone Beacon: on (${n} origin${n === 1 ? "" : "s"}) in ${input.plantedIn}`);
  }
  lines.push(...markerLines(input));
  lines.push(...inventoryLines(input));
  lines.push(...routeLines(input));
  lines.push(...logicLines(input));
  if (input.registered) {
    lines.push("build_id" in input.registered ? `  registered: ${input.registered.build_id}` : `  register error`);
  }
  lines.push(...findingsLines(input));
  lines.push(...assessmentLines(input));
  if (input.rrsGate?.result === "error") {
    lines.push(`✗ RRS gate not evaluated: ${input.rrsGate.reason}`);
  } else if (input.rrsGate && input.assessment && "id" in input.assessment) {
    lines.push(...rrsGateLines(input.rrsGate, input.assessment.id, input.assessment.tier));
  }
  io.stdout(`${lines.join("\n")}\n`);
}

/** Protected files the marker could have listed (at most 32) and did not. */
function markerDropped(marker: PlantedMarker): number {
  return Math.min(marker.eligible, INTEGRITY_LIMITS.filesMax) - marker.files.length;
}

/** The integrity marker's line: on, degraded (and why), or off. Nothing without --register. */
function markerLines(input: ReportInput): string[] {
  if (!input.flags.register) return [];
  if (input.marker === null) return ["  Integrity marker: off (--no-integrity-marker)"];
  const listed = input.marker.files.length;
  const wanted = listed + markerDropped(input.marker);
  if (listed === 0) {
    return [
      "! Integrity marker: not planted (it does not fit the size budget); this Build cannot be checked for tampering",
    ];
  }
  // With --integrity the planted file is a string inside the self-check wrapper: Guard, which looks for the marker
  // in the bytes it is served, does not find it there.
  if (input.integrity) {
    return [
      "! Integrity marker: with --integrity this Build is not watched for tampering (the self-check wrapper hides the marker from Guard)",
    ];
  }
  if (listed < wanted) {
    return [
      `! Integrity marker: ${listed} of ${wanted} files in ${input.plantedIn} (the rest did not fit the size budget)`,
    ];
  }
  return [`✓ Integrity marker: ${listed} file${listed === 1 ? "" : "s"} in ${input.plantedIn}`];
}

/** Counts only — never a package name. */
function inventoryLines(input: ReportInput): string[] {
  if (input.inventory === null && input.allSkipped !== null) {
    const n = input.allSkipped;
    return [
      `  lockfile lists ${n} dependenc${n === 1 ? "y" : "ies"} but none could be read (all skipped): component inventory off for this Build`,
    ];
  }
  if (input.inventory === null) return ["  no lockfile: component inventory skipped"];
  const n = input.inventory.components.length;
  const lines = [`✓ ${n} component${n === 1 ? "" : "s"} in inventory (${input.inventory.skipped} skipped)`];
  if (!input.flags.register) lines.push(`  ${n} component${n === 1 ? "" : "s"} read (not sent: pass --register)`);
  return lines;
}

/** Count only — never a route. */
function routeLines(input: ReportInput): string[] {
  if (input.routes === null) return [];
  const n = input.routes.length;
  const noun = `route${n === 1 ? "" : "s"}`;
  return input.flags.register ? [`✓ ${n} ${noun} in inventory`] : [`  ${n} ${noun} read (not sent: pass --register)`];
}

/** Count only — never a function, an example or a vector. */
function logicLines(input: ReportInput): string[] {
  if (input.logic === null) return [];
  const n = input.logic.functions.length;
  const noun = `protected function${n === 1 ? "" : "s"}`;
  return input.flags.register ? [`✓ ${n} ${noun} designated`] : [`  ${n} ${noun} read (not sent: pass --register)`];
}

function assessmentLines(input: ReportInput): string[] {
  const assessment = input.assessment;
  if (assessment === undefined) return [];
  if ("error" in assessment) {
    return [`✗ ${assessment.skipped ? "assessment skipped" : "assessment request failed"}: ${assessment.error}`];
  }
  return [`✓ assessment ${assessment.id} ${assessment.status} (${assessment.tier})`, `  Console: ${assessment.url}`];
}

/** The findings summary's counts and, with --fail-on, the gate and the items at or above its level. */
function findingsLines(input: ReportInput): string[] {
  const lines: string[] = [];
  const open = input.findings?.open;
  if (open) {
    lines.push(
      `  open findings: critical ${open.critical}, high ${open.high}, medium ${open.medium}, low ${open.low}, unknown ${open.unknown}`,
    );
  }
  const gate = input.gate;
  if (gate === null) return lines;
  if (gate.noSummary) {
    lines.push(`✗ findings gate could not be evaluated: ${NO_SUMMARY}`);
    return lines;
  }
  if (gate.count === 0) {
    lines.push(`✓ no open findings at or above ${gate.level}`);
  } else {
    lines.push(`✗ ${gateCount(gate)} at or above ${gate.level}`);
    for (const item of gate.failed) {
      const fixed = item.fixed.length > 0 ? `fixed in ${item.fixed.join(", ")}` : "no fixed version";
      lines.push(`  ${item.advisory}  ${item.package}@${item.version}  ${item.severity}  ${fixed}`);
    }
    if (gate.failed.length < gate.count) lines.push(`  (${gate.count - gate.failed.length} more not listed)`);
  }
  if (gate.unknown > 0) {
    lines.push(`  + ${gate.unknown} open finding${gate.unknown === 1 ? "" : "s"} with unknown severity, not counted`);
  }
  return lines;
}

/**
 * Whether this module is the program Node was started with. Both paths are resolved through symlinks: started through
 * the npm bin (`npx antireverse …`), process.argv[1] is the link in node_modules/.bin, and comparing it unresolved
 * would never run main — a silent exit 0 that passes every CI gate. Handles paths with spaces, and tsx running the
 * .ts directly. A path that cannot be resolved is compared as given.
 */
function isEntryPoint(argv1: string | undefined): boolean {
  if (argv1 === undefined) return false;
  const real = (path: string) => {
    try {
      return realpathSync(path);
    } catch {
      return resolve(path);
    }
  };
  return real(fileURLToPath(import.meta.url)) === real(argv1);
}

const isMain = isEntryPoint(process.argv[1]);
if (isMain) {
  main(process.argv.slice(2), {
    env: process.env,
    stdout: (s) => process.stdout.write(s),
    stderr: (s) => process.stderr.write(s),
  }).then(
    (code) => {
      process.exitCode = code;
    },
    (error) => {
      process.stderr.write(`harden: unexpected error: ${error instanceof Error ? error.message : String(error)}\n`);
      process.exitCode = 1;
    },
  );
}
