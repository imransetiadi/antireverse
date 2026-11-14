// The harden engine: pure (no I/O), deterministic, and it never throws on valid JS — a file that cannot be
// parsed is reported, not thrown. Profiles: light = mangle; balanced = mangle + strings; maximum = balanced
// (heavier passes land in a later slice). Passes run mangle-first so the string decoder's 6+ character names
// can never collide with a mangled identifier (the mangler emits at most 5 characters).
import { gzipSync } from "node:zlib";
import type { Canary, LeakAllowlist, ManifestBeacon } from "@antireverse/protocol";
import { type CanaryScope, deriveCanaries } from "@antireverse/protocol/server";
import type * as t from "@babel/types";
import { generateCode, parseSource } from "./babel.ts";
import { type BeaconConfig, beaconStatement } from "./beacon.ts";
import { isDeclarationFile, type PlantedMarker, plantCanaries } from "./canaries.ts";
import { EMPTY_ALLOWLIST, type LeakFinding, scanLeaks } from "./leaks/scan.ts";
import { assertMarkerBuildId } from "./marker.ts";
import { createManglePass } from "./passes/mangle.ts";
import { createStringsPass } from "./passes/strings.ts";
import { mulberry32 } from "./rng.ts";
import type { FileResult, HardenOptions, HardenResult, Pass, TransformSummary } from "./types.ts";

/** Default overhead ceilings (percent). Balanced holds size ≤ 35% and run ≤ 15% per PERFORMANCE.md. */
export const DEFAULT_BUDGET = { sizePct: 35, runPct: 15 } as const;

interface Transformed {
  code: string;
  renamed: number;
  stringsEncrypted: number;
  /** True when the mangle pass skipped the whole file because it calls eval (review finding F4). */
  evalSkipped: boolean;
}

/** Parses `code` fresh and runs the given passes in order. A fresh parse keeps each attempt independent. */
function transform(code: string, path: string, passes: Pass[], seed: number): Transformed {
  const ast = parseSource(code, path);
  const rng = mulberry32(seed);
  const ctx = { rng, seed, types: undefined as unknown as typeof t };
  let renamed = 0;
  let stringsEncrypted = 0;
  let evalSkipped = false;
  for (const pass of passes) {
    const { count, note } = pass.run(ast, ctx);
    if (pass.name === "mangle") {
      renamed = count;
      if (note === "eval") evalSkipped = true;
    } else {
      stringsEncrypted = count;
    }
  }
  return { code: generateCode(ast), renamed, stringsEncrypted, evalSkipped };
}

/** gzip-size overhead of `out` over `original`, as a percentage. 0 when the original is empty. */
function sizeOverheadPct(original: string, out: string): number {
  const before = gzipSync(Buffer.from(original, "utf8")).length;
  if (before === 0) return 0;
  const after = gzipSync(Buffer.from(out, "utf8")).length;
  return ((after - before) / before) * 100;
}

function hardenOne(path: string, code: string, options: HardenOptions): FileResult {
  // A declaration file carries only types: it is emitted unchanged (and is never planted into).
  if (options.protectionMap?.[path] === "skip" || isDeclarationFile(path)) {
    return { path, code, skipped: true, renamed: 0, stringsEncrypted: 0 };
  }

  const sizePct = options.budget?.sizePct ?? DEFAULT_BUDGET.sizePct;
  const wantsStrings = options.profile === "balanced" || options.profile === "maximum";

  try {
    const manglePass = createManglePass();
    const passes: Pass[] = wantsStrings ? [manglePass, createStringsPass()] : [manglePass];
    const primary = transform(code, path, passes, options.seed);

    // The candidate we intend to ship, and why it is not fully protected (if so).
    let candidate = {
      code: primary.code,
      renamed: primary.renamed,
      stringsEncrypted: primary.stringsEncrypted,
      reason: primary.evalSkipped
        ? "mangling skipped: the file calls eval, which can reference a local by name"
        : (undefined as string | undefined),
    };

    // Budget guard 1: if string encryption pushed gzip size over budget, fall back to mangle-only.
    if (wantsStrings && candidate.stringsEncrypted > 0) {
      const overhead = sizeOverheadPct(code, primary.code);
      if (overhead > sizePct) {
        const mangleOnly = transform(code, path, [createManglePass()], options.seed);
        candidate = {
          code: mangleOnly.code,
          renamed: mangleOnly.renamed,
          stringsEncrypted: 0,
          reason: `string encryption skipped: gzip size +${overhead.toFixed(1)}% over the ${sizePct}% budget`,
        };
      }
    }

    // Budget guard 2 (the gate on what actually ships, every profile): if the chosen output is still over
    // budget, emit the file unchanged. Nothing over budget is ever shipped (review finding F3).
    const shippedOverhead = sizeOverheadPct(code, candidate.code);
    if (candidate.code !== code && shippedOverhead > sizePct) {
      const reason = `emitted unchanged: protected output +${shippedOverhead.toFixed(1)}% over the ${sizePct}% budget`;
      return { path, code, skipped: true, mangleOnly: reason, renamed: 0, stringsEncrypted: 0 };
    }

    return {
      path,
      code: candidate.code,
      skipped: candidate.code === code,
      ...(candidate.reason ? { mangleOnly: candidate.reason } : {}),
      renamed: candidate.renamed,
      stringsEncrypted: candidate.stringsEncrypted,
    };
  } catch (error) {
    // A file that will not parse is reported and passed through unchanged; the engine never throws.
    const message = error instanceof Error ? error.message : String(error);
    return { path, code, skipped: true, error: `parse error: ${message}`, renamed: 0, stringsEncrypted: 0 };
  }
}

/**
 * Hardens a set of files. Deterministic: the same files, profile and seed give byte-identical output. Never
 * throws on valid JS; a parse failure is reported per file.
 */
export function harden(files: Record<string, string>, options: HardenOptions): HardenResult {
  const results: FileResult[] = [];
  for (const [path, code] of Object.entries(files)) {
    results.push(hardenOne(path, code, options));
  }

  const transform: TransformSummary = {
    mangled: results.reduce((n, r) => n + r.renamed, 0),
    strings_encrypted: results.reduce((n, r) => n + r.stringsEncrypted, 0),
    files_mangle_only: results.filter((r) => r.mangleOnly !== undefined).length,
    integrity: false,
  };

  return { files: results, transform };
}

/** The input of a whole-bundle harden: the JS sources, plus the bundle's other text files and all file names. */
export interface BundleInput {
  /** JavaScript/TypeScript sources to protect, keyed by path relative to the bundle (posix). */
  sources: Record<string, string>;
  /** The bundle's other text files (JSON, HTML, CSS, maps…): scanned for leaks, never transformed. */
  extraFiles?: ReadonlyArray<{ path: string; text: string }>;
  /** Every file name of the bundle, binary ones included (checked for `*.map`). Defaults to the scanned paths. */
  fileNames?: readonly string[];
}

export interface BundleOptions extends HardenOptions {
  /** Reviewed findings, by fingerprint. Default: empty. */
  allow?: LeakAllowlist;
  /**
   * The App and version a registered Build's Canaries are scoped to (protocol derivation v2), so Builds with the
   * same pinned seed get different Canaries. Default: unscoped (v1).
   */
  canaryScope?: CanaryScope;
  /**
   * The Clone Beacon to plant (slice 10): its token, allowed origins and the API base URL. Planted together
   * with the Canaries, in the same file, in one planting step (the budget counts both). Default: none.
   */
  beacon?: BeaconConfig;
  /**
   * The integrity marker to plant (slice 21a): the Build id it names. Planted after the Canaries (and the beacon), in
   * the same file, with as many files as the size budget holds; it never fails the bundle. Default: none.
   */
  integrityMarker?: { buildId: string };
}

export interface BundleLeakScan {
  /** `failed` = at least one unsuppressed finding: nothing was transformed, planted or emitted. */
  status: "clean" | "suppressed" | "failed";
  findings: LeakFinding[];
  suppressed: number;
}

export interface BundleResult extends HardenResult {
  leakScan: BundleLeakScan;
  /** The seed actually used (`seed >>> 0`, plan amendment A1). */
  seed: number;
  /** The planted Canaries (empty when the scan failed). */
  canaries: Canary[];
  /** The path the Canary statement was planted in, or null when the scan failed or planting failed. */
  plantedIn: string | null;
  /** Why the Canaries could not be planted (the run must fail; they are never silently dropped). */
  plantError?: string;
  /** The planted Clone Beacon (token and origins; it sits in `plantedIn`), or null when none was asked for. */
  beacon: ManifestBeacon | null;
  /**
   * The planted integrity marker: the files it lists, in order (empty: it did not fit the size budget and was not
   * planted), of the `eligible` protected JavaScript files. Null when none was asked for, or nothing was planted.
   */
  integrity: PlantedMarker | null;
}

/**
 * The whole Harden pipeline for a bundle, in order: leak scan of the INPUT (every source and extra text file,
 * every file name) → transforms → Canary (+ Clone Beacon) planting → budget gate (the planted statement is counted) → result.
 * There is no option to skip the scan. On an unsuppressed finding nothing is transformed or planted. Pure and
 * deterministic: the same input and seed give byte-identical files and the same Canaries.
 */
export function hardenBundle(input: BundleInput, options: BundleOptions): BundleResult {
  // The one input that throws: an integrity marker for something that is not a Build id (a programming error of the
  // caller, never a property of the bundle). Refused before the scan, so nothing is half done.
  if (options.integrityMarker !== undefined) assertMarkerBuildId(options.integrityMarker.buildId);
  const seed = options.seed >>> 0;
  const scanned = new Map<string, string>();
  for (const [path, text] of Object.entries(input.sources)) scanned.set(path, text);
  for (const f of input.extraFiles ?? []) if (!scanned.has(f.path)) scanned.set(f.path, f.text);
  const fileNames = input.fileNames ?? [...scanned.keys()];
  const scan = scanLeaks(
    [...scanned].map(([path, text]) => ({ path, text })),
    fileNames,
    options.allow ?? EMPTY_ALLOWLIST,
  );

  const emptyTransform: TransformSummary = { mangled: 0, strings_encrypted: 0, files_mangle_only: 0, integrity: false };
  if (scan.findings.length > 0) {
    return {
      leakScan: { status: "failed", findings: scan.findings, suppressed: scan.suppressed },
      seed,
      files: [],
      transform: emptyTransform,
      canaries: [],
      plantedIn: null,
      beacon: null,
      integrity: null,
    };
  }
  const leakScan: BundleLeakScan = {
    status: scan.suppressed > 0 ? "suppressed" : "clean",
    findings: [],
    suppressed: scan.suppressed,
  };

  const { protectionMap, budget } = options;
  const result = harden(input.sources, {
    profile: options.profile,
    seed,
    ...(protectionMap ? { protectionMap } : {}),
    ...(budget ? { budget } : {}),
  });
  const canaries = options.canaryScope ? deriveCanaries(seed, options.canaryScope) : deriveCanaries(seed);
  const wanted = options.beacon;
  try {
    // A bad beacon configuration throws here and becomes a plant error: the engine never throws.
    const beacon = wanted ? beaconStatement(wanted.appId, wanted.token, wanted.origins, wanted.endpoint) : undefined;
    const planted = plantCanaries(
      result.files,
      canaries,
      { originals: input.sources, sizePct: budget?.sizePct ?? DEFAULT_BUDGET.sizePct },
      beacon,
      options.integrityMarker,
    );
    return {
      ...result,
      files: planted.files,
      leakScan,
      seed,
      canaries,
      plantedIn: planted.plantedIn,
      beacon: wanted ? { token: wanted.token, origins: [...wanted.origins] } : null,
      integrity: planted.integrity ?? null,
    };
  } catch (error) {
    const plantError = error instanceof Error ? error.message : String(error);
    return { ...result, leakScan, seed, canaries, plantedIn: null, plantError, beacon: null, integrity: null };
  }
}
