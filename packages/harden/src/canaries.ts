// Canary planting (slice 07): after all transforms, the Build's Canaries are appended as plain text (never
// string-encrypted) to exactly one emitted JavaScript file — the first protected file in sorted path order
// whose size budget still holds with the statement counted. The statement is one behaviour-neutral expression:
// `void {apiKey:"…",internalApi:"…",exportUrl:"…"};` — no binding, no global, no side effect, valid in an ES
// module and in a script. A skipped file is never planted into, and Canaries are never dropped silently: if no
// protected file can hold them within budget, planting throws with a clear message. From slice 10 the Clone
// Beacon statement (src/beacon.ts) is planted in the same step, into the same file, right after the Canaries.
// From slice 21a the integrity marker (src/marker.ts) follows them, in the same file. Unlike the Canaries it may be
// dropped: the file is chosen exactly as without it, and the marker is then planted with as many files as the
// budget still holds — all, fewer, or none. It never fails a build and never moves the Canaries.
import { gzipSync } from "node:zlib";
import type { Canary } from "@antireverse/protocol";
import { assertMarkerBuildId, markerFiles, markerStatement } from "./marker.ts";

/** The planted statement for a Build's Canaries (one key, two routes, per `CANARY_PLAN`). */
export function canaryStatement(canaries: readonly Canary[]): string {
  const key = canaries.find((c) => c.kind === "key");
  const routes = canaries.filter((c) => c.kind === "route");
  const [internalApi, exportUrl] = routes;
  if (!key || !internalApi || !exportUrl || canaries.length !== 3) {
    throw new Error("harden: a Build plants exactly one decoy key and two decoy routes");
  }
  // Decoy values are restricted by CANARY_VALUE_PATTERNS ([0-9A-Za-z_/]), so JSON quoting is exact.
  return `void {apiKey:${JSON.stringify(key.value)},internalApi:${JSON.stringify(internalApi.value)},exportUrl:${JSON.stringify(exportUrl.value)}};`;
}

export interface PlantableFile {
  path: string;
  code: string;
  /** Skipped files (protection map, parse error, or emitted unchanged) are never planted into. */
  skipped: boolean;
}

export interface PlantBudget {
  /** The original source per path: the base of the gzip size overhead. */
  originals: Record<string, string>;
  /** The per-file gzip size ceiling, in percent. */
  sizePct: number;
}

/** A TypeScript declaration file (`.d.ts`, `.d.mts`, `.d.cts`): it may not contain a statement (TS1036). */
export function isDeclarationFile(path: string): boolean {
  return /\.d\.[mc]?ts$/i.test(path);
}

function gzipLen(code: string): number {
  return gzipSync(Buffer.from(code, "utf8")).length;
}

/** Appends the statement on its own line; a leading newline keeps it out of any trailing line comment. */
function withStatement(code: string, statement: string): string {
  return `${code}${code.endsWith("\n") ? "" : "\n"}${statement}\n`;
}

/** The integrity marker as planted: the files it lists (none: not planted) of the `eligible` protected files. */
export interface PlantedMarker {
  files: string[];
  eligible: number;
}

/**
 * Plants `canaries` — and, when given, the Clone Beacon statement (slice 10) — into the first protected file
 * (sorted by path) that stays within `budget` with everything planted counted. One combined planting step: the
 * Canary statement and the beacon statement are appended together, each on its own line, to the same file, so
 * the budget counts both and they are never split across files. Returns the files (same order, only the planted
 * one changed) and the planted path. Throws when there is no protected file, or none fits the budget.
 * With `marker` (slice 21a) the integrity marker of that Build follows on its own line when it fits, with fewer
 * files or not at all when it does not; `integrity` says which.
 */
export function plantCanaries<F extends PlantableFile>(
  files: readonly F[],
  canaries: readonly Canary[],
  budget?: PlantBudget,
  beacon?: string,
  marker?: { buildId: string },
): { files: F[]; plantedIn: string; integrity?: PlantedMarker } {
  // A marker that names no Build is the caller's mistake: refused before anything is planted, so that it can never be
  // taken for a planting failure and cost the Canaries.
  if (marker !== undefined) assertMarkerBuildId(marker.buildId);
  const statement = beacon === undefined ? canaryStatement(canaries) : `${canaryStatement(canaries)}\n${beacon}`;
  const what = beacon === undefined ? "Canaries" : "Canaries and the Clone Beacon";
  const candidates = files
    .filter((f) => !f.skipped && !isDeclarationFile(f.path))
    .map((f) => f.path)
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  if (candidates.length === 0) {
    throw new Error(`harden: cannot plant ${what}: no protected file (every file was skipped)`);
  }
  for (const path of candidates) {
    const file = files.find((f) => f.path === path) as F;
    const fits = (code: string): boolean => {
      if (!budget) return true;
      const before = gzipLen(budget.originals[path] ?? file.code);
      const overhead = before === 0 ? Number.POSITIVE_INFINITY : ((gzipLen(code) - before) / before) * 100;
      return overhead <= budget.sizePct;
    };
    let planted = withStatement(file.code, statement);
    if (!fits(planted)) continue;
    let integrity: PlantedMarker | undefined;
    if (marker !== undefined) {
      // The file is chosen; the marker takes what room is left: every listed file, else the longest prefix of the
      // list that fits, else nothing.
      const listed = markerFiles(
        path,
        candidates.map((candidate) => ({
          path: candidate,
          bytes: Buffer.byteLength((files.find((f) => f.path === candidate) as F).code, "utf8"),
        })),
      );
      integrity = { files: [], eligible: candidates.length };
      for (let count = listed.length; count >= 1; count--) {
        const kept = listed.slice(0, count);
        const withMarker = withStatement(file.code, `${statement}\n${markerStatement(marker.buildId, kept)}`);
        if (!fits(withMarker)) continue;
        planted = withMarker;
        integrity.files = kept;
        break;
      }
    }
    return {
      files: files.map((f) => (f.path === path ? { ...f, code: planted } : f)),
      plantedIn: path,
      ...(integrity ? { integrity } : {}),
    };
  }
  throw new Error(
    `harden: cannot plant ${what} within the ${budget?.sizePct}% size budget: no protected file can hold the planted statement${beacon === undefined ? "" : "s"} (${candidates.length} tried). Protect a larger file of the bundle (the ${what} are never dropped).`,
  );
}
