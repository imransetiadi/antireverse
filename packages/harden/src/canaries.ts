// Canary planting (slice 07): after all transforms, the Build's Canaries are appended as plain text (never
// string-encrypted) to exactly one emitted JavaScript file — the first protected file in sorted path order
// whose size budget still holds with the statement counted. The statement is one behaviour-neutral expression:
// `void {apiKey:"…",internalApi:"…",exportUrl:"…"};` — no binding, no global, no side effect, valid in an ES
// module and in a script. A skipped file is never planted into, and Canaries are never dropped silently: if no
// protected file can hold them within budget, planting throws with a clear message. From slice 10 the Clone
// Beacon statement (src/beacon.ts) is planted in the same step, into the same file, right after the Canaries.
import { gzipSync } from "node:zlib";
import type { Canary } from "@antireverse/protocol";

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

/**
 * Plants `canaries` — and, when given, the Clone Beacon statement (slice 10) — into the first protected file
 * (sorted by path) that stays within `budget` with everything planted counted. One combined planting step: the
 * Canary statement and the beacon statement are appended together, each on its own line, to the same file, so
 * the budget counts both and they are never split across files. Returns the files (same order, only the planted
 * one changed) and the planted path. Throws when there is no protected file, or none fits the budget.
 */
export function plantCanaries<F extends PlantableFile>(
  files: readonly F[],
  canaries: readonly Canary[],
  budget?: PlantBudget,
  beacon?: string,
): { files: F[]; plantedIn: string } {
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
    const planted = withStatement(file.code, statement);
    if (budget) {
      const original = budget.originals[path] ?? file.code;
      const before = gzipLen(original);
      const overhead = before === 0 ? Number.POSITIVE_INFINITY : ((gzipLen(planted) - before) / before) * 100;
      if (overhead > budget.sizePct) continue;
    }
    return { files: files.map((f) => (f.path === path ? { ...f, code: planted } : f)), plantedIn: path };
  }
  throw new Error(
    `harden: cannot plant ${what} within the ${budget?.sizePct}% size budget: no protected file can hold the planted statement${beacon === undefined ? "" : "s"} (${candidates.length} tried). Protect a larger file of the bundle (the ${what} are never dropped).`,
  );
}
