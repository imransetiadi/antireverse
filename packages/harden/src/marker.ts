// The integrity marker (slice 21a, D-100). Planted with the Canaries, after all transforms, as plain text: one
// self-contained statement that pushes `{ b: <Build id>, f: [<artifact paths>] }` onto the array under
// `globalThis[Symbol.for("ar.build")]` (created when absent), so that Guard can learn which Build a page runs and
// which of its files to hash. Identifiers only: the marker never carries a hash, so a tampered copy cannot read the
// expected value from it. Everything runs inside try/catch in an IIFE: no global binding, no timer, no listener, and
// nothing throws when `Symbol` or `globalThis` is missing or the slot holds something that is not an array. Every
// embedded string is an HTML-safe literal (`literal`), as in the Clone Beacon: the bundle may be inlined in HTML.
//
// `f` lists at most 32 paths: the planted file first, then the largest protected JavaScript artifacts (by UTF-8
// bytes at planting time, ties by path). The Manifest records the same list in the same order (`integrity.files`);
// an integrity report names a file by its index into it.
import { ID_PATTERNS, INTEGRITY_LIMITS } from "@antireverse/protocol";

/** The registered-symbol key of the page-wide marker list: `globalThis[Symbol.for(MARKER_KEY)]`. */
export const MARKER_KEY = "ar.build";

/**
 * A JS string literal for `value`, safe inside an HTML <script> element too: `<`, `>` and `&` are escaped, and the
 * line and paragraph separators, which older parsers end a line at.
 */
export function literal(value: string): string {
  return JSON.stringify(value)
    .replace(/</g, "\\u003c")
    .replace(/>/g, "\\u003e")
    .replace(/&/g, "\\u0026")
    .replace(/\u2028/g, "\\u2028")
    .replace(/\u2029/g, "\\u2029");
}

/** Throws unless `buildId` is a Build id: a marker naming anything else could never be matched to a Build. */
export function assertMarkerBuildId(buildId: unknown): asserts buildId is string {
  if (typeof buildId !== "string" || !ID_PATTERNS.bld.test(buildId)) {
    throw new TypeError(
      "harden: integrityMarker.buildId must be a Build id (bld_ followed by 24 lowercase hex characters)",
    );
  }
}

/**
 * The planted marker statement of a Build. Deterministic. Throws on a Build id that is not `bld_<24 hex>` and on
 * files that are not 1..32 distinct non-empty paths.
 */
export function markerStatement(buildId: string, files: readonly string[]): string {
  if (typeof buildId !== "string" || !ID_PATTERNS.bld.test(buildId)) {
    throw new Error("harden: the integrity marker needs the Build id (bld_ followed by 24 lowercase hex characters)");
  }
  if (files.length < 1 || files.length > INTEGRITY_LIMITS.filesMax) {
    throw new Error(`harden: the integrity marker lists 1 to ${INTEGRITY_LIMITS.filesMax} files`);
  }
  if (files.some((path) => typeof path !== "string" || path.length === 0)) {
    throw new Error("harden: the integrity marker lists each file by its path");
  }
  if (new Set(files).size !== files.length) {
    throw new Error("harden: the integrity marker must not list a file twice");
  }
  return (
    ";(function(){try{" +
    `var s=Symbol.for(${literal(MARKER_KEY)}),g=globalThis;` +
    `(g[s]||(g[s]=[])).push({b:${literal(buildId)},f:[${files.map(literal).join(",")}]})` +
    "}catch(e){}})();"
  );
}

/**
 * The files a marker planted in `plantedIn` lists, of the protected JavaScript files given: the planted file first,
 * then the largest (ties by path), at most 32.
 */
export function markerFiles(plantedIn: string, files: ReadonlyArray<{ path: string; bytes: number }>): string[] {
  const others = files
    .filter((file) => file.path !== plantedIn)
    .sort((a, b) => b.bytes - a.bytes || (a.path < b.path ? -1 : a.path > b.path ? 1 : 0))
    .map((file) => file.path);
  return [plantedIn, ...others].slice(0, INTEGRITY_LIMITS.filesMax);
}
