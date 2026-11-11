// The leak scan (slice 07): runs on every INPUT file of a bundle before any transform, so a secret that string
// encryption would hide is still found. A finding carries the rule, path, line, a mask and a fingerprint —
// never the value. An allowlist suppresses findings by fingerprint. The scan never runs on Harden's output:
// the planted Canary statement would match `secret-assignment` (plan amendment A3).
import { existsSync, readFileSync } from "node:fs";
import { resolve } from "node:path";
import { type LeakAllowlist, LeakAllowlistSchema, type LeakRuleId } from "@antireverse/protocol";
import { leakFingerprint } from "@antireverse/protocol/server";
import { isSourceMapPath, LEAK_DETECTORS } from "./rules.ts";

export interface LeakFinding {
  rule: LeakRuleId;
  /** The file's path relative to the bundle directory (posix separators). */
  path: string;
  /** 1-based line of the match (1 for a finding on the file name). */
  line: number;
  /** At most the first 4 characters (and never more than a quarter of the value), then `…`. */
  masked: string;
  /** `leakFingerprint(rule, path, value)`: the first 32 hex of a SHA-256. The key of an allowlist entry. */
  fingerprint: string;
}

export interface LeakScanResult {
  /** Unsuppressed findings, sorted by path, line, rule. */
  findings: LeakFinding[];
  /** How many findings the allowlist suppressed. */
  suppressed: number;
}

/** The default allowlist path, relative to the working directory. */
export const DEFAULT_ALLOWLIST_PATH = ".antireverse/leak-allow.json";

export const EMPTY_ALLOWLIST: LeakAllowlist = Object.freeze({ version: 1, allow: [] }) as LeakAllowlist;

/** Masks a value: at most its first 4 characters, never more than a quarter of it, then `…`. */
export function maskValue(value: string): string {
  const chars = [...value];
  const shown = Math.min(4, Math.floor(chars.length / 4));
  return `${chars.slice(0, shown).join("")}…`;
}

/** The offsets at which each line of `text` starts (line 1 at offset 0). */
function lineStarts(text: string): number[] {
  const starts = [0];
  for (let i = text.indexOf("\n"); i !== -1; i = text.indexOf("\n", i + 1)) starts.push(i + 1);
  return starts;
}

/** The 1-based line of `index`, by binary search over the line starts. */
function lineAt(starts: readonly number[], index: number): number {
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if ((starts[mid] as number) <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

/**
 * Scans text files and the bundle's file names. `files` are the text contents to scan; `fileNames` are every
 * file of the bundle (incl. binary ones), checked for `*.map`. Deterministic; the result never holds a value.
 */
export function scanLeaks(
  files: ReadonlyArray<{ path: string; text: string }>,
  fileNames: readonly string[],
  allow: LeakAllowlist,
): LeakScanResult {
  const allowed = new Set(allow.allow.map((entry) => entry.fingerprint));
  const all: LeakFinding[] = [];
  const add = (rule: LeakRuleId, path: string, line: number, value: string) => {
    all.push({ rule, path, line, masked: maskValue(value), fingerprint: leakFingerprint(rule, path, value) });
  };

  for (const name of new Set(fileNames)) {
    // For a map file the "value" is its path: it is not a secret, and it keeps the fingerprint stable.
    if (isSourceMapPath(name)) add("source-map", name, 1, name);
  }
  for (const file of files) {
    let starts: number[] | undefined;
    for (const detector of LEAK_DETECTORS) {
      for (const match of detector.find(file.text, file.path)) {
        starts ??= lineStarts(file.text);
        add(detector.id, file.path, lineAt(starts, match.index), match.value);
      }
    }
  }

  // One finding per fingerprint (the same value twice on one path is one thing to fix or allow).
  const unique = new Map<string, LeakFinding>();
  for (const f of all) if (!unique.has(f.fingerprint)) unique.set(f.fingerprint, f);
  let suppressed = 0;
  const findings: LeakFinding[] = [];
  for (const f of unique.values()) {
    if (allowed.has(f.fingerprint)) suppressed++;
    else findings.push(f);
  }
  findings.sort((a, b) =>
    a.path !== b.path ? (a.path < b.path ? -1 : 1) : a.line !== b.line ? a.line - b.line : a.rule < b.rule ? -1 : 1,
  );
  return { findings, suppressed };
}

/**
 * Loads the allowlist: `file` (resolved against `cwd`) when given, else the default path under `cwd`. A missing
 * default file is an empty allowlist; a given file that is missing, or any malformed file, is an error. Error
 * messages never echo the file's content.
 */
export function loadAllowlist(opts: {
  cwd: string;
  file?: string | undefined;
}): { allow: LeakAllowlist } | { error: string } {
  const given = opts.file !== undefined;
  const path = resolve(opts.cwd, opts.file ?? DEFAULT_ALLOWLIST_PATH);
  if (!existsSync(path)) {
    return given ? { error: `leak allowlist not found: ${path}` } : { allow: { version: 1, allow: [] } };
  }
  let raw: unknown;
  try {
    raw = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    return { error: `leak allowlist is not valid JSON: ${path}` };
  }
  const parsed = LeakAllowlistSchema.safeParse(raw);
  if (!parsed.success) {
    return {
      error: `leak allowlist is malformed: ${path} (expected { "version": 1, "allow": [{ "fingerprint": "<32 hex>", "reason": "<1-200 chars>" }] })`,
    };
  }
  return { allow: parsed.data };
}
