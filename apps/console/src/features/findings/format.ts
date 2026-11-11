import { type Advisory, compareSemver, type Finding, parseSemver } from "@antireverse/protocol";

// Pure formatting of Findings and advisories: server and browser render the same text.

/** `name@version`, as npm writes it. */
export const packageLabel = (finding: Pick<Finding, "package" | "version">): string =>
  `${finding.package}@${finding.version}`;

/** The advisory's page on osv.dev. A plain link: the Console itself never calls a third party. */
export const osvUrl = (advisoryId: string): string => `https://osv.dev/vulnerability/${encodeURIComponent(advisoryId)}`;

/** The first CVE alias and how many more there are; other aliases (GHSA, …) are not counted. */
export function cveSummary(aliases: readonly string[]): { first: string | null; more: number } {
  const cves = aliases.filter((alias) => alias.startsWith("CVE-"));
  return { first: cves[0] ?? null, more: Math.max(0, cves.length - 1) };
}

/**
 * The fix to suggest: the lowest fixed version above the installed one (`fixed_versions` is ascending), or
 * null when the advisory names none.
 */
export function suggestedFix(finding: Pick<Finding, "version" | "fixed_versions">): string | null {
  if (parseSemver(finding.version) === null) return finding.fixed_versions[0] ?? null;
  return finding.fixed_versions.find((fixed) => compareSemver(fixed, finding.version) > 0) ?? null;
}

type Event = { introduced: string } | { fixed: string } | { last_affected: string } | { limit: string };

/** Events in version order, `introduced: "0"` first; events whose version is not semver are dropped. */
function sortedEvents(events: readonly Event[]): Array<[keyof Event | string, string]> {
  const pairs = events
    .map((event) => Object.entries(event)[0] as [string, string])
    .filter(([kind, value]) => (kind === "introduced" && value === "0") || parseSemver(value) !== null);
  return pairs.sort(([, a], [, b]) => (a === "0" ? (b === "0" ? 0 : -1) : b === "0" ? 1 : compareSemver(a, b)));
}

/**
 * One OSV range as readable intervals, e.g. `>= 1.0.0, < 1.2.3`. `introduced: "0"` has no lower bound; fixed
 * and limit are exclusive, last_affected inclusive. Null stands for an interval open at both ends: every version.
 */
function intervals(events: readonly Event[]): Array<string | null> {
  const out: Array<string | null> = [];
  let open = false;
  let lower: string | null = null;
  const close = (upper: string | null): void => {
    const parts = [lower === null ? null : `>= ${lower}`, upper].filter((part) => part !== null);
    out.push(parts.length === 0 ? null : parts.join(", "));
    open = false;
  };
  for (const [kind, value] of sortedEvents(events)) {
    if (kind === "introduced") {
      if (!open) {
        open = true;
        lower = value === "0" ? null : value;
      }
    } else if (open) {
      close(kind === "last_affected" ? `<= ${value}` : `< ${value}`);
    }
  }
  if (open) close(null);
  return out;
}

/**
 * The affected versions of the npm package `name` in the advisory: each range as text (null: all versions),
 * each once, and the explicitly listed versions, each once, in version order.
 */
export function affectedRanges(advisory: Advisory, name: string): { ranges: Array<string | null>; versions: string[] } {
  const ranges: Array<string | null> = [];
  const versions = new Set<string>();
  for (const entry of advisory.affected) {
    if (entry.package.ecosystem !== "npm" || entry.package.name !== name) continue;
    for (const range of entry.ranges) {
      for (const text of intervals(range.events)) if (!ranges.includes(text)) ranges.push(text);
    }
    for (const version of entry.versions ?? []) versions.add(version);
  }
  const listed = [...versions].sort((a, b) => {
    const known = parseSemver(a) !== null && parseSemver(b) !== null;
    return known ? compareSemver(a, b) : a.localeCompare(b);
  });
  return { ranges, versions: listed };
}

const DAY_MS = 86_400_000;
/** Days an ignore may reach ahead (the API's limit), and the default. */
const IGNORE_DAYS_MAX = 90;
const IGNORE_DAYS_DEFAULT = 30;
const DATE = /^(\d{4})-(\d{2})-(\d{2})$/;

/** `YYYY-MM-DD` of the UTC day `days` after the one of `nowMs`. */
function utcDate(nowMs: number, days: number): string {
  const day = new Date(Math.floor(nowMs / DAY_MS) * DAY_MS + days * DAY_MS);
  return day.toISOString().slice(0, 10);
}

/** The dates an ignore can end on, in UTC: tomorrow to 90 days ahead, 30 days ahead by default. */
export function ignoreWindow(nowMs: number): { min: string; max: string; initial: string } {
  return {
    min: utcDate(nowMs, 1),
    max: utcDate(nowMs, IGNORE_DAYS_MAX),
    initial: utcDate(nowMs, IGNORE_DAYS_DEFAULT),
  };
}

/**
 * The expiry for a chosen date: the start of that day in UTC, when it is a real date inside the ignore window;
 * otherwise null. The start of the day keeps the last day of the window within 90 days of now.
 */
export function untilFromDate(value: string, nowMs: number): string | null {
  const match = DATE.exec(value);
  if (match === null) return null;
  const at = Date.UTC(Number(match[1]), Number(match[2]) - 1, Number(match[3]));
  // A date that does not exist (2026-02-30) rolls over and no longer reads the same.
  if (new Date(at).toISOString().slice(0, 10) !== value) return null;
  const { min, max } = ignoreWindow(nowMs);
  if (value < min || value > max) return null;
  return new Date(at).toISOString();
}
