import type { PolicyRule } from "@antireverse/protocol";

// Whether a login protection covers the route of an Event: the fallback for an Event of a Shield from before plan 08
// amendment A7, which does not stamp `decision.limit_rule_id` (D-064). A Shield of A7 says which login protection
// matched a request, and none of this is used for its Events. A login protection is a limit Rule that counts
// failures; a plain request limit covers nothing.
//
// Shield matches a Rule's path pattern against the concrete path of a request. An Event never carries that path:
// it carries the route template (`/login`, `/orgs/:orgId/apps/:appId`, `/files/*path`), or `(unmatched)` when no
// route matched or the template is unknown, or a template that starts with `(mount)`. So coverage is judged
// template against pattern, and only where the answer is certain for every request the template stands for:
//
//   - a literal segment of the pattern covers the same literal segment of the template, without regard to ASCII
//     case (as Rules match), and nothing else: a parameter (`:id`) may or may not take that value, so it is not
//     covered;
//   - `*` covers any one segment of the template that is plain text or parameters — not a template wildcard
//     (`*path` spans several segments) and not a segment with `{`, `}`, `(` or `)` (an optional group or a regular
//     expression may stand for no segment or for several);
//   - a final `**` covers whatever follows, and the prefix itself;
//   - one final slash of the template is ignored (Express routes `/login/` to `/login` unless it is strict);
//   - a route that does not start with a slash — `(unmatched)`, `(mount)/…` — is never covered;
//   - the Rule's methods apply as in Shield: none is every method, and HEAD counts with GET.
//
// Undecidable means not covered: the rule under-counts on parameterised and unmatched routes and never counts an
// Event on a route no limit Rule protects. An Event whose decision names the limit Rule needs none of this.
//
// The pattern is written once, as a regular expression over the ASCII-lowered template, and read twice: here (the
// Detector) and in SQL (an Incident's evidence, `ruleConditionSql`). It uses only what JavaScript (with the `s`
// flag) and PostgreSQL read alike: anchors, literal text, `\.`, a negated bracket, `+`, `?`, a group and `.*`.

/** One login protection (a failure-counting limit Rule) of one Policy version, as the evidence query receives it: a JSON array of these is its parameter. */
export interface CoverageEntry {
  /** The Policy version, as the text `payload->'decision'->>'policy_version'` gives. */
  v: string;
  /** The Rule's methods; empty means every method. */
  m: string[];
  /** `coveragePattern` of the Rule's path. */
  p: string;
  /** The Rule's id: an older Shield's throttle that names it counts (plan 08 amendment A7). */
  i: string;
}

/** The limit Rules of one Policy version, ready to judge routes. */
export type Coverage = readonly { id: string; methods: readonly string[]; source: string; pattern: RegExp }[];

/** `text` with its ASCII letters in lower case, as Rules compare. */
export const asciiLower = (text: string): string => text.replace(/[A-Z]/g, (letter) => letter.toLowerCase());

/** `asciiLower` of a column, in SQL: `lower()` would follow the database's locale. */
export const ASCII_LOWER_SQL = (expression: string): string =>
  `translate(${expression}, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'abcdefghijklmnopqrstuvwxyz')`;

/** One template segment `*` covers: no slash, and none of the characters of a wildcard, a group or an expression. */
const ONE_SEGMENT = "[^/{}()*]+";

/**
 * A Rule's path pattern as the source of a regular expression over the ASCII-lowered route template. The pattern
 * is a valid one (`PATH_PATTERN`): literal segments over `A-Z a-z 0-9 . _ ~ -`, `*`, a final `**`.
 */
export function coveragePattern(path: string): string {
  if (path === "/") return "^/$";
  const segments = path.slice(1).split("/");
  const everythingBelow = segments.at(-1) === "**";
  if (everythingBelow) segments.pop();
  // Of a literal segment's characters only the dot means something in a regular expression.
  const prefix = segments
    .map((segment) => (segment === "*" ? `/${ONE_SEGMENT}` : `/${asciiLower(segment).replace(/\./g, "\\.")}`))
    .join("");
  return everythingBelow ? `^${prefix}(/.*)?$` : `^${prefix}/?$`;
}

/** `rules`, each as its id, its methods and its pattern. */
export function coverageOf(rules: readonly (Pick<PolicyRule, "path" | "methods"> & { id?: string })[]): Coverage {
  return rules.map((rule) => {
    const source = coveragePattern(rule.path);
    return { id: rule.id ?? "", methods: [...rule.methods], source, pattern: new RegExp(source, "s") };
  });
}

/**
 * The login protections of a Policy version: `coverageOf` of the Rules whose limit counts failures (D-064). A plain
 * request limit covers nothing: its route's failures and its throttles open no Credential stuffing Incident.
 */
export function limitCoverage(rules: readonly PolicyRule[]): Coverage {
  return coverageOf(rules.filter((rule) => rule.limit?.count === "failures"));
}

/** Whether `ruleId` is one of the login protections. */
export function namesRule(coverage: Coverage, ruleId: string | null): boolean {
  return ruleId !== null && coverage.some((rule) => rule.id === ruleId);
}

/** `matchMethod` of Shield: an empty list is every method, and HEAD also matches a list with GET. */
export function methodApplies(methods: readonly string[], method: string): boolean {
  return methods.length === 0 || methods.includes(method) || (method === "HEAD" && methods.includes("GET"));
}

/** Whether one of the limit Rules covers a request of `method` on the route template `route`. */
export function covers(coverage: Coverage, method: string, route: string): boolean {
  if (coverage.length === 0) return false;
  const lowered = asciiLower(route);
  return coverage.some((rule) => methodApplies(rule.methods, method) && rule.pattern.test(lowered));
}

/** A Policy version's limit Rules as entries of the evidence query's parameter. */
export function coverageEntries(version: number | string, rules: readonly PolicyRule[]): CoverageEntry[] {
  return limitCoverage(rules).map((rule) => ({ v: String(version), m: [...rule.methods], p: rule.source, i: rule.id }));
}
