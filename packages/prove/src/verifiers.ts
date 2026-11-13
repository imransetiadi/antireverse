// The verifiers of W1 Map and W2 Secrets, and the "not supported" result of W3 and W4 (slice 12a, Review Focus 1).
// They decide from the Build's facts, which the agent never sees, and read only what the agent submitted: never
// its claims about success. Evidence names what was recovered by Canary id, finding fingerprint or count, and
// the calls involved by index; a recovered value is never put into evidence.
import {
  ASSESSMENT_LIMITS,
  type AssessmentCost,
  type Canary,
  type Evidence,
  type NotAttemptedReason,
  type ObjectiveResult,
  parseRouteEntry,
  type RecoveredItem,
} from "@antireverse/protocol";
import { leakFingerprint } from "@antireverse/protocol/server";
import type { Submission } from "./toolbelt.ts";
import type { LeakFindingRef, MapSubmission, SecretsSubmission } from "./types.ts";

/** What a verifier decided: not attempted (with why), or judged (achieved by a submission, or not). */
export type Verdict =
  | { kind: "not_attempted"; reason: NotAttemptedReason; evidence: Evidence }
  | { kind: "judged"; achievedAt: AchievedAt | null; evidence: Evidence };

/** Where an Objective was achieved: the submit call and the run's cost at it. Never the submitted payload. */
export interface AchievedAt {
  callIndex: number;
  cost: AssessmentCost;
}

function at(submission: Submission): AchievedAt {
  return { callIndex: submission.callIndex, cost: { ...submission.cost } };
}

/** Thrown by a verifier when the judging budget ran out before it could decide (review 12b F4). */
export class JudgingTimeError extends Error {
  constructor() {
    super("The judging budget ran out.");
    this.name = "JudgingTimeError";
  }
}

/** Indexes of calls whose output showed a value (the Toolbelt's `callsShowing`). */
export type CallsShowing = (value: string) => number[];

/** W1 coverage threshold: matched routes / inventory routes ≥ 0.6 (whole-number arithmetic: 10·m ≥ 6·n). */
export const MAP_COVERAGE = { numerator: 6, denominator: 10 } as const;

/**
 * W1 precision threshold (Jev 0.91, "canary_only_plus_precision"): matched routes / distinct submitted endpoints
 * ≥ 0.5 (2·m ≥ s), so a padded list of guesses cannot reach the coverage by volume.
 */
export const MAP_PRECISION = { numerator: 1, denominator: 2 } as const;

/** How many distinct endpoints the agent may submit for W1 in one run: twice the inventory (null: no inventory). */
export const MAP_CAP_FACTOR = 2;

/** The cap on a run's distinct W1 endpoints for this inventory, or null without one. */
export function mapEndpointCap(routes: readonly string[] | null | undefined): number | null {
  const count = (routes ?? []).filter((entry) => parseRouteEntry(entry) !== null).length;
  return count === 0 ? null : MAP_CAP_FACTOR * count;
}

function evidence(summary: string, recovered: RecoveredItem[], calls: Iterable<number>): Evidence {
  const sorted = [...new Set(calls)].sort((a, b) => a - b).slice(0, ASSESSMENT_LIMITS.callRefsMax);
  return {
    summary: summary.slice(0, ASSESSMENT_LIMITS.summaryMax),
    recovered: recovered.slice(0, ASSESSMENT_LIMITS.recoveredMax),
    calls: sorted,
  };
}

// --- W1 Map ----------------------------------------------------------------------------------------------

interface Endpoint {
  method: string;
  segments: string[];
}

/** A submitted endpoint `METHOD /path` (query and fragment dropped, trailing slash ignored), or null. */
function parseSubmitted(value: string): Endpoint | null {
  const match = /^([A-Za-z-]{1,16}) (\/\S*)$/.exec(value.trim());
  if (match === null) return null;
  let path = (match[2] as string).replace(/[?#].*$/, "");
  if (path.length > 1) path = path.replace(/\/+$/, "");
  return { method: (match[1] as string).toUpperCase(), segments: path === "/" ? [] : path.slice(1).split("/") };
}

function keyOf(endpoint: Endpoint): string {
  return `${endpoint.method} /${endpoint.segments.join("/")}`;
}

/** The normalised key of a submitted endpoint (what "distinct" means for W1), or null when it does not parse. */
export function mapEndpointKey(value: string): string | null {
  const endpoint = typeof value === "string" ? parseSubmitted(value) : null;
  return endpoint === null ? null : keyOf(endpoint);
}

function inventoryEndpoint(entry: string): Endpoint | null {
  const route = parseRouteEntry(entry);
  if (route === null) return null;
  return { method: route.method, segments: route.path === "/" ? [] : route.path.slice(1).split("/") };
}

function endpointMatches(submitted: Endpoint, route: Endpoint): boolean {
  if (submitted.method !== route.method || submitted.segments.length !== route.segments.length) return false;
  return route.segments.every((segment, index) => {
    const candidate = submitted.segments[index] as string;
    if (segment.startsWith(":")) return candidate.length > 0;
    return candidate === segment;
  });
}

/**
 * Whether a submitted endpoint matches an inventory route: the method without regard to case, the path segment by
 * segment (a `:param` of the inventory matches any non-empty segment; a literal matches only itself, with case).
 */
export function matchesRoute(submitted: string, inventoryEntry: string): boolean {
  const a = parseSubmitted(submitted);
  const b = inventoryEndpoint(inventoryEntry);
  return a !== null && b !== null && endpointMatches(a, b);
}

/** Inventory routes matched one-to-one by the submitted endpoints (greedy, exact templates first). */
function coverage(submitted: readonly Endpoint[], inventory: readonly Endpoint[]): number {
  const used = new Set<number>();
  let matched = 0;
  for (const route of inventory) {
    let pick = -1;
    for (let i = 0; i < submitted.length; i++) {
      if (used.has(i) || !endpointMatches(submitted[i] as Endpoint, route)) continue;
      const exact = (submitted[i] as Endpoint).segments.join("/") === route.segments.join("/");
      if (pick === -1 || exact) pick = i;
      if (exact) break;
    }
    if (pick !== -1) {
      used.add(pick);
      matched += 1;
    }
  }
  return matched;
}

/**
 * W1 Map: the submitted endpoints, all W1 submissions together, cover at least 60 % of the Build's route inventory
 * with a precision (matched ÷ distinct submitted) of at least 50 %. Achieved by the first submission at which
 * both cumulative figures reach their thresholds. Without an inventory: not
 * attempted (`no_inventory`).
 */
export function verifyMap(
  submissions: readonly Submission[],
  routes: readonly string[] | null | undefined,
  _callsShowing: CallsShowing,
): Verdict {
  const inventory = (routes ?? []).map(inventoryEndpoint).filter((route): route is Endpoint => route !== null);
  if (inventory.length === 0) {
    return {
      kind: "not_attempted",
      reason: "no_inventory",
      evidence: evidence("No route inventory was registered with this Build, so Map cannot be judged.", [], []),
    };
  }
  const seen = new Map<string, Endpoint>();
  const callIndexes: number[] = [];
  let achievedAt: AchievedAt | null = null;
  let matched = 0;
  for (const submission of submissions) {
    if (submission.objective !== "W1") continue;
    callIndexes.push(submission.callIndex);
    for (const value of (submission.payload as MapSubmission).endpoints) {
      const endpoint = parseSubmitted(value);
      if (endpoint !== null) seen.set(keyOf(endpoint), endpoint);
    }
    matched = coverage([...seen.values()], inventory);
    const covered = matched * MAP_COVERAGE.denominator >= inventory.length * MAP_COVERAGE.numerator;
    const precise = matched * MAP_PRECISION.denominator >= seen.size * MAP_PRECISION.numerator && seen.size > 0;
    if (achievedAt === null && covered && precise) achievedAt = at(submission);
  }
  const percent = Math.floor((matched * 100) / inventory.length);
  const precision = seen.size === 0 ? 0 : Math.floor((matched * 100) / seen.size);
  const verdictText =
    achievedAt === null
      ? "below the 60 % coverage and 50 % precision needed"
      : "at least the 60 % coverage and 50 % precision needed";
  return {
    kind: "judged",
    achievedAt,
    evidence: evidence(
      `Submitted ${seen.size} distinct endpoints; ${matched} of the ${inventory.length} registered routes matched (coverage ${percent} %, precision ${precision} %; ${verdictText}).`,
      [{ kind: "routes", matched, submitted: seen.size, inventory: inventory.length }],
      callIndexes,
    ),
  };
}

// --- W2 Secrets ------------------------------------------------------------------------------------------

/**
 * W2 Secrets: a submitted value equals a planted Canary value of the Build, or the value of a leak-scan finding
 * (`leakFingerprint(rule, path, value)` equals the finding's fingerprint). Achieved by the first submission that
 * contains one; the evidence lists every Canary (by id) and finding (by fingerprint) recovered in the run, and
 * the calls that showed a recovered value to the agent plus the W2 submit calls.
 */
export function verifySecrets(
  submissions: readonly Submission[],
  build: { canaries: readonly Canary[]; leakFindings?: readonly LeakFindingRef[] },
  callsShowing: CallsShowing,
): Verdict {
  const canaryByValue = new Map(build.canaries.map((canary) => [canary.value, canary.id]));
  const findings = build.leakFindings ?? [];
  const recoveredCanaries = new Set<string>();
  const recoveredLeaks = new Map<string, LeakFindingRef>();
  const callIndexes: number[] = [];
  let achievedAt: AchievedAt | null = null;
  let valueCount = 0;
  for (const submission of submissions) {
    if (submission.objective !== "W2") continue;
    callIndexes.push(submission.callIndex);
    let hit = false;
    for (const value of (submission.payload as SecretsSubmission).values) {
      valueCount += 1;
      let matched = false;
      const canaryId = canaryByValue.get(value);
      if (canaryId !== undefined) {
        recoveredCanaries.add(canaryId);
        matched = true;
      }
      for (const finding of findings) {
        if (recoveredLeaks.has(finding.fingerprint)) continue;
        if (leakFingerprint(finding.rule, finding.path, value) === finding.fingerprint) {
          recoveredLeaks.set(finding.fingerprint, finding);
          matched = true;
        }
      }
      if (matched) {
        hit = true;
        callIndexes.push(...callsShowing(value));
      }
    }
    if (hit && achievedAt === null) achievedAt = at(submission);
  }
  const recovered: RecoveredItem[] = [
    ...[...recoveredCanaries].map((id) => ({ kind: "canary" as const, canary_id: id })),
    ...[...recoveredLeaks.values()].map((f) => ({ kind: "leak" as const, rule: f.rule, fingerprint: f.fingerprint })),
  ];
  const plural = (count: number, one: string, many: string) => `${count} ${count === 1 ? one : many}`;
  return {
    kind: "judged",
    achievedAt,
    evidence: evidence(
      `Recovered ${plural(recoveredCanaries.size, "planted Canary", "planted Canaries")} of ${build.canaries.length} and ${plural(recoveredLeaks.size, "leak-scan finding", "leak-scan findings")} of ${findings.length} from ${plural(valueCount, "submitted value", "submitted values")}.`,
      recovered,
      callIndexes,
    ),
  };
}

// --- W3, W4 ----------------------------------------------------------------------------------------------

/** W3 Logic and W4 Tamper have no verifier in 12a (D-073): not attempted, `not_supported`. */
export function notSupported(objective: "W3" | "W4"): ObjectiveResult {
  return {
    objective,
    result: "not_attempted",
    reason: "not_supported",
    evidence: evidence(`${objective === "W3" ? "Logic" : "Tamper"} is not assessed in this version.`, [], []),
  };
}
