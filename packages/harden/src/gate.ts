// The CI gate on the Reverse Resistance Score (slice 13). `waitForAssessment` polls GET /v1/assessments/:id with the
// admin key (a Bearer header only, never logged or returned) until the Assessment finishes or the wait runs out:
// backoff 2 s doubling to 30 s, sleeping at most until the deadline, with a last poll there; each poll is aborted after
// min(15 s, max(time left, 2 s)), so a run overruns --wait by at most 2 s and never reports the wait ended before the
// deadline; network errors, timeouts, 429 and 5xx are retried within the wait; any other 4xx, a
// response that is not an Assessment, or a different Assessment stops at once. Progress is reported every 60 s. `evaluateRrsGate` turns the outcome into the gate: passed | failed |
// no_score | skipped. Only Objective names and results are reported — never evidence.
import {
  ADMIN_KEY_PATTERN,
  type Assessment,
  AssessmentResponseSchema,
  type AssessmentStatus,
  type AssessmentTier,
  OBJECTIVES,
  type ObjectiveId,
  type ObjectiveResult,
  RESISTANCE_VALUES,
  SHIELD_KEY_PATTERN,
  TIER_IDS,
  TIERS,
} from "@antireverse/protocol";

/** Exit code of an RRS below `--min-rrs`. */
export const EXIT_RRS_BELOW = 5;
/** Exit code of no score: inconclusive, failed, or still unfinished when the wait ended. */
export const EXIT_NO_SCORE = 6;

export const MIN_RRS_RANGE = { min: 0, max: 100 } as const;
export const WAIT_RANGE = { min: 1, max: 86_400 } as const;
/** Seconds added to the tier's own seconds for the default wait. */
export const WAIT_SLACK_SECONDS = 300;
export const BACKOFF = { firstMs: 2000, maxMs: 30_000 } as const;
/** Each poll is aborted after 15 s, or the time left in the wait if less, and retried. */
export const POLL_TIMEOUT_MS = 15_000;
/** The shortest poll timeout: the last poll at the deadline gets this long, so a run overruns --wait by at most 2 s. */
export const MIN_POLL_TIMEOUT_MS = 2000;
/** A progress line (stderr) every 60 s of waiting. */
export const PROGRESS_EVERY_MS = 60_000;
export const ON_NO_SCORE = ["fail", "pass"] as const;
export type OnNoScore = (typeof ON_NO_SCORE)[number];

/** A `--key-env` value that can be named in a message: an environment variable name. */
const ENV_NAME = /^[A-Za-z_][A-Za-z0-9_]{0,63}$/;
/** A key that can travel in an Authorization header: visible ASCII only. */
const HEADER_VALUE = /^[\x21-\x7e]+$/;

/**
 * The admin key from the variable `--key-env` names, or the usage error. The value is named in a message only when it
 * is a variable name and not a key itself (a key passed as `--key-env` must never be echoed); the key is never printed.
 */
export function readAdminKey(
  command: string,
  keyEnv: string | null | undefined,
  env: Record<string, string | undefined>,
): { key: string } | { error: string } {
  if (
    typeof keyEnv !== "string" ||
    !ENV_NAME.test(keyEnv) ||
    ADMIN_KEY_PATTERN.test(keyEnv) ||
    SHIELD_KEY_PATTERN.test(keyEnv)
  ) {
    return { error: `${command}: the --key-env value is not a valid variable name` };
  }
  const key = env[keyEnv];
  if (!key)
    return { error: `${command}: environment variable ${keyEnv} is not set (the admin key is read only from it)` };
  if (!HEADER_VALUE.test(key)) {
    return { error: `${command}: the admin key in ${keyEnv} is not a valid header value (visible ASCII only)` };
  }
  return { key };
}

/** Whether an endpoint carries credentials (user:pass@), which a request can never send. Unparseable: false. */
export function endpointHasCredentials(endpoint: string): boolean {
  try {
    const url = new URL(endpoint);
    return url.username !== "" || url.password !== "";
  } catch {
    return false;
  }
}

/** Milliseconds a `Retry-After` header asks for (seconds or an HTTP date), or 0. */
function retryAfterMs(header: string | null): number {
  if (header === null) return 0;
  const value = header.trim();
  if (/^\d{1,9}$/.test(value)) return Number.parseInt(value, 10) * 1000;
  const date = Date.parse(value);
  return Number.isFinite(date) ? Math.max(0, date - Date.now()) : 0;
}

/** The default `--wait`: the tier's seconds plus 5 minutes. */
export function defaultWaitSeconds(tier: AssessmentTier): number {
  return TIERS[tier].seconds + WAIT_SLACK_SECONDS;
}

/** The parsed integer when `raw` is a plain decimal integer within [min, max], else null. */
export function parseBoundedInt(raw: string | null | undefined, range: { min: number; max: number }): number | null {
  if (typeof raw !== "string" || !/^-?\d{1,6}$/.test(raw)) return null;
  const n = Number.parseInt(raw, 10);
  return n >= range.min && n <= range.max ? n : null;
}

export interface WaitIo {
  fetch: typeof globalThis.fetch;
  now: () => number;
  sleep: (ms: number) => Promise<void>;
  /** The abort signal of one poll. Default in the CLI: AbortSignal.timeout. */
  timeout: (ms: number) => AbortSignal;
  /** Called every 60 s of waiting with the last known status (null before any answer) and the seconds elapsed. */
  onProgress?: (status: AssessmentStatus | null, elapsedSeconds: number) => void;
}

export interface WaitArgs {
  endpoint: string;
  /** The admin key. Used only as a Bearer header; never logged or returned. */
  key: string;
  id: string;
  /** Seconds to wait; undefined = the tier's seconds plus 5 minutes (T3's until the tier is known). */
  waitSeconds?: number | undefined;
}

export type WaitResult =
  | { finished: Assessment }
  | { timedOut: true; waitSeconds: number; last: Assessment | null }
  | { error: string };

const FINISHED: readonly AssessmentStatus[] = ["scored", "inconclusive", "failed"];

/** Polls the Assessment until it finishes or the wait runs out. Never throws. */
export async function waitForAssessment(args: WaitArgs, io: WaitIo): Promise<WaitResult> {
  const url = `${args.endpoint.replace(/\/+$/, "")}/v1/assessments/${encodeURIComponent(args.id)}`;
  const start = io.now();
  // Until the tier is known (the first answer), the default wait is the longest tier's.
  let waitSeconds = args.waitSeconds ?? defaultWaitSeconds(TIER_IDS[TIER_IDS.length - 1] as AssessmentTier);
  let deadline = start + waitSeconds * 1000;
  let delay: number = BACKOFF.firstMs;
  let last: Assessment | null = null;
  let lastProgress = start;

  for (;;) {
    let response: Response | null = null;
    let raw = "";
    let retryAfter = 0;
    try {
      // Aborted after min(15 s, max(time left, 2 s)). The body is read under the same signal, so a body that stalls
      // after the headers is a timed-out poll too.
      const signal = io.timeout(Math.min(POLL_TIMEOUT_MS, Math.max(deadline - io.now(), MIN_POLL_TIMEOUT_MS)));
      response = await io.fetch(url, { method: "GET", headers: { authorization: `Bearer ${args.key}` }, signal });
      raw = await response.text();
    } catch (error) {
      // A TypeError with no cause code is a request that can never be made (fetch refused it before any network
      // work): stop. Its message may quote the header, so it is never printed. Anything else — a network error (a
      // cause code such as ECONNREFUSED) or a timed-out poll — is retried within the wait.
      const code = (error as { cause?: { code?: unknown } } | null)?.cause?.code;
      if (error instanceof TypeError && typeof code !== "string") {
        return { error: "the request could not be made (TypeError)" };
      }
      response = null;
    }

    if (response !== null) {
      let body: unknown;
      try {
        body = JSON.parse(raw);
      } catch {
        body = undefined;
      }
      const retryable = response.status === 408 || response.status === 429 || response.status >= 500;
      if (response.status === 429 || response.status === 503) {
        retryAfter = retryAfterMs(response.headers.get("retry-after"));
      }
      if (!response.ok && !retryable) {
        const problem = body as { title?: unknown; detail?: unknown } | undefined;
        const detail = typeof problem?.detail === "string" ? problem.detail : undefined;
        const title = typeof problem?.title === "string" ? problem.title : undefined;
        return { error: detail ?? title ?? `the API responded ${response.status}` };
      }
      if (response.ok) {
        const parsed = AssessmentResponseSchema.safeParse(body);
        if (!parsed.success) return { error: "the API returned a response that was not an Assessment" };
        const assessment = parsed.data.assessment;
        if (assessment.id !== args.id) {
          return { error: `the API returned a different Assessment (${assessment.id}) than ${args.id}` };
        }
        if (last === null && args.waitSeconds === undefined) {
          waitSeconds = defaultWaitSeconds(assessment.tier);
          deadline = start + waitSeconds * 1000;
        }
        last = assessment;
        if (FINISHED.includes(assessment.status)) return { finished: assessment };
      }
    }

    const now = io.now();
    if (now - lastProgress >= PROGRESS_EVERY_MS) {
      lastProgress = now;
      io.onProgress?.(last?.status ?? null, Math.round((now - start) / 1000));
    }
    // The wait has ended only once the deadline is reached; until then, sleep (at most up to the deadline) and poll
    // again, so the last poll happens at the deadline.
    const remaining = deadline - now;
    if (remaining <= 0) return { timedOut: true, waitSeconds, last };
    // At least the backoff, at least a Retry-After (429, 503), never past the deadline.
    await io.sleep(Math.min(Math.max(delay, retryAfter), remaining));
    delay = Math.min(delay * 2, BACKOFF.maxMs);
  }
}

export type RrsGateResult = "passed" | "failed" | "no_score" | "skipped";

export interface WeakObjective {
  objective: ObjectiveId;
  name: string;
  result: "achieved" | "not_achieved";
  /** The tier it was achieved at; absent when not achieved. */
  tier?: AssessmentTier;
}

export interface RrsGate {
  result: RrsGateResult;
  rrs: number | null;
  threshold: number;
  /** The Assessment's last known status; null when the API was never reached. */
  status: AssessmentStatus | null;
  /** Why there is no score; null when scored. */
  reason: string | null;
  /** The two lowest-scoring decided Objectives (achieved or not achieved), lowest first. */
  weakest: WeakObjective[];
}

/** The two lowest-scoring decided Objectives: rᵢ ascending; ties keep the Objectives' order (W1 … W5). */
export function weakestObjectives(assessment: Assessment): WeakObjective[] {
  const order = new Map(OBJECTIVES.map((objective, index) => [objective.id as ObjectiveId, index]));
  const value = (r: ObjectiveResult) =>
    r.result === "achieved"
      ? RESISTANCE_VALUES.achieved[r.tier]
      : r.result === "not_achieved"
        ? RESISTANCE_VALUES.not_achieved[assessment.tier]
        : Number.POSITIVE_INFINITY;
  return assessment.results
    .filter((r) => r.result !== "not_attempted")
    .sort((a, b) => value(a) - value(b) || (order.get(a.objective) ?? 0) - (order.get(b.objective) ?? 0))
    .slice(0, 2)
    .map((r) => {
      const name = OBJECTIVES.find((o) => o.id === r.objective)?.name ?? r.objective;
      return r.result === "achieved"
        ? { objective: r.objective, name, result: "achieved", tier: r.tier }
        : { objective: r.objective, name, result: "not_achieved" };
    });
}

/** The gate from a wait's outcome (a wait that stopped with an error is not a gate: the caller exits 1). */
export function evaluateRrsGate(
  outcome: Exclude<WaitResult, { error: string }>,
  threshold: number,
  onNoScore: OnNoScore,
): RrsGate {
  const noScore = (status: AssessmentStatus | null, reason: string, weakest: WeakObjective[] = []): RrsGate => ({
    result: onNoScore === "pass" ? "skipped" : "no_score",
    rrs: null,
    threshold,
    status,
    reason,
    weakest,
  });
  if ("timedOut" in outcome) {
    return noScore(
      outcome.last?.status ?? null,
      `the wait of ${outcome.waitSeconds} s ended before the Assessment finished${outcome.last === null ? " (the API could not be reached)" : ""}`,
    );
  }
  const a = outcome.finished;
  if (a.status === "scored" && a.rrs !== null) {
    return {
      result: a.rrs >= threshold ? "passed" : "failed",
      rrs: a.rrs,
      threshold,
      status: a.status,
      reason: null,
      weakest: weakestObjectives(a),
    };
  }
  if (a.status === "failed")
    return noScore(a.status, `the Assessment failed: ${a.failure_reason ?? "no reason given"}`);
  return noScore(a.status, a.inconclusive_reason ?? "the Assessment is inconclusive", weakestObjectives(a));
}

/** The exit code of the RRS gate alone: 0, 5 or 6. */
export function rrsGateExit(gate: RrsGate): number {
  if (gate.result === "failed") return EXIT_RRS_BELOW;
  if (gate.result === "no_score") return EXIT_NO_SCORE;
  return 0;
}

function weakestText(weakest: WeakObjective[]): string {
  return weakest
    .map((w) => `${w.objective} ${w.name} (${w.result === "achieved" ? `achieved at ${w.tier}` : "not achieved"})`)
    .join(", ");
}

/** The human lines of the gate: the score, the threshold, the status and the weakest Objectives. */
export function rrsGateLines(gate: RrsGate, id: string, tier: AssessmentTier | null): string[] {
  const about = ` — assessment ${id} ${gate.status ?? "unknown"}${tier ? ` (${tier})` : ""}`;
  const noRrs = `no RRS for assessment ${id} (${gate.status ?? "unknown"}): ${gate.reason}`;
  const lines: string[] = [];
  if (gate.result === "passed") lines.push(`✓ RRS ${gate.rrs} meets --min-rrs ${gate.threshold}${about}`);
  else if (gate.result === "failed") lines.push(`✗ RRS ${gate.rrs} is below --min-rrs ${gate.threshold}${about}`);
  else if (gate.result === "no_score") lines.push(`✗ ${noRrs}`);
  else lines.push(`! RRS gate skipped (--on-no-score pass): ${noRrs}`);
  if (gate.weakest.length > 0) lines.push(`  weakest: ${weakestText(gate.weakest)}`);
  return lines;
}

/** The stderr line of a gate that did not pass, or the warning of a skipped one; null when passed. */
export function rrsGateMessage(gate: RrsGate, command: string): string | null {
  if (gate.result === "failed") return `${command}: RRS gate failed: ${gate.rrs} is below ${gate.threshold}`;
  if (gate.result === "no_score") return `${command}: RRS gate has no score: ${gate.reason}`;
  if (gate.result === "skipped") {
    return `${command}: warning: RRS gate skipped (--on-no-score pass): no score: ${gate.reason}`;
  }
  return null;
}
