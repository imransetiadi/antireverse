// W4 Tamper (slice 12b; review 12b F1–F4, N1–N3). The agent submits a modified version of one artifact JS file;
// the verifier runs it in a fresh sandbox child process (child.ts, sandbox-child.mjs) — a new V8 context with stub
// browser globals (non-writable proxies that record a trace of names: reads, writes, calls), every static import
// linked to a stub module, `eval` and the Function-family constructors replaced by guards of the context's own
// realm that refuse import() and record every evaluation — and decides from facts the child establishes, never
// from anything the submitted code can post (Jev: behavioural_trace, review N2):
//   1. no error whose message contains "integrity check failed";
//   2. the marker statement `globalThis.__airverse_tamper="<nonce>";` is textually inside the code that ran, and the
//      marker equals the nonce afterwards. For a Build hardened with integrity, the code that ran is an evaluation
//      that completed normally (no throw, no SyntaxError), with the marker absent before it and set after it;
//      otherwise it is the submitted file, whose run must complete normally;
//   3. that code, with the marker statement removed, is ≥ 90 % similar (common prefix + common suffix) to the
//      original — the payload the original file evaluates (integrity) or the original file;
//   4. the run reproduces ≥ 90 % (longest common subsequence) of the trace the original file leaves on the stub
//      globals when it runs as the baseline. When the original leaves no trace, rule 3 alone decides, and the
//      evidence says so.
// A Build without integrity has no tamper check, so a small marker edit achieves W4 (owner, D-075). Deleting the
// protected code and setting the marker never counts. Any source with a dynamic import() or import.meta is refused
// before it compiles (review N1). Judging time is shared over the submissions (review N3): a submission cut short
// by its share is not judged; W4 is decided from the judged ones, and is a JudgingTimeError only when none was.
import { TAMPER_LIMITS } from "@antireverse/protocol";
import { runChild } from "./child.ts";
import type { Submission } from "./toolbelt.ts";
import type { TamperSubmissionPayload } from "./types.ts";
import { type AchievedAt, JudgingTimeError, type Verdict } from "./verifiers.ts";

/** The global the submitted code must set to this run's nonce. */
export const TAMPER_MARKER = "globalThis.__airverse_tamper";

/** The exact marker statement the modified code must contain for a nonce. */
export function markerStatement(nonce: string): string {
  return `${TAMPER_MARKER}=${JSON.stringify(nonce)};`;
}

export const TAMPER_RUN_LIMITS = Object.freeze({
  /** Milliseconds a tamper run may take (`TAMPER_LIMITS.timeoutMs`). */
  timeoutMs: TAMPER_LIMITS.timeoutMs,
  /** Extra milliseconds before the parent kills the child (start-up, module analysis, reading the facts). */
  graceMs: 2_500,
  /** Errors kept, and characters of each. */
  errorsMax: 20,
  errorCharsMax: 1_000,
  /** The child's heap, in MB (a file of up to 25 MB, its edit up to twice that, the module analysis). */
  heapMb: 512,
  /** The share of the original's trace a run must reproduce. */
  traceMin: 0.9,
  /** A run shorter than this is not worth starting within a submission's judging share. */
  minRunMs: 100,
});

/** What one tamper run established. */
export interface TamperRun {
  /** The file ran as an ES module. */
  module: boolean;
  /** Messages of the errors the run threw (bounded). */
  errors: string[];
  /** An error mentioned "integrity check failed". */
  integrityFailed: boolean;
  /** The marker's value after the run when it is a string data property, else null. */
  marker: string | null;
  /** The file's own run completed without throwing (and within its time). */
  completedNormally: boolean;
  /** The run completed normally, or ended with exactly the error the original's run ended with. */
  completedLikeBaseline: boolean;
  /** Evaluations that completed normally and compiled. */
  evalCount: number;
  /**
   * The best similarity to the reference, marker statement removed, among evaluations that completed normally,
   * contain the marker statement and set the marker (absent before, the nonce after); else 0.
   */
  bestSetInside: number;
  /** The share of the baseline trace the run reproduced, or null without a baseline trace. */
  traceRatio: number | null;
  /** Entries in this run's trace. */
  traceLength: number;
  /** The run hit its time limit, or the child had to be killed. */
  timedOut: boolean;
  /** The child's own realm was found modified after the run (never expected; the run then counts for nothing). */
  polluted: boolean;
}

export interface TamperRunOptions {
  /** Milliseconds the code may run (tests). Default 5,000. */
  timeoutMs?: number;
  /** This run's nonce (for crediting the marker). */
  nonce?: string;
  /** The original payload evaluations are compared with (integrity Builds). */
  reference?: string | null;
  /** The original's trace on the stub globals, to be reproduced. */
  baselineTrace?: readonly string[];
  /** How the original's run ended when it threw ("Name: message"); the same ending counts as completing. */
  baselineError?: string | null;
  /** How the original's payload evaluation ended when it threw; the same ending counts as completing. */
  payloadError?: string | null;
}

export interface TamperBaseline {
  /** The longest string the original evaluated that completed normally and compiled: the integrity payload. */
  payload: string | null;
  /** How the payload's evaluation ended when it threw, else null. */
  payloadError: string | null;
  /** How the original's own run ended when it threw, else null. */
  endError: string | null;
  /** The original's trace on the stub globals (at most 2,000 entries, names only). */
  trace: string[];
  /** The baseline run hit its time limit. */
  timedOut: boolean;
}

const NO_FACTS: TamperRun = {
  module: false,
  errors: ["The sandbox ended without a result."],
  integrityFailed: false,
  marker: null,
  completedNormally: false,
  completedLikeBaseline: false,
  evalCount: 0,
  bestSetInside: 0,
  traceRatio: null,
  traceLength: 0,
  timedOut: true,
  polluted: false,
};

function childRequest(code: string, timeoutMs: number, extra: Record<string, unknown>): Record<string, unknown> {
  return {
    mode: "tamper",
    code,
    timeoutMs,
    errorsMax: TAMPER_RUN_LIMITS.errorsMax,
    errorCharsMax: TAMPER_RUN_LIMITS.errorCharsMax,
    ...extra,
  };
}

const strings = (value: unknown, max: number): string[] =>
  Array.isArray(value) ? value.filter((entry): entry is string => typeof entry === "string").slice(0, max) : [];
const finite = (value: unknown): number | null => (typeof value === "number" && Number.isFinite(value) ? value : null);

/** Runs `code` once in a fresh tamper sandbox child. Never rejects. */
export async function runTamper(code: string, options: TamperRunOptions = {}): Promise<TamperRun> {
  const timeoutMs = options.timeoutMs ?? TAMPER_RUN_LIMITS.timeoutMs;
  const outcome = await runChild(
    childRequest(code, timeoutMs, {
      nonce: options.nonce ?? null,
      reference: options.reference ?? null,
      baselineTrace: options.baselineTrace ?? [],
      baselineError: options.baselineError ?? null,
      payloadError: options.payloadError ?? null,
      baseline: false,
    }),
    {
      heapMb: TAMPER_RUN_LIMITS.heapMb,
      timeoutMs: timeoutMs + TAMPER_RUN_LIMITS.graceMs,
      maxOutputBytes: TAMPER_RUN_LIMITS.errorsMax * (TAMPER_RUN_LIMITS.errorCharsMax * 6 + 64) + 65_536,
    },
  );
  const line = outcome.lines[0];
  if (line === undefined) return { ...NO_FACTS, timedOut: outcome.killed || !outcome.outOfMemory };
  if (line.polluted === true)
    return { ...NO_FACTS, errors: ["The sandbox's realm was modified."], polluted: true, timedOut: false };
  const errors = strings(line.errors, TAMPER_RUN_LIMITS.errorsMax);
  const ratio = finite(line.traceRatio);
  return {
    module: line.module === true,
    errors,
    integrityFailed: line.integrityFailed === true || errors.some((e) => e.includes("integrity check failed")),
    marker: typeof line.marker === "string" ? line.marker : null,
    completedNormally: line.completedNormally === true,
    completedLikeBaseline: line.completedLikeBaseline === true,
    evalCount: finite(line.evalCount) ?? 0,
    bestSetInside: Math.min(1, Math.max(0, finite(line.bestSetInside) ?? 0)),
    traceRatio: ratio === null || ratio < 0 ? null : Math.min(1, ratio),
    traceLength: finite(line.traceLength) ?? 0,
    timedOut: line.timedOut === true,
    polluted: false,
  };
}

/** Runs the original file once under the recorder and the tracing stubs. The original is the tenant's file. */
export async function runBaseline(original: string, options: { timeoutMs?: number } = {}): Promise<TamperBaseline> {
  const timeoutMs = options.timeoutMs ?? TAMPER_RUN_LIMITS.timeoutMs;
  const outcome = await runChild(childRequest(original, timeoutMs, { baseline: true }), {
    heapMb: TAMPER_RUN_LIMITS.heapMb,
    timeoutMs: timeoutMs + TAMPER_RUN_LIMITS.graceMs,
    maxOutputBytes: original.length * 6 + 2_097_152,
  });
  const line = outcome.lines[0];
  if (line === undefined || line.polluted === true) {
    return { payload: null, payloadError: null, endError: null, trace: [], timedOut: true };
  }
  return {
    payload: typeof line.payload === "string" ? line.payload : null,
    payloadError: typeof line.payloadError === "string" ? line.payloadError : null,
    endError: typeof line.endError === "string" ? line.endError : null,
    trace: strings(line.trace, 2_000),
    timedOut: line.timedOut === true,
  };
}

/** The integrity wrapper's payload, or null when the original evaluates none (no wrapper). Never rejects. */
export async function extractPayload(original: string, options: { timeoutMs?: number } = {}): Promise<string | null> {
  return (await runBaseline(original, options)).payload;
}

function removeFirst(source: string, part: string): string {
  const at = source.indexOf(part);
  return at === -1 ? source : source.slice(0, at) + source.slice(at + part.length);
}

export function similarity(original: string, candidate: string): number {
  if (original.length === 0) return 0;
  const shorter = Math.min(original.length, candidate.length);
  let prefix = 0;
  while (prefix < shorter && original.charCodeAt(prefix) === candidate.charCodeAt(prefix)) prefix++;
  let suffix = 0;
  const room = shorter - prefix;
  while (
    suffix < room &&
    original.charCodeAt(original.length - 1 - suffix) === candidate.charCodeAt(candidate.length - 1 - suffix)
  ) {
    suffix++;
  }
  return Math.min(1, (prefix + suffix) / original.length);
}

export interface TamperFacts {
  /** The artifact's files (path → bytes or text). */
  artifact: ReadonlyMap<string, Uint8Array | string>;
  /** Whether the Build was hardened with the integrity pass (the Manifest's `transform.integrity`). */
  integrity: boolean;
  /** This run's nonce, shown to the agent. */
  nonce: string;
  /** Milliseconds per run (tests). Default 5,000. */
  timeoutMs?: number;
  /** Milliseconds of judging each submission may use (its share of the judging budget). Default: unbounded. */
  shareMs?: number;
}

const decoder = new TextDecoder("utf-8");
function textOf(content: Uint8Array | string | undefined): string | null {
  if (content === undefined) return null;
  return typeof content === "string" ? content : decoder.decode(content);
}

interface Attempt {
  path: string;
  /** Judged against the integrity payload (an integrity Build whose file evaluates one). */
  payload: boolean;
  achieved: boolean;
  integrityFailed: boolean;
  markerSet: boolean;
  share: number;
  /** The share of the original's trace reproduced, or null when the original left none. */
  trace: number | null;
  traceEntries: number;
  timedOut: boolean;
}

function describe(attempt: Attempt, index: number, count: number, unjudged: number): string {
  const parts: string[] = [];
  parts.push(attempt.integrityFailed ? "the integrity check failed" : "no integrity check failed");
  parts.push(
    attempt.markerSet
      ? attempt.payload
        ? "the marker was set inside a completed evaluation"
        : "the marker was set by the completed run"
      : attempt.payload
        ? "the marker was not set inside a completed evaluation"
        : "the marker was not set by a completed run",
  );
  parts.push(
    attempt.share >= TAMPER_LIMITS.similarityMin
      ? `code similar to the original was evaluated (${Math.floor(attempt.share * 100)} %)`
      : `the evaluated code was ${Math.floor(attempt.share * 100)} % similar to the original`,
  );
  parts.push(
    attempt.trace === null
      ? "the original has no global interactions to trace; judged on the text"
      : `it reproduced ${Math.floor(attempt.trace * 100)} % of the original's global interactions (${attempt.traceEntries} traced)`,
  );
  if (attempt.timedOut) parts.push("the run hit its time limit");
  const path = attempt.path.length > 80 ? `${attempt.path.slice(0, 77)}...` : attempt.path;
  const cut = unjudged > 0 ? ` ${unjudged} of ${count} submissions could not be judged within the judging time.` : "";
  return `Evaluated the modified ${path} (submission ${index + 1} of ${count}): ${parts.join(", ")}; ${attempt.achieved ? "achieved" : "not achieved"}.${cut}`;
}

/**
 * W4 Tamper over the run's W4 submissions (at most `TAMPER_LIMITS.submissionsMax`, in order). Achieved by the
 * first judged submission that meets the conditions. Null when nothing was submitted (the orchestrator decides).
 * Throws a `JudgingTimeError` when no submission could be judged within its share of the judging time.
 */
export async function verifyTamper(submissions: readonly Submission[], facts: TamperFacts): Promise<Verdict | null> {
  const mine = submissions.filter((s) => s.objective === "W4").slice(0, TAMPER_LIMITS.submissionsMax);
  if (mine.length === 0) return null;
  const ruleTimeout = facts.timeoutMs ?? TAMPER_RUN_LIMITS.timeoutMs;
  const baselines = new Map<string, TamperBaseline>();
  const attempts: Attempt[] = [];
  let unjudged = 0;
  let achievedAt: AchievedAt | null = null;
  const statement = markerStatement(facts.nonce);
  for (const submission of mine) {
    const { path, code } = submission.payload as TamperSubmissionPayload;
    const original = textOf(facts.artifact.get(path));
    if (original === null) {
      attempts.push({
        path,
        payload: false,
        achieved: false,
        integrityFailed: false,
        markerSet: false,
        share: 0,
        trace: null,
        traceEntries: 0,
        timedOut: false,
      });
      continue;
    }
    const windowEnd = facts.shareMs === undefined ? Number.POSITIVE_INFINITY : Date.now() + facts.shareMs;
    /** This child's time: the rule's, or less when the submission's share is running out (null: no time left). */
    const allowance = (): number | null => {
      const left = windowEnd - Date.now() - TAMPER_RUN_LIMITS.graceMs;
      const time = Math.min(ruleTimeout, left);
      return time < TAMPER_RUN_LIMITS.minRunMs ? null : time;
    };
    let baseline = baselines.get(path);
    if (baseline === undefined) {
      const time = allowance();
      if (time === null) {
        unjudged += 1;
        continue;
      }
      baseline = await runBaseline(original, { timeoutMs: time });
      if (baseline.timedOut && time < ruleTimeout) {
        unjudged += 1;
        continue;
      }
      baselines.set(path, baseline);
    }
    const time = allowance();
    if (time === null) {
      unjudged += 1;
      continue;
    }
    const payload = facts.integrity ? baseline.payload : null;
    const run = await runTamper(code, {
      timeoutMs: time,
      nonce: facts.nonce,
      reference: payload,
      baselineTrace: baseline.trace,
      baselineError: baseline.endError,
      payloadError: baseline.payloadError,
    });
    if (run.timedOut && time < ruleTimeout) {
      unjudged += 1;
      continue;
    }
    const traceOk = baseline.trace.length === 0 || (run.traceRatio ?? 0) >= TAMPER_RUN_LIMITS.traceMin;
    let attempt: Attempt;
    if (payload !== null) {
      const share = run.bestSetInside;
      attempt = {
        path,
        payload: true,
        achieved:
          !run.polluted &&
          !run.integrityFailed &&
          run.marker === facts.nonce &&
          share >= TAMPER_LIMITS.similarityMin &&
          traceOk,
        integrityFailed: run.integrityFailed,
        markerSet: share > 0,
        share,
        trace: baseline.trace.length === 0 ? null : (run.traceRatio ?? 0),
        traceEntries: baseline.trace.length,
        timedOut: run.timedOut,
      };
    } else {
      const markerSet = run.completedLikeBaseline && run.marker === facts.nonce && code.includes(statement);
      const share = code.includes(statement) ? similarity(original, removeFirst(code, statement)) : 0;
      attempt = {
        path,
        payload: false,
        achieved: !run.polluted && !run.integrityFailed && markerSet && share >= TAMPER_LIMITS.similarityMin && traceOk,
        integrityFailed: run.integrityFailed,
        markerSet,
        share,
        trace: baseline.trace.length === 0 ? null : (run.traceRatio ?? 0),
        traceEntries: baseline.trace.length,
        timedOut: run.timedOut,
      };
    }
    attempts.push(attempt);
    if (attempt.achieved) {
      achievedAt = { callIndex: submission.callIndex, cost: { ...submission.cost } };
      break;
    }
  }
  if (attempts.length === 0) throw new JudgingTimeError();
  const shown = attempts.find((a) => a.achieved) ?? (attempts[attempts.length - 1] as Attempt);
  return {
    kind: "judged",
    achievedAt,
    evidence: {
      summary: describe(shown, attempts.indexOf(shown), mine.length, unjudged).slice(0, 500),
      recovered: [],
      calls: mine.map((s) => s.callIndex),
    },
  };
}
