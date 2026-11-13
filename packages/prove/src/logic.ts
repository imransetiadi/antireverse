// W3 Logic (slice 12b; review 12b F1, F4). The agent submits a reimplementation of a designated function as a JS
// function body; the verifier runs it against every hidden vector of that function in one sandbox child process
// per submission (child.ts: a new V8 context without require, process, network, timers or code generation;
// arguments as a0..aN and as `args`; 1 s per vector, 20 s per batch, stopping at the first vector that times out)
// and compares outputs with the expected ones by canonical JSON, in the parent. Only the inputs enter the child;
// the expected outputs never do. Achieved when every vector of that function passes. Evidence names the function
// id and the pass count, never a vector.
import { canonicalJson, LOGIC_LIMITS, type LogicFile } from "@antireverse/protocol";
import { runChild } from "./child.ts";
import type { Submission } from "./toolbelt.ts";
import type { LogicSubmissionPayload } from "./types.ts";
import { type AchievedAt, JudgingTimeError, type Verdict } from "./verifiers.ts";

export const LOGIC_RUN_LIMITS = Object.freeze({
  /** Milliseconds one vector may run (`LOGIC_LIMITS.vectorTimeoutMs`). */
  vectorTimeoutMs: LOGIC_LIMITS.vectorTimeoutMs,
  /** Milliseconds all vectors of one submission may run (`LOGIC_LIMITS.batchTimeoutMs`). */
  batchTimeoutMs: LOGIC_LIMITS.batchTimeoutMs,
  /** Extra milliseconds before the host gives up on one vector the script timeout could not stop. */
  graceMs: 500,
  /** Characters of one vector's output JSON. */
  outputCharsMax: 65_536,
  /** The child's heap, in MB. */
  heapMb: 128,
});

export type VectorResult = { ok: true; output: string } | { ok: false; kind: "timeout" | "error"; error: string };

export interface LogicRunOptions {
  vectorTimeoutMs?: number;
  batchTimeoutMs?: number;
  /** Milliseconds of judging each submission may use (its share of the judging budget, review N3). */
  shareMs?: number;
}

/** One batch: the results, and whether the submission's judging share (not the 20 s rule) cut it short. */
export interface LogicBatch {
  results: VectorResult[];
  cutByShare: boolean;
}

/**
 * Runs `body` once per input in one sandbox child, in order. One result per input. After the first vector that
 * times out the rest are not run and count as timed out (review 12b F4). Never rejects.
 */
export async function runLogicVectors(
  body: string,
  inputs: readonly (readonly unknown[])[],
  options: LogicRunOptions = {},
): Promise<VectorResult[]> {
  return (await runLogicBatch(body, inputs, options)).results;
}

/** As `runLogicVectors`, also saying whether the judging share cut the batch short. */
export async function runLogicBatch(
  body: string,
  inputs: readonly (readonly unknown[])[],
  options: LogicRunOptions = {},
): Promise<LogicBatch> {
  const vectorTimeoutMs = options.vectorTimeoutMs ?? LOGIC_RUN_LIMITS.vectorTimeoutMs;
  const ruleBatchMs = options.batchTimeoutMs ?? LOGIC_RUN_LIMITS.batchTimeoutMs;
  const batchTimeoutMs = Math.max(1, Math.min(ruleBatchMs, options.shareMs ?? Number.POSITIVE_INFINITY));
  if (inputs.length === 0) return { results: [], cutByShare: false };
  const arity = inputs.reduce((max, input) => Math.max(max, input.length), 0);
  const params = [...Array.from({ length: arity }, (_, i) => `a${i}`), "args"];
  const results: (VectorResult | undefined)[] = inputs.map(() => undefined);
  let rest: VectorResult = { ok: false, kind: "timeout", error: "The batch ran over its time limit." };
  const outcome = await runChild(
    {
      mode: "logic",
      body,
      inputs: inputs.map((input) => JSON.stringify(input)),
      params,
      timeoutMs: vectorTimeoutMs,
      outputCharsMax: LOGIC_RUN_LIMITS.outputCharsMax,
    },
    {
      heapMb: LOGIC_RUN_LIMITS.heapMb,
      timeoutMs: batchTimeoutMs,
      // Start-up and compilation fall in the first vector's allowance plus the grace.
      idleMs: vectorTimeoutMs + LOGIC_RUN_LIMITS.graceMs,
      maxOutputBytes: inputs.length * (LOGIC_RUN_LIMITS.outputCharsMax + 512) + 65_536,
      onLine: (line) => {
        if (typeof line.compileError === "string") {
          rest = { ok: false, kind: "error", error: line.compileError.slice(0, 300) };
          return true;
        }
        const index = line.index;
        if (typeof index !== "number" || !Number.isInteger(index) || index < 0 || index >= results.length) return false;
        if (results[index] !== undefined) return false;
        if (line.ok === true && typeof line.output === "string") {
          results[index] = { ok: true, output: line.output };
        } else {
          results[index] = {
            ok: false,
            kind: line.kind === "timeout" ? "timeout" : "error",
            error: typeof line.error === "string" ? line.error.slice(0, 300) : "failed",
          };
        }
        if (line.stop === true) {
          rest = { ok: false, kind: "timeout", error: "Not run: an earlier vector ran over its time limit." };
          return true;
        }
        return results.every((result) => result !== undefined);
      },
    },
  );
  if (outcome.outOfMemory && rest.ok === false && rest.kind === "timeout") {
    rest = { ok: false, kind: "error", error: "The body ran over the memory limit." };
  }
  const cutByShare = outcome.killedBy === "timeout" && batchTimeoutMs < ruleBatchMs;
  return { results: results.map((result) => result ?? rest), cutByShare };
}

function sameOutput(output: string, expected: unknown): boolean {
  try {
    return canonicalJson(JSON.parse(output)) === canonicalJson(expected);
  } catch {
    return false;
  }
}

/**
 * W3 Logic over the run's W3 submissions (at most `LOGIC_LIMITS.submissionsMax`, in order). Without designated
 * functions: not attempted (`not_designated`). Null when there are functions but nothing was submitted.
 */
export async function verifyLogic(
  submissions: readonly Submission[],
  logic: LogicFile | null | undefined,
  options: LogicRunOptions = {},
): Promise<Verdict | null> {
  const functions = logic?.functions ?? [];
  if (functions.length === 0) {
    return {
      kind: "not_attempted",
      reason: "not_designated",
      evidence: {
        summary: "No protected function was designated; add --logic to Harden.",
        recovered: [],
        calls: [],
      },
    };
  }
  const mine = submissions.filter((s) => s.objective === "W3").slice(0, LOGIC_LIMITS.submissionsMax);
  if (mine.length === 0) return null;
  let achievedAt: AchievedAt | null = null;
  let best: { id: string; passed: number; total: number } | null = null;
  let judged = 0;
  let unjudged = 0;
  for (const submission of mine) {
    const { function_id: id, body } = submission.payload as LogicSubmissionPayload;
    const designated = functions.find((entry) => entry.id === id);
    if (designated === undefined) {
      best ??= { id, passed: 0, total: 0 };
      judged += 1;
      continue;
    }
    const { results, cutByShare } = await runLogicBatch(
      body,
      designated.vectors.map((vector) => vector.input),
      options,
    );
    // A batch cut short by its judging share (not by the 20 s rule) decides nothing (review N3).
    if (cutByShare) {
      unjudged += 1;
      continue;
    }
    judged += 1;
    const passed = results.filter((result, index) => {
      const vector = designated.vectors[index];
      return result.ok && vector !== undefined && sameOutput(result.output, vector.output);
    }).length;
    const total = designated.vectors.length;
    if (best === null || best.total === 0 || passed / total > best.passed / Math.max(1, best.total)) {
      best = { id, passed, total };
    }
    if (total > 0 && passed === total && achievedAt === null) {
      achievedAt = { callIndex: submission.callIndex, cost: { ...submission.cost } };
      best = { id, passed, total };
      break;
    }
  }
  if (judged === 0 || best === null) throw new JudgingTimeError();
  const shown = best;
  const cut =
    unjudged > 0 ? ` ${unjudged} of ${mine.length} submissions could not be judged within the judging time.` : "";
  const summary =
    shown.total === 0
      ? `The submitted function ${shown.id} was not designated for this Build.${cut}`
      : `Function ${shown.id}: ${shown.passed} of ${shown.total} hidden vectors passed (best of ${judged} judged submission${judged === 1 ? "" : "s"}); ${achievedAt === null ? "every vector must pass" : "achieved"}.${cut}`;
  return {
    kind: "judged",
    achievedAt,
    evidence: { summary: summary.slice(0, 500), recovered: [], calls: mine.map((s) => s.callIndex) },
  };
}
