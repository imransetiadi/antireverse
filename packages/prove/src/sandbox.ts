// The Toolbelt's code runner (slice 12a, Review Focus 2; review 12b F1). Each call starts a fresh sandbox child
// process (child.ts: permission model, no code generation in its own realm, empty environment, heap limit); inside
// it the code runs in a new V8 context (node:vm) that has only the language built-ins: no require, import, process,
// Buffer, network classes or timers, and code generation from strings is off (eval, new Function and the
// constructor escape all throw). import() rejects with an error of the context's own realm. The input crosses as
// a JSON string and the output comes back as one. The script timeout stops loops (microtasks included); the parent
// kills the child for anything the script timeout cannot interrupt.
// Honest limit: a child process on the same machine is not the hosted isolated account (SDD §12.2).
import { runChild } from "./child.ts";
import type { RunResult, ToolFailure } from "./types.ts";

export const RUN_LIMITS = Object.freeze({
  /** Milliseconds one run may take. */
  timeoutMs: 5_000,
  /** Characters of code. */
  codeCharsMax: 100_000,
  /** Characters of the input's JSON. */
  inputCharsMax: 1_000_000,
  /** Characters of the output's JSON. */
  outputCharsMax: 65_536,
  /** Characters of an error message passed back. */
  errorCharsMax: 300,
  /** The child's heap limit, in MB. */
  heapMb: 128,
});

/** Grace after the script timeout before the parent kills the child (start-up included). */
const KILL_GRACE_MS = 750;

export interface RunOptions {
  /** Milliseconds this run may take. Default `RUN_LIMITS.timeoutMs`. */
  timeoutMs?: number;
  /** Called with the exit code once the child has really exited (tests: termination is real). */
  onExit?: (code: number | null) => void;
}

/** Runs `code` (a function body of `input`) in a fresh sandbox child. Never rejects. */
export function runIsolated(code: string, input: unknown, options: RunOptions = {}): Promise<RunResult | ToolFailure> {
  const timeoutMs = options.timeoutMs ?? RUN_LIMITS.timeoutMs;
  if (typeof code !== "string" || code.length > RUN_LIMITS.codeCharsMax) {
    return Promise.resolve({
      ok: false,
      kind: "invalid",
      error: `Code is a string of at most ${RUN_LIMITS.codeCharsMax} characters.`,
    });
  }
  let json: string | undefined;
  try {
    json = JSON.stringify(input === undefined ? null : input, (_key, value) => {
      if (typeof value === "function" || typeof value === "symbol" || typeof value === "bigint") {
        throw new TypeError("not JSON");
      }
      return value;
    });
  } catch {
    json = undefined;
  }
  if (json === undefined || json.length > RUN_LIMITS.inputCharsMax) {
    return Promise.resolve({
      ok: false,
      kind: "invalid",
      error: `Input is JSON data of at most ${RUN_LIMITS.inputCharsMax} characters.`,
    });
  }

  return runChild(
    { mode: "run", code, input: json, timeoutMs },
    {
      heapMb: RUN_LIMITS.heapMb,
      timeoutMs: timeoutMs + KILL_GRACE_MS,
      maxOutputBytes: RUN_LIMITS.outputCharsMax * 2 + 4_096,
      ...(options.onExit === undefined ? {} : { onExit: options.onExit }),
    },
  ).then((outcome): RunResult | ToolFailure => {
    const line = outcome.lines[0];
    if (line === undefined) {
      if (outcome.outOfMemory) return { ok: false, kind: "memory", error: "The code ran over the memory limit." };
      if (outcome.killed) return { ok: false, kind: "timeout", error: "The code ran over the time limit." };
      return { ok: false, kind: "sandbox", error: "The sandbox ended without a result." };
    }
    if (line.ok === true && typeof line.output === "string") {
      if (line.output.length > RUN_LIMITS.outputCharsMax) {
        return {
          ok: false,
          kind: "invalid",
          error: `The output is over ${RUN_LIMITS.outputCharsMax} characters of JSON.`,
        };
      }
      return { ok: true, output: line.output };
    }
    const kind = line.kind === "timeout" ? "timeout" : "error";
    const error = typeof line.error === "string" ? line.error.slice(0, RUN_LIMITS.errorCharsMax) : "The code failed.";
    return { ok: false, kind, error };
  });
}
