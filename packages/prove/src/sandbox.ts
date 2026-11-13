// The Toolbelt's code runner (slice 12a, Review Focus 2). Each call starts a fresh worker_threads worker with
// resource limits and an empty environment; inside it the code runs in a new V8 context (node:vm) that has only
// the language built-ins: no require, import, process, Buffer, network classes or timers, and code generation
// from strings is off (eval, new Function and the constructor escape all throw). The input crosses as a JSON
// string and the output comes back as one, so no host object is ever reachable. The script timeout stops loops
// (microtasks included); a host timer terminates the worker for anything the script timeout cannot interrupt.
// Honest limit: node:vm in a worker is process-level isolation, not the hosted isolated account (SDD §12.2).
import { Worker } from "node:worker_threads";
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
  /** The worker's heap limits, in MB. */
  oldGenerationMb: 64,
  youngGenerationMb: 16,
  stackMb: 4,
});

/** Grace after the script timeout before the host terminates the worker. */
const KILL_GRACE_MS = 250;

// Plain JavaScript (an eval worker is a CommonJS script). Only this code has require; the agent's code runs in
// the context, which has none.
const WORKER_SOURCE = `
"use strict";
const vm = require("node:vm");
const { parentPort, workerData } = require("node:worker_threads");
process.on("unhandledRejection", () => {});
const { code, input, timeoutMs, errorCharsMax } = workerData;
function text(value) {
  try { return String(value).slice(0, errorCharsMax); } catch { return "unreadable error"; }
}
let message;
try {
  const context = vm.createContext(Object.create(null), {
    name: "prove-run",
    codeGeneration: { strings: false, wasm: false },
    microtaskMode: "afterEvaluate",
  });
  context.__input = input;
  // The code is compiled as the body of a function of input (it cannot close the function and run outside
  // it), in the context, and called by a fixed wrapper that runs under the script timeout.
  context.__fn = vm.compileFunction('"use strict";\\n' + code, ["input"], {
    parsingContext: context,
    filename: "run.js",
  });
  const source =
    '"use strict";(function () {' +
    "const __parse = JSON.parse; const __stringify = JSON.stringify; const __fn = globalThis.__fn;" +
    "delete globalThis.__fn;" +
    "const __result = __fn.call(undefined, __parse(__input));" +
    'if (__result !== null && (typeof __result === "object" || typeof __result === "function") && typeof __result.then === "function") {' +
    'throw new TypeError("The code must return a value, not a Promise.");}' +
    "return __stringify(__result === undefined ? null : __result);" +
    "})()";
  const script = new vm.Script(source, { filename: "wrapper.js", importModuleDynamically: undefined });
  const output = script.runInContext(context, { timeout: timeoutMs, breakOnSigint: false });
  // The output must be JSON text, checked with this realm's JSON (the code may have changed the context's).
  // (JSON.stringify gives undefined for a function or symbol: that is null, as for undefined.)
  let isJson = output === undefined;
  if (typeof output === "string") {
    try { JSON.parse(output); isJson = true; } catch {}
  }
  if (!isJson) message = { ok: false, kind: "error", error: "The result is not JSON data." };
  else message = { ok: true, output: output === undefined ? "null" : output };
} catch (error) {
  let timedOut = false;
  try { timedOut = error && error.code === "ERR_SCRIPT_EXECUTION_TIMEOUT"; } catch {}
  if (timedOut) {
    message = { ok: false, kind: "timeout", error: "The code ran over the time limit." };
  } else {
    let name = "Error";
    let detail = "";
    try { name = text(error && error.name); detail = text(error && error.message); } catch {}
    message = { ok: false, kind: "error", error: text(name + ": " + detail) };
  }
}
parentPort.postMessage(message);
`;

export interface RunOptions {
  /** Milliseconds this run may take. Default `RUN_LIMITS.timeoutMs`. */
  timeoutMs?: number;
  /** Called with the exit code once the worker has really exited (tests: termination is real). */
  onWorkerExit?: (code: number) => void;
}

/** Runs `code` (a function body of `input`) in a fresh isolated worker. Never rejects. */
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

  return new Promise((resolve) => {
    let settled = false;
    let worker: Worker;
    const finish = (result: RunResult | ToolFailure) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      void worker.terminate().catch(() => {});
      resolve(result);
    };
    try {
      worker = new Worker(WORKER_SOURCE, {
        eval: true,
        workerData: { code, input: json, timeoutMs, errorCharsMax: RUN_LIMITS.errorCharsMax },
        env: {},
        argv: [],
        execArgv: [],
        stdin: false,
        stdout: true,
        stderr: true,
        resourceLimits: {
          maxOldGenerationSizeMb: RUN_LIMITS.oldGenerationMb,
          maxYoungGenerationSizeMb: RUN_LIMITS.youngGenerationMb,
          stackSizeMb: RUN_LIMITS.stackMb,
        },
      });
    } catch {
      resolve({ ok: false, kind: "sandbox", error: "The sandbox could not start." });
      return;
    }
    // Whatever the worker writes is discarded.
    worker.stdout?.resume();
    worker.stderr?.resume();
    const timer = setTimeout(() => {
      finish({ ok: false, kind: "timeout", error: "The code ran over the time limit." });
    }, timeoutMs + KILL_GRACE_MS);
    worker.on("message", (message: unknown) => {
      const m = message as { ok?: unknown; output?: unknown; kind?: unknown; error?: unknown };
      if (m?.ok === true && typeof m.output === "string") {
        if (m.output.length > RUN_LIMITS.outputCharsMax) {
          finish({
            ok: false,
            kind: "invalid",
            error: `The output is over ${RUN_LIMITS.outputCharsMax} characters of JSON.`,
          });
        } else {
          finish({ ok: true, output: m.output });
        }
        return;
      }
      const kind = m?.kind === "timeout" ? "timeout" : "error";
      finish({ ok: false, kind, error: typeof m?.error === "string" ? m.error : "The code failed." });
    });
    worker.on("error", (error: Error & { code?: string }) => {
      if (error?.code === "ERR_WORKER_OUT_OF_MEMORY") {
        finish({ ok: false, kind: "memory", error: "The code ran over the memory limit." });
      } else {
        finish({ ok: false, kind: "sandbox", error: "The sandbox ended unexpectedly." });
      }
    });
    worker.on("exit", (code: number) => {
      try {
        options.onWorkerExit?.(code);
      } catch {
        // An observer's failure changes nothing.
      }
      finish({ ok: false, kind: "sandbox", error: "The sandbox ended without a result." });
    });
  });
}
