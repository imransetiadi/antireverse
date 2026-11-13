// assessInWorker (review F2, Jev 0.96): one Assessment per worker_threads worker, so the agent's and the
// Toolbelt's synchronous work never blocks the caller's event loop. The artifact is copied into fresh
// ArrayBuffers that are transferred (the caller's bytes stay intact); the worker's heap is limited; the worker is
// terminated on abort or at the deadline, and the promise then rejects with an AbortError or a TimeoutError. The
// agent is chosen by a built-in name or a module specifier, since an object cannot cross into the worker.
import { Worker } from "node:worker_threads";
import { TIER_IDS } from "@antireverse/protocol";
import { resolveTiers } from "./budget.ts";
import type { AssessInput, AssessOutcome } from "./types.ts";

export const ASSESS_WORKER_LIMITS = Object.freeze({
  /** The worker's old-generation heap, in MB (the artifact is at most 25 MB). */
  oldGenerationMb: 256,
  /** The worker's young-generation heap, in MB. */
  youngGenerationMb: 32,
  /** The worker's stack, in MB. */
  stackMb: 4,
  /** Milliseconds allowed after the tier's time, by default: the judging budget (60 s) plus 30 s of margin. */
  graceMs: 90_000,
});

/** The built-in agents, by name. */
export const BUILT_IN_AGENTS = ["stand-in"] as const;

/**
 * Which agent runs: a built-in by name, or a module (specifier or absolute path) whose export (default `default`)
 * is an `AdversaryAgent` or a function that returns one.
 */
export type AgentSpec = (typeof BUILT_IN_AGENTS)[number] | { module: string; export?: string };

export interface WorkerAssessInput extends Omit<AssessInput, "agent" | "now"> {
  /** Default: "stand-in". */
  agent?: AgentSpec;
}

export interface AssessInWorkerOptions {
  /** Aborting terminates the worker; the promise rejects with an AbortError. */
  signal?: AbortSignal;
  /**
   * Milliseconds after which the worker is terminated and the promise rejects with a TimeoutError. Default: the
   * tier's seconds plus `ASSESS_WORKER_LIMITS.graceMs`.
   */
  deadlineMs?: number;
}

/** What crosses into the worker: the input without the artifact, and the artifact as paths and buffers. */
export interface WorkerPayload {
  input: Omit<WorkerAssessInput, "artifact">;
  paths: string[];
  buffers: ArrayBuffer[];
}

export type WorkerReply = { ok: true; outcome: AssessOutcome } | { ok: false; name: string; message: string };

function domError(message: string, name: "AbortError" | "TimeoutError"): Error {
  return new DOMException(message, name) as unknown as Error;
}

function checkAgent(agent: unknown): void {
  if (agent === undefined) return;
  if (typeof agent === "string") {
    if (!(BUILT_IN_AGENTS as readonly string[]).includes(agent)) throw new TypeError(`Unknown built-in agent.`);
    return;
  }
  const spec = agent as { module?: unknown; export?: unknown };
  if (
    typeof agent !== "object" ||
    agent === null ||
    typeof spec.module !== "string" ||
    spec.module.length === 0 ||
    (spec.export !== undefined && typeof spec.export !== "string")
  ) {
    throw new TypeError('The agent is "stand-in" or { module, export? }.');
  }
}

/** The artifact as fresh buffers to transfer (copies: the caller's bytes are never detached). */
function packArtifact(artifact: WorkerAssessInput["artifact"]): { paths: string[]; buffers: ArrayBuffer[] } {
  const entries: [string, Uint8Array | string][] =
    artifact instanceof Map
      ? [...(artifact as ReadonlyMap<string, Uint8Array | string>).entries()]
      : Object.entries(artifact as Record<string, Uint8Array | string>);
  const encoder = new TextEncoder();
  const paths: string[] = [];
  const buffers: ArrayBuffer[] = [];
  for (const [path, content] of entries) {
    if (typeof path !== "string" || path.length === 0) throw new TypeError("Artifact paths are non-empty strings.");
    let copy: Uint8Array;
    if (typeof content === "string") copy = encoder.encode(content);
    else if (content instanceof Uint8Array) copy = new Uint8Array(content);
    else throw new TypeError("Artifact files are bytes or strings.");
    paths.push(path);
    buffers.push(copy.buffer as ArrayBuffer);
  }
  return { paths, buffers };
}

/** Node options for the worker: the host's, plus type stripping when this Node does not strip by default. */
function workerExecArgv(): string[] {
  const inherited = process.execArgv.filter((arg) => !arg.startsWith("--inspect") && arg !== "--eval" && arg !== "-e");
  const strips = (process.features as { typescript?: unknown }).typescript;
  if (strips === "strip" || strips === "transform") return inherited;
  return [...inherited, "--experimental-strip-types", "--disable-warning=ExperimentalWarning"];
}

/**
 * Runs `assess` in a dedicated worker. Same outcome as `assess`. Rejects with a TypeError for invalid input (as
 * `assess` does), an AbortError on abort, a TimeoutError at the deadline, and an Error when the worker fails
 * (for example its heap limit).
 */
export function assessInWorker(input: WorkerAssessInput, options: AssessInWorkerOptions = {}): Promise<AssessOutcome> {
  try {
    if (!TIER_IDS.includes(input?.tier)) throw new TypeError("The tier is T1, T2 or T3.");
    checkAgent(input.agent);
    const tiers = resolveTiers(input.budgets);
    const { signal } = options;
    if (signal?.aborted) return Promise.reject(domError("The Assessment was aborted.", "AbortError"));
    const deadlineMs = options.deadlineMs ?? tiers[input.tier].seconds * 1000 + ASSESS_WORKER_LIMITS.graceMs;
    if (!Number.isFinite(deadlineMs) || deadlineMs <= 0)
      throw new TypeError("The deadline is a positive number of ms.");
    const { artifact, ...rest } = input;
    const { paths, buffers } = packArtifact(artifact);
    const payload: WorkerPayload = { input: rest, paths, buffers };

    return new Promise<AssessOutcome>((resolve, reject) => {
      let settled = false;
      const worker = new Worker(new URL("./assess-worker.ts", import.meta.url), {
        workerData: payload,
        transferList: buffers,
        execArgv: workerExecArgv(),
        stdout: false,
        stderr: false,
        resourceLimits: {
          maxOldGenerationSizeMb: ASSESS_WORKER_LIMITS.oldGenerationMb,
          maxYoungGenerationSizeMb: ASSESS_WORKER_LIMITS.youngGenerationMb,
          stackSizeMb: ASSESS_WORKER_LIMITS.stackMb,
        },
      });
      const settle = (action: () => void) => {
        if (settled) return;
        settled = true;
        clearTimeout(timer);
        signal?.removeEventListener("abort", onAbort);
        void worker.terminate().catch(() => {});
        action();
      };
      const onAbort = () => settle(() => reject(domError("The Assessment was aborted.", "AbortError")));
      const timer = setTimeout(
        () => settle(() => reject(domError(`The Assessment ran over its ${deadlineMs} ms deadline.`, "TimeoutError"))),
        deadlineMs,
      );
      signal?.addEventListener("abort", onAbort, { once: true });
      worker.on("message", (reply: WorkerReply) => {
        settle(() => {
          if (reply.ok) resolve(reply.outcome);
          else {
            const error = reply.name === "TypeError" ? new TypeError(reply.message) : new Error(reply.message);
            if (reply.name !== "TypeError") error.name = reply.name;
            reject(error);
          }
        });
      });
      worker.on("error", (error: Error & { code?: string }) => {
        settle(() =>
          reject(
            new Error(
              error?.code === "ERR_WORKER_OUT_OF_MEMORY"
                ? "The Assessment worker ran over its memory limit."
                : "The Assessment worker failed.",
            ),
          ),
        );
      });
      worker.on("exit", () => settle(() => reject(new Error("The Assessment worker ended without a result."))));
    });
  } catch (error) {
    return Promise.reject(error);
  }
}
