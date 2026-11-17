// runCampaignEngine (slice 15a, D-105 item 1): one Campaign engine per worker_threads worker, talking to its host by
// messages only. The host answers each probe through `request` — the API passes its request gate — and is told each
// check and Finding. A stop terminates the worker: `signal` aborts → the worker is terminated and the promise rejects
// with an AbortError; at `deadlineMs` it rejects with a TimeoutError. Whatever the worker posts is untrusted: a probe
// is handed to `request` as it came (the gate judges it), and checks and Findings are for the caller to validate.
import { Worker, type WorkerOptions } from "node:worker_threads";
import { CAMPAIGN_LIMITS, type CampaignExchange, type CampaignIntensity } from "@antireverse/protocol";
import type { EngineCheck, EngineFinding } from "./stand-in.ts";

export const CAMPAIGN_WORKER_LIMITS = Object.freeze({
  oldGenerationMb: 64,
  youngGenerationMb: 16,
  stackMb: 4,
  /** Milliseconds allowed after the Campaign's wall time before the worker is terminated. */
  graceMs: 10_000,
});

export type WorkerMessage =
  | { t: "request"; id: number; probe: unknown }
  | { t: "check"; check: EngineCheck }
  | { t: "finding"; finding: EngineFinding }
  | { t: "done" }
  | { t: "error" };
export type HostMessage = { t: "exchange"; id: number; exchange: CampaignExchange };

export interface RunCampaignEngineOptions {
  intensity: CampaignIntensity;
  /** Answers one probe. The probe is whatever the engine posted: judge it. Never rejects. */
  request(probe: unknown): Promise<CampaignExchange>;
  onCheck(check: unknown): void;
  onFinding(finding: unknown): void | Promise<void>;
  /** Aborting terminates the worker. */
  signal?: AbortSignal;
  /** Default: the Campaign's wall time plus `CAMPAIGN_WORKER_LIMITS.graceMs`. */
  deadlineMs?: number;
}

function domError(message: string, name: "AbortError" | "TimeoutError"): Error {
  return new DOMException(message, name) as unknown as Error;
}

/** Node options for the worker: the host's, plus type stripping when this Node does not strip by default. */
function workerExecArgv(): string[] {
  const inherited = process.execArgv.filter((arg) => !arg.startsWith("--inspect") && arg !== "--eval" && arg !== "-e");
  const strips = (process.features as { typescript?: unknown }).typescript;
  if (strips === "strip" || strips === "transform") return inherited;
  return [...inherited, "--experimental-strip-types", "--disable-warning=ExperimentalWarning"];
}

/**
 * How the engine's worker is started: no standard streams, memory limits, and an empty environment — by default a
 * worker gets a copy of the host's `process.env`, which holds the API's configuration and secrets, and the engine
 * needs none of it. (A worker thread is still not a sandbox: this removes one thing it could read, no more.)
 */
export function campaignWorkerOptions(intensity: CampaignIntensity): WorkerOptions {
  return {
    workerData: { intensity },
    execArgv: workerExecArgv(),
    env: {},
    stdout: false,
    stderr: false,
    resourceLimits: {
      maxOldGenerationSizeMb: CAMPAIGN_WORKER_LIMITS.oldGenerationMb,
      maxYoungGenerationSizeMb: CAMPAIGN_WORKER_LIMITS.youngGenerationMb,
      stackSizeMb: CAMPAIGN_WORKER_LIMITS.stackMb,
    },
  };
}

/** Runs the stand-in engine in a dedicated worker until it is done. Resolves when the engine finished its catalog. */
export function runCampaignEngine(options: RunCampaignEngineOptions): Promise<void> {
  const { signal } = options;
  if (signal?.aborted) return Promise.reject(domError("The Campaign was stopped.", "AbortError"));
  const deadlineMs = options.deadlineMs ?? CAMPAIGN_LIMITS.wallTimeS * 1000 + CAMPAIGN_WORKER_LIMITS.graceMs;
  return new Promise<void>((resolve, reject) => {
    let settled = false;
    const worker = new Worker(new URL("./worker.ts", import.meta.url), campaignWorkerOptions(options.intensity));
    // Findings are handed over in order. However the run ends — done, stopped, over its deadline, failed — the end
    // waits for the Findings already handed over: the caller never ends a Campaign while one is still being stored.
    let reported: Promise<void> = Promise.resolve();
    const settle = (action: () => void): void => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal?.removeEventListener("abort", onAbort);
      void worker.terminate().catch(() => {});
      void reported.then(action, action);
    };
    const onAbort = (): void => settle(() => reject(domError("The Campaign was stopped.", "AbortError")));
    const timer = setTimeout(
      () => settle(() => reject(domError("The Campaign engine ran over its deadline.", "TimeoutError"))),
      deadlineMs,
    );
    signal?.addEventListener("abort", onAbort, { once: true });
    worker.on("message", (message: WorkerMessage) => {
      if (settled || typeof message !== "object" || message === null) return;
      if (message.t === "request" && Number.isInteger(message.id)) {
        const { id } = message;
        options.request(message.probe).then(
          (exchange) => {
            if (!settled) worker.postMessage({ t: "exchange", id, exchange } satisfies HostMessage);
          },
          () => settle(() => reject(new Error("The Campaign gate failed."))),
        );
      } else if (message.t === "check") {
        options.onCheck(message.check);
      } else if (message.t === "finding") {
        const { finding } = message;
        reported = reported.then(() => options.onFinding(finding)).catch(() => {});
      } else if (message.t === "done") {
        settle(resolve);
      } else if (message.t === "error") {
        settle(() => reject(new Error("The Campaign engine stopped with an error.")));
      }
    });
    worker.on("error", () => settle(() => reject(new Error("The Campaign engine worker failed."))));
    worker.on("exit", () => settle(() => reject(new Error("The Campaign engine worker ended without finishing."))));
  });
}
