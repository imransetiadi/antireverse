// The worker side of assessInWorker: rebuilds the artifact from the transferred buffers, loads the agent by name
// or module, runs `assess`, and posts the outcome (or the error's name and message) back. Started only by
// assess-worker-host.ts.
import { pathToFileURL } from "node:url";
import { parentPort, workerData } from "node:worker_threads";
import { StandInAgent } from "./agent.ts";
import { assess } from "./assess.ts";
import type { AgentSpec, WorkerPayload, WorkerReply } from "./assess-worker-host.ts";
import type { AdversaryAgent } from "./types.ts";

function isAgent(value: unknown): value is AdversaryAgent {
  const agent = value as AdversaryAgent | null;
  return typeof agent === "object" && agent !== null && typeof agent.run === "function";
}

async function loadAgent(spec: AgentSpec | undefined): Promise<AdversaryAgent> {
  if (spec === undefined || spec === "stand-in") return new StandInAgent();
  const specifier = spec.module.startsWith("/") ? pathToFileURL(spec.module).href : spec.module;
  const loaded = (await import(specifier)) as Record<string, unknown>;
  const exported = loaded[spec.export ?? "default"];
  const agent = typeof exported === "function" ? (exported as () => unknown)() : exported;
  if (!isAgent(agent)) throw new TypeError("The agent module's export is not an AdversaryAgent or a factory of one.");
  return agent;
}

async function main(): Promise<WorkerReply> {
  const payload = workerData as WorkerPayload;
  const artifact = new Map<string, Uint8Array>();
  payload.paths.forEach((path, index) => {
    artifact.set(path, new Uint8Array(payload.buffers[index] as ArrayBuffer));
  });
  try {
    const { agent: spec, ...input } = payload.input;
    const agent = await loadAgent(spec);
    const outcome = await assess({ ...input, artifact, agent });
    return { ok: true, outcome };
  } catch (error) {
    const name = error instanceof Error ? error.name : "Error";
    const message = error instanceof Error ? error.message : "The Assessment failed.";
    return { ok: false, name, message: message.slice(0, 500) };
  }
}

const reply = await main();
parentPort?.postMessage(reply);
