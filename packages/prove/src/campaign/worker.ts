// The worker side of runCampaignEngine (slice 15a): runs the engine and talks to the host by messages only. A probe
// goes out as a message and its exchange comes back as one; the worker has no other way to reach anything (and the
// host's gate decides whether a probe is sent at all). Started only by host.ts.
import { parentPort, workerData } from "node:worker_threads";
import type { CampaignExchange, CampaignIntensity } from "@antireverse/protocol";
import type { HostMessage, WorkerMessage } from "./host.ts";
import { standInEngine } from "./stand-in.ts";

const port = parentPort;
if (port === null) throw new Error("The Campaign engine worker has no parent.");
const post = (message: WorkerMessage): void => port.postMessage(message);

const waiting = new Map<number, (exchange: CampaignExchange) => void>();
let nextId = 0;
port.on("message", (message: HostMessage) => {
  if (message?.t !== "exchange") return;
  const resolve = waiting.get(message.id);
  waiting.delete(message.id);
  resolve?.(message.exchange);
});

try {
  const { intensity } = workerData as { intensity: CampaignIntensity };
  await standInEngine.run({
    intensity,
    request: (probe) =>
      new Promise<CampaignExchange>((resolve) => {
        const id = ++nextId;
        waiting.set(id, resolve);
        post({ t: "request", id, probe });
      }),
    check: (check) => post({ t: "check", check }),
    finding: (finding) => post({ t: "finding", finding }),
  });
  post({ t: "done" });
} catch {
  // Never the error's message: it could quote what a target answered.
  post({ t: "error" });
}
