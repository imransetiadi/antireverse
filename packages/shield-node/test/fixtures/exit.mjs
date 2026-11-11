// Child process of shield.test.ts. Run with `node --experimental-strip-types`.
// It creates a Shield against an ingest server that never answers, records one Event, waits until the flush
// is in flight and returns. Neither the flush timer nor the in-flight request may keep this process alive:
// the parent asserts exit code 0 within 2 s.
// Mode "policy": a Shield with a policyPublicKey and no Event. The Policy request is in flight against the
// silent server and the poll timer is armed; neither may keep the process alive.
import { generateKeyPairSync } from "node:crypto";
import { EventEmitter } from "node:events";
import { setTimeout as sleep } from "node:timers/promises";

const [mode, endpoint] = process.argv.slice(2);
const key = `ark_dev_${"A".repeat(43)}`; // synthetic, well-formed
let stats;

if (mode === "emitter") {
  const { createEmitter } = await import("../../src/emitter.ts");
  const { createNodeTransport } = await import("../../src/transport.ts");
  const emitter = createEmitter({
    key,
    endpoint,
    flushIntervalMs: 20,
    maxBatchSize: 100,
    maxBufferSize: 10_000,
    requestTimeoutMs: 30_000,
    transport: createNodeTransport().send,
    now: () => Date.now(),
    warn: () => {},
  });
  emitter.record({
    event_id: "01a1c486-c94b-7c3a-9f21-5d8e6a0b1c2d",
    ts: new Date().toISOString(),
    type: "request.decision",
    surface: "api",
    request: { method: "GET", route: "/", status: 200, latency_ms: 1 },
    decision: { action: "allow", mode: "monitor", rule_id: null, policy_version: 0 },
    actor: { ip_prefix: null },
    signals: [],
  });
  await sleep(200); // the flush timer fired and the request is in flight against the silent server
  stats = emitter.stats();
} else if (mode === "policy") {
  const { createShield } = await import("../../src/index.ts");
  const policyPublicKey = generateKeyPairSync("ed25519").publicKey.export({ format: "jwk" }).x;
  const shield = createShield({ key, endpoint, policyPublicKey, policyPollIntervalMs: 100, requestTimeoutMs: 30_000 });
  await sleep(400); // the first Policy request was sent and is still unanswered
  stats = shield.stats();
} else {
  const { createShield } = await import("../../src/index.ts");
  const shield = createShield({ key, endpoint, flushIntervalMs: 20, requestTimeoutMs: 30_000, logger: { warn() {} } });
  const request = { method: "GET", url: "/", socket: { remoteAddress: "127.0.0.1" } };
  const response = Object.assign(new EventEmitter(), { statusCode: 200 });
  shield.express()(request, response, () => {});
  response.emit("close");
  await sleep(200);
  stats = shield.stats();
}

console.log(JSON.stringify(stats));
// No process.exit(): the event loop must drain on its own.
