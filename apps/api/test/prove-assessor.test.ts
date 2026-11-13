import { fileURLToPath } from "node:url";
import { type Canary, ObjectiveResultSchema, STAND_IN_MODEL } from "@antireverse/protocol";
import { describe, expect, it, vi } from "vitest";
import { proveAssessor } from "../src/assess/prove-assessor.ts";

vi.setConfig({ testTimeout: 30_000 });

const AGENTS = fileURLToPath(new URL("./fixtures/agents.ts", import.meta.url));
const TEST_AGENT = { name: "broken", version: "0.0.1", model: "test-model" };

// Slice 12a: the API's Assessor on the real engine of `packages/prove` (the deterministic stand-in agent, D-067).

const CANARY: Canary = {
  id: "cny_33d265fca16c848eb2f23f43",
  kind: "key",
  value: "ak_live_083n1BMwZhfu13secInfCOzZrq2cfyQE",
};

describe("proveAssessor", () => {
  it("states the stand-in's scope for a queued Assessment", () => {
    const scope = proveAssessor().scope("T2");
    expect(scope).toMatchObject({ model: STAND_IN_MODEL, tier: "T2" });
    expect(scope.agent.name.length).toBeGreaterThan(0);
  });

  it("runs the stand-in agent on the artifact and lets the verifiers decide (W2 achieved on a planted Canary)", async () => {
    const artifact = new Map([
      ["dist/index.js", new TextEncoder().encode(`const key = "${CANARY.value}"; fetch("/api/products");`)],
    ]);
    const outcome = await proveAssessor().assess({
      tier: "T1",
      artifact,
      build: { canaries: [CANARY], leakFindings: [], routes: ["GET /api/products", "POST /api/cart"] },
      signal: new AbortController().signal,
    });
    expect(outcome.results.map((result) => result.objective)).toEqual(["W1", "W2", "W3", "W4", "W5"]);
    for (const result of outcome.results) ObjectiveResultSchema.parse(result);
    expect(outcome.results.find((result) => result.objective === "W2")).toMatchObject({ result: "achieved" });
    expect(JSON.stringify(outcome)).not.toContain(CANARY.value);
    expect(outcome.scope).toEqual(proveAssessor().scope("T1"));
    expect(outcome.end).toBe("finished");
  });

  it("reports an agent that stopped with an error as end agent_error, with the verifiers' results", async () => {
    const outcome = await proveAssessor({ agent: { module: AGENTS, export: "broken" }, identity: TEST_AGENT }).assess({
      tier: "T1",
      artifact: new Map([["dist/index.js", new TextEncoder().encode("1;")]]),
      build: { canaries: [CANARY], leakFindings: [], routes: null },
      signal: new AbortController().signal,
    });
    expect(outcome.end).toBe("agent_error");
    expect(outcome.results).toHaveLength(5);
  });

  it("runs in a worker: the caller's event loop stays free, and the signal ends the run at once", async () => {
    const controller = new AbortController();
    const started = performance.now();
    const run = proveAssessor({ agent: { module: AGENTS, export: "blocking" }, identity: TEST_AGENT }).assess({
      tier: "T1",
      artifact: new Map([["dist/index.js", new TextEncoder().encode("1;")]]),
      build: { canaries: [CANARY], leakFindings: [], routes: null },
      signal: controller.signal,
    });
    // The agent spins forever in its worker; this thread still runs timers.
    await new Promise((resolve) => setTimeout(resolve, 300));
    expect(performance.now() - started).toBeLessThan(2_000);
    controller.abort();
    await expect(run).rejects.toMatchObject({ name: "AbortError" });
    expect(performance.now() - started).toBeLessThan(3_000);
  });

  it("states a module agent's scope from the identity it was given", () => {
    const scope = proveAssessor({ agent: { module: AGENTS, export: "broken" }, identity: TEST_AGENT }).scope("T1");
    expect(scope).toMatchObject({ agent: { name: "broken", version: "0.0.1" }, model: "test-model" });
  });
});
