import { EXAMPLE_LOGIC } from "@antireverse/protocol";
import { describe, expect, it, vi } from "vitest";

// Slice 12b: proveAssessor forwards the logic file and the integrity flag to the engine's worker, beside the Canaries
// and routes, and never leak findings. The engine is mocked here to see exactly what it receives.

const received: unknown[] = [];
vi.mock("@antireverse/prove", async (importOriginal) => {
  const actual = await importOriginal<typeof import("@antireverse/prove")>();
  return {
    ...actual,
    assessInWorker: vi.fn(async (input: unknown, options: unknown) => {
      received.push({ input, options });
      return { results: [], scope: {}, end: "finished", calls: [], cost: { calls: 0, seconds: 0 } };
    }),
  };
});

const { proveAssessor } = await import("../src/assess/prove-assessor.ts");

describe("proveAssessor forwarding", () => {
  it("passes logic and integrity as Build facts, and the runner's signal", async () => {
    const signal = new AbortController().signal;
    await proveAssessor().assess({
      tier: "T2",
      artifact: new Map([["dist/index.js", new Uint8Array([49])]]),
      build: { canaries: [], leakFindings: [], routes: null, logic: EXAMPLE_LOGIC, integrity: true },
      signal,
    });
    const [call] = received as Array<{ input: { build: Record<string, unknown>; tier: string }; options: unknown }>;
    expect(call?.input.tier).toBe("T2");
    expect(call?.input.build).toEqual({ canaries: [], routes: null, logic: EXAMPLE_LOGIC, integrity: true });
    expect(call?.options).toEqual({ signal });
  });
});
