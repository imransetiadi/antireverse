// Review F2 — an Assessment must not block the host's event loop: assessInWorker runs the whole assess() in its
// own worker (artifact transferred, heap limited), terminates it on abort or at the deadline, and loads the agent
// by built-in name or module specifier. Inside, every Toolbelt call yields a macrotask so timers can fire.
import { fileURLToPath } from "node:url";
import { applyIntegrity } from "@antireverse/harden";
import { EXAMPLE_CANARIES, EXAMPLE_LOGIC, EXAMPLE_ROUTE_INVENTORY } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { assess } from "../src/assess.ts";
import { ASSESS_WORKER_LIMITS, assessInWorker } from "../src/assess-worker-host.ts";
import type { AdversaryAgent } from "../src/types.ts";

const FIXTURES = fileURLToPath(new URL("./fixtures/agents.ts", import.meta.url));
const APP = 'fetch("/api/cart", { method: "POST" }); void {apiKey:"ak_live_083n1BMwZhfu13secInfCOzZrq2cfyQE"};';
const BUILD = { canaries: EXAMPLE_CANARIES, routes: EXAMPLE_ROUTE_INVENTORY };
const MB = 1024 * 1024;

/** Hostile text for the stand-in's patterns and the Toolbelt (about `mb` megabytes per file). */
function hostile(mb: number): Record<string, string> {
  return {
    "a.js": "x".repeat(mb * MB),
    "b.js": `a:"${"y".repeat(1020)}`.repeat(Math.floor((mb * MB) / 1023)),
    "c.js": `fetch("${"/".repeat(2040)}`.repeat(Math.floor((mb * MB) / 2047)),
  };
}

describe("assessInWorker", () => {
  it("returns the same outcome as assess for the stand-in", async () => {
    const input = { artifact: { "dist/app.js": APP }, build: BUILD, tier: "T1" as const };
    const inWorker = await assessInWorker({ ...input, agent: "stand-in" });
    const inline = await assess(input);
    const shape = (o: typeof inline) => o.results.map((r) => [r.objective, r.result, "tier" in r ? r.tier : null]);
    expect(shape(inWorker)).toEqual(shape(inline));
    expect(inWorker.scope).toEqual(inline.scope);
    expect(inWorker.score).toEqual(inline.score);
    expect(inWorker.calls.map((c) => c.tool)).toEqual(inline.calls.map((c) => c.tool));
  });

  it("a fully decided T1 run with logic and integrity is scored in the worker too", async () => {
    const script = 'function add(i) { return fetch("/api/cart", { method: "POST" }); }\nvar k = 1;';
    const outcome = await assessInWorker({
      artifact: { "dist/app.js": applyIntegrity(script) },
      build: { ...BUILD, logic: EXAMPLE_LOGIC, integrity: true },
      tier: "T1",
      agent: "stand-in",
    });
    expect(outcome.results.find((r) => r.objective === "W4")).toMatchObject({ result: "achieved" });
    expect(outcome.results.find((r) => r.objective === "W3")).toMatchObject({ result: "not_achieved" });
    expect(outcome.score).toMatchObject({ status: "scored" });
  }, 20_000);

  it("copies the artifact: the caller's bytes stay readable", async () => {
    const bytes = new TextEncoder().encode(APP);
    await assessInWorker({ artifact: new Map([["dist/app.js", bytes]]), build: BUILD, tier: "T1" });
    expect(bytes.byteLength).toBe(APP.length);
    expect(new TextDecoder().decode(bytes)).toBe(APP);
  });

  it("keeps the host's event loop free while a large hostile artifact is assessed", async () => {
    let longest = 0;
    let last = performance.now();
    const ticker = setInterval(() => {
      const now = performance.now();
      longest = Math.max(longest, now - last);
      last = now;
    }, 10);
    try {
      const outcome = await assessInWorker(
        { artifact: hostile(6), build: BUILD, tier: "T1", budgets: { T1: { calls: 150, seconds: 3 } } },
        { deadlineMs: 30_000 },
      );
      expect(outcome.results).toHaveLength(5);
    } finally {
      clearInterval(ticker);
    }
    expect(longest).toBeLessThan(250);
  }, 40_000);

  it.each([
    ["fetch calls", (mb: number) => `fetch("${"/".repeat(2040)}`.repeat(Math.floor((mb * MB) / 2047))],
    ["fetch options", (mb: number) => `fetch("/a",{${"m".repeat(510)}`.repeat(Math.floor((mb * MB) / 522))],
    ["XHR opens", (mb: number) => `.open("GET","${"/".repeat(2040)}`.repeat(Math.floor((mb * MB) / 2053))],
    ["internal URLs", (mb: number) => `http://localhost${"/".repeat(2040)}`.repeat(Math.floor((mb * MB) / 2056))],
  ])(
    "never reports more seconds than the tier's limit plus a small slack (%s)",
    async (_name, make) => {
      const outcome = await assessInWorker(
        { artifact: { "a.js": make(12) }, build: BUILD, tier: "T1", budgets: { T1: { calls: 150, seconds: 1 } } },
        { deadlineMs: 30_000 },
      );
      expect(outcome.cost.seconds).toBeLessThanOrEqual(1.5);
      for (const result of outcome.results) {
        if ("cost" in result) expect(result.cost.seconds).toBeLessThanOrEqual(1.5);
      }
    },
    40_000,
  );

  it("terminates a run that blocks forever at the deadline, with a TimeoutError", async () => {
    const started = Date.now();
    await expect(
      assessInWorker(
        { artifact: { "a.js": "x" }, build: BUILD, tier: "T1", agent: { module: FIXTURES, export: "blocking" } },
        { deadlineMs: 800 },
      ),
    ).rejects.toMatchObject({ name: "TimeoutError" });
    expect(Date.now() - started).toBeLessThan(5_000);
  }, 10_000);

  it("terminates on abort with an AbortError, also when the signal is already aborted", async () => {
    const controller = new AbortController();
    const run = assessInWorker(
      { artifact: { "a.js": "x" }, build: BUILD, tier: "T1", agent: { module: FIXTURES, export: "blocking" } },
      { signal: controller.signal, deadlineMs: 30_000 },
    );
    setTimeout(() => controller.abort(), 300);
    await expect(run).rejects.toMatchObject({ name: "AbortError" });
    await expect(
      assessInWorker({ artifact: { "a.js": "x" }, build: BUILD, tier: "T1" }, { signal: AbortSignal.abort() }),
    ).rejects.toMatchObject({ name: "AbortError" });
  }, 10_000);

  it("loads an agent from a module (named export or default factory) and refuses unknown agents", async () => {
    const named = await assessInWorker({
      artifact: { "a.js": "x" },
      build: BUILD,
      tier: "T1",
      agent: { module: FIXTURES, export: "makeSubmitter" },
    });
    expect(named.scope.agent.name).toBe("submitter");
    expect(named.results.find((r) => r.objective === "W2")).toMatchObject({ result: "achieved" });
    const byDefault = await assessInWorker({
      artifact: { "a.js": "x" },
      build: BUILD,
      tier: "T1",
      agent: { module: FIXTURES },
    });
    expect(byDefault.scope.agent.name).toBe("submitter");
    await expect(
      assessInWorker({ artifact: { "a.js": "x" }, build: BUILD, tier: "T1", agent: "gpt-anything" as never }),
    ).rejects.toThrow(TypeError);
    await expect(assessInWorker({ artifact: { "a.js": "x" }, build: BUILD, tier: "T9" as never })).rejects.toThrow(
      TypeError,
    );
  }, 20_000);

  it("limits the worker's heap to about 256 MB, and its default grace covers the judging budget", () => {
    expect(ASSESS_WORKER_LIMITS.oldGenerationMb).toBe(256);
    expect(ASSESS_WORKER_LIMITS.graceMs).toBe(90_000);
  });

  // Review 12b F3: the module analysis ran a full Babel parse in this worker and blew its heap on 2 MB.
  it.each([2, 8])(
    "a %i MB JS file with the stand-in finishes",
    async (mb) => {
      const body = "a.b.c(1, [2, 3], { d: 4 });\n".repeat(Math.floor((mb * 1024 * 1024) / 27));
      for (const code of [body, `import { a } from "lib";\n${body}`]) {
        const outcome = await assessInWorker({
          artifact: new Map([["app.js", code]]),
          build: { canaries: [], routes: null, integrity: false },
          tier: "T1",
          agent: "stand-in",
        });
        expect(outcome.results).toHaveLength(5);
      }
    },
    120_000,
  );
});

describe("Toolbelt calls yield a macrotask", () => {
  it("a timer set before the agent's calls fires while it is still calling (an agent that only awaits tools)", async () => {
    let firedAt: number | null = null;
    let calls = 0;
    const agent: AdversaryAgent = {
      name: "looper",
      version: "1.0.0",
      model: "test-model",
      async run(_context, toolbelt) {
        setTimeout(() => {
          firedAt = calls;
        }, 0);
        // Without a macrotask between calls, these resolve through microtasks only and the timer waits for all.
        while (firedAt === null && calls < 3_000) {
          await toolbelt.list();
          calls += 1;
        }
      },
    };
    await assess({ artifact: { "a.js": "x" }, build: BUILD, tier: "T3", agent });
    expect(firedAt).not.toBeNull();
    expect(calls).toBeLessThan(3_000);
  });
});
