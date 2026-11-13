// Task 2.5 — assess(): the agent runs once within the tier's budget, the verifiers judge W1, W2 and W5 from the
// Build's hidden facts, W3 and W4 are not supported, each achieved Objective is mapped to the earliest tier its
// cost fits, and the score comes from the protocol's scoreAssessment with the scope statement.
import { canaryStatement, hardenBundle } from "@antireverse/harden";
import {
  EXAMPLE_CANARIES,
  EXAMPLE_ROUTE_INVENTORY,
  ObjectiveResultSchema,
  ScopeStatementSchema,
  STAND_IN_MODEL,
  scoreAssessment,
} from "@antireverse/protocol";
import { leakFingerprint } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import { assess } from "../src/assess.ts";
import { BudgetExhaustedError } from "../src/budget.ts";
import type { AdversaryAgent, AgentContext, BudgetView, Toolbelt } from "../src/types.ts";
import { TOOLBELT_VERSION } from "../src/types.ts";

const KEY = EXAMPLE_CANARIES[0]?.value as string;
const UNPROTECTED = [
  'export function add(item) { return fetch("/api/cart", { method: "POST", body: JSON.stringify(item) }); }',
  // biome-ignore lint/suspicious/noTemplateCurlyInString: the fixture is source text with a template literal
  "export function product(id) { return fetch(`/api/products/${id}`); }",
  "export function products() { return fetch('/api/products'); }",
  canaryStatement(EXAMPLE_CANARIES),
].join("\n");
const BUILD = { canaries: EXAMPLE_CANARIES, routes: EXAMPLE_ROUTE_INVENTORY };

/** A scripted agent: its steps get the Toolbelt and the budget. */
function scripted(
  steps: (toolbelt: Toolbelt, budget: BudgetView, context: AgentContext) => Promise<void>,
): AdversaryAgent {
  return {
    name: "scripted",
    version: "1.0.0",
    model: "test-model",
    run: (context, toolbelt, budget) => steps(toolbelt, budget, context),
  };
}

const byObjective = (results: { objective: string }[], id: string) => results.find((r) => r.objective === id);

describe("assess with the stand-in agent", () => {
  it("on an unprotected build: W2 achieved at T1, W1 judged, W5 refused, W3/W4 not attempted, inconclusive", async () => {
    const outcome = await assess({ artifact: { "dist/app.js": UNPROTECTED }, build: BUILD, tier: "T1" });

    expect(outcome.results.map((r) => r.objective)).toEqual(["W1", "W2", "W3", "W4", "W5"]);
    for (const result of outcome.results) expect(ObjectiveResultSchema.safeParse(result).success).toBe(true);
    expect(byObjective(outcome.results, "W2")).toMatchObject({
      result: "achieved",
      tier: "T1",
      evidence: { recovered: expect.arrayContaining([{ kind: "canary", canary_id: EXAMPLE_CANARIES[0]?.id }]) },
    });
    expect(byObjective(outcome.results, "W1")).toMatchObject({
      result: "achieved",
      tier: "T1",
      evidence: { recovered: [{ kind: "routes", matched: 3, inventory: 5 }] },
    });
    expect(byObjective(outcome.results, "W5")).toMatchObject({
      result: "not_achieved",
      evidence: { recovered: [{ kind: "replay", status: 403 }] },
    });
    expect(byObjective(outcome.results, "W3")).toMatchObject({ result: "not_attempted", reason: "not_supported" });
    expect(byObjective(outcome.results, "W4")).toMatchObject({ result: "not_attempted", reason: "not_supported" });

    expect(outcome.score).toEqual(scoreAssessment(outcome.results, "T1"));
    expect(outcome.score).toMatchObject({ status: "inconclusive", rrs: null, code: "excluded_over_limit" });
    expect(outcome.scope).toEqual({
      agent: { name: "stand-in", version: "0.1.0" },
      model: STAND_IN_MODEL,
      toolbelt: TOOLBELT_VERSION,
      tier: "T1",
    });
    expect(ScopeStatementSchema.safeParse(outcome.scope).success).toBe(true);
    expect(outcome.end).toBe("finished");
    expect(outcome.agentError).toBeNull();
    expect(outcome.cost.calls).toBe(outcome.calls.length);
  });

  it("never puts a recovered value into results, evidence or the call log", async () => {
    const outcome = await assess({ artifact: { "dist/app.js": UNPROTECTED }, build: BUILD, tier: "T1" });
    const text = JSON.stringify(outcome);
    for (const canary of EXAMPLE_CANARIES) expect(text).not.toContain(canary.value);
  });

  it("without a route inventory W1 is not attempted (no_inventory)", async () => {
    const outcome = await assess({
      artifact: { "dist/app.js": UNPROTECTED },
      build: { canaries: EXAMPLE_CANARIES },
      tier: "T1",
    });
    expect(byObjective(outcome.results, "W1")).toMatchObject({ result: "not_attempted", reason: "no_inventory" });
  });

  it("recovers the planted decoy key from a hardened bundle", async () => {
    const hardened = hardenBundle(
      { sources: { "dist/app.js": "export function f(a) { return a + 1; }\n" } },
      { profile: "balanced", seed: 7, budget: { sizePct: 100_000, runPct: 100_000 } },
    );
    expect(hardened.plantError).toBeUndefined();
    const artifact = Object.fromEntries(hardened.files.map((file) => [file.path, file.code]));
    const outcome = await assess({ artifact, build: { canaries: hardened.canaries, routes: null }, tier: "T1" });
    const key = hardened.canaries.find((canary) => canary.kind === "key");
    expect(byObjective(outcome.results, "W2")).toMatchObject({
      result: "achieved",
      evidence: { recovered: expect.arrayContaining([{ kind: "canary", canary_id: key?.id }]) },
    });
  });

  it("is not achieved for W2 when nothing in the artifact matches the Build's facts", async () => {
    const outcome = await assess({
      artifact: { "dist/app.js": "export const x = 1;" },
      build: BUILD,
      tier: "T1",
    });
    expect(byObjective(outcome.results, "W2")).toMatchObject({ result: "not_achieved" });
    expect(byObjective(outcome.results, "W1")).toMatchObject({ result: "not_achieved" });
  });
});

describe("assess: W1 precision", () => {
  it("caps the agent's distinct W1 endpoints at twice the inventory; padding is refused and not achieved", async () => {
    const results: unknown[] = [];
    const outcome = await assess({
      artifact: { "a.js": "x" },
      build: BUILD,
      tier: "T1",
      agent: scripted(async (toolbelt) => {
        const padded = ["GET /api/products", "GET /api/products/1", "POST /api/cart"];
        for (let i = 0; i < 8; i++) padded.push(`GET /api/guess${i}`);
        results.push(await toolbelt.submit("W1", { endpoints: padded })); // 11 > 10: refused
        results.push(await toolbelt.submit("W1", { endpoints: padded.slice(0, 10) })); // 10: accepted, 30 % precision
      }),
    });
    expect(results).toEqual([expect.objectContaining({ ok: false }), { ok: true, accepted: true }]);
    expect(byObjective(outcome.results, "W1")).toMatchObject({
      result: "not_achieved",
      evidence: { recovered: [{ kind: "routes", matched: 3, submitted: 10, inventory: 5 }] },
    });
  });
});

describe("assess: judging is independent of the agent", () => {
  it("tells the agent the tier and the Objectives, nothing about the Build", async () => {
    let seen: AgentContext | null = null;
    await assess({
      artifact: { "a.js": "x" },
      build: { ...BUILD, leakFindings: [] },
      tier: "T2",
      agent: scripted(async (_t, _b, context) => {
        seen = context;
      }),
    });
    expect(Object.keys(seen ?? {}).sort()).toEqual(["objectives", "tier"]);
    expect(JSON.stringify(seen)).not.toContain(KEY);
    expect(JSON.stringify(seen)).not.toContain("/api/cart");
    expect((seen as AgentContext | null)?.objectives.map((o) => o.id)).toEqual(["W1", "W2", "W5"]);
  });

  it("matches leak-scan findings by fingerprint", async () => {
    const value = "AKIAABCDEFGHIJKLMNOP";
    const finding = {
      rule: "aws-access-key" as const,
      path: "src/a.js",
      fingerprint: leakFingerprint("aws-access-key", "src/a.js", value),
    };
    const outcome = await assess({
      artifact: { "a.js": "x" },
      build: { canaries: [], leakFindings: [finding] },
      tier: "T1",
      agent: scripted(async (toolbelt) => {
        await toolbelt.submit("W2", { values: ["AKIAWRONGWRONGWRONG0", value] });
      }),
    });
    expect(byObjective(outcome.results, "W2")).toMatchObject({
      result: "achieved",
      evidence: { recovered: [{ kind: "leak", rule: "aws-access-key", fingerprint: finding.fingerprint }] },
    });
    expect(JSON.stringify(outcome)).not.toContain(value);
  });

  it("an agent that submits nothing gets not achieved, with what the run spent", async () => {
    const outcome = await assess({
      artifact: { "a.js": "x" },
      build: BUILD,
      tier: "T1",
      agent: scripted(async (toolbelt) => {
        await toolbelt.list();
        await toolbelt.read("a.js");
      }),
    });
    for (const id of ["W1", "W2", "W5"]) {
      expect(byObjective(outcome.results, id)).toMatchObject({ result: "not_achieved", cost: { calls: 2 } });
    }
  });
});

describe("assess: tiers and budgets", () => {
  const achieveW2At = (call: number) =>
    scripted(async (toolbelt) => {
      for (let i = 1; i < call; i++) await toolbelt.list();
      await toolbelt.submit("W2", { values: [KEY] });
    });

  it("maps an achievement to the earliest tier whose limits its cost fits (a T3 run can say T1)", async () => {
    const outcome = await assess({ artifact: { "a.js": "x" }, build: BUILD, tier: "T3", agent: achieveW2At(3) });
    expect(byObjective(outcome.results, "W2")).toMatchObject({ result: "achieved", tier: "T1", cost: { calls: 3 } });
    expect(outcome.scope.tier).toBe("T3");
  });

  it("uses overridden budgets for the mapping", async () => {
    const outcome = await assess({
      artifact: { "a.js": "x" },
      build: BUILD,
      tier: "T2",
      budgets: { T1: { calls: 5, seconds: 900 }, T2: { calls: 10, seconds: 7200 } },
      agent: achieveW2At(7),
    });
    expect(byObjective(outcome.results, "W2")).toMatchObject({ result: "achieved", tier: "T2", cost: { calls: 7 } });
  });

  it("stops the agent when the calls are spent; Objectives never submitted were not attempted", async () => {
    let refused: unknown = null;
    const outcome = await assess({
      artifact: { "a.js": "x" },
      build: BUILD,
      tier: "T1",
      budgets: { T1: { calls: 4, seconds: 900 } },
      agent: scripted(async (toolbelt) => {
        try {
          for (;;) await toolbelt.list();
        } catch (error) {
          refused = error;
          throw error;
        }
      }),
    });
    expect(refused).toBeInstanceOf(BudgetExhaustedError);
    expect(outcome.end).toBe("budget_calls");
    expect(outcome.calls).toHaveLength(4);
    expect(outcome.cost.calls).toBe(4);
    for (const id of ["W1", "W2", "W5"]) {
      expect(byObjective(outcome.results, id)).toMatchObject({
        result: "not_attempted",
        reason: "budget_exhausted_before_attempt",
      });
    }
  });

  it("stops waiting for an agent when the time is spent, and closes the Toolbelt", async () => {
    let kept: Toolbelt | null = null;
    const started = Date.now();
    const outcome = await assess({
      artifact: { "a.js": "x" },
      build: BUILD,
      tier: "T1",
      budgets: { T1: { calls: 150, seconds: 0.2 } },
      agent: scripted(async (toolbelt) => {
        kept = toolbelt;
        await toolbelt.submit("W2", { values: [KEY] });
        await new Promise(() => {}); // never ends
      }),
    });
    expect(Date.now() - started).toBeLessThan(2_000);
    expect(outcome.end).toBe("budget_time");
    expect(byObjective(outcome.results, "W2")).toMatchObject({ result: "achieved", tier: "T1" });
    expect(byObjective(outcome.results, "W1")).toMatchObject({ reason: "budget_exhausted_before_attempt" });
    await expect((kept as unknown as Toolbelt).list()).rejects.toBeInstanceOf(BudgetExhaustedError);
  });

  it("a failing agent keeps what it submitted; the rest is not attempted (tool_failure)", async () => {
    const outcome = await assess({
      artifact: { "a.js": "x" },
      build: BUILD,
      tier: "T1",
      agent: scripted(async (toolbelt) => {
        await toolbelt.submit("W2", { values: [KEY] });
        throw new Error(`model gateway down ${"x".repeat(1000)}`);
      }),
    });
    expect(outcome.end).toBe("agent_error");
    expect(outcome.agentError).toMatch(/^model gateway down/);
    expect((outcome.agentError ?? "").length).toBeLessThanOrEqual(200);
    expect(byObjective(outcome.results, "W2")).toMatchObject({ result: "achieved" });
    expect(byObjective(outcome.results, "W5")).toMatchObject({ result: "not_attempted", reason: "tool_failure" });
  });

  it("states the agent's scope, and refuses an agent whose scope cannot be stated", async () => {
    const outcome = await assess({
      artifact: { "a.js": "x" },
      build: BUILD,
      tier: "T1",
      agent: scripted(async () => {}),
    });
    expect(outcome.scope).toEqual({
      agent: { name: "scripted", version: "1.0.0" },
      model: "test-model",
      toolbelt: TOOLBELT_VERSION,
      tier: "T1",
    });
    await expect(
      assess({ artifact: { "a.js": "x" }, build: BUILD, tier: "T1", agent: { ...scripted(async () => {}), name: "" } }),
    ).rejects.toThrow(TypeError);
    await expect(assess({ artifact: { "a.js": "x" }, build: BUILD, tier: "T9" as never })).rejects.toThrow(TypeError);
  });
});
