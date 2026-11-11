// @vitest-environment node
import {
  EXAMPLE_LIMIT_RULE,
  EXAMPLE_POLICY,
  SIMULATION_LIMITS,
  SIMULATION_NOT_SIMULATED,
  SimulatePolicyResponseSchema,
  type SimulationRuleResult,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { stubSimulation } from "../scripts/stub-simulation.mjs";

// The stand-in API answers a simulation with figures that the protocol accepts (slice 11): the Console is
// looked at against the same shape the real API returns.

const NOW = Date.parse("2026-11-11T09:00:00.000Z");
const signed = { name: "Checkout", path: "/api/checkout", methods: ["POST"], action: "block", requires: "signature" };
// Every Rule in Monitor mode: nothing of what they match was refused when it happened.
const rules = [...EXAMPLE_POLICY.rules.map((rule) => ({ ...rule, mode: "monitor" })), signed, EXAMPLE_LIMIT_RULE];

describe("stubSimulation", () => {
  it("answers with a response the protocol accepts, one row per Rule in order", () => {
    const body = { simulation: stubSimulation(rules, NOW) };
    const parsed = SimulatePolicyResponseSchema.safeParse(body);
    expect(parsed.success ? [] : parsed.error.issues).toEqual([]);
    if (!parsed.success) return;
    // Nothing the stub sends is stripped by the contract.
    expect(parsed.data).toEqual(body);
    const { simulation } = parsed.data;
    expect(simulation.rules.map((row) => [row.index, row.id, row.name])).toEqual(
      rules.map((rule, index) => [index, "id" in rule ? rule.id : undefined, rule.name]),
    );
    expect(simulation.period).toEqual({ from: "2026-11-10T09:00:00.000Z", to: "2026-11-11T09:00:00.000Z" });
    expect(simulation.truncated).toBe(false);
    expect(simulation.ran_at).toBe("2026-11-11T09:00:00.000Z");
    expect(simulation.not_simulated).toEqual([...SIMULATION_NOT_SIMULATED]);
    expect(simulation.events).toBeGreaterThan(0);
  });

  it("counts each kind of refusal only for the kind of Rule that makes it", () => {
    const { rules: rows } = stubSimulation(rules, NOW);
    const [block, , signature, limit] = rows;
    expect(block.would_block).toBeGreaterThan(0);
    expect([block.would_fail_signature, block.would_throttle]).toEqual([0, 0]);
    expect(signature.would_fail_signature).toBeGreaterThan(0);
    expect([signature.would_block, signature.would_throttle]).toEqual([0, 0]);
    expect(limit.would_throttle).toBeGreaterThan(0);
    expect([limit.would_block, limit.would_fail_signature]).toEqual([0, 0]);
    // The sample routes are those of the requests a Rule would refuse: together never more than it refuses.
    for (const row of rows as SimulationRuleResult[]) {
      expect(row.sample_routes.length).toBeLessThanOrEqual(SIMULATION_LIMITS.sampleRoutesMax);
      const refused = row.would_block + row.would_fail_signature + row.would_throttle;
      expect(row.sample_routes.reduce((sum, sample) => sum + sample.count, 0)).toBe(refused);
    }
  });

  it("counts what an enforced Rule matched as already refused by Shield, not again as an outcome", () => {
    const [enforced] = stubSimulation([{ ...EXAMPLE_POLICY.rules[0], mode: "enforce" }], NOW).rules;
    expect(enforced.already_refused).toBe(enforced.matched);
    expect(enforced.would_block).toBe(0);
    expect(enforced.clients_affected).toBe(0);
    expect(enforced.sample_routes).toEqual([]);
  });

  it("says what promoting would do for every Rule in Monitor mode, and for no enforced Rule", () => {
    const mixed = [{ ...EXAMPLE_POLICY.rules[0], mode: "enforce" }, ...rules.slice(1)];
    const rows: SimulationRuleResult[] = stubSimulation(mixed, NOW).rules;
    expect(rows.map((row) => row.if_promoted !== undefined)).toEqual([false, true, true, true]);
    for (const row of rows) {
      if (!row.if_promoted) continue;
      // Promoted alone a Rule refuses at least what it refuses with every Rule enforced.
      const refused = row.would_block + row.would_fail_signature + row.would_throttle;
      expect(row.if_promoted.would_refuse).toBeGreaterThanOrEqual(refused);
      expect(row.if_promoted.undecidable).toBe(row.undecidable);
    }
  });

  it("leaves the clients of some refused requests unknown, per Rule and in total", () => {
    const { rules: rows, totals }: { rules: SimulationRuleResult[]; totals: Record<string, number> } = stubSimulation(
      rules,
      NOW,
    );
    const unknown = rows.reduce((sum, row) => sum + row.unknown_client_events, 0);
    expect(unknown).toBeGreaterThan(0);
    expect(totals.unknown_client_events).toBe(unknown);
  });

  it("gives the same figures for the same Rules, and totals that are the sum of the rows", () => {
    const first = stubSimulation(rules, NOW);
    expect(stubSimulation(rules, NOW)).toEqual(first);
    const refused = first.rules.reduce(
      (sum: number, row: SimulationRuleResult) => sum + row.would_block + row.would_fail_signature + row.would_throttle,
      0,
    );
    expect(first.totals.would_refuse).toBe(refused);
    expect(first.totals.would_refuse).toBeLessThanOrEqual(first.events);
  });

  it("accepts no Rules and the most Rules a Policy holds", () => {
    expect(SimulatePolicyResponseSchema.safeParse({ simulation: stubSimulation([], NOW) }).success).toBe(true);
    const many = Array.from({ length: 50 }, (_, n) => ({ name: `Rule ${n}`, path: `/api/r${n}/**`, methods: [] }));
    expect(SimulatePolicyResponseSchema.safeParse({ simulation: stubSimulation(many, NOW) }).success).toBe(true);
  });
});
