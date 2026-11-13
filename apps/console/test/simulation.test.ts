// @vitest-environment node
import {
  EXAMPLE_LIMIT_RULE,
  EXAMPLE_POLICY,
  EXAMPLE_SIMULATION_RESULT,
  type PolicyRule,
  SIMULATION_NOT_SIMULATED,
  type SimulationResult,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import {
  estimateText,
  notSimulatedText,
  promotionEstimate,
  ruleFingerprint,
  type SimulationRun,
  wouldRefuse,
} from "@/features/policy/simulation.ts";

// What the Policy screen makes of a simulation result (slice 11): which figures belong to which Rule, and the
// words for them. A figure is shown for a Rule only while the Rule is the one that was simulated.

const [enforced, monitored] = EXAMPLE_POLICY.rules as [PolicyRule, PolicyRule];
const rules = [enforced, monitored, EXAMPLE_LIMIT_RULE];

function result(overrides: Partial<SimulationResult> = {}): SimulationResult {
  const [first, , third] = EXAMPLE_SIMULATION_RESULT.rules;
  if (!first || !third) throw new Error("the example has three rows");
  return {
    ...EXAMPLE_SIMULATION_RESULT,
    rules: [
      first,
      {
        index: 1,
        id: monitored.id,
        name: monitored.name,
        matched: 1_300,
        would_block: 1_260,
        would_fail_signature: 0,
        would_throttle: 0,
        already_refused: 0,
        undecidable: 325,
        clients_affected: 12,
        unknown_client_events: 0,
        // Promoted alone it refuses more than with every Rule enforced: no earlier Rule takes its requests first.
        if_promoted: { would_refuse: 1_300, clients_affected: 14, unknown_client_events: 0, undecidable: 330 },
        sample_routes: [{ route: "/api/users/:id/export", method: "GET", count: 1_260 }],
      },
      { ...third, if_promoted: { would_refuse: 180, clients_affected: 4, unknown_client_events: 0, undecidable: 310 } },
    ],
    ...overrides,
  };
}
const run = (overrides: Partial<SimulationResult> = {}): SimulationRun => ({
  simulation: result(overrides),
  rules: rules.map(ruleFingerprint),
  withDraft: false,
});

describe("ruleFingerprint", () => {
  it("is the same for the same pattern, methods, action, requirement and limit, whatever the mode, the id or the name", () => {
    expect(ruleFingerprint({ ...monitored, mode: "enforce" })).toBe(ruleFingerprint(monitored));
    expect(ruleFingerprint({ ...monitored, name: "Another name" })).toBe(ruleFingerprint(monitored));
    const { id: _id, ...draft } = monitored;
    expect(ruleFingerprint(draft)).toBe(ruleFingerprint(monitored));
    // The order of the methods says nothing, and a Rule sent without what the API fills in is the same Rule.
    expect(ruleFingerprint({ ...monitored, methods: ["POST", "GET"] })).toBe(ruleFingerprint(monitored));
    expect(ruleFingerprint({ name: "x", path: "/a" })).toBe(
      ruleFingerprint({ name: "x", path: "/a", methods: [], action: "block" }),
    );
  });

  it("differs when anything the simulation judges by differs", () => {
    const base = ruleFingerprint(monitored);
    expect(ruleFingerprint({ ...monitored, path: "/api/users/*" })).not.toBe(base);
    expect(ruleFingerprint({ ...monitored, methods: ["GET"] })).not.toBe(base);
    expect(ruleFingerprint({ ...monitored, requires: "signature" })).not.toBe(base);
    const limited = ruleFingerprint(EXAMPLE_LIMIT_RULE);
    expect(ruleFingerprint({ ...EXAMPLE_LIMIT_RULE, limit: { ...EXAMPLE_LIMIT_RULE.limit, requests: 11 } })).not.toBe(
      limited,
    );
    expect(ruleFingerprint({ ...EXAMPLE_LIMIT_RULE, limit: { ...EXAMPLE_LIMIT_RULE.limit, key: "device" } })).not.toBe(
      limited,
    );
  });
});

describe("promotionEstimate", () => {
  it("finds what promoting a Rule would do, at the Rule's position in the Policy: never the all-enforced row", () => {
    expect(promotionEstimate(run(), rules, monitored)).toEqual({
      would_refuse: 1_300,
      clients_affected: 14,
      unknown_client_events: 0,
      undecidable: 330,
    });
    expect(promotionEstimate(run(), rules, EXAMPLE_LIMIT_RULE)?.would_refuse).toBe(180);
  });

  it("finds nothing for a Rule whose row says nothing about promoting it", () => {
    // The enforced Rule has none; and one the simulation did not reach in time has none either.
    expect(promotionEstimate(run(), rules, enforced)).toBeNull();
    const unreached = run();
    const rows = unreached.simulation.rules.map(({ if_promoted: _dropped, ...row }) => row);
    expect(
      promotionEstimate({ ...unreached, simulation: { ...unreached.simulation, rules: rows } }, rules, monitored),
    ).toBeNull();
  });

  it("finds nothing when no simulation ran", () => {
    expect(promotionEstimate(null, rules, monitored)).toBeNull();
  });

  it("finds nothing for any Rule once one Rule changed since the simulation: the first outcome wins across Rules", () => {
    const changed = { ...monitored, path: "/api/users/**" };
    const now = [enforced, changed, EXAMPLE_LIMIT_RULE];
    expect(promotionEstimate(run(), now, changed)).toBeNull();
    expect(promotionEstimate(run(), now, EXAMPLE_LIMIT_RULE)).toBeNull();
    expect(promotionEstimate(run(), now, enforced)).toBeNull();
  });

  it("finds nothing when the simulation was of more or fewer Rules than the Policy holds", () => {
    expect(promotionEstimate(run(), [enforced, monitored], monitored)).toBeNull();
    const extra = { ...monitored, id: "rul_000000000000000000000001", path: "/extra" };
    expect(promotionEstimate(run(), [...rules, extra], monitored)).toBeNull();
  });

  it("finds nothing in a simulation with the Rule being typed, even for a Rule that is unchanged", () => {
    expect(promotionEstimate({ ...run(), withDraft: true }, rules, monitored)).toBeNull();
    // Also when the typed Rule was simulated after exactly the current Rules.
    const withTyped = run();
    const typed = { name: "Login", path: "/login" };
    const draft = { ...withTyped, rules: [...withTyped.rules, ruleFingerprint(typed)], withDraft: true };
    expect(promotionEstimate(draft, rules, monitored)).toBeNull();
  });

  it("finds nothing when the Rule moved, is not part of the Policy, or the row is about another Rule", () => {
    expect(promotionEstimate(run(), [monitored, enforced, EXAMPLE_LIMIT_RULE], monitored)).toBeNull();
    expect(promotionEstimate(run(), [enforced], monitored)).toBeNull();
    const other = run();
    const rows = other.simulation.rules.map((row) => (row.index === 1 ? { ...row, id: EXAMPLE_LIMIT_RULE.id } : row));
    expect(
      promotionEstimate({ ...other, simulation: { ...other.simulation, rules: rows } }, rules, monitored),
    ).toBeNull();
  });

  it("finds nothing in a result that has no row for the position", () => {
    const short = run();
    const cut = { ...short, simulation: { ...short.simulation, rules: short.simulation.rules.slice(0, 1) } };
    expect(promotionEstimate(cut, rules, monitored)).toBeNull();
  });
});

describe("the words of an estimate", () => {
  const row = result().rules[1];
  if (!row?.if_promoted) throw new Error("no row");
  const promoted = row.if_promoted;
  const RAN = "2026-11-11T09:05:59.000Z";

  it("adds the three kinds of refusal", () => {
    expect(wouldRefuse(row)).toBe(1_260);
    expect(wouldRefuse({ ...row, would_fail_signature: 5, would_throttle: 7 })).toBe(1_272);
  });

  it("says when it is from, what promoting would refuse, from how many clients, and what could not be judged", () => {
    expect(estimateText(promoted, RAN, false)).toBe(
      "Estimate from 09:05 UTC: promoting this Rule would refuse 1,300 requests from 14 clients in the last 24 hours; 330 could not be judged.",
    );
  });

  it("says one request and one client in the singular", () => {
    expect(estimateText({ ...promoted, would_refuse: 1, clients_affected: 1, undecidable: 0 }, RAN, false)).toBe(
      "Estimate from 09:05 UTC: promoting this Rule would refuse 1 request from 1 client in the last 24 hours; 0 could not be judged.",
    );
  });

  it("says for how many requests the clients are unknown, only when there are any", () => {
    expect(estimateText({ ...promoted, unknown_client_events: 1_204 }, RAN, false)).toBe(
      "Estimate from 09:05 UTC: promoting this Rule would refuse 1,300 requests from 14 clients in the last 24 hours; 330 could not be judged. Clients unknown for 1,204 requests.",
    );
    expect(estimateText({ ...promoted, unknown_client_events: 1 }, RAN, false)).toMatch(
      / Clients unknown for 1 request\.$/,
    );
  });

  it("says so when the period was cut short, after everything else", () => {
    expect(estimateText({ ...promoted, unknown_client_events: 2 }, RAN, true)).toBe(
      "Estimate from 09:05 UTC: promoting this Rule would refuse 1,300 requests from 14 clients in the last 24 hours; 330 could not be judged. Clients unknown for 2 requests. The period was cut short: only the most recent requests were replayed.",
    );
  });

  it("names what a simulation leaves out, one line per value, and shows a value it does not know as it came", () => {
    expect(notSimulatedText("patches")).toBe("Virtual patches are not simulated.");
    expect(notSimulatedText("containments")).toBe("Blocks on individual clients are not simulated.");
    expect(notSimulatedText("decoded_paths")).toBe(
      "Requests whose path Shield decodes or resolves differently may be missed.",
    );
    expect(notSimulatedText("device_limits")).toBe(
      "Limits per device are a lower bound: recorded requests carry no device.",
    );
    expect(notSimulatedText("body_verification")).toBe(
      "Whether Shield checks request bodies on your routes is not known to the simulation.",
    );
    expect(notSimulatedText("unrecorded_requests")).toBe(
      "Requests Shield could not deliver, or that were still open when the simulation ran, are not included.",
    );
    expect(notSimulatedText("counter_eviction")).toBe(
      "Shield may forget counters when it holds too many clients; the simulation does not.",
    );
    expect(notSimulatedText("custom_counter_store")).toBe(
      "If Shield uses your own counter store, its counting may differ.",
    );
    expect(notSimulatedText("timing")).toBe(
      "Clock changes or pauses on your server can shift counts by a few milliseconds.",
    );
    expect(notSimulatedText("canaries")).toBe("Not simulated: canaries");
    // A name of something every object has is still only a value.
    expect(notSimulatedText("constructor")).toBe("Not simulated: constructor");
  });

  it("explains every value the protocol names today, each in its own words", () => {
    expect(SIMULATION_NOT_SIMULATED.length).toBe(9);
    for (const value of SIMULATION_NOT_SIMULATED) {
      expect([value, notSimulatedText(value).startsWith("Not simulated:")]).toEqual([value, false]);
      // Sentence case, a full stop, no hyphen in the prose.
      expect(notSimulatedText(value)).toMatch(/^[A-Z][^-]*\.$/);
    }
    expect(new Set(SIMULATION_NOT_SIMULATED.map(notSimulatedText)).size).toBe(SIMULATION_NOT_SIMULATED.length);
  });
});
