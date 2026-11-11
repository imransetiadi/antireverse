import type {
  PolicyRule,
  PolicyRuleInput,
  SimulationIfPromoted,
  SimulationResult,
  SimulationRuleResult,
} from "@antireverse/protocol";
import { formatCount, formatTime } from "@/lib/format.ts";
import { type MessageKey, t } from "@/lib/t.ts";

// A Policy simulation (slice 11, D-066) as the Console reads and words it. Isomorphic: the Server Action marks what
// it simulated, the screen decides with the same mark which figures still belong to which Rule. Every figure is an
// estimate from the recorded requests of the last 24 hours.

/**
 * The mark of a Rule as a simulation judged it: its pattern, methods, action, requirement and limit. The mode, the
 * id and the name are not part of it: a simulation shows what Enforce would do, whatever the mode is now. A Rule as
 * sent may leave out what the API fills in (no methods: all; no action: block, or throttle with a limit). Two
 * Rules with the same mark get the same figures at the same position of the same Policy.
 */
export function ruleFingerprint(rule: PolicyRuleInput): string {
  const limit = rule.limit
    ? [rule.limit.requests, rule.limit.window_s, rule.limit.key, rule.limit.count ?? "requests"]
    : null;
  return JSON.stringify([
    rule.path,
    [...(rule.methods ?? [])].sort(),
    rule.action ?? (limit ? "throttle" : "block"),
    rule.requires ?? null,
    limit,
  ]);
}

/** A simulation that succeeded in this page view: its result, and what it was run with. */
export interface SimulationRun {
  simulation: SimulationResult;
  /** The mark of every Rule that was simulated, in order. */
  rules: readonly string[];
  /** True when the Rule being typed in the add-Rule form was simulated after the current Rules. */
  withDraft: boolean;
}

/**
 * What promoting `rule` would do, from the last successful simulation, or null. It is the row's `if_promoted` (the
 * enforced Rules plus this one), never the row's own figures, which assume every Rule enforced. It is given only
 * when that simulation was of exactly the Rules the Policy holds now: the same list in the same order, each Rule
 * unchanged, and never one with the Rule being typed. Any Rule that changed can change what this one would refuse,
 * so a figure that may be stale is not shown; nor is one for a Rule the simulation says nothing about promoting.
 */
export function promotionEstimate(
  run: SimulationRun | null,
  rules: readonly PolicyRule[],
  rule: PolicyRule,
): SimulationIfPromoted | null {
  if (!run || run.withDraft) return null;
  if (run.rules.length !== rules.length || run.simulation.rules.length !== rules.length) return null;
  const same = rules.every((current, position) => {
    const row = run.simulation.rules[position];
    return (
      run.rules[position] === ruleFingerprint(current) &&
      row?.index === position &&
      (row.id === undefined || row.id === current.id)
    );
  });
  if (!same) return null;
  return run.simulation.rules[rules.indexOf(rule)]?.if_promoted ?? null;
}

/** The requests a Rule would refuse: blocked, without a valid signature or throttled. */
export function wouldRefuse(row: SimulationRuleResult): number {
  return row.would_block + row.would_fail_signature + row.would_throttle;
}

/** `1 request`, `1,260 requests`. */
export function requestsText(count: number): string {
  return count === 1 ? t("policy.simulate.requests.one") : t("policy.simulate.requests", { n: formatCount(count) });
}

/** `1 client`, `12 clients`. */
export function clientsText(count: number): string {
  return count === 1 ? t("policy.simulate.clients.one") : t("policy.simulate.clients", { n: formatCount(count) });
}

/** `Clients unknown for 40 requests`: the refused requests that carry no client, so cannot be counted as clients. */
export function unknownClientsText(count: number, sentence = false): string {
  return t(sentence ? "policy.simulate.unknown.sentence" : "policy.simulate.unknown", {
    requests: requestsText(count),
  });
}

/**
 * The line of the promote confirmation: when the estimate is from (`ranAt`, as HH:MM UTC), what promoting the Rule
 * would have refused, from how many clients, and what could not be judged; then for how many requests the clients
 * are unknown, when there are any, and the note of a period that was cut short when `truncated`.
 */
export function estimateText(promoted: SimulationIfPromoted, ranAt: string, truncated: boolean): string {
  const parts = [
    t("policy.simulate.estimate", {
      time: formatTime(ranAt).text.slice(0, 5),
      requests: requestsText(promoted.would_refuse),
      clients: clientsText(promoted.clients_affected),
      undecidable: formatCount(promoted.undecidable),
    }),
  ];
  if (promoted.unknown_client_events > 0) parts.push(unknownClientsText(promoted.unknown_client_events, true));
  if (truncated) parts.push(t("policy.simulate.truncated"));
  return parts.join(" ");
}

/** What a simulation leaves out, one explained line per value this Console knows. */
const NOT_SIMULATED: ReadonlyMap<string, MessageKey> = new Map([
  ["patches", "policy.simulate.not.patches"],
  ["containments", "policy.simulate.not.containments"],
  ["decoded_paths", "policy.simulate.not.decoded_paths"],
  ["device_limits", "policy.simulate.not.device_limits"],
  ["body_verification", "policy.simulate.not.body_verification"],
]);

/** What a simulation leaves out, in words; a value this Console does not know is shown as it came. */
export function notSimulatedText(value: string): string {
  const known = NOT_SIMULATED.get(value);
  return known ? t(known) : t("policy.simulate.not.other", { name: value });
}
