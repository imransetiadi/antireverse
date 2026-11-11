import { isBroadPattern, type PolicyRule } from "@antireverse/protocol";

// Which Rules need the stronger confirmation. Isomorphic: the page decides with it what to ask, the Server
// Action decides with it what to require — the action's answer is the one that counts.

/** A stored Rule, or one about to be sent (whose mode may be left to the API's default, Monitor). */
type RuleShape = Pick<PolicyRule, "path"> & { id?: string | undefined; mode?: PolicyRule["mode"] | undefined };

/** True for a Rule in Enforce mode whose pattern starts with a wildcard (see `isBroadPattern`). */
export function isBroadEnforce(rule: RuleShape): boolean {
  return rule.mode === "enforce" && isBroadPattern(rule.path);
}

/**
 * The broad Enforce Rules of `after` that `before` did not enforce already (same id, same pattern): the
 * ones a person has not acknowledged yet. A broad Rule that was enforced before was acknowledged then.
 */
export function newlyBroad(before: readonly RuleShape[], after: readonly RuleShape[]): RuleShape[] {
  return after.filter(
    (rule) =>
      isBroadEnforce(rule) &&
      !before.some((earlier) => earlier.id === rule.id && earlier.path === rule.path && isBroadEnforce(earlier)),
  );
}
