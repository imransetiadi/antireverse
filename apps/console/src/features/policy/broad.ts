import { canonicalJson, isBroadPattern, type PolicyRule } from "@antireverse/protocol";

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

/** A Rule as it is enforced: what it applies to and what it does. Methods in any order are the same traffic. */
type EnforcedShape = Pick<PolicyRule, "path" | "methods" | "action"> &
  Partial<Pick<PolicyRule, "requires" | "limit">> & { id?: string | undefined; mode?: PolicyRule["mode"] | undefined };

/** What an Enforce Rule enforces, as one comparable text: the API compares Rules the same way. */
function enforcement(rule: EnforcedShape): string {
  return canonicalJson({
    path: rule.path,
    methods: [...rule.methods].sort(),
    action: rule.action,
    requires: rule.requires ?? null,
    limit: rule.limit ?? null,
  });
}

/**
 * The Enforce Rules of `after` that promote (slice 18a): not enforced in `before` (by id), or enforced there on other
 * traffic — another path, methods, action, requirement or limit. Publishing them is a sensitive change that carries a
 * reason. This mirrors the API's rule exactly; the API decides.
 */
export function newlyEnforced(before: readonly EnforcedShape[], after: readonly EnforcedShape[]): EnforcedShape[] {
  const enforcedBefore = new Map(
    before.filter((rule) => rule.mode === "enforce").map((rule) => [rule.id, enforcement(rule)] as const),
  );
  return after.filter((rule) => rule.mode === "enforce" && enforcedBefore.get(rule.id) !== enforcement(rule));
}
