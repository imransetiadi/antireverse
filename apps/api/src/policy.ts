import { isBroadPattern, type ParsedPolicyRuleInput, type PolicyRule, type ProblemError } from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";

// What the API decides about the Rules of a Policy beyond their shape (the shape is the protocol's schema).

/** The pattern that matches every request path. */
const EVERY_PATH = "/**";

/**
 * The guardrail: a Rule in Enforce mode whose pattern matches every path would block every request of
 * the App, whatever its methods. One error per such Rule, at `rules.<index>.mode`: Monitor mode is the way out.
 *
 * A Rule in Enforce mode with any other broad pattern (`isBroadPattern`: the first segment is a wildcard)
 * may block most of the App's traffic: it is refused the same way unless `allowBroad` acknowledges it.
 * The message never quotes the pattern. A Rule with a requirement (`requires: "signature"`) is judged exactly like
 * a block Rule: in Enforce mode it blocks every request on its paths that does not meet the requirement.
 */
export function guardrailErrors(
  rules: ReadonlyArray<Pick<PolicyRule, "path" | "mode">>,
  options: { allowBroad: boolean },
): ProblemError[] {
  const errors: ProblemError[] = [];
  for (const [index, rule] of rules.entries()) {
    if (rule.mode !== "enforce") continue;
    if (rule.path === EVERY_PATH) {
      errors.push({
        path: `rules.${index}.mode`,
        message: `A Rule for ${EVERY_PATH} would block every request and cannot be in enforce mode.`,
      });
    } else if (!options.allowBroad && isBroadPattern(rule.path)) {
      errors.push({
        path: `rules.${index}.mode`,
        message:
          "A pattern that starts with a wildcard may block most of the App's traffic in enforce mode. " +
          "Send allow_broad: true to acknowledge it.",
      });
    }
  }
  return errors;
}

/** One error per Rule that repeats the id of an earlier Rule, at `rules.<index>.id`. */
function duplicateIdErrors(rules: ReadonlyArray<Pick<ParsedPolicyRuleInput, "id">>): ProblemError[] {
  const seen = new Set<string>();
  const errors: ProblemError[] = [];
  for (const [index, { id }] of rules.entries()) {
    if (id === undefined) continue;
    if (seen.has(id)) errors.push({ path: `rules.${index}.id`, message: "Must not repeat the id of another Rule." });
    seen.add(id);
  }
  return errors;
}

/**
 * The Rules of the next version from what a client sent: a Rule keeps the id it came with and gets a new
 * one otherwise. Refused, with every error named, when an id repeats or the guardrail is violated.
 */
export function prepareRules(
  input: readonly ParsedPolicyRuleInput[],
): { rules: PolicyRule[] } | { errors: ProblemError[] } {
  // Broad patterns are judged inside the publishing transaction, after the check of the expected version.
  const errors = [...duplicateIdErrors(input), ...guardrailErrors(input, { allowBroad: true })];
  if (errors.length > 0) return { errors };
  return {
    rules: input.map((rule) => ({
      id: rule.id ?? newId("rul"),
      name: rule.name,
      path: rule.path,
      methods: rule.methods,
      action: rule.action,
      mode: rule.mode,
      // Only when set: a Rule without a requirement has no `requires` member, as before slice 04.
      ...(rule.requires === undefined ? {} : { requires: rule.requires }),
    })),
  };
}
