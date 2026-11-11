import { ENVIRONMENTS, type Environment, type Policy, type PolicyVersionSummary } from "@antireverse/protocol";
import type { PolicyConfirmation } from "@/lib/routes.ts";

// What the address of the Policy screen says. Nothing in it is trusted: a value that is not exactly what
// the screen itself links to is ignored.

type QueryValue = string | string[] | undefined;

/** The Environment of `?environment=`. Development without one, and for any value that is not an Environment. */
export function environmentFrom(value: QueryValue): Environment {
  const known = ENVIRONMENTS.find((environment) => environment === value);
  return known ?? "development";
}

const VERSION = /^[1-9][0-9]{0,8}$/;

/**
 * The confirmation step the address asks for: `?promote=<Rule id>` for a Rule of this Policy that is in
 * Monitor mode, or `?rollback=<version>` for a listed version other than the current one. Anything else
 * opens no confirmation. One at a time: a promotion comes first.
 */
export function confirmationFrom(
  query: Readonly<{ promote?: QueryValue; rollback?: QueryValue }>,
  policy: Policy,
  versions: readonly PolicyVersionSummary[],
): PolicyConfirmation {
  const { promote, rollback } = query;
  if (typeof promote === "string" && policy.rules.some((rule) => rule.id === promote && rule.mode === "monitor")) {
    return { promote };
  }
  if (typeof rollback === "string" && VERSION.test(rollback)) {
    const version = Number(rollback);
    if (version !== policy.version && versions.some((listed) => listed.version === version)) {
      return { rollback: version };
    }
  }
  return {};
}
