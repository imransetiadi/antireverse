import { type AgentSpec, assessInWorker, STAND_IN_AGENT, TOOLBELT_VERSION } from "@antireverse/prove";
import type { Assessor } from "./assessor.ts";

/** Who a module agent is, for the scope statement of a queued Assessment (the run then states its own). */
export interface AgentIdentity {
  name: string;
  version: string;
  model: string;
}

/**
 * The Assessor on the engine of `packages/prove`, by default with its deterministic stand-in agent (D-067: no model and
 * no network until the owner installs a provider key and spend caps). Each run goes through `assessInWorker`: its own
 * worker thread with a limited heap, so the agent's and the Toolbelt's synchronous work never blocks the API's event
 * loop, terminated when the runner's signal aborts or at the engine's deadline (the tier's seconds plus 30 s; the
 * runner's own deadline, the tier plus 60 s, stays the backstop). It rejects with a TypeError for invalid input, an
 * AbortError on abort, a TimeoutError at its deadline, and a plain Error when the worker fails; the runner maps these
 * and never stores or logs the message. The engine keeps the Build's facts out of the agent's context. Leak-scan
 * findings are not passed: W2 runs on the planted Canaries only in 12a. The engine reports no results before it
 * returns, so a run that is aborted or times out keeps no partial results.
 */
export function proveAssessor(options: { agent?: AgentSpec; identity?: AgentIdentity } = {}): Assessor {
  const agent = options.agent ?? "stand-in";
  const identity = options.identity ?? STAND_IN_AGENT;
  return {
    scope: (tier) => ({
      agent: { name: identity.name, version: identity.version },
      model: identity.model,
      toolbelt: TOOLBELT_VERSION,
      tier,
    }),
    async assess(input) {
      // Slice 12b: the logic file and the integrity flag go to the W3 and W4 verifiers. Not leak findings (12a).
      const build = {
        canaries: input.build.canaries,
        routes: input.build.routes,
        logic: input.build.logic,
        integrity: input.build.integrity,
      };
      const outcome = await assessInWorker(
        {
          artifact: input.artifact,
          build,
          tier: input.tier,
          agent,
          ...(input.budgets === undefined ? {} : { budgets: input.budgets }),
        },
        { signal: input.signal },
      );
      return {
        results: outcome.results,
        scope: outcome.scope,
        end: outcome.end,
        calls: outcome.calls,
        cost: outcome.cost,
      };
    },
  };
}
