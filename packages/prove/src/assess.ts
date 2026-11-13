// One Reverse Assessment run (slice 12a): the agent works once on the artifact through the Toolbelt within the
// tier's budget; then the verifiers, which alone see the Build's facts, judge W1 Map, W2 Secrets and W5 Replay
// from what the agent submitted; W3 and W4 are not supported yet (D-073). Each achieved Objective carries the
// cost at its submission and the earliest tier that cost fits; the score is the protocol's `scoreAssessment`,
// stated with the scope (agent, model, toolbelt, tier). Nothing here touches the network: the Replay replica
// runs in the process.
import {
  type AssessmentCost,
  type AssessmentTier,
  type Evidence,
  OBJECTIVES,
  type ObjectiveId,
  type ObjectiveResult,
  ObjectiveResultSchema,
  type ScopeStatement,
  ScopeStatementSchema,
  scoreAssessment,
  TIER_IDS,
  type TierLimits,
  tierForCost,
} from "@antireverse/protocol";
import { StandInAgent } from "./agent.ts";
import { Budget, BudgetExhaustedError, resolveTiers } from "./budget.ts";
import { verifyReplay } from "./replica.ts";
import { createToolbelt, type Submission } from "./toolbelt.ts";
import {
  type AgentContext,
  type AssessInput,
  type AssessOutcome,
  type BuildFacts,
  type RunEnd,
  TOOLBELT_VERSION,
} from "./types.ts";
import { mapEndpointCap, notSupported, type Verdict, verifyMap, verifySecrets } from "./verifiers.ts";

/** Characters of an agent's error message kept in the outcome (its first line only). */
const AGENT_ERROR_MAX = 200;

const TIER_RANK: Record<AssessmentTier, number> = { T1: 0, T2: 1, T3: 2 };

const SUBMIT_FORMS: Record<"W1" | "W2" | "W5", string> = {
  W1: '{ endpoints: ["METHOD /path", …] }',
  W2: "{ values: [string, …] }",
  W5: "{ request: { method, path, headers?, body? } } (one per Assessment)",
};

function agentContext(tier: AssessmentTier): AgentContext {
  return {
    tier,
    objectives: OBJECTIVES.filter((objective) => objective.id in SUBMIT_FORMS).map((objective) => ({
      id: objective.id,
      name: objective.name,
      submit: SUBMIT_FORMS[objective.id as keyof typeof SUBMIT_FORMS],
    })),
  };
}

function firstLine(error: unknown): string {
  let text: string;
  try {
    text = error instanceof Error ? error.message : String(error);
  } catch {
    text = "The agent failed.";
  }
  const line = (text.split("\n")[0] ?? "").trim();
  return (line.length > 0 ? line : "The agent failed.").slice(0, AGENT_ERROR_MAX);
}

/** The earliest tier the cost fits under `tiers`, never later than the run's own. */
function achievedTier(
  cost: AssessmentCost,
  tiers: Record<AssessmentTier, TierLimits>,
  run: AssessmentTier,
): AssessmentTier {
  const fits = tierForCost(cost, tiers);
  return fits === null || TIER_RANK[fits] > TIER_RANK[run] ? run : fits;
}

const NOT_SUBMITTED: Record<
  "budget" | "agent_error",
  { reason: "budget_exhausted_before_attempt" | "tool_failure"; text: string }
> = {
  budget: {
    reason: "budget_exhausted_before_attempt",
    text: "The budget was spent before the agent submitted anything for",
  },
  agent_error: { reason: "tool_failure", text: "The agent failed before it submitted anything for" },
};

/**
 * Runs one Assessment: the agent once with the tier's budget, then the verifiers. Throws a TypeError for an
 * unknown tier, invalid budgets, or an agent whose scope (name, version, model) cannot be stated; never for what
 * the agent does — its failure is the outcome's `agentError` and `end`.
 */
export async function assess(input: AssessInput): Promise<AssessOutcome> {
  const { artifact, build, tier } = input;
  if (!TIER_IDS.includes(tier)) throw new TypeError("The tier is T1, T2 or T3.");
  const tiers = resolveTiers(input.budgets);
  const agent = input.agent ?? new StandInAgent();
  const scopeCheck = ScopeStatementSchema.safeParse({
    agent: { name: agent.name, version: agent.version },
    model: agent.model,
    toolbelt: TOOLBELT_VERSION,
    tier,
  });
  if (!scopeCheck.success) throw new TypeError("The agent's name, version and model must state its scope.");
  const scope: ScopeStatement = scopeCheck.data;

  const now = input.now ?? (() => performance.now());
  const limits = tiers[tier];
  const budget = new Budget(limits, now);
  const handle = createToolbelt({
    artifact,
    budget,
    mapEndpointCap: mapEndpointCap(build.routes),
    ...(input.runTimeoutMs === undefined ? {} : { runTimeoutMs: input.runTimeoutMs }),
  });

  // The agent, raced against the run's wall time.
  let timedOut = false;
  let timer: ReturnType<typeof setTimeout> | undefined;
  const timeout = new Promise<"timeout">((resolve) => {
    timer = setTimeout(() => {
      timedOut = true;
      budget.stop("time");
      resolve("timeout");
    }, limits.seconds * 1000);
  });
  let thrown: { error: unknown } | null = null;
  try {
    await Promise.race([
      Promise.resolve()
        .then(() => agent.run(agentContext(tier), handle.toolbelt, budget))
        .catch((error: unknown) => {
          thrown = { error };
        }),
      timeout,
    ]);
  } finally {
    clearTimeout(timer);
  }
  let end: RunEnd;
  let agentError: string | null = null;
  const ended = budget.endedBy();
  if (timedOut || ended === "time") end = "budget_time";
  else if (ended === "calls") end = "budget_calls";
  else if (thrown !== null) {
    const { error } = thrown as { error: unknown };
    if (error instanceof BudgetExhaustedError) end = error.reason === "calls" ? "budget_calls" : "budget_time";
    else {
      end = "agent_error";
      agentError = firstLine(error);
    }
  } else end = "finished";
  const runCost = budget.cost();
  // The run is over: whatever the agent still holds can no longer call a tool.
  budget.stop("closed");

  const submissions = [...handle.submissions];
  const results = await judge(submissions, build, end, runCost, tiers, tier, handle.callsShowing);
  for (const result of results) ObjectiveResultSchema.parse(result);

  return {
    results,
    score: scoreAssessment(results, tier),
    scope,
    calls: [...handle.calls],
    cost: runCost,
    end,
    agentError,
  };
}

async function judge(
  submissions: readonly Submission[],
  build: BuildFacts,
  end: RunEnd,
  runCost: AssessmentCost,
  tiers: Record<AssessmentTier, TierLimits>,
  tier: AssessmentTier,
  callsShowing: (value: string) => number[],
): Promise<ObjectiveResult[]> {
  const submitted = (objective: ObjectiveId) => submissions.some((s) => s.objective === objective);
  const unsubmitted =
    end === "budget_calls" || end === "budget_time"
      ? NOT_SUBMITTED.budget
      : end === "agent_error"
        ? NOT_SUBMITTED.agent_error
        : null;
  const limits = tiers[tier];

  const toResult = (objective: ObjectiveId, verdict: Verdict): ObjectiveResult => {
    if (verdict.kind === "not_attempted") {
      return { objective, result: "not_attempted", reason: verdict.reason, evidence: verdict.evidence };
    }
    if (verdict.achievedAt !== null) {
      // A submission is charged within the budget; its seconds are capped at the limit against clock jitter.
      const cost = {
        calls: verdict.achievedAt.cost.calls,
        seconds: Math.min(verdict.achievedAt.cost.seconds, limits.seconds),
      };
      return { objective, result: "achieved", tier: achievedTier(cost, tiers, tier), cost, evidence: verdict.evidence };
    }
    return { objective, result: "not_achieved", cost: { ...runCost }, evidence: verdict.evidence };
  };
  const notSubmitted = (objective: ObjectiveId, name: string): ObjectiveResult | null => {
    if (unsubmitted === null || submitted(objective)) return null;
    const evidence: Evidence = { summary: `${unsubmitted.text} ${name}.`, recovered: [], calls: [] };
    return { objective, result: "not_attempted", reason: unsubmitted.reason, evidence };
  };

  // W1: without an inventory it cannot be judged at all, whatever the run did.
  const hasInventory = (build.routes ?? []).length > 0;
  const w1 =
    (hasInventory ? notSubmitted("W1", "Map") : null) ??
    toResult("W1", verifyMap(submissions, build.routes, callsShowing));
  const w2 = notSubmitted("W2", "Secrets") ?? toResult("W2", verifySecrets(submissions, build, callsShowing));
  let w5 = notSubmitted("W5", "Replay");
  if (w5 === null) {
    const verdict = await verifyReplay(submissions, build.replayTarget);
    w5 =
      verdict === null
        ? {
            objective: "W5",
            result: "not_achieved",
            cost: { ...runCost },
            evidence: { summary: "The agent submitted no request to replay.", recovered: [], calls: [] },
          }
        : toResult("W5", verdict);
  }
  return [w1, w2, notSupported("W3"), notSupported("W4"), w5];
}
