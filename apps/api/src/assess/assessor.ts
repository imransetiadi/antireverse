import type {
  AssessmentTier,
  Canary,
  LeakRuleId,
  LogicFile,
  ObjectiveResult,
  ScopeStatement,
  TierLimits,
} from "@antireverse/protocol";

// The seam between the API and the Reverse Assessment engine (slice 12a). The API stores, queues and runs
// Assessments; the engine (`packages/prove`) runs the adversary agent on the artifact inside the tier's budget and
// lets its verifiers decide each Objective. The boundary between what the agent sees and what only the verifiers see
// is the engine's: the API hands over the artifact and, separately, the Build's facts (planted Canary values, leak-scan
// fingerprints, the route inventory) as verifier inputs, and never anything else.

/** A leak-scan finding as the verifiers know it: by rule, path and fingerprint, never by value. */
export interface AssessorLeakFinding {
  rule: LeakRuleId;
  path: string;
  /** 32 hex. */
  fingerprint: string;
}

/** What only the verifiers see. Never part of the agent's context. */
export interface AssessorBuildFacts {
  /** The Build's planted Canaries with their decoy values (W2). */
  canaries: readonly Canary[];
  /**
   * The Build's leak-scan findings by fingerprint (W2). Always empty in 12a, and not passed to the engine: the Manifest
   * carries no fingerprints, so W2 runs on Canaries only (Jev decision, coordinator 2026-11-13).
   */
  leakFindings: readonly AssessorLeakFinding[];
  /** The tenant's route inventory (`METHOD /path`), or null when none was registered (W1: not attempted). */
  routes: readonly string[] | null;
  /**
   * The Build's logic file (slice 12b, W3): designated functions with their hidden vectors, or null when none was
   * registered. The engine shows the agent only ids, descriptions and examples; the vectors stay verifier inputs.
   */
  logic: LogicFile | null;
  /** Whether the Build was hardened with the integrity pass (the Manifest's `transform.integrity`), for W4. */
  integrity: boolean;
}

export interface AssessorInput {
  tier: AssessmentTier;
  /** The protected artifact, path → bytes, exactly the Manifest's artifacts (Proof of Ownership passed). */
  artifact: ReadonlyMap<string, Uint8Array>;
  build: AssessorBuildFacts;
  /** Overrides of the tier limits (tests). Absent: the protocol's `TIERS`. */
  budgets?: Partial<Record<AssessmentTier, TierLimits>>;
  /** Aborted when the runner gives up on the run (its own time budget, or the API stopping). */
  signal: AbortSignal;
  /**
   * Told each Objective's result as soon as its verifier decided it, so that a run that fails afterwards keeps what
   * was decided. Optional for an engine: one that never calls it leaves a failed run without partial results.
   */
  onResult?: (result: ObjectiveResult) => void;
}

/** What a finished run returns. The API scores it itself with `scoreAssessment`; any other field is ignored. */
export interface AssessorOutcome {
  /** One per Objective, W1…W5. */
  results: readonly ObjectiveResult[];
  /** The scope statement of the run; its tier must be the run's. */
  scope: ScopeStatement;
  /**
   * How the agent's run ended. `agent_error`: the agent stopped with an error, so the run failed; its results are kept
   * as partial results, never scored. Absent: finished.
   */
  end?: "finished" | "budget_calls" | "budget_time" | "agent_error";
  /**
   * The run's call log in order (index, tool, cumulative cost, a summary naming paths and counts only). The runner
   * stores the calls the evidence references (fork 5). Absent: no log, nothing stored.
   */
  calls?: readonly { index: number; tool: string; cost: { calls: number; seconds: number }; summary: string }[];
  /** What the whole run spent. Absent: the last call's cost. */
  cost?: { calls: number; seconds: number };
}

export interface Assessor {
  /** The scope statement a run at `tier` will carry: stored with the queued Assessment, replaced by the run's own. */
  scope(tier: AssessmentTier): ScopeStatement;
  /**
   * Runs one Assessment. Rejects on an engine failure; the runner then marks the Assessment failed: a rejection named
   * `TimeoutError` as a timeout, `AbortError` as interrupted, any other as an engine error. The message is never kept.
   */
  assess(input: AssessorInput): Promise<AssessorOutcome>;
}

/** The engine stand-in used until an engine is wired: every run fails with this reason. */
export const ENGINE_UNAVAILABLE = "The assessment engine is not available.";

/** An Assessor that has no engine: Assessments are accepted and queued, and each run fails, saying why. */
export function unavailableAssessor(): Assessor {
  return {
    scope: (tier) => ({ agent: { name: "none", version: "0.0.0" }, model: "none", toolbelt: "0.0.0", tier }),
    assess: () => Promise.reject(new Error(ENGINE_UNAVAILABLE)),
  };
}
