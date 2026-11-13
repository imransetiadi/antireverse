// Entry "@antireverse/prove": the Reverse Assessment core (slice 12a). `assess` runs one Assessment — the agent
// within its budget through the Toolbelt, then the verifiers — and returns the results, the score and the scope.
// No network access of its own: the code runner is an isolated worker and the Replay replica runs in the process.
export { STAND_IN_AGENT, STAND_IN_VERSION, StandInAgent } from "./agent.ts";
export { assess } from "./assess.ts";
export {
  type AgentSpec,
  ASSESS_WORKER_LIMITS,
  type AssessInWorkerOptions,
  assessInWorker,
  BUILT_IN_AGENTS,
  type WorkerAssessInput,
} from "./assess-worker-host.ts";
export { Budget, type BudgetEnd, BudgetExhaustedError, resolveTiers } from "./budget.ts";
export { DEFAULT_REPLAY_TARGET, type ReplicaOptions, replayAgainstReplica, verifyReplay } from "./replica.ts";
export { RUN_LIMITS, runIsolated } from "./sandbox.ts";
export {
  createToolbelt,
  normaliseArtifact,
  type Submission,
  TOOLBELT_LIMITS,
  type ToolbeltHandle,
  type ToolbeltOptions,
} from "./toolbelt.ts";
export * from "./types.ts";
export {
  type AchievedAt,
  MAP_CAP_FACTOR,
  MAP_COVERAGE,
  MAP_PRECISION,
  mapEndpointCap,
  mapEndpointKey,
  matchesRoute,
  notSupported,
  type Verdict,
  verifyMap,
  verifySecrets,
} from "./verifiers.ts";
