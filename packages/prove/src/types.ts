// The shapes of the Reverse Assessment core (slice 12a): the artifact the agent works on, the Build facts only
// the verifiers see, the Toolbelt the agent works through, the agent seam, and what `assess` returns.
import type {
  AssessmentCost,
  AssessmentScore,
  AssessmentTier,
  Canary,
  LeakRuleId,
  ObjectiveId,
  ObjectiveResult,
  ScopeStatement,
  TierLimits,
} from "@antireverse/protocol";

/** The version of the Toolbelt, stated in every scope statement. */
export const TOOLBELT_VERSION = "0.1.0";

/**
 * The protected artifact: path → bytes (a string is taken as UTF-8). Paths are as in the Manifest, `/`-separated.
 * It is the only thing the agent can see, and only through the Toolbelt.
 */
export type ArtifactInput = ReadonlyMap<string, Uint8Array | string> | Readonly<Record<string, Uint8Array | string>>;

/** A leak-scan finding as the verifiers know it: by rule, path and fingerprint, never by value. */
export interface LeakFindingRef {
  rule: LeakRuleId;
  /** The path the scan reported, which is part of the fingerprint. */
  path: string;
  /** `leakFingerprint(rule, path, value)`: 32 hex. */
  fingerprint: string;
}

/** The route the Replay replica protects: a Policy path pattern (`/api/orders/**`) and its methods (empty: all). */
export interface ReplayTarget {
  path: string;
  methods?: readonly string[];
}

/** What the verifiers know about the Build and the agent never sees. */
export interface BuildFacts {
  /** The Build's planted Canaries, with their decoy values (W2). */
  canaries: readonly Canary[];
  /** The leak-scan findings of the Build's input files, by fingerprint (W2). */
  leakFindings?: readonly LeakFindingRef[];
  /** The tenant's route inventory (`METHOD /path`), or null/absent when none was registered (W1). */
  routes?: readonly string[] | null;
  /** The route the Replay replica requires a signature on (W5). Default: every route (`/**`, all methods). */
  replayTarget?: ReplayTarget;
}

/** What one Toolbelt call cost, cumulatively since the run started. */
export type CallCost = AssessmentCost;

export type ToolName = "list" | "read" | "search" | "beautify" | "run" | "submit";

/** One recorded Toolbelt call. The summary names paths and counts, never content, patterns, code or values. */
export interface CallRecord {
  /** 0-based position in the call log. */
  index: number;
  tool: ToolName;
  /** The cumulative cost of the run when the call finished (this call included). */
  cost: CallCost;
  summary: string;
}

export interface ListEntry {
  path: string;
  bytes: number;
}
export interface ListResult {
  ok: true;
  files: ListEntry[];
  /** True when more than `TOOLBELT_LIMITS.listMax` files matched. */
  truncated: boolean;
}
export interface ReadResult {
  ok: true;
  path: string;
  offset: number;
  /** UTF-8 decoded bytes `[offset, offset + length)` (at most `TOOLBELT_LIMITS.readBytesMax`). */
  text: string;
  /** The file's total size in bytes. */
  bytes: number;
  /** True when bytes remain after this range. */
  more: boolean;
}
export interface SearchHit {
  path: string;
  /** 1-based line. */
  line: number;
  /** 1-based column (UTF-16 units) of the match in its line. */
  column: number;
  /** The matching line, cut to `TOOLBELT_LIMITS.previewChars` around the match. */
  preview: string;
}
export interface SearchResult {
  ok: true;
  hits: SearchHit[];
  /** True when more than the hit limit matched. */
  truncated: boolean;
}
export interface BeautifyResult {
  ok: true;
  path: string;
  code: string;
  /** True when the output was cut at `TOOLBELT_LIMITS.beautifyCharsMax`. */
  truncated: boolean;
}
export interface RunResult {
  ok: true;
  /** The JSON of what the code returned (null for undefined), at most `TOOLBELT_LIMITS.runOutputMax` characters. */
  output: string;
}
export interface SubmitResult {
  ok: true;
  /** Accepted for verification. Not a verdict: the agent never learns whether it achieved the Objective. */
  accepted: true;
}
/** A call that was made and counted but could not do what was asked (unknown path, parse error, sandbox error…). */
export interface ToolFailure {
  ok: false;
  error: string;
  /** For `run`: the sandbox refused or ended the code (`timeout`, `memory`, `error`), or the sandbox failed (`sandbox`). */
  kind?: "invalid" | "timeout" | "memory" | "error" | "sandbox";
}

/** Payloads of `submit`, per Objective. */
export interface MapSubmission {
  /** Endpoints as `METHOD /path` (`:param` or a concrete segment). */
  endpoints: readonly string[];
}
export interface SecretsSubmission {
  values: readonly string[];
}
export interface ReplayRequest {
  method: string;
  /** Path and optional query, starting with `/`. */
  path: string;
  headers?: Readonly<Record<string, string>>;
  body?: string;
}
export interface ReplaySubmission {
  request: ReplayRequest;
}
export type SubmissionPayload = MapSubmission | SecretsSubmission | ReplaySubmission;

/**
 * The agent's only access to the artifact. Every call costs one tool call and is recorded; once the budget is
 * spent every call rejects with a `BudgetExhaustedError`. The artifact is read-only.
 */
export interface Toolbelt {
  list(dir?: string): Promise<ListResult | ToolFailure>;
  read(path: string, range?: { offset?: number; length?: number }): Promise<ReadResult | ToolFailure>;
  /** Literal (not a regular expression), case-sensitive; at most 200 hits. `path` limits it to one file or folder. */
  search(pattern: string, options?: { path?: string; maxHits?: number }): Promise<SearchResult | ToolFailure>;
  beautify(path: string): Promise<BeautifyResult | ToolFailure>;
  /**
   * Runs `code` as the body of a function of `input` in an isolated worker: no require, import, process,
   * network, file system or timers; time and memory limited. Synchronous: the returned value is sent back as JSON.
   */
  run(code: string, input?: unknown): Promise<RunResult | ToolFailure>;
  submit(objective: ObjectiveId, payload: SubmissionPayload): Promise<SubmitResult | ToolFailure>;
}

/** What the agent may read about its budget. */
export interface BudgetView {
  readonly limits: TierLimits;
  /** Calls made so far. */
  calls(): number;
  /** Seconds since the run started. */
  seconds(): number;
  /** Calls left (0 when spent). */
  callsLeft(): number;
  /** Seconds left (0 when spent). */
  secondsLeft(): number;
  exhausted(): boolean;
}

/** What the agent is told: the run's tier and the Objectives it may submit, and nothing about the Build. */
export interface AgentContext {
  tier: AssessmentTier;
  /** The Objectives with a verifier in this version, with their names. */
  objectives: ReadonlyArray<{ id: ObjectiveId; name: string; submit: string }>;
}

/** The seam for an adversary agent: the deterministic stand-in now, a model-backed agent later (D-067). */
export interface AdversaryAgent {
  readonly name: string;
  readonly version: string;
  /** The model, or "stand-in". */
  readonly model: string;
  run(context: AgentContext, toolbelt: Toolbelt, budget: BudgetView): Promise<void>;
}

/** How the agent's run ended. */
export type RunEnd = "finished" | "budget_calls" | "budget_time" | "agent_error";

export interface AssessInput {
  artifact: ArtifactInput;
  build: BuildFacts;
  tier: AssessmentTier;
  /** Default: a new `StandInAgent`. */
  agent?: AdversaryAgent;
  /** Overrides of the tier limits (tests). Each tier's limits must not be below the previous tier's. */
  budgets?: Partial<Record<AssessmentTier, TierLimits>>;
  /** Milliseconds a `run` call may take. Default 5,000. */
  runTimeoutMs?: number;
  /** The clock in milliseconds (tests). Default `performance.now`-based. */
  now?: () => number;
}

export interface AssessOutcome {
  /** One result per Objective, W1…W5, each valid against the protocol's `ObjectiveResultSchema`. */
  results: ObjectiveResult[];
  /** `scoreAssessment(results, tier)`: the RRS, or inconclusive with its reason and code. */
  score: AssessmentScore;
  scope: ScopeStatement;
  /** The call log, in order. */
  calls: CallRecord[];
  /** What the whole run spent. */
  cost: AssessmentCost;
  end: RunEnd;
  /** The agent's error message when `end` is `agent_error` (bounded, never echoing artifact content). */
  agentError: string | null;
}
