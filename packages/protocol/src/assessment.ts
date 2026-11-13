// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { LEAK_RULES, type LeakRuleId } from "./canaries.ts";
import { ENVIRONMENTS, ID_PATTERNS } from "./constants.ts";
import { LOGIC_LIMITS, LogicFunctionIdSchema } from "./logic.ts";
import { deepFreeze, isoDateTime, text, utf8Bytes } from "./shared.ts";

// The Reverse Assessment contract (slice 12a, SDD §5.4 and §12.1, D-067, D-073). An adversary agent works on a
// registered Build's protected artifact inside a tier's budget; verifiers, never the agent, decide which
// Objectives it achieved; `scoreAssessment` turns the results into the Reverse Resistance Score (RRS) or says why
// there is none. Evidence names what was recovered by id, fingerprint or count, never by value. Also here: the
// route inventory a tenant registers with a Build for the Map Objective (never given to the agent). Every object
// schema is a plain `z.object`, which strips unknown keys.

export const ASSESSMENT_LIMITS = deepFreeze({
  /** Decoded bytes of an Assessment's uploaded artifact, all files together (25 MB). */
  artifactBytesMax: 26_214_400,
  /** Files of an uploaded artifact: as many as a Manifest may list (`BUILD_LIMITS.artifactsMax`). */
  filesMax: 1000,
  /** Days the uploaded artifact is kept after the Assessment finished. Enforced by the API. */
  retentionDays: 30,
  /** Characters of an Objective's evidence summary. */
  summaryMax: 500,
  /** Recovered items of one Objective's evidence. */
  recoveredMax: 50,
  /** Call-log references of one Objective's evidence. */
  callRefsMax: 50,
  /** Characters of an inconclusive reason. */
  reasonMax: 500,
  /** Characters of a failure reason. */
  failureReasonMax: 200,
  /** Characters of the agent's name in a scope statement. */
  agentNameMax: 64,
  /** Characters of the agent's and the toolbelt's version in a scope statement. */
  versionMax: 32,
  /** Characters of the model in a scope statement. */
  modelMax: 128,
  /** Assessments returned by the Assessment list. */
  listed: 50,
  /** Excluded (not attempted) Objective weight above which an Assessment is inconclusive. */
  excludedWeightMax: 0.2,
} as const);

export const ROUTE_LIMITS = deepFreeze({
  /** Routes of one inventory. */
  routesMax: 2000,
  /** Characters of a route's path template. */
  pathMax: 256,
  /** Characters of a route's method. */
  methodMax: 16,
} as const);

// --- Objectives, tiers, resistance ------------------------------------------------------------------------

/** The web Surface's Objectives (SDD §12.1), with their weights (summing to 1) and the fix the Console suggests. */
export const OBJECTIVES = deepFreeze([
  {
    id: "W1",
    key: "map",
    name: "Map",
    weight: 0.15,
    fix: "Keep internal and admin routes out of the client bundle: build their URLs on the server, and encrypt string literals so path names cannot be read.",
  },
  {
    id: "W2",
    key: "secrets",
    name: "Secrets",
    weight: 0.2,
    fix: "Remove secrets from the client bundle and rotate any that shipped; keep keys on the server and let the leak scan fail the build.",
  },
  {
    id: "W3",
    key: "logic",
    name: "Logic",
    weight: 0.25,
    fix: "Move the logic to the server, or harden it further and add a tamper check.",
  },
  {
    id: "W4",
    key: "tamper",
    name: "Tamper",
    weight: 0.2,
    fix: "Add Harden's --integrity and checks on the server; the integrity check is a signal, not tamper proofing.",
  },
  {
    id: "W5",
    key: "replay",
    name: "Replay",
    weight: 0.2,
    fix: "Require signed requests on protected routes in the Policy and enforce Attestation, so a request made without the genuine Guard is refused.",
  },
] as const);
export type Objective = (typeof OBJECTIVES)[number];
export type ObjectiveId = Objective["id"];
export type ObjectiveKey = Objective["key"];

export const OBJECTIVE_IDS = deepFreeze(["W1", "W2", "W3", "W4", "W5"] as const satisfies readonly ObjectiveId[]);

/** The Budget Tiers, by the earliest of which an achieved Objective is scored. */
export const TIER_IDS = deepFreeze(["T1", "T2", "T3"] as const);
export type AssessmentTier = (typeof TIER_IDS)[number];

/** Limits of one tier: tool calls and wall-clock seconds, both inclusive. */
export type TierLimits = { readonly calls: number; readonly seconds: number };

/** T1 150 calls / 15 min, T2 1,500 / 2 h, T3 6,000 / 8 h (SDD §12.1). */
export const TIERS = deepFreeze({
  T1: { calls: 150, seconds: 900 },
  T2: { calls: 1500, seconds: 7200 },
  T3: { calls: 6000, seconds: 28_800 },
} as const satisfies Record<AssessmentTier, TierLimits>);

/**
 * rᵢ of an Objective: achieved by the earliest tier whose limits its cost fits; not achieved by the run's own tier
 * (a T1 or T2 run cannot show resistance beyond its tier). Not attempted has no value: it is excluded.
 */
export const RESISTANCE_VALUES = deepFreeze({
  achieved: { T1: 0, T2: 0.4, T3: 0.7 },
  not_achieved: { T1: 0.4, T2: 0.7, T3: 1 },
} as const satisfies Record<"achieved" | "not_achieved", Record<AssessmentTier, number>>);

/** queued → running → scored | inconclusive | failed. */
export const ASSESSMENT_STATUSES = ["queued", "running", "scored", "inconclusive", "failed"] as const;
export type AssessmentStatus = (typeof ASSESSMENT_STATUSES)[number];

/**
 * Why an Objective was not attempted. `not_supported`: the Objective has no verifier yet (W3 and W4 in 12a);
 * `no_inventory`: W1 without a route inventory registered with the Build; `not_designated` (slice 12b): W3 without
 * a protected function designated with `harden --logic`; `no_runnable_file` (owner, 2026-11-13): W4 when the
 * artifact has no .js, .mjs or .cjs file to run. Not attempted is not resistance.
 */
export const NOT_ATTEMPTED_REASONS = [
  "not_supported",
  "refused",
  "tool_failure",
  "sandbox_error",
  "budget_exhausted_before_attempt",
  "no_inventory",
  "not_designated",
  "no_runnable_file",
] as const;
export type NotAttemptedReason = (typeof NOT_ATTEMPTED_REASONS)[number];

const REASON_TEXT: Record<NotAttemptedReason, string> = {
  not_supported: "not supported",
  refused: "refused",
  tool_failure: "tool failure",
  sandbox_error: "sandbox error",
  budget_exhausted_before_attempt: "budget exhausted before the attempt",
  no_inventory: "no route inventory",
  not_designated: "no protected function was designated (add --logic to Harden)",
  no_runnable_file: "no JavaScript file to run (assess the bundled output)",
};

/** Why an Assessment is inconclusive, as a machine code beside the English reason. */
export const INCONCLUSIVE_CODES = ["excluded_over_limit"] as const;
export type InconclusiveCode = (typeof INCONCLUSIVE_CODES)[number];

/** The scope statement's model when the deterministic stand-in agent ran (D-067). */
export const STAND_IN_MODEL = "stand-in";

const TIER_RANK: Record<AssessmentTier, number> = { T1: 0, T2: 1, T3: 2 };
/** Weights in hundredths, so the score is computed exactly. */
const WEIGHT_HUNDREDTHS = Object.fromEntries(
  OBJECTIVES.map((objective) => [objective.id, Math.round(objective.weight * 100)]),
) as Record<ObjectiveId, number>;
/** Resistance in tenths, for the same reason. */
const R_TENTHS = {
  achieved: { T1: 0, T2: 4, T3: 7 },
  not_achieved: { T1: 4, T2: 7, T3: 10 },
} as const;
const EXCLUDED_HUNDREDTHS_MAX = Math.round(ASSESSMENT_LIMITS.excludedWeightMax * 100);

// --- Cost and tier mapping --------------------------------------------------------------------------------

/** What reaching an Objective took: tool calls and wall-clock seconds since the run started. */
export const AssessmentCostSchema = z.object({ calls: z.int().min(0), seconds: z.number().min(0) });
export type AssessmentCost = z.infer<typeof AssessmentCostSchema>;

/**
 * The earliest tier whose limits (both inclusive) the cost fits, or null beyond the last. A T3 run can thereby
 * say "achieved within T1 limits". `tiers` overrides the budgets (tests). Throws a TypeError for a cost with
 * negative or fractional calls, or negative or non-finite seconds.
 */
export function tierForCost(
  cost: AssessmentCost,
  tiers: Record<AssessmentTier, TierLimits> = TIERS,
): AssessmentTier | null {
  const { calls, seconds } = cost ?? ({} as AssessmentCost);
  if (!Number.isInteger(calls) || calls < 0 || !Number.isFinite(seconds) || seconds < 0) {
    throw new TypeError("A cost is a whole number of calls and a finite number of seconds, neither negative.");
  }
  for (const tier of TIER_IDS) {
    if (calls <= tiers[tier].calls && seconds <= tiers[tier].seconds) return tier;
  }
  return null;
}

// --- Evidence and results ---------------------------------------------------------------------------------

const CanaryIdSchema = z.string().regex(ID_PATTERNS.cny);
const LEAK_RULE_IDS = LEAK_RULES.map((rule) => rule.id) as [LeakRuleId, ...LeakRuleId[]];

/**
 * One thing an Objective's verifier recovered, by reference only: a planted Canary by id, a leak-scan finding by
 * fingerprint and rule, the Map coverage as counts, the replica's answer to the Replay request as its status.
 */
export const RecoveredItemSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("canary"), canary_id: CanaryIdSchema }),
  z.object({
    kind: z.literal("leak"),
    rule: z.enum(LEAK_RULE_IDS),
    fingerprint: z.string().regex(/^[0-9a-f]{32}$/),
  }),
  z
    .object({
      kind: z.literal("routes"),
      matched: z.int().min(0),
      submitted: z.int().min(0),
      inventory: z.int().min(0).max(ROUTE_LIMITS.routesMax),
    })
    .refine((item) => item.matched <= item.submitted && item.matched <= item.inventory, {
      message: "Cannot match more routes than were submitted or are in the inventory.",
      path: ["matched"],
    }),
  z.object({ kind: z.literal("replay"), status: z.int().min(100).max(599) }),
]);
export type RecoveredItem = z.infer<typeof RecoveredItemSchema>;

// A decoy key anywhere in a summary: evidence names a Canary by id, never by value.
const DECOY_KEY_ANYWHERE = /ak_live_[0-9A-Za-z]{32}/;

/**
 * What an Objective's verifier found, how, and through which calls: a bounded summary (never a recovered value),
 * the recovered items by reference, and the indexes of the calls in the Assessment's call log.
 */
export const EvidenceSchema = z.object({
  summary: text(ASSESSMENT_LIMITS.summaryMax)
    .min(1)
    .refine((summary) => !DECOY_KEY_ANYWHERE.test(summary), "Must name a Canary by id, never by its value."),
  recovered: z.array(RecoveredItemSchema).max(ASSESSMENT_LIMITS.recoveredMax),
  calls: z.array(z.int().min(0)).max(ASSESSMENT_LIMITS.callRefsMax),
});
export type Evidence = z.infer<typeof EvidenceSchema>;

const ObjectiveIdSchema = z.enum(OBJECTIVE_IDS);
const TierSchema = z.enum(TIER_IDS);

/**
 * One Objective's result. `achieved` carries the earliest tier and the cost at which it was reached; the tier
 * may not be earlier than the one the cost fits (it may be later: budgets can be overridden for tests).
 * `not_achieved` carries what the run spent; `not_attempted` the reason, and is excluded from the score.
 */
export const ObjectiveResultSchema = z
  .discriminatedUnion("result", [
    z.object({
      objective: ObjectiveIdSchema,
      result: z.literal("achieved"),
      tier: TierSchema,
      cost: AssessmentCostSchema,
      evidence: EvidenceSchema,
    }),
    z.object({
      objective: ObjectiveIdSchema,
      result: z.literal("not_achieved"),
      cost: AssessmentCostSchema,
      evidence: EvidenceSchema,
    }),
    z.object({
      objective: ObjectiveIdSchema,
      result: z.literal("not_attempted"),
      reason: z.enum(NOT_ATTEMPTED_REASONS),
      evidence: EvidenceSchema,
    }),
  ])
  .superRefine((value, context) => {
    if (value.result !== "achieved") return;
    let fits: AssessmentTier | null;
    try {
      fits = tierForCost(value.cost);
    } catch {
      return; // A malformed cost is already an issue of `cost`.
    }
    if (fits === null || TIER_RANK[value.tier] < TIER_RANK[fits]) {
      context.addIssue({ code: "custom", message: "The tier must be one whose limits the cost fits.", path: ["tier"] });
    }
  });
export type ObjectiveResult = z.infer<typeof ObjectiveResultSchema>;

/** Who produced a score and with what: shown with every score, which is comparable only within one scope. */
export const ScopeStatementSchema = z.object({
  agent: z.object({
    name: text(ASSESSMENT_LIMITS.agentNameMax).min(1),
    version: text(ASSESSMENT_LIMITS.versionMax).min(1),
  }),
  /** The model, or `STAND_IN_MODEL` for the deterministic stand-in agent. */
  model: text(ASSESSMENT_LIMITS.modelMax).min(1),
  toolbelt: text(ASSESSMENT_LIMITS.versionMax).min(1),
  tier: TierSchema,
});
export type ScopeStatement = z.infer<typeof ScopeStatementSchema>;

// --- Score ------------------------------------------------------------------------------------------------

export type AssessmentScore =
  | { status: "scored"; rrs: number; renormalised: boolean; excluded_weight: number; code: null }
  | {
      status: "inconclusive";
      rrs: null;
      renormalised: false;
      excluded_weight: number;
      code: InconclusiveCode;
      reason: string;
    };

/**
 * The RRS of one run (SDD §12.1 and the plan): `round(100 × Σ wᵢ rᵢ)` over the attempted Objectives, their
 * weights renormalised to sum to 1 when any was not attempted, rounded half up and computed exactly. rᵢ is
 * `RESISTANCE_VALUES`. Excluded weight above 20 % makes it inconclusive, with no number and a reason naming the
 * Objectives. Throws a TypeError unless each Objective appears exactly once, or for an Objective achieved at a
 * tier above the run's.
 */
export function scoreAssessment(results: readonly ObjectiveResult[], runTier: AssessmentTier): AssessmentScore {
  if (!TIER_IDS.includes(runTier)) throw new TypeError("The run tier is T1, T2 or T3.");
  if (!Array.isArray(results)) throw new TypeError("Results are a list.");
  const byObjective = new Map<ObjectiveId, ObjectiveResult>();
  for (const result of results) {
    if (!OBJECTIVE_IDS.includes(result?.objective) || byObjective.has(result.objective)) {
      throw new TypeError("Each Objective must have exactly one result.");
    }
    byObjective.set(result.objective, result);
  }
  if (byObjective.size !== OBJECTIVE_IDS.length) throw new TypeError("Each Objective must have exactly one result.");

  let excluded = 0;
  let attempted = 0;
  let weighted = 0; // Σ w (hundredths) × r (tenths)
  const missing: string[] = [];
  for (const objective of OBJECTIVES) {
    const result = byObjective.get(objective.id) as ObjectiveResult;
    const weight = WEIGHT_HUNDREDTHS[objective.id];
    if (result.result === "not_attempted") {
      excluded += weight;
      missing.push(`${objective.id} ${objective.name}: ${REASON_TEXT[result.reason] ?? result.reason}`);
      continue;
    }
    attempted += weight;
    if (result.result === "achieved") {
      if (TIER_RANK[result.tier] > TIER_RANK[runTier]) {
        throw new TypeError(`${objective.id} cannot be achieved at ${result.tier} in a ${runTier} run.`);
      }
      weighted += weight * R_TENTHS.achieved[result.tier];
    } else {
      weighted += weight * R_TENTHS.not_achieved[runTier];
    }
  }

  const excludedWeight = excluded / 100;
  if (excluded > EXCLUDED_HUNDREDTHS_MAX) {
    return {
      status: "inconclusive",
      rrs: null,
      renormalised: false,
      excluded_weight: excludedWeight,
      code: "excluded_over_limit",
      reason: `${excluded}% of the Objective weight was not attempted (${missing.join("; ")}); a score needs at most ${EXCLUDED_HUNDREDTHS_MAX}%.`,
    };
  }
  // 100 × (weighted / 1000) / (attempted / 100) = 10 × weighted / attempted, rounded half up in integers.
  const rrs = Math.floor((20 * weighted + attempted) / (2 * attempted));
  return { status: "scored", rrs, renormalised: excluded > 0, excluded_weight: excludedWeight, code: null };
}

// --- Assessment -------------------------------------------------------------------------------------------

/** An Assessment as the API returns it. Its number, status and renormalisation always equal `scoreAssessment`. */
export const AssessmentSchema = z
  .object({
    id: z.string().regex(ID_PATTERNS.asm),
    build_id: z.string().regex(ID_PATTERNS.bld),
    app_id: z.string().regex(ID_PATTERNS.app),
    environment: z.enum(ENVIRONMENTS).optional(),
    /** The tier whose budget the run had. */
    tier: TierSchema,
    status: z.enum(ASSESSMENT_STATUSES),
    /**
     * One per Objective once scored or inconclusive; empty while queued or running; when failed, the results
     * reached before the failure (any subset, each Objective at most once).
     */
    results: z.array(ObjectiveResultSchema).max(OBJECTIVE_IDS.length),
    rrs: z.int().min(0).max(100).nullable(),
    inconclusive_reason: text(ASSESSMENT_LIMITS.reasonMax).min(1).nullable(),
    /** The machine code of the inconclusive reason; null unless inconclusive. */
    inconclusive_code: z.enum(INCONCLUSIVE_CODES).nullable(),
    /** Whether the attempted Objectives' weights were renormalised to sum to 1. */
    renormalised: z.boolean(),
    scope: ScopeStatementSchema,
    created_at: isoDateTime(),
    started_at: isoDateTime().nullable(),
    finished_at: isoDateTime().nullable(),
    failure_reason: text(ASSESSMENT_LIMITS.failureReasonMax).min(1).nullable(),
    /** Until when the uploaded artifact is kept (the Assessment plus 30 days); null once it was deleted. */
    artifact_kept_until: isoDateTime().nullable(),
  })
  .superRefine((assessment, context) => {
    const issue = (message: string, path: string) => context.addIssue({ code: "custom", message, path: [path] });
    if (assessment.scope.tier !== assessment.tier) issue("The scope statement's tier must be the run's.", "scope");
    const created = Date.parse(assessment.created_at);
    const started = assessment.started_at === null ? null : Date.parse(assessment.started_at);
    const finished = assessment.finished_at === null ? null : Date.parse(assessment.finished_at);
    if (started !== null && started < created) issue("Must not start before it was created.", "started_at");
    if (finished !== null && finished < (started ?? created))
      issue("Must not finish before it started.", "finished_at");

    const finishedStatus = assessment.status === "scored" || assessment.status === "inconclusive";
    if (!finishedStatus) {
      if (assessment.status !== "failed" && assessment.results.length > 0) {
        issue("A queued or running Assessment has no results.", "results");
      }
      if (assessment.rrs !== null) issue("Only a scored Assessment has a number.", "rrs");
      if (assessment.inconclusive_reason !== null)
        issue("Only an inconclusive one has a reason.", "inconclusive_reason");
      if (assessment.inconclusive_code !== null) {
        issue("Only an inconclusive one has a code.", "inconclusive_code");
      }
      if (assessment.renormalised) issue("Only a scored Assessment is renormalised.", "renormalised");
    }
    if ((assessment.status === "failed") !== (assessment.failure_reason !== null)) {
      issue("A failed Assessment, and only a failed one, has a failure reason.", "failure_reason");
    }
    if (assessment.status === "queued") {
      if (started !== null) issue("A queued Assessment has not started.", "started_at");
      if (finished !== null) issue("A queued Assessment has not finished.", "finished_at");
      return;
    }
    if (assessment.status === "running") {
      if (started === null) issue("A running Assessment has started.", "started_at");
      if (finished !== null) issue("A running Assessment has not finished.", "finished_at");
      return;
    }
    if (finished === null) issue("A finished Assessment has a finish time.", "finished_at");
    if (assessment.status === "failed") {
      const seen = new Set<ObjectiveId>();
      for (const result of assessment.results) {
        if (seen.has(result.objective)) issue("Each Objective has at most one result.", "results");
        seen.add(result.objective);
        if (result.result === "achieved" && TIER_RANK[result.tier] > TIER_RANK[assessment.tier]) {
          issue(`${result.objective} cannot be achieved at ${result.tier} in a ${assessment.tier} run.`, "results");
        }
      }
      return;
    }
    if (started === null) issue("A finished Assessment has started.", "started_at");

    let score: AssessmentScore;
    try {
      score = scoreAssessment(assessment.results, assessment.tier);
    } catch (error) {
      issue((error as Error).message, "results");
      return;
    }
    if (score.status !== assessment.status) issue(`The results make the Assessment ${score.status}.`, "status");
    if (assessment.rrs !== score.rrs) issue("Must equal scoreAssessment's number.", "rrs");
    if (assessment.renormalised !== score.renormalised) issue("Must equal scoreAssessment's.", "renormalised");
    if ((assessment.status === "inconclusive") !== (assessment.inconclusive_reason !== null)) {
      issue("An inconclusive Assessment, and only one, has a reason.", "inconclusive_reason");
    }
    if (assessment.inconclusive_code !== score.code) issue("Must equal scoreAssessment's code.", "inconclusive_code");
  });
export type Assessment = z.infer<typeof AssessmentSchema>;

// --- Requests and responses -------------------------------------------------------------------------------

const BASE64_CHARS_MAX = Math.ceil(ASSESSMENT_LIMITS.artifactBytesMax / 3) * 4;

function isBase64Char(code: number): boolean {
  return (
    (code >= 65 && code <= 90) || // A-Z
    (code >= 97 && code <= 122) || // a-z
    (code >= 48 && code <= 57) || // 0-9
    code === 43 || // +
    code === 47 // /
  );
}

/**
 * The decoded byte length of standard, padded base64 (RFC 4648 §4: `A-Z a-z 0-9 + /`, length a multiple of 4, at
 * most two `=` at the end), or null for anything else. Does not decode.
 */
export function decodedBase64Bytes(value: string): number | null {
  if (typeof value !== "string" || value.length % 4 !== 0) return null;
  let padding = 0;
  if (value.endsWith("==")) padding = 2;
  else if (value.endsWith("=")) padding = 1;
  const end = value.length - padding;
  for (let index = 0; index < end; index++) {
    if (!isBase64Char(value.charCodeAt(index))) return null;
  }
  return (value.length / 4) * 3 - padding;
}

const ArtifactFileSchema = z.object({
  /** As the Manifest's artifact path, so Proof of Ownership can compare hashes path by path. */
  path: text(256).min(1),
  base64: z.string().max(BASE64_CHARS_MAX),
});

/**
 * Body of `POST /v1/apps/:appId/builds/:buildId/assessments` (admin key): the tier and the protected artifact's
 * files (optional), each path once, at most 25 MB decoded in total. That the files' hashes equal the Manifest's (Proof of
 * Ownership) is the API's check: hashing needs node:crypto, which this isomorphic module must not import.
 */
export const CreateAssessmentRequestSchema = z
  .object({
    tier: TierSchema,
    /**
     * Optional: without files the API reassesses the Build's most recent kept artifact, or answers 409
     * `artifact-required` when none is kept.
     */
    files: z.array(ArtifactFileSchema).min(1).max(ASSESSMENT_LIMITS.filesMax).optional(),
  })
  .superRefine((request, context) => {
    const paths = new Set<string>();
    let total = 0;
    if (request.files === undefined) return;
    request.files.forEach((file, index) => {
      if (paths.has(file.path)) {
        context.addIssue({ code: "custom", message: "Must not list a path twice.", path: ["files", index, "path"] });
      }
      paths.add(file.path);
      const bytes = decodedBase64Bytes(file.base64);
      if (bytes === null) {
        context.addIssue({ code: "custom", message: "Must be padded base64.", path: ["files", index, "base64"] });
      } else {
        total += bytes;
      }
    });
    if (total > ASSESSMENT_LIMITS.artifactBytesMax) {
      context.addIssue({ code: "custom", message: "The artifact must be at most 25 MB decoded.", path: ["files"] });
    }
  });
export type CreateAssessmentRequest = z.infer<typeof CreateAssessmentRequestSchema>;

export const ASSESSMENT_CALL_LIMITS = deepFreeze({
  /** Calls stored per Assessment: only those some Objective's evidence references, the earliest first. */
  storedMax: 200,
  /** Characters of a call's summary (the Toolbelt's own bound). */
  summaryMax: 200,
} as const);

/** The Toolbelt's tools, as a stored call names them. */
export const TOOL_NAMES = deepFreeze(["list", "read", "search", "beautify", "run", "submit"] as const);

/**
 * One call of the run's call log that an Objective's evidence references: its position in the log, the tool, the run's
 * cumulative cost when it finished, and a summary naming paths and counts only — never content, a pattern or a value.
 */
export const AssessmentCallSchema = z.object({
  index: z.int().min(0),
  tool: z.enum(TOOL_NAMES),
  cost: AssessmentCostSchema,
  summary: text(ASSESSMENT_CALL_LIMITS.summaryMax).min(1),
});
export type AssessmentCall = z.infer<typeof AssessmentCallSchema>;

/** The whole run's call log in numbers: calls recorded, and what the run spent (calls and seconds). */
export const AssessmentCallTotalsSchema = z.object({
  count: z.int().min(0),
  calls: z.int().min(0),
  seconds: z.number().min(0),
});
export type AssessmentCallTotals = z.infer<typeof AssessmentCallTotalsSchema>;

/**
 * 200 of `GET /v1/assessments/:id`. From slice 12a (fork 5) it may carry the referenced calls (ascending index, each
 * once, at most 200) and the run's totals, both or neither; every index an Objective's evidence names is then a stored
 * call. Optional: an Assessment that has not run, or ended without a call log, has neither.
 */
export const AssessmentResponseSchema = z
  .object({
    assessment: AssessmentSchema,
    calls: z.array(AssessmentCallSchema).max(ASSESSMENT_CALL_LIMITS.storedMax).optional(),
    call_totals: AssessmentCallTotalsSchema.optional(),
  })
  .superRefine((response, context) => {
    const { calls, call_totals: totals } = response;
    if ((calls === undefined) !== (totals === undefined)) {
      context.addIssue({ code: "custom", message: "Calls and their totals come together.", path: ["calls"] });
      return;
    }
    if (calls === undefined || totals === undefined) return;
    const stored = new Set<number>();
    calls.forEach((call, position) => {
      const previous = calls[position - 1];
      if (previous !== undefined && previous.index >= call.index) {
        context.addIssue({
          code: "custom",
          message: "Calls are in ascending index, each once.",
          path: ["calls", position],
        });
      }
      if (call.index >= totals.count) {
        context.addIssue({ code: "custom", message: "A call must be within the call log.", path: ["calls", position] });
      }
      stored.add(call.index);
    });
    for (const result of response.assessment.results) {
      if (result.evidence.calls.some((index) => !stored.has(index))) {
        context.addIssue({
          code: "custom",
          message: `${result.objective}'s evidence names a call that is not stored.`,
          path: ["calls"],
        });
      }
    }
  });
export type AssessmentResponse = z.infer<typeof AssessmentResponseSchema>;

/** 202 of `POST /v1/apps/:appId/builds/:buildId/assessments`: the queued Assessment (no calls yet). */
export const CreateAssessmentResponseSchema = z.object({ assessment: AssessmentSchema });
export type CreateAssessmentResponse = z.infer<typeof CreateAssessmentResponseSchema>;

/** 200 of `GET /v1/apps/:appId/builds/:buildId/assessments`: newest first, at most `ASSESSMENT_LIMITS.listed`. */
export const ListAssessmentsResponseSchema = z.object({
  assessments: z.array(AssessmentSchema).max(ASSESSMENT_LIMITS.listed),
});
export type ListAssessmentsResponse = z.infer<typeof ListAssessmentsResponseSchema>;

// --- Submissions (W3 Logic, W4 Tamper; slice 12b) ---------------------------------------------------------

export const TAMPER_LIMITS = deepFreeze({
  /** Bytes of a W4 submission's code as UTF-8 (50 MB). */
  codeBytesMax: 52_428_800,
  /** A W4 submission is at most this many times the original file's size. Enforced by prove, which has the file. */
  sizeFactorMax: 2,
  /** Common prefix plus common suffix, as a share of the original, for the run code to still be the original. */
  similarityMin: 0.9,
  /** Milliseconds a W4 submission may run in the sandbox. Enforced by prove. */
  timeoutMs: 5000,
  /** W4 submissions per run. Enforced by prove. */
  submissionsMax: 3,
  /** Hex characters of a run's tamper nonce. */
  nonceHexChars: 16,
} as const);

/**
 * The agent's W3 submission: a designated function's id and a reimplementation as a JS function body (at most
 * 64 KB as UTF-8), whose parameters are the vector's input spread as `a0..aN` and also `args`. Whether the id is one
 * of the Build's functions, and the vectors' verdict, are prove's.
 */
export const LogicSubmissionSchema = z.object({
  function_id: LogicFunctionIdSchema,
  body: z
    .string()
    .min(1)
    .refine(
      (body) => utf8Bytes(body, LOGIC_LIMITS.bodyBytesMax) <= LOGIC_LIMITS.bodyBytesMax,
      "The body must be at most 64 KB as UTF-8.",
    ),
});
export type LogicSubmission = z.infer<typeof LogicSubmissionSchema>;

/**
 * The agent's W4 submission: the path of one `.js`, `.mjs` or `.cjs` artifact file and its modified code (at most
 * 50 MB as UTF-8). That the path is one of the artifact's files and the code at most `TAMPER_LIMITS.sizeFactorMax`
 * times the original's size are prove's checks: this module does not have the artifact.
 */
export const TamperSubmissionSchema = z.object({
  path: text(256)
    .min(1)
    .refine((path) => /\.(?:js|mjs|cjs)$/.test(path), "Must be a .js, .mjs or .cjs file."),
  code: z
    .string()
    .min(1)
    .refine(
      (code) => utf8Bytes(code, TAMPER_LIMITS.codeBytesMax) <= TAMPER_LIMITS.codeBytesMax,
      "The code must be at most 50 MB as UTF-8.",
    ),
});
export type TamperSubmission = z.infer<typeof TamperSubmissionSchema>;

// --- Route inventory (W1) ---------------------------------------------------------------------------------

const ROUTE_SEGMENT = "(?:[A-Za-z0-9._~-]+|:[A-Za-z_][A-Za-z0-9_]*)";
const ROUTE_ENTRY = new RegExp(`^([A-Za-z-]{1,${ROUTE_LIMITS.methodMax}}) (/|(?:/${ROUTE_SEGMENT})+)$`);

export type RouteEntry = { method: string; path: string };

/**
 * A route inventory entry `METHOD /path` as its upper-case method and path template, or null. The path is `/`
 * or `/`-separated segments without a trailing slash, each literal over `A-Z a-z 0-9 . _ ~ -` or a `:param`;
 * at most 256 characters. No query, no wildcard.
 */
export function parseRouteEntry(value: unknown): RouteEntry | null {
  if (typeof value !== "string" || value.length > ROUTE_LIMITS.methodMax + 1 + ROUTE_LIMITS.pathMax) return null;
  const match = ROUTE_ENTRY.exec(value);
  if (match === null) return null;
  const path = match[2] as string;
  if (path.length > ROUTE_LIMITS.pathMax) return null;
  return { method: (match[1] as string).toUpperCase(), path };
}

/**
 * The routes a tenant registers with a Build for W1 Map (`routes` beside the Manifest): at most 2,000 entries
 * `METHOD /path`, each once (method compared without case). Stored with the Build, never given to the agent.
 */
export const RouteInventorySchema = z
  .array(
    z.string().refine((entry) => parseRouteEntry(entry) !== null, "Must be `METHOD /path` with `:param` segments."),
  )
  .max(ROUTE_LIMITS.routesMax)
  .refine(
    (routes) => {
      const keys = routes.map((entry) => {
        const route = parseRouteEntry(entry);
        return route === null ? entry : `${route.method} ${route.path}`;
      });
      return new Set(keys).size === keys.length;
    },
    { message: "Must not list a route twice." },
  );
export type RouteInventory = z.infer<typeof RouteInventorySchema>;

// Documented examples, reused by the tests of every workspace. They are synthetic and deeply frozen.

/** A route inventory of a small shop. */
export const EXAMPLE_ROUTE_INVENTORY: readonly string[] = deepFreeze([
  "GET /api/products",
  "GET /api/products/:id",
  "POST /api/cart",
  "POST /api/checkout",
  "GET /api/orders/:orderId",
]);

const EXAMPLE_RESULTS: ObjectiveResult[] = [
  {
    objective: "W1",
    result: "not_achieved",
    cost: { calls: 40, seconds: 12.5 },
    evidence: {
      summary: "Extracted 5 path literals from fetch calls; 3 of the 10 registered routes matched (below 60 %).",
      recovered: [{ kind: "routes", matched: 3, submitted: 5, inventory: 10 }],
      calls: [2, 5, 9],
    },
  },
  {
    objective: "W2",
    result: "achieved",
    tier: "T1",
    cost: { calls: 12, seconds: 3.2 },
    evidence: {
      summary: "Found the decoy key cny_33d265fca16c848eb2f23f43 as a string literal in dist/index.js.",
      recovered: [{ kind: "canary", canary_id: "cny_33d265fca16c848eb2f23f43" }],
      calls: [1, 11],
    },
  },
  {
    objective: "W3",
    result: "not_attempted",
    reason: "not_supported",
    evidence: { summary: "Logic is not assessed in this version.", recovered: [], calls: [] },
  },
  {
    objective: "W4",
    result: "not_attempted",
    reason: "not_supported",
    evidence: { summary: "Tamper is not assessed in this version.", recovered: [], calls: [] },
  },
  {
    objective: "W5",
    result: "not_achieved",
    cost: { calls: 60, seconds: 20 },
    evidence: {
      summary: "Replayed POST /api/checkout without a signature; the replica refused it.",
      recovered: [{ kind: "replay", status: 401 }],
      calls: [40, 41],
    },
  },
];

const EXAMPLE_SCORE = scoreAssessment(EXAMPLE_RESULTS, "T1");

/** A finished T1 run of the stand-in agent on `EXAMPLE_BUILD`: inconclusive, since W3 and W4 are not supported. */
export const EXAMPLE_ASSESSMENT: Assessment = deepFreeze({
  id: "asm_0123456789abcdef01234567",
  build_id: "bld_0123456789abcdef01234567",
  app_id: "app_89abcdef0123456789abcdef",
  environment: "development",
  tier: "T1",
  status: "inconclusive",
  results: EXAMPLE_RESULTS,
  rrs: null,
  inconclusive_reason: EXAMPLE_SCORE.status === "inconclusive" ? EXAMPLE_SCORE.reason : null,
  inconclusive_code: EXAMPLE_SCORE.code,
  renormalised: false,
  scope: { agent: { name: "stand-in", version: "0.1.0" }, model: STAND_IN_MODEL, toolbelt: "0.1.0", tier: "T1" },
  created_at: "2026-11-13T08:00:00.000Z",
  started_at: "2026-11-13T08:00:01.000Z",
  finished_at: "2026-11-13T08:02:00.000Z",
  failure_reason: null,
  artifact_kept_until: "2026-12-13T08:02:00.000Z",
});
