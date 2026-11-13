import { describe, expect, it } from "vitest";
import {
  ASSESSMENT_CALL_LIMITS,
  ASSESSMENT_LIMITS,
  ASSESSMENT_STATUSES,
  type Assessment,
  AssessmentResponseSchema,
  AssessmentSchema,
  type AssessmentTier,
  BUILD_LIMITS,
  CONFLICT_REASONS,
  CreateAssessmentRequestSchema,
  CreateAssessmentResponseSchema,
  decodedBase64Bytes,
  EvidenceSchema,
  EXAMPLE_ASSESSMENT,
  EXAMPLE_ROUTE_INVENTORY,
  ID_PATTERNS,
  INCONCLUSIVE_CODES,
  ListAssessmentsResponseSchema,
  LOGIC_LIMITS,
  LogicSubmissionSchema,
  NOT_ATTEMPTED_REASONS,
  OBJECTIVE_IDS,
  OBJECTIVES,
  type ObjectiveId,
  type ObjectiveResult,
  ObjectiveResultSchema,
  parseRouteEntry,
  RESISTANCE_VALUES,
  ROUTE_LIMITS,
  RouteInventorySchema,
  ScopeStatementSchema,
  STAND_IN_MODEL,
  scoreAssessment,
  TAMPER_LIMITS,
  TamperSubmissionSchema,
  TIER_IDS,
  TIERS,
  tierForCost,
} from "../src/index.ts";

const EVIDENCE = { summary: "Searched the bundle.", recovered: [], calls: [] };
const COST = { calls: 10, seconds: 60 };

const achieved = (objective: ObjectiveId, tier: AssessmentTier): ObjectiveResult => ({
  objective,
  result: "achieved",
  tier,
  cost: COST,
  evidence: EVIDENCE,
});
const notAchieved = (objective: ObjectiveId): ObjectiveResult => ({
  objective,
  result: "not_achieved",
  cost: COST,
  evidence: EVIDENCE,
});
const notAttempted = (objective: ObjectiveId, reason = "not_supported") =>
  ({ objective, result: "not_attempted", reason, evidence: EVIDENCE }) as ObjectiveResult;

/** Five results in order W1..W5 from a short code per Objective: 1/2/3 achieved at that tier, n not achieved, x not attempted. */
function results(codes: string): ObjectiveResult[] {
  return OBJECTIVE_IDS.map((id, index) => {
    const code = codes[index];
    if (code === "1" || code === "2" || code === "3") return achieved(id, `T${code}` as AssessmentTier);
    if (code === "n") return notAchieved(id);
    return notAttempted(id);
  });
}

// --- Ids, Objectives, tiers -------------------------------------------------------------------------------

describe("Assessment ids, Objectives and tiers", () => {
  it("has an Assessment id asm_<24 hex>", () => {
    expect(ID_PATTERNS.asm.test("asm_0123456789abcdef01234567")).toBe(true);
    expect(ID_PATTERNS.asm.test("asm_0123456789ABCDEF01234567")).toBe(false);
    expect(ID_PATTERNS.asm.test("bld_0123456789abcdef01234567")).toBe(false);
  });

  it("lists the five web Objectives W1..W5 with their keys, names and weights (SDD §12.1)", () => {
    expect(OBJECTIVE_IDS).toEqual(["W1", "W2", "W3", "W4", "W5"]);
    expect(OBJECTIVES.map(({ id, key, name, weight }) => ({ id, key, name, weight }))).toEqual([
      { id: "W1", key: "map", name: "Map", weight: 0.15 },
      { id: "W2", key: "secrets", name: "Secrets", weight: 0.2 },
      { id: "W3", key: "logic", name: "Logic", weight: 0.25 },
      { id: "W4", key: "tamper", name: "Tamper", weight: 0.2 },
      { id: "W5", key: "replay", name: "Replay", weight: 0.2 },
    ]);
    for (const objective of OBJECTIVES) expect(objective.fix.length).toBeGreaterThan(0);
  });

  it("suggests the slice 12b fixes for Logic and Tamper, written without hyphenated words", () => {
    const fix = (id: string) => OBJECTIVES.find((objective) => objective.id === id)?.fix;
    expect(fix("W3")).toBe("Move the logic to the server, or harden it further and add a tamper check.");
    expect(fix("W4")).toBe(
      "Add Harden's --integrity and checks on the server; the integrity check is a signal, not tamper proofing.",
    );
  });

  it("suggests for Replay only what Shield enforces today (signed requests), written without hyphenated words", () => {
    const fix = OBJECTIVES.find((objective) => objective.id === "W5")?.fix;
    expect(fix).toBe(
      "Require signed requests on protected routes in the Policy, so a request made without the genuine Guard is refused.",
    );
    // Attestation is observe only in Shield: nothing is blocked on it yet.
    expect(fix).not.toMatch(/attestation/i);
    expect(fix).not.toMatch(/\w-\w/);
  });

  it("has weights that sum to 1 exactly", () => {
    expect(OBJECTIVES.reduce((sum, objective) => sum + objective.weight, 0)).toBe(1);
  });

  it("has the tier budgets T1 150 calls / 15 min, T2 1,500 / 2 h, T3 6,000 / 8 h", () => {
    expect(TIER_IDS).toEqual(["T1", "T2", "T3"]);
    expect(TIERS).toEqual({
      T1: { calls: 150, seconds: 900 },
      T2: { calls: 1500, seconds: 7200 },
      T3: { calls: 6000, seconds: 28_800 },
    });
  });

  it("has the resistance values of SDD §12.1 and the plan (not achieved counts at the run's own tier)", () => {
    expect(RESISTANCE_VALUES).toEqual({
      achieved: { T1: 0, T2: 0.4, T3: 0.7 },
      not_achieved: { T1: 0.4, T2: 0.7, T3: 1 },
    });
  });

  it("lists the statuses and the reasons an Objective was not attempted", () => {
    expect(ASSESSMENT_STATUSES).toEqual(["queued", "running", "scored", "inconclusive", "failed"]);
    expect(NOT_ATTEMPTED_REASONS).toEqual([
      "not_supported",
      "refused",
      "tool_failure",
      "sandbox_error",
      "budget_exhausted_before_attempt",
      "no_inventory",
      "not_designated",
      "no_runnable_file",
    ]);
    expect(STAND_IN_MODEL).toBe("stand-in");
  });

  it("deep-freezes its constants", () => {
    expect(Object.isFrozen(OBJECTIVES)).toBe(true);
    expect(Object.isFrozen(OBJECTIVES[0])).toBe(true);
    expect(Object.isFrozen(TIERS)).toBe(true);
    expect(Object.isFrozen(TIERS.T1)).toBe(true);
    expect(Object.isFrozen(RESISTANCE_VALUES.achieved)).toBe(true);
    expect(Object.isFrozen(ASSESSMENT_LIMITS)).toBe(true);
    expect(Object.isFrozen(ROUTE_LIMITS)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_ASSESSMENT)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_ASSESSMENT.results[0])).toBe(true);
    expect(Object.isFrozen(EXAMPLE_ROUTE_INVENTORY)).toBe(true);
  });
});

// --- tierForCost ------------------------------------------------------------------------------------------

describe("tierForCost", () => {
  it("maps a cost to the earliest tier whose limits it fits, both limits inclusive", () => {
    expect(tierForCost({ calls: 0, seconds: 0 })).toBe("T1");
    expect(tierForCost({ calls: 150, seconds: 900 })).toBe("T1");
    expect(tierForCost({ calls: 151, seconds: 0 })).toBe("T2");
    expect(tierForCost({ calls: 0, seconds: 900.001 })).toBe("T2");
    expect(tierForCost({ calls: 150, seconds: 901 })).toBe("T2");
    expect(tierForCost({ calls: 1500, seconds: 7200 })).toBe("T2");
    expect(tierForCost({ calls: 1501, seconds: 0 })).toBe("T3");
    expect(tierForCost({ calls: 0, seconds: 7201 })).toBe("T3");
    expect(tierForCost({ calls: 6000, seconds: 28_800 })).toBe("T3");
  });

  it("returns null for a cost beyond T3", () => {
    expect(tierForCost({ calls: 6001, seconds: 0 })).toBeNull();
    expect(tierForCost({ calls: 0, seconds: 28_800.5 })).toBeNull();
  });

  it("takes other tier limits (budgets overridden for tests)", () => {
    const tiers = { T1: { calls: 2, seconds: 1 }, T2: { calls: 4, seconds: 2 }, T3: { calls: 8, seconds: 4 } };
    expect(tierForCost({ calls: 2, seconds: 1 }, tiers)).toBe("T1");
    expect(tierForCost({ calls: 3, seconds: 1 }, tiers)).toBe("T2");
    expect(tierForCost({ calls: 8, seconds: 4 }, tiers)).toBe("T3");
    expect(tierForCost({ calls: 9, seconds: 4 }, tiers)).toBeNull();
  });

  it("throws a TypeError for a negative, fractional-call or non-finite cost", () => {
    expect(() => tierForCost({ calls: -1, seconds: 0 })).toThrow(TypeError);
    expect(() => tierForCost({ calls: 1.5, seconds: 0 })).toThrow(TypeError);
    expect(() => tierForCost({ calls: 0, seconds: -0.1 })).toThrow(TypeError);
    expect(() => tierForCost({ calls: 0, seconds: Number.NaN })).toThrow(TypeError);
    expect(() => tierForCost({ calls: 0, seconds: Number.POSITIVE_INFINITY })).toThrow(TypeError);
  });
});

// --- scoreAssessment --------------------------------------------------------------------------------------

/** Weights in hundredths and resistance in tenths, so the reference is exact. */
const W = [15, 20, 25, 20, 20];
const R_ACHIEVED: Record<string, number> = { "1": 0, "2": 4, "3": 7 };
const R_NOT: Record<AssessmentTier, number> = { T1: 4, T2: 7, T3: 10 };

/** The plan's rule, computed independently with exact rationals (BigInt), round half up. */
function reference(codes: string, tier: AssessmentTier): { rrs: number | null; renormalised: boolean } {
  let excluded = 0n;
  let attempted = 0n;
  let weighted = 0n;
  for (let index = 0; index < 5; index++) {
    const code = codes[index] as string;
    const w = BigInt(W[index] as number);
    if (code === "x") {
      excluded += w;
      continue;
    }
    attempted += w;
    weighted += w * BigInt(code === "n" ? R_NOT[tier] : (R_ACHIEVED[code] as number));
  }
  if (excluded > 20n) return { rrs: null, renormalised: false };
  // 100 × (weighted / 1000) / (attempted / 100) = 10 × weighted / attempted.
  const numerator = 10n * weighted;
  const rrs = (2n * numerator + attempted) / (2n * attempted);
  return { rrs: Number(rrs), renormalised: excluded > 0n };
}

function* allCodes(tier: AssessmentTier): Generator<string> {
  const allowed = ["n", "x", "1", "2", "3"].filter((code) => !["1", "2", "3"].includes(code) || `T${code}` <= tier);
  const walk = function* (prefix: string): Generator<string> {
    if (prefix.length === 5) {
      yield prefix;
      return;
    }
    for (const code of allowed) yield* walk(prefix + code);
  };
  yield* walk("");
}

describe("scoreAssessment", () => {
  it("matches the exact reference for every combination of outcomes at every run tier", () => {
    let combinations = 0;
    for (const tier of TIER_IDS) {
      for (const codes of allCodes(tier)) {
        combinations++;
        const expected = reference(codes, tier);
        const score = scoreAssessment(results(codes), tier);
        if (expected.rrs === null) {
          expect(score.status, `${codes} ${tier}`).toBe("inconclusive");
          expect(score.rrs).toBeNull();
          expect(score.renormalised).toBe(false);
        } else {
          expect(score.status, `${codes} ${tier}`).toBe("scored");
          expect(score.rrs, `${codes} ${tier}`).toBe(expected.rrs);
          expect(score.renormalised, `${codes} ${tier}`).toBe(expected.renormalised);
          expect(score.rrs).toBeGreaterThanOrEqual(0);
          expect(score.rrs).toBeLessThanOrEqual(100);
        }
      }
    }
    // T1: 3 outcomes each, T2: 4, T3: 5.
    expect(combinations).toBe(3 ** 5 + 4 ** 5 + 5 ** 5);
  });

  it("scores 0 when everything was achieved within T1 limits and 100 when nothing was achieved in a T3 run", () => {
    expect(scoreAssessment(results("11111"), "T3")).toMatchObject({ status: "scored", rrs: 0, renormalised: false });
    expect(scoreAssessment(results("nnnnn"), "T3")).toMatchObject({ status: "scored", rrs: 100 });
  });

  it("counts not achieved as 0.4 in a T1 run and 0.7 in a T2 run: a run cannot show resistance beyond its tier", () => {
    expect(scoreAssessment(results("nnnnn"), "T1").rrs).toBe(40);
    expect(scoreAssessment(results("nnnnn"), "T2").rrs).toBe(70);
  });

  it("uses the earliest tier at which an Objective was achieved: T2 0.4, T3 0.7", () => {
    expect(scoreAssessment(results("22222"), "T3").rrs).toBe(40);
    expect(scoreAssessment(results("33333"), "T3").rrs).toBe(70);
    expect(scoreAssessment(results("21111"), "T2").rrs).toBe(6);
  });

  it("rounds half up, computed exactly where floating point would not", () => {
    // 100 × 0.15 × 0.7 = 10.5 → 11.
    expect(scoreAssessment(results("31111"), "T3").rrs).toBe(11);
    // T2 run: 0.15 × 0.7 + 0.2 × 0.7 + 0.25 × 0.4 + 0.2 × 0.7 + 0.2 × 0.4 = 0.565 → 57; in floating point 56.4999….
    const float = 100 * (0.15 * 0.7 + 0.2 * 0.7 + 0.25 * 0.4 + 0.2 * 0.7 + 0.2 * 0.4);
    expect(Math.round(float)).toBe(56);
    expect(scoreAssessment(results("nn2n2"), "T2").rrs).toBe(57);
    // Renormalised: (0.15 × 0.7 + 0.2 × 0.7 + 0.25 × 0.7 + 0.2 × 0) / 0.8 = 52.5 % → 53.
    expect(scoreAssessment(results("nxnn1"), "T2").rrs).toBe(53);
  });

  it("is scored and renormalised at exactly 20 % excluded weight", () => {
    // W2 alone excluded: 0.20. Remaining 0.80: W1, W3, W4, W5 not achieved in a T3 run → 100.
    expect(scoreAssessment(results("nxnnn"), "T3")).toMatchObject({
      status: "scored",
      rrs: 100,
      renormalised: true,
      excluded_weight: 0.2,
    });
    expect(scoreAssessment(results("111nx"), "T3")).toMatchObject({ status: "scored", rrs: 25, renormalised: true });
    expect(scoreAssessment(results("1111x"), "T3")).toMatchObject({ status: "scored", rrs: 0, renormalised: true });
  });

  it("renormalises the attempted weights: W1 excluded, W2 not achieved, the rest achieved in T1 → 0.20 / 0.85", () => {
    expect(scoreAssessment(results("xn111"), "T3")).toMatchObject({
      status: "scored",
      rrs: 24,
      renormalised: true,
      excluded_weight: 0.15,
    });
  });

  it("is inconclusive above 20 % excluded weight, with no number and a reason naming the Objectives", () => {
    const score = scoreAssessment(results("nnxxn"), "T1");
    expect(score).toMatchObject({
      status: "inconclusive",
      rrs: null,
      renormalised: false,
      excluded_weight: 0.45,
      code: "excluded_over_limit",
    });
    expect(INCONCLUSIVE_CODES).toEqual(["excluded_over_limit"]);
    expect(scoreAssessment(results("nnnnn"), "T3")).toMatchObject({ status: "scored", code: null });
    if (score.status !== "inconclusive") throw new Error("expected inconclusive");
    expect(score.reason).toContain("45%");
    expect(score.reason).toContain("W3 Logic");
    expect(score.reason).toContain("W4 Tamper");
    expect(score.reason).toContain("not supported");
    expect(score.reason.length).toBeLessThanOrEqual(ASSESSMENT_LIMITS.reasonMax);
    expect(scoreAssessment(results("xxnnn"), "T3").status).toBe("inconclusive");
    expect(scoreAssessment(results("nnxnn"), "T3").status).toBe("inconclusive");
    expect(scoreAssessment(results("xxxxx"), "T3")).toMatchObject({ status: "inconclusive", excluded_weight: 1 });
  });

  it("names every not-attempted reason in the inconclusive reason", () => {
    const list: ObjectiveResult[] = [
      notAttempted("W1", "no_inventory"),
      notAttempted("W2", "refused"),
      notAchieved("W3"),
      notAttempted("W4", "budget_exhausted_before_attempt"),
      notAchieved("W5"),
    ];
    const score = scoreAssessment(list, "T1");
    if (score.status !== "inconclusive") throw new Error("expected inconclusive");
    expect(score.reason).toContain("W1 Map: no route inventory");
    expect(score.reason).toContain("W2 Secrets: refused");
    expect(score.reason).toContain("W4 Tamper: budget exhausted before the attempt");
  });

  it("does not depend on the order of the results", () => {
    const list = results("n2x1n");
    expect(scoreAssessment([...list].reverse(), "T3")).toEqual(scoreAssessment(list, "T3"));
  });

  it("throws a TypeError unless every Objective appears exactly once", () => {
    const list = results("nnnnn");
    expect(() => scoreAssessment(list.slice(1), "T3")).toThrow(TypeError);
    expect(() => scoreAssessment([...list, list[0] as ObjectiveResult], "T3")).toThrow(TypeError);
    expect(() => scoreAssessment([...list.slice(1), list[1] as ObjectiveResult], "T3")).toThrow(TypeError);
  });

  it("throws a TypeError for an Objective achieved at a tier above the run's", () => {
    expect(() => scoreAssessment(results("21111"), "T1")).toThrow(TypeError);
    expect(() => scoreAssessment(results("13111"), "T2")).toThrow(TypeError);
  });
});

// --- Evidence and results ---------------------------------------------------------------------------------

describe("Evidence", () => {
  it("records what was recovered as ids, fingerprints and counts, never a value", () => {
    const evidence = EvidenceSchema.parse({
      summary: "Found the decoy key in dist/index.js.",
      recovered: [
        { kind: "canary", canary_id: "cny_33d265fca16c848eb2f23f43" },
        { kind: "leak", rule: "stripe-secret", fingerprint: "0123456789abcdef0123456789abcdef" },
        { kind: "routes", matched: 7, submitted: 9, inventory: 10 },
        { kind: "replay", status: 403 },
      ],
      calls: [0, 3, 17],
    });
    expect(evidence.recovered).toHaveLength(4);
    const refused = (recovered: unknown) => EvidenceSchema.safeParse({ ...EVIDENCE, recovered: [recovered] }).success;
    expect(refused({ kind: "canary", canary_id: "cny_x", value: "ak_live_x" })).toBe(false);
    expect(
      EvidenceSchema.parse({
        ...EVIDENCE,
        recovered: [{ kind: "canary", canary_id: "cny_33d265fca16c848eb2f23f43", value: "ak_live_x" }],
      }).recovered[0],
    ).not.toHaveProperty("value");
    expect(refused({ kind: "leak", rule: "stripe-secret", fingerprint: "sk_live_abc" })).toBe(false);
    expect(refused({ kind: "leak", rule: "not-a-rule", fingerprint: "0123456789abcdef0123456789abcdef" })).toBe(false);
    expect(refused({ kind: "routes", matched: 11, submitted: 9, inventory: 10 })).toBe(false);
    expect(refused({ kind: "routes", matched: -1, submitted: 9, inventory: 10 })).toBe(false);
    expect(refused({ kind: "replay", status: 99 })).toBe(false);
    expect(refused({ kind: "replay", status: 600 })).toBe(false);
    expect(refused({ kind: "secret", value: "x" })).toBe(false);
  });

  it("bounds the summary, the recovered items and the call references", () => {
    const parse = (evidence: object) => EvidenceSchema.safeParse({ ...EVIDENCE, ...evidence }).success;
    expect(parse({ summary: "x".repeat(ASSESSMENT_LIMITS.summaryMax) })).toBe(true);
    expect(parse({ summary: "x".repeat(ASSESSMENT_LIMITS.summaryMax + 1) })).toBe(false);
    expect(parse({ summary: "" })).toBe(false);
    expect(parse({ summary: "a\u0000b" })).toBe(false);
    const replay = { kind: "replay", status: 200 };
    expect(parse({ recovered: Array(ASSESSMENT_LIMITS.recoveredMax).fill(replay) })).toBe(true);
    expect(parse({ recovered: Array(ASSESSMENT_LIMITS.recoveredMax + 1).fill(replay) })).toBe(false);
    expect(parse({ calls: Array.from({ length: ASSESSMENT_LIMITS.callRefsMax }, (_, i) => i) })).toBe(true);
    expect(parse({ calls: Array.from({ length: ASSESSMENT_LIMITS.callRefsMax + 1 }, (_, i) => i) })).toBe(false);
    expect(parse({ calls: [-1] })).toBe(false);
    expect(parse({ calls: [1.5] })).toBe(false);
  });

  it("refuses a summary that carries a decoy key value", () => {
    const parse = (summary: string) => EvidenceSchema.safeParse({ ...EVIDENCE, summary }).success;
    expect(parse("Recovered ak_live_083n1BMwZhfu13secInfCOzZrq2cfyQE from dist/index.js")).toBe(false);
    expect(parse("Recovered the decoy key cny_33d265fca16c848eb2f23f43")).toBe(true);
  });
});

describe("ObjectiveResultSchema", () => {
  it("parses achieved (tier and cost), not achieved (cost) and not attempted (reason)", () => {
    expect(ObjectiveResultSchema.parse(achieved("W2", "T1"))).toEqual(achieved("W2", "T1"));
    expect(ObjectiveResultSchema.parse(notAchieved("W1"))).toEqual(notAchieved("W1"));
    for (const reason of NOT_ATTEMPTED_REASONS) {
      expect(ObjectiveResultSchema.parse(notAttempted("W3", reason))).toMatchObject({ reason });
    }
  });

  it("refuses an unknown Objective, tier, reason, or a malformed cost", () => {
    const fails = (value: object) => ObjectiveResultSchema.safeParse(value).success === false;
    expect(fails({ ...achieved("W1", "T1"), objective: "W6" })).toBe(true);
    expect(fails({ ...achieved("W1", "T1"), tier: "T4" })).toBe(true);
    expect(fails({ ...achieved("W1", "T1"), cost: undefined })).toBe(true);
    expect(fails({ ...achieved("W1", "T1"), cost: { calls: -1, seconds: 0 } })).toBe(true);
    expect(fails({ ...achieved("W1", "T1"), cost: { calls: 1.5, seconds: 0 } })).toBe(true);
    expect(fails({ ...achieved("W1", "T1"), cost: { calls: 1, seconds: -1 } })).toBe(true);
    expect(fails({ ...notAchieved("W1"), cost: undefined })).toBe(true);
    expect(fails(notAttempted("W1", "lazy"))).toBe(true);
    expect(fails({ objective: "W1", result: "maybe", evidence: EVIDENCE })).toBe(true);
  });

  it("refuses an achieved tier that its cost does not fit", () => {
    const fails = (value: object) => ObjectiveResultSchema.safeParse(value).success === false;
    expect(fails({ ...achieved("W1", "T1"), cost: { calls: 151, seconds: 0 } })).toBe(true);
    expect(fails({ ...achieved("W1", "T2"), cost: { calls: 151, seconds: 0 } })).toBe(false);
    // An earlier tier than the cost fits is refused; a later one is allowed (budgets may be overridden).
    expect(fails({ ...achieved("W1", "T3"), cost: { calls: 1, seconds: 0 } })).toBe(false);
  });
});

describe("ScopeStatementSchema", () => {
  it("names the agent and its version, the model or stand-in, the toolbelt version and the tier", () => {
    const scope = {
      agent: { name: "stand-in", version: "0.1.0" },
      model: STAND_IN_MODEL,
      toolbelt: "0.1.0",
      tier: "T1",
    };
    expect(ScopeStatementSchema.parse(scope)).toEqual(scope);
    const fails = (value: object) => ScopeStatementSchema.safeParse({ ...scope, ...value }).success === false;
    expect(fails({ model: "" })).toBe(true);
    expect(fails({ toolbelt: "" })).toBe(true);
    expect(fails({ tier: "T0" })).toBe(true);
    expect(fails({ agent: { name: "", version: "1" } })).toBe(true);
    expect(fails({ agent: { name: "a", version: "x".repeat(ASSESSMENT_LIMITS.versionMax + 1) } })).toBe(true);
  });
});

// --- Assessment -------------------------------------------------------------------------------------------

describe("AssessmentSchema", () => {
  const base: Assessment = EXAMPLE_ASSESSMENT;

  it("parses the example: a T1 stand-in run, inconclusive because W3 and W4 were not attempted", () => {
    const parsed = AssessmentSchema.parse(base);
    expect(parsed).toEqual(base);
    expect(parsed.status).toBe("inconclusive");
    expect(parsed.rrs).toBeNull();
    expect(parsed.scope.model).toBe(STAND_IN_MODEL);
    expect(AssessmentResponseSchema.parse({ assessment: base }).assessment).toEqual(base);
    expect(CreateAssessmentResponseSchema.parse({ assessment: base }).assessment).toEqual(base);
  });

  const scored: Assessment = {
    ...EXAMPLE_ASSESSMENT,
    status: "scored",
    results: results("2nn1x"),
    tier: "T3",
    scope: { ...EXAMPLE_ASSESSMENT.scope, tier: "T3" },
    rrs: scoreAssessment(results("2nn1x"), "T3").rrs,
    inconclusive_reason: null,
    inconclusive_code: null,
    renormalised: true,
  };

  it("parses a scored Assessment whose number, status and renormalisation equal scoreAssessment's", () => {
    expect(scored.rrs).toBe(Math.round((100 * (0.15 * 0.4 + 0.2 + 0.25)) / 0.8));
    expect(AssessmentSchema.parse(scored)).toEqual(scored);
    const fails = (value: object) => AssessmentSchema.safeParse({ ...scored, ...value }).success === false;
    expect(fails({ rrs: (scored.rrs as number) + 1 })).toBe(true);
    expect(fails({ renormalised: false })).toBe(true);
    expect(fails({ rrs: null })).toBe(true);
    expect(fails({ inconclusive_reason: "x" })).toBe(true);
    expect(fails({ inconclusive_code: "excluded_over_limit" })).toBe(true);
    expect(
      fails({
        status: "inconclusive",
        rrs: null,
        renormalised: false,
        inconclusive_reason: "x",
        inconclusive_code: "excluded_over_limit",
      }),
    ).toBe(true);
    expect(fails({ failure_reason: "x" })).toBe(true);
    expect(fails({ finished_at: null })).toBe(true);
    expect(fails({ rrs: 101 })).toBe(true);
    expect(fails({ rrs: 1.5 })).toBe(true);
  });

  it("refuses an inconclusive Assessment that carries a number, no reason, or results that would score", () => {
    const fails = (value: object) => AssessmentSchema.safeParse({ ...base, ...value }).success === false;
    expect(fails({ rrs: 40 })).toBe(true);
    expect(fails({ inconclusive_reason: null })).toBe(true);
    expect(fails({ inconclusive_reason: "" })).toBe(true);
    expect(fails({ inconclusive_code: null })).toBe(true);
    expect(fails({ inconclusive_code: "other" })).toBe(true);
    expect(fails({ inconclusive_code: undefined })).toBe(true);
    expect(AssessmentSchema.parse(base).inconclusive_code).toBe("excluded_over_limit");
    expect(fails({ renormalised: true })).toBe(true);
    expect(fails({ results: results("nnnnn") })).toBe(true);
  });

  it("requires every Objective exactly once in a finished result, and none achieved above the run tier", () => {
    const fails = (value: object) => AssessmentSchema.safeParse({ ...base, ...value }).success === false;
    expect(fails({ results: base.results.slice(1) })).toBe(true);
    expect(fails({ results: [...base.results, base.results[0]] })).toBe(true);
    expect(fails({ results: results("2nxxn") })).toBe(true);
  });

  it("requires the scope statement's tier to equal the run tier", () => {
    expect(AssessmentSchema.safeParse({ ...base, scope: { ...base.scope, tier: "T2" } }).success).toBe(false);
    expect(AssessmentSchema.safeParse({ ...base, scope: undefined }).success).toBe(false);
  });

  it("keeps queued and running Assessments without results, number or reason, and times in order", () => {
    const queued = {
      ...base,
      status: "queued",
      results: [],
      rrs: null,
      inconclusive_reason: null,
      inconclusive_code: null,
      renormalised: false,
      started_at: null,
      finished_at: null,
    };
    expect(AssessmentSchema.safeParse(queued).success).toBe(true);
    expect(AssessmentSchema.safeParse({ ...queued, started_at: base.started_at }).success).toBe(false);
    expect(AssessmentSchema.safeParse({ ...queued, results: base.results }).success).toBe(false);
    const running = { ...queued, status: "running", started_at: base.started_at };
    expect(AssessmentSchema.safeParse(running).success).toBe(true);
    expect(AssessmentSchema.safeParse({ ...running, started_at: null }).success).toBe(false);
    expect(AssessmentSchema.safeParse({ ...running, finished_at: base.finished_at }).success).toBe(false);
    expect(AssessmentSchema.safeParse({ ...running, rrs: 10 }).success).toBe(false);
    expect(AssessmentSchema.safeParse({ ...running, inconclusive_code: "excluded_over_limit" }).success).toBe(false);
    expect(AssessmentSchema.safeParse({ ...running, started_at: "2026-11-13T07:00:00.000Z" }).success).toBe(false);
  });

  it("keeps a failed Assessment with its failure reason, partial results and never a number", () => {
    const failed = {
      ...base,
      status: "failed",
      results: [],
      rrs: null,
      inconclusive_reason: null,
      inconclusive_code: null,
      renormalised: false,
      failure_reason: "The API restarted while the Assessment ran.",
    };
    const ok = (value: object) => AssessmentSchema.safeParse({ ...failed, ...value }).success;
    expect(ok({})).toBe(true);
    expect(ok({ failure_reason: null })).toBe(false);
    expect(ok({ finished_at: null })).toBe(false);
    expect(ok({ failure_reason: "x".repeat(ASSESSMENT_LIMITS.failureReasonMax + 1) })).toBe(false);
    // A failed Assessment may have been queued and never started.
    expect(ok({ started_at: null })).toBe(true);
    // Partial results: any subset, each Objective at most once, none achieved above the run tier.
    expect(ok({ results: base.results })).toBe(true);
    expect(ok({ results: base.results.slice(0, 2) })).toBe(true);
    expect(ok({ results: [base.results[4]] })).toBe(true);
    expect(ok({ results: [base.results[1], base.results[1]] })).toBe(false);
    expect(ok({ results: [achieved("W1", "T2")] })).toBe(false);
    expect(ok({ results: base.results.slice(0, 2), rrs: 10 })).toBe(false);
    expect(ok({ results: base.results.slice(0, 2), inconclusive_reason: "x" })).toBe(false);
    expect(ok({ inconclusive_code: "excluded_over_limit" })).toBe(false);
    expect(ok({ renormalised: true })).toBe(false);
  });

  it("says until when the uploaded artifact is kept, or null once it was deleted", () => {
    expect(EXAMPLE_ASSESSMENT.artifact_kept_until).toBe("2026-12-13T08:02:00.000Z");
    const ok = (value: unknown) => AssessmentSchema.safeParse({ ...base, artifact_kept_until: value }).success;
    expect(ok(null)).toBe(true);
    expect(ok("2027-01-01T00:00:00.000Z")).toBe(true);
    expect(ok(undefined)).toBe(false);
    expect(ok("next month")).toBe(false);
    expect(ok("2026-12-13")).toBe(false);
  });

  it("refuses malformed ids, an unknown status and an Environment outside the list; Environment is optional", () => {
    const fails = (value: object) => AssessmentSchema.safeParse({ ...base, ...value }).success === false;
    expect(fails({ id: "bld_0123456789abcdef01234567" })).toBe(true);
    expect(fails({ build_id: "asm_0123456789abcdef01234567" })).toBe(true);
    expect(fails({ app_id: "x" })).toBe(true);
    expect(fails({ status: "done" })).toBe(true);
    expect(fails({ environment: "qa" })).toBe(true);
    const { environment: _environment, ...withoutEnvironment } = base;
    expect(AssessmentSchema.parse(withoutEnvironment)).not.toHaveProperty("environment");
  });

  it("lists at most ASSESSMENT_LIMITS.listed Assessments", () => {
    const many = (count: number) => ({ assessments: Array(count).fill(base) });
    expect(ListAssessmentsResponseSchema.safeParse(many(ASSESSMENT_LIMITS.listed)).success).toBe(true);
    expect(ListAssessmentsResponseSchema.safeParse(many(ASSESSMENT_LIMITS.listed + 1)).success).toBe(false);
  });
});

// --- Create request ---------------------------------------------------------------------------------------

describe("CreateAssessmentRequestSchema", () => {
  const file = { path: "dist/index.js", base64: "aGVsbG8=" };

  it("takes a tier and the artifact files as path and base64", () => {
    expect(CreateAssessmentRequestSchema.parse({ tier: "T1", files: [file] })).toEqual({ tier: "T1", files: [file] });
    const fails = (value: object) =>
      CreateAssessmentRequestSchema.safeParse({ tier: "T1", files: [file], ...value }).success === false;
    expect(fails({ tier: "T4" })).toBe(true);
    expect(fails({ files: [] })).toBe(true);
    expect(fails({ files: null })).toBe(true);
    expect(fails({ files: [file, file] })).toBe(true);
    expect(fails({ files: [{ ...file, path: "" }] })).toBe(true);
    expect(fails({ files: [{ ...file, path: "x".repeat(257) }] })).toBe(true);
    expect(fails({ files: [{ ...file, base64: "aGVsbG8" }] })).toBe(true);
    expect(fails({ files: [{ ...file, base64: "aGV$bG8=" }] })).toBe(true);
    expect(fails({ files: [{ ...file, base64: "a=GVsbG8" }] })).toBe(true);
    expect(fails({ files: [{ ...file, base64: "aGVsbG8===" }] })).toBe(true);
    expect(fails({ files: [{ ...file, base64: "aGVsbG8-" }] })).toBe(true);
    expect(fails({ files: [{ ...file, base64: "" }] })).toBe(false);
  });

  it("may leave the files out: the API then reassesses the Build's most recent kept artifact, or answers 409", () => {
    const parsed = CreateAssessmentRequestSchema.parse({ tier: "T2" });
    expect(parsed).toEqual({ tier: "T2" });
    expect(parsed).not.toHaveProperty("files");
    expect(CreateAssessmentRequestSchema.safeParse({}).success).toBe(false);
    expect(CONFLICT_REASONS).toContain("artifact-required");
  });

  it("caps the files at the Manifest's artifact count", () => {
    expect(ASSESSMENT_LIMITS.filesMax).toBe(BUILD_LIMITS.artifactsMax);
    const files = (count: number) => Array.from({ length: count }, (_, i) => ({ path: `f${i}.js`, base64: "" }));
    expect(
      CreateAssessmentRequestSchema.safeParse({ tier: "T1", files: files(ASSESSMENT_LIMITS.filesMax) }).success,
    ).toBe(true);
    expect(
      CreateAssessmentRequestSchema.safeParse({ tier: "T1", files: files(ASSESSMENT_LIMITS.filesMax + 1) }).success,
    ).toBe(false);
  });

  it("caps the decoded total at 25 MB across all files", () => {
    expect(ASSESSMENT_LIMITS.artifactBytesMax).toBe(26_214_400);
    const groups = Math.floor(ASSESSMENT_LIMITS.artifactBytesMax / 3); // 8,738,133 × 3 = 26,214,399 bytes
    const big = "A".repeat(groups * 4);
    const parse = (files: object[]) => CreateAssessmentRequestSchema.safeParse({ tier: "T1", files }).success;
    expect(parse([{ path: "a.js", base64: `${big}AA==` }])).toBe(true);
    expect(parse([{ path: "a.js", base64: `${big}AAA=` }])).toBe(false);
    expect(
      parse([
        { path: "a.js", base64: big },
        { path: "b.js", base64: "AA==" },
      ]),
    ).toBe(true);
    expect(
      parse([
        { path: "a.js", base64: big },
        { path: "b.js", base64: "AAA=" },
      ]),
    ).toBe(false);
  });
});

describe("decodedBase64Bytes", () => {
  it("returns the decoded length of standard padded base64, or null", () => {
    expect(decodedBase64Bytes("")).toBe(0);
    expect(decodedBase64Bytes("AA==")).toBe(1);
    expect(decodedBase64Bytes("AAA=")).toBe(2);
    expect(decodedBase64Bytes("AAAA")).toBe(3);
    expect(decodedBase64Bytes(Buffer.from("hello world!!").toString("base64"))).toBe(13);
    expect(decodedBase64Bytes("+/+/")).toBe(3);
    expect(decodedBase64Bytes("AAA")).toBeNull();
    expect(decodedBase64Bytes("A===")).toBeNull();
    expect(decodedBase64Bytes("AA=A")).toBeNull();
    expect(decodedBase64Bytes("AA-_")).toBeNull();
    expect(decodedBase64Bytes("AA AA")).toBeNull();
    expect(decodedBase64Bytes(42 as unknown as string)).toBeNull();
  });
});

// --- Route inventory --------------------------------------------------------------------------------------

describe("Route inventory", () => {
  it("is a list of 'METHOD /path' with :param segments", () => {
    expect(RouteInventorySchema.parse([...EXAMPLE_ROUTE_INVENTORY])).toEqual(EXAMPLE_ROUTE_INVENTORY);
    const ok = (entry: string) => RouteInventorySchema.safeParse([entry]).success;
    expect(ok("GET /")).toBe(true);
    expect(ok("GET /api/users/:id")).toBe(true);
    expect(ok("get /api/users/:userId/orders/:order_id")).toBe(true);
    expect(ok("DELETE /api/v1.2/items~x")).toBe(true);
    expect(ok("GET /api/users/")).toBe(false);
    expect(ok("GET api/users")).toBe(false);
    expect(ok("GET  /api")).toBe(false);
    expect(ok("GET /api//users")).toBe(false);
    expect(ok("GET /api?x=1")).toBe(false);
    expect(ok("GET /api/*")).toBe(false);
    expect(ok("GET /api/:")).toBe(false);
    expect(ok("GET /api/:1d")).toBe(false);
    expect(ok("GET /api/a:id")).toBe(false);
    expect(ok("/api")).toBe(false);
    expect(ok("G3T /api")).toBe(false);
    expect(ok(`${"X".repeat(17)} /api`)).toBe(false);
    expect(ok(`GET /${"a".repeat(ROUTE_LIMITS.pathMax - 1)}`)).toBe(true);
    expect(ok(`GET /${"a".repeat(ROUTE_LIMITS.pathMax)}`)).toBe(false);
  });

  it("lists each route once, the method compared without case, and at most 2,000 routes", () => {
    expect(RouteInventorySchema.safeParse(["GET /a", "get /a"]).success).toBe(false);
    expect(RouteInventorySchema.safeParse(["GET /a", "POST /a"]).success).toBe(true);
    expect(ROUTE_LIMITS.routesMax).toBe(2000);
    const many = (count: number) => Array.from({ length: count }, (_, i) => `GET /r${i}`);
    expect(RouteInventorySchema.safeParse(many(2000)).success).toBe(true);
    expect(RouteInventorySchema.safeParse(many(2001)).success).toBe(false);
    expect(RouteInventorySchema.safeParse([]).success).toBe(true);
  });

  it("parses an entry into its upper-case method and path template, or null", () => {
    expect(parseRouteEntry("get /api/users/:id")).toEqual({ method: "GET", path: "/api/users/:id" });
    expect(parseRouteEntry("GET /")).toEqual({ method: "GET", path: "/" });
    expect(parseRouteEntry("GET /api/")).toBeNull();
    expect(parseRouteEntry(7)).toBeNull();
  });
});

// --- Stored calls (fork 5: Jev "store_referenced_calls", 0.70) ---------------------------------------------

describe("AssessmentResponseSchema calls", () => {
  const assessment = EXAMPLE_ASSESSMENT;
  const referenced = [...new Set(assessment.results.flatMap((result) => result.evidence.calls))].sort((a, b) => a - b);
  const calls = referenced.map((index) => ({
    index,
    tool: "search" as const,
    cost: { calls: index + 1, seconds: index / 10 },
    summary: `search: pattern of 8 characters in "/": ${index} hits`,
  }));
  const totals = { count: 120, calls: 120, seconds: 30 };

  it("keeps the response without calls valid (the field is optional)", () => {
    const parsed = AssessmentResponseSchema.parse({ assessment });
    expect(parsed.calls).toBeUndefined();
    expect(parsed.call_totals).toBeUndefined();
  });

  it("parses the referenced calls and the totals", () => {
    const parsed = AssessmentResponseSchema.parse({ assessment, calls, call_totals: totals });
    expect(parsed.calls).toEqual(calls);
    expect(parsed.call_totals).toEqual(totals);
    expect(ASSESSMENT_CALL_LIMITS.storedMax).toBe(200);
  });

  it("refuses an evidence index without a stored call, unordered or repeated calls, and more than 200", () => {
    const fails = (value: object) =>
      AssessmentResponseSchema.safeParse({ assessment, call_totals: totals, ...value }).success === false;
    expect(fails({ calls: calls.slice(1) })).toBe(true);
    expect(fails({ calls: [...calls].reverse() })).toBe(true);
    expect(fails({ calls: [...calls, calls[0]] })).toBe(true);
    expect(fails({ calls: [{ ...calls[0], tool: "fetch" }, ...calls.slice(1)] })).toBe(true);
    expect(fails({ calls: [{ ...calls[0], summary: "x".repeat(201) }, ...calls.slice(1)] })).toBe(true);
    const many = Array.from({ length: 201 }, (_, index) => ({ ...calls[0], index }));
    expect(fails({ calls: many })).toBe(true);
    expect(fails({ calls, call_totals: undefined })).toBe(true);
  });
});

// --- W3 and W4 (slice 12b) --------------------------------------------------------------------------------

describe("W3 and W4 in the score (slice 12b)", () => {
  it("scores a fully decided W1–W5 run, W3 and W4 included, without renormalising", () => {
    const list: ObjectiveResult[] = [
      notAchieved("W1"),
      achieved("W2", "T1"),
      notAchieved("W3"),
      achieved("W4", "T1"),
      notAchieved("W5"),
    ];
    // T1 run: 0.15 × 0.4 + 0.2 × 0 + 0.25 × 0.4 + 0.2 × 0 + 0.2 × 0.4 = 0.24.
    expect(scoreAssessment(list, "T1")).toEqual({
      status: "scored",
      rrs: 24,
      renormalised: false,
      excluded_weight: 0,
      code: null,
    });
    const assessment = AssessmentSchema.parse({
      ...EXAMPLE_ASSESSMENT,
      status: "scored",
      results: list,
      rrs: 24,
      inconclusive_reason: null,
      inconclusive_code: null,
    });
    expect(assessment.rrs).toBe(24);
  });

  it("still scores a Build with logic and without routes: W1 no_inventory alone is 15 %, renormalised", () => {
    const list: ObjectiveResult[] = [
      notAttempted("W1", "no_inventory"),
      achieved("W2", "T1"),
      notAchieved("W3"),
      achieved("W4", "T1"),
      notAchieved("W5"),
    ];
    // (0.25 × 0.4 + 0.2 × 0.4) / 0.85 = 21.18 % → 21.
    expect(scoreAssessment(list, "T1")).toMatchObject({
      status: "scored",
      rrs: 21,
      renormalised: true,
      excluded_weight: 0.15,
    });
  });

  it("names no_runnable_file (W4 without a JavaScript file) in the inconclusive reason, excluded from the score", () => {
    const list: ObjectiveResult[] = [
      notAchieved("W1"),
      notAttempted("W2", "sandbox_error"),
      notAchieved("W3"),
      notAttempted("W4", "no_runnable_file"),
      notAchieved("W5"),
    ];
    const score = scoreAssessment(list, "T1");
    if (score.status !== "inconclusive") throw new Error("expected inconclusive");
    expect(score.reason).toContain("W4 Tamper: no JavaScript file to run (assess the bundled output)");
    expect(ObjectiveResultSchema.safeParse(notAttempted("W4", "no_runnable_file")).success).toBe(true);
    const alone = scoreAssessment(
      [
        notAchieved("W1"),
        notAchieved("W2"),
        notAchieved("W3"),
        notAttempted("W4", "no_runnable_file"),
        notAchieved("W5"),
      ],
      "T1",
    );
    expect(alone).toMatchObject({ status: "scored", renormalised: true, excluded_weight: 0.2 });
  });

  it("names not_designated with the Harden hint in the inconclusive reason", () => {
    const list: ObjectiveResult[] = [
      notAttempted("W1", "no_inventory"),
      notAchieved("W2"),
      notAttempted("W3", "not_designated"),
      notAchieved("W4"),
      notAchieved("W5"),
    ];
    const score = scoreAssessment(list, "T1");
    if (score.status !== "inconclusive") throw new Error("expected inconclusive");
    expect(score.reason).toContain(
      "W1 Map: no route inventory; W3 Logic: no protected function was designated (add --logic to Harden))",
    );
    expect(score.reason).not.toContain("Harden.");
    expect(ObjectiveResultSchema.safeParse(notAttempted("W3", "not_designated")).success).toBe(true);
  });
});

describe("LogicSubmissionSchema (W3)", () => {
  const accepts = (value: unknown) => LogicSubmissionSchema.safeParse(value).success;

  it("takes a designated function's id and a JS function body of at most 64 KB as UTF-8", () => {
    const body = "return args.length === 1\n\t? a0 * 2\n\t: null;";
    expect(LogicSubmissionSchema.parse({ function_id: "double", body })).toEqual({ function_id: "double", body });
    expect(accepts({ function_id: "double", body: "x".repeat(LOGIC_LIMITS.bodyBytesMax) })).toBe(true);
    expect(accepts({ function_id: "double", body: "x".repeat(LOGIC_LIMITS.bodyBytesMax + 1) })).toBe(false);
    // 3 bytes each in UTF-8.
    expect(accepts({ function_id: "double", body: "\u20ac".repeat(LOGIC_LIMITS.bodyBytesMax / 4) })).toBe(true);
    expect(accepts({ function_id: "double", body: "\u20ac".repeat(LOGIC_LIMITS.bodyBytesMax / 2) })).toBe(false);
  });

  it("refuses an empty body, a malformed id and missing fields", () => {
    expect(accepts({ function_id: "double", body: "" })).toBe(false);
    expect(accepts({ function_id: "Double", body: "return 1;" })).toBe(false);
    expect(accepts({ function_id: "double" })).toBe(false);
    expect(accepts({ body: "return 1;" })).toBe(false);
  });
});

describe("TamperSubmissionSchema (W4)", () => {
  const accepts = (value: unknown) => TamperSubmissionSchema.safeParse(value).success;

  it("has the W4 limits of the plan", () => {
    expect(TAMPER_LIMITS).toEqual({
      codeBytesMax: 52_428_800,
      sizeFactorMax: 2,
      similarityMin: 0.9,
      timeoutMs: 5000,
      submissionsMax: 3,
      nonceHexChars: 16,
    });
    expect(Object.isFrozen(TAMPER_LIMITS)).toBe(true);
  });

  it("takes the path of a .js, .mjs or .cjs artifact file and its modified code", () => {
    const code = 'globalThis.__airverse_tamper="0123456789abcdef";\nmain();';
    expect(TamperSubmissionSchema.parse({ path: "dist/index.js", code })).toEqual({ path: "dist/index.js", code });
    for (const path of ["dist/a.mjs", "b.cjs", "x/y/z.js"]) expect(accepts({ path, code }), path).toBe(true);
    for (const path of ["dist/a.ts", "dist/a.json", "dist/a.js.map", "", "dist/js", "a\u0000.js"]) {
      expect(accepts({ path, code }), path).toBe(false);
    }
    expect(accepts({ path: `${"d".repeat(253)}.js`, code })).toBe(true);
    expect(accepts({ path: `${"d".repeat(254)}.js`, code })).toBe(false);
  });

  it("caps the code at 50 MB as UTF-8 and refuses empty code (the 2x rule is prove's)", () => {
    expect(accepts({ path: "a.js", code: "" })).toBe(false);
    expect(accepts({ path: "a.js", code: "x".repeat(TAMPER_LIMITS.codeBytesMax) })).toBe(true);
    expect(accepts({ path: "a.js", code: "x".repeat(TAMPER_LIMITS.codeBytesMax + 1) })).toBe(false);
  });
});
