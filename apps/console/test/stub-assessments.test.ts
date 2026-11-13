// @vitest-environment node
import {
  type Assessment,
  AssessmentResponseSchema,
  CreateAssessmentResponseSchema,
  EXAMPLE_BUILD,
  ListAssessmentsResponseSchema,
  STAND_IN_MODEL,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { createAssessmentStore } from "../scripts/stub-assessments.mjs";

// The stand-in API answers Reverse Assessments (slice 12a) in the shape of the protocol: every 2xx body is parsed
// with its response schema and must come back unchanged, so the Console is looked at against the real contract.

const NOW = Date.parse("2026-11-13T10:00:00.000Z");
const ORG = "org_0123456789abcdef01234567";
const OTHER_ORG = "org_ffffffffffffffffffffffff";
const app = EXAMPLE_BUILD.app_id;
const NEWEST = "bld_111111111111111111111111";
const NEXT = "bld_222222222222222222222222";
const OLDEST = "bld_333333333333333333333333";
const builds = [
  {
    ...EXAMPLE_BUILD,
    build_id: "bld_111111111111111111111111",
    canaries: [{ id: "cny_33d265fca16c848eb2f23f43", kind: "key" as const }],
    // Slice 12b: two protected functions designated with `harden --logic`.
    logic_digest: "ab".repeat(32),
    logic_count: 2,
  },
  { ...EXAMPLE_BUILD, build_id: "bld_222222222222222222222222" },
  { ...EXAMPLE_BUILD, build_id: "bld_333333333333333333333333" },
];
/** A Build of the App without any Assessment, so no artifact is kept for it. */
const UNASSESSED = "bld_444444444444444444444444";
const allBuilds = [...builds, { ...EXAMPLE_BUILD, build_id: UNASSESSED }];

interface Answer {
  status: number;
  body: unknown;
}

function setup(clock: { ms: number } = { ms: NOW }) {
  const store = createAssessmentStore({ now: () => clock.ms });
  store.seed(ORG, builds);
  const find = (appId: string, buildId: string) =>
    appId === app ? (allBuilds.find((build) => build.build_id === buildId) ?? null) : null;
  const call = (method: string, path: string, body?: unknown, org: string = ORG): Answer => {
    const answer = store.handle(org, method, path, body, find);
    if (answer === null) throw new Error(`no answer for ${method} ${path}`);
    return answer as Answer;
  };
  return { call, clock };
}

function parsed<T>(
  schema: { safeParse(value: unknown): { success: boolean; data?: T; error?: unknown } },
  body: unknown,
): T {
  const result = schema.safeParse(body);
  expect(result.success ? [] : (result.error as { issues: unknown[] }).issues).toEqual([]);
  expect(result.data).toEqual(body);
  return result.data as T;
}

const listOf = (call: ReturnType<typeof setup>["call"], buildId: string): Assessment[] => {
  const answer = call("GET", `/v1/apps/${app}/builds/${buildId}/assessments`);
  expect(answer.status).toBe(200);
  return parsed(ListAssessmentsResponseSchema, answer.body).assessments;
};

describe("stub Assessments — seed", () => {
  it("gives the newest Build a scored stand-in run with all five Objectives decided (slice 12b)", () => {
    const { call } = setup();
    const [latest] = listOf(call, NEWEST) as [Assessment];
    expect([latest.status, latest.tier, latest.scope.model, latest.renormalised]).toEqual([
      "scored",
      "T1",
      STAND_IN_MODEL,
      false,
    ]);
    expect(latest.rrs).toEqual(expect.any(Number));
    expect(latest.results.map((result) => [result.objective, result.result])).toEqual([
      ["W1", "not_achieved"],
      ["W2", "achieved"],
      ["W3", "not_achieved"],
      ["W4", "achieved"],
      ["W5", "not_achieved"],
    ]);
    // W3 names the designated function and a pass count; W4 names the edited file, never code.
    expect(latest.results[2]?.evidence.summary).toMatch(/price-total/);
    const tamper = latest.results[3]?.evidence;
    expect(tamper?.summary).toContain("dist/index.js");
    expect(tamper?.summary).not.toMatch(/__airverse_tamper|[{}=;]\s*\S*\(|globalThis/);
    expect(tamper?.recovered).toEqual([]);
  });

  it("gives the newest Build an older inconclusive stand-in run, then a failed one", () => {
    const { call } = setup();
    const list = listOf(call, NEWEST);
    expect(list.map((one) => [one.status, one.tier])).toEqual([
      ["scored", "T1"],
      ["inconclusive", "T1"],
      ["failed", "T1"],
    ]);
    const [, latest, failed] = list as [Assessment, Assessment, Assessment];
    expect(latest.scope.model).toBe(STAND_IN_MODEL);
    expect(latest.rrs).toBeNull();
    expect(latest.inconclusive_reason).toMatch(/not attempted/);
    expect(latest.results.map((result) => [result.objective, result.result])).toEqual([
      ["W1", "not_achieved"],
      ["W2", "achieved"],
      ["W3", "not_attempted"],
      ["W4", "not_attempted"],
      ["W5", "not_achieved"],
    ]);
    // W2 names the Build's own planted Canary by id.
    expect(JSON.stringify(latest.results[1])).toContain("cny_33d265fca16c848eb2f23f43");
    expect(latest.inconclusive_code).toBe("excluded_over_limit");
    expect(failed.failure_reason).toMatch(/\S/);
    // A failed run keeps the results it reached, never a number.
    expect(failed.results.map((result) => [result.objective, result.result])).toEqual([["W2", "achieved"]]);
    expect(failed.rrs).toBeNull();
    expect(Date.parse(latest.created_at)).toBeGreaterThan(Date.parse(failed.created_at));
  });

  it("gives the next Build a scored, renormalised run and an older scored one", () => {
    const { call } = setup();
    const list = listOf(call, NEXT);
    expect(list.map((one) => one.status)).toEqual(["scored", "scored"]);
    expect(list[0]?.renormalised).toBe(true);
    expect(list[0]?.rrs).toEqual(expect.any(Number));
    expect(list[1]?.renormalised).toBe(false);
  });

  it("gives the oldest Build a running run", () => {
    const { call } = setup();
    expect(listOf(call, OLDEST).map((one) => one.status)).toEqual(["running"]);
  });

  it("reads one Assessment by its id, and not one of another Organization", () => {
    const { call } = setup();
    const [latest] = listOf(call, NEWEST);
    const latestId = latest?.id ?? "";
    const one = call("GET", `/v1/assessments/${latestId}`);
    expect(one.status).toBe(200);
    expect(parsed(AssessmentResponseSchema, one.body).assessment).toEqual(latest);
    expect(call("GET", `/v1/assessments/${latestId}`, undefined, OTHER_ORG).status).toBe(404);
    expect(call("GET", "/v1/assessments/asm_000000000000000000000000").status).toBe(404);
  });

  it("answers 404 for an unknown Build and null for paths it does not own", () => {
    const { call } = setup();
    expect(call("GET", `/v1/apps/${app}/builds/bld_999999999999999999999999/assessments`).status).toBe(404);
    const store = createAssessmentStore({ now: () => NOW });
    expect(store.handle(ORG, "GET", "/v1/apps", undefined, () => null)).toBeNull();
  });
});

describe("stub Assessments — request", () => {
  const files = [{ path: "dist/index.js", base64: "Y29uc29sZS5sb2coMSk7" }];

  it("scores a requested run of a Build with designated functions", () => {
    const { call, clock } = setup();
    const created = call("POST", `/v1/apps/${app}/builds/${NEWEST}/assessments`, { tier: "T1" });
    const { assessment } = parsed(CreateAssessmentResponseSchema, created.body);
    clock.ms += 60_000;
    const done = parsed(AssessmentResponseSchema, call("GET", `/v1/assessments/${assessment.id}`).body).assessment;
    expect(done.status).toBe("scored");
    expect(done.rrs).toEqual(expect.any(Number));
  });

  it("queues a run with the uploaded files, which runs and then turns inconclusive without a designated function", () => {
    const { call, clock } = setup();
    const created = call("POST", `/v1/apps/${app}/builds/${OLDEST}/assessments`, { tier: "T2", files });
    expect(created.status).toBe(202);
    const { assessment } = parsed(CreateAssessmentResponseSchema, created.body);
    expect([assessment.status, assessment.tier, assessment.scope.tier]).toEqual(["queued", "T2", "T2"]);
    expect(listOf(call, OLDEST)[0]?.id).toBe(assessment.id);

    clock.ms += 5_000;
    expect(
      parsed(AssessmentResponseSchema, call("GET", `/v1/assessments/${assessment.id}`).body).assessment.status,
    ).toBe("running");
    clock.ms += 60_000;
    const done = parsed(AssessmentResponseSchema, call("GET", `/v1/assessments/${assessment.id}`).body).assessment;
    expect(done.status).toBe("inconclusive");
    expect(done.results).toHaveLength(5);
    expect(done.results.find((result) => result.objective === "W3")).toMatchObject({
      result: "not_attempted",
      reason: "not_designated",
    });
    expect(done.inconclusive_reason).toMatch(/--logic/);
  });

  it("keeps every seeded artifact until 30 days after its run, except one already deleted", () => {
    const { call } = setup();
    const kept = [NEWEST, NEXT, OLDEST].flatMap((id) => listOf(call, id).map((one) => one.artifact_kept_until));
    expect(kept.filter((until) => until === null)).toHaveLength(1);
    for (const until of kept) if (until !== null) expect(Date.parse(until)).toBeGreaterThan(NOW);
  });

  it("assesses the kept artifact again from the tier alone, and keeps it for the new run", () => {
    const { call } = setup();
    const created = call("POST", `/v1/apps/${app}/builds/${NEWEST}/assessments`, { tier: "T3" });
    expect(created.status).toBe(202);
    const { assessment } = parsed(CreateAssessmentResponseSchema, created.body);
    expect([assessment.status, assessment.tier]).toEqual(["queued", "T3"]);
    expect(Date.parse(assessment.artifact_kept_until ?? "")).toBeGreaterThan(NOW);
  });

  it("answers 409 artifact-required to the tier alone when no artifact is kept", () => {
    const { call, clock } = setup();
    const created = call("POST", `/v1/apps/${app}/builds/${UNASSESSED}/assessments`, { tier: "T1" });
    expect(created.status).toBe(409);
    expect(created.body).toMatchObject({ status: 409, reason: "artifact-required" });
    // Once every kept artifact has expired, the same holds for an assessed Build.
    clock.ms += 400 * 24 * 3_600_000;
    expect(call("POST", `/v1/apps/${app}/builds/${NEWEST}/assessments`, { tier: "T1" }).status).toBe(409);
  });

  it("refuses an empty file list or an unknown tier (400), and a foreign Build (404)", () => {
    const { call } = setup();
    const path = `/v1/apps/${app}/builds/${NEWEST}/assessments`;
    expect(call("POST", path, { tier: "T1", files: [] }).status).toBe(400);
    expect(call("POST", path, { tier: "T4", files }).status).toBe(400);
    expect(
      call("POST", `/v1/apps/${app}/builds/bld_999999999999999999999999/assessments`, { tier: "T1", files }).status,
    ).toBe(404);
  });
});
