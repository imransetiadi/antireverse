import {
  type Assessment,
  AssessmentResponseSchema,
  type BuildManifest,
  type Canary,
  CreateAssessmentResponseSchema,
  EXAMPLE_LOGIC,
  EXAMPLE_ROUTE_INVENTORY,
  type LogicFile,
  scoreAssessment,
} from "@antireverse/protocol";
import { logicDigest, newId, routesDigest } from "@antireverse/protocol/server";
import { ASSESS_WORKER_LIMITS } from "@antireverse/prove";
import { afterAll, afterEach, beforeAll, describe, expect, it } from "vitest";
import {
  type AssessmentRunner,
  createAssessmentRunner,
  FAILURE_REASONS,
  RUNNER_DEFAULTS,
} from "../src/assess/runner.ts";
import { type OwnedDb, openDb } from "../src/db/db.ts";
import {
  artifactFor,
  type FakeAssessor,
  fakeAssessor,
  fakeScope,
  inconclusiveResults,
  scoredResults,
} from "./fake-assessor.ts";
import { bearer, createAppFor, createOrganization, json, makeTestApi, type TestApi, within } from "./helpers.ts";

// Slice 12a: the Assessment queue and runner. One running Assessment per Organization, two at once in all; each run
// goes through the Assessor with the Build's facts as verifier inputs; queued → running → scored | inconclusive |
// failed, scored by the protocol's `scoreAssessment`; partial results kept on failure; the runner's own time budget;
// on start, running Assessments become failed (interrupted) and queued ones resume; artifacts expire 30 days after.

const T0 = Date.parse("2026-11-13T09:00:00.000Z");
const DAY = 86_400_000;

function canaries(): Canary[] {
  const suffix = newId("cny").slice(-8);
  return [
    { id: newId("cny"), kind: "key", value: `ak_live_${"Q".repeat(24)}${suffix}` },
    { id: newId("cny"), kind: "route", value: `/api/internal/${suffix}/backup` },
  ];
}

const settle = () => new Promise((resolve) => setTimeout(resolve, 20));

describe("Assessment runner", () => {
  let db: OwnedDb;
  let api: TestApi;
  let assessor: FakeAssessor;
  let runner: AssessmentRunner;
  const clock = { now: new Date(T0) };
  const orgs: Array<{ admin: string; organizationId: string; appId: string }> = [];
  const runners: AssessmentRunner[] = [];

  function makeRunner(options: Partial<Parameters<typeof createAssessmentRunner>[0]> = {}): AssessmentRunner {
    const made = createAssessmentRunner({ db, assessor, now: () => clock.now, logger: api.logger, ...options });
    runners.push(made);
    return made;
  }

  async function queue(
    org: { admin: string; appId: string },
    options: { manifest?: Partial<BuildManifest>; routes?: string[]; logic?: LogicFile; tier?: string } = {},
  ): Promise<{ assessment: Assessment; manifest: BuildManifest; contents: Map<string, string> }> {
    const routes = options.routes;
    const { manifest, files, contents } = artifactFor(org.appId, {
      ...(routes === undefined ? {} : { route_count: routes.length, routes_digest: routesDigest(routes) }),
      ...options.manifest,
    });
    const registered = await api.app.request(
      `/v1/apps/${org.appId}/builds`,
      json(
        {
          manifest,
          ...(routes === undefined ? {} : { routes }),
          ...(options.logic === undefined ? {} : { logic: options.logic }),
        },
        bearer(org.admin),
      ),
    );
    expect(registered.status).toBe(201);
    const res = await api.app.request(
      `/v1/apps/${org.appId}/builds/${manifest.build_id}/assessments`,
      json({ tier: options.tier ?? "T1", files }, bearer(org.admin)),
    );
    expect(res.status).toBe(202);
    return { assessment: CreateAssessmentResponseSchema.parse(await res.json()).assessment, manifest, contents };
  }

  async function read(org: { admin: string }, id: string): Promise<Assessment> {
    const res = await api.app.request(`/v1/assessments/${id}`, { headers: bearer(org.admin) });
    expect(res.status).toBe(200);
    return AssessmentResponseSchema.parse(await res.json()).assessment;
  }

  beforeAll(async () => {
    db = await openDb();
    // The app wakes whichever runner the test made last.
    api = await makeTestApi({
      db,
      now: () => clock.now,
      assessments: { wake: () => runner?.wake() },
    });
    for (const name of ["A", "B", "C"]) {
      const created = await createOrganization(api, name);
      const app = await createAppFor(api, created.admin_key.key, { name: `Shop ${name}` });
      orgs.push({ admin: created.admin_key.key, organizationId: created.organization.id, appId: app.app.id });
    }
  });
  afterEach(async () => {
    for (const made of runners.splice(0)) await made.stop();
    // Nothing of one test may stay running into the next.
    await db.tx("none", (q) => q.query("SELECT 1"));
  });
  afterAll(async () => {
    await api.close();
  });

  const [A, B, C] = [0, 1, 2].map((index) => () => orgs[index] as (typeof orgs)[number]) as [
    () => (typeof orgs)[number],
    () => (typeof orgs)[number],
    () => (typeof orgs)[number],
  ];

  it("runs a queued Assessment through the Assessor with the Build's facts and scores it", async () => {
    assessor = fakeAssessor();
    runner = makeRunner();
    await runner.start();
    clock.now = new Date(T0 + 1_000);
    const planted = canaries();
    const routes = [...EXAMPLE_ROUTE_INVENTORY];
    const { assessment, manifest, contents } = await queue(A(), { manifest: { canaries: planted }, routes });

    const run = await within(assessor.run(0), 2_000, "the run");
    expect(Object.keys(run.input).sort()).toEqual(["artifact", "budgets", "build", "onResult", "signal", "tier"]);
    expect(run.input.tier).toBe("T1");
    expect(run.input.build).toEqual({ canaries: planted, leakFindings: [], routes, logic: null, integrity: false });
    expect([...run.input.artifact.keys()].sort()).toEqual([...contents.keys()].sort());
    for (const [path, text] of contents) {
      expect(Buffer.from(run.input.artifact.get(path) as Uint8Array).toString("utf8")).toBe(text);
    }
    expect(run.input.signal.aborted).toBe(false);

    const running = await read(A(), assessment.id);
    expect(running.status).toBe("running");
    expect(running.started_at).toBe(new Date(T0 + 1_000).toISOString());

    clock.now = new Date(T0 + 61_000);
    const scope = { ...fakeScope("T1"), agent: { name: "fake", version: "1.0.1" } };
    run.resolve({ results: scoredResults(), scope });
    await runner.idle();
    const done = await read(A(), assessment.id);
    const score = scoreAssessment(scoredResults(), "T1");
    expect(done).toMatchObject({
      status: "scored",
      rrs: score.rrs,
      renormalised: false,
      inconclusive_reason: null,
      inconclusive_code: null,
      scope,
      results: scoredResults(),
      finished_at: new Date(T0 + 61_000).toISOString(),
      failure_reason: null,
      artifact_kept_until: new Date(T0 + 61_000 + 30 * DAY).toISOString(),
    });
    expect(manifest.build_id).toBe(done.build_id);
  });

  it("records SLO-10 for each T1 Assessment that ends: good with a result within 30 min of its creation (slice 18d)", async () => {
    const recorded: [string, boolean, number][] = [];
    assessor = fakeAssessor();
    runner = makeRunner({ slo: { record: (id, good, ms) => recorded.push([id, good, ms]) } });
    await runner.start();
    const base = T0 + 10 * DAY;

    // Scored one minute after creation: good.
    clock.now = new Date(base);
    await queue(B());
    const first = await within(assessor.run(0), 2_000, "the first run");
    clock.now = new Date(base + 60_000);
    first.resolve({ results: scoredResults(), scope: fakeScope("T1") });
    await runner.idle();

    // Inconclusive 31 minutes after creation: a result, but late.
    clock.now = new Date(base + 100_000);
    await queue(B());
    const second = await within(assessor.run(1), 2_000, "the second run");
    clock.now = new Date(base + 100_000 + 31 * 60_000);
    second.resolve({ results: inconclusiveResults(), scope: fakeScope("T1") });
    await runner.idle();

    // Failed two seconds after creation: no result.
    clock.now = new Date(base + 3_000_000);
    await queue(B());
    const third = await within(assessor.run(2), 2_000, "the third run");
    clock.now = new Date(base + 3_002_000);
    third.reject(new Error("engine crashed"));
    await runner.idle();

    expect(recorded).toEqual([
      ["SLO-10", true, 60_000],
      ["SLO-10", false, 31 * 60_000],
      ["SLO-10", false, 2_000],
    ]);
  });

  it("forwards the Build's stored logic file and its integrity flag to the Assessor (slice 12b)", async () => {
    assessor = fakeAssessor();
    runner = makeRunner();
    await runner.start();
    const logic = EXAMPLE_LOGIC;
    const { manifest } = artifactFor(C().appId);
    const { assessment } = await queue(C(), {
      manifest: {
        transform: { ...manifest.transform, integrity: true },
        logic_count: logic.functions.length,
        logic_digest: logicDigest(logic),
      },
      logic,
    });
    const run = await within(assessor.run(0), 2_000, "the run");
    expect(run.input.build.logic).toEqual(logic);
    expect(run.input.build.integrity).toBe(true);
    run.resolve({ results: scoredResults(), scope: fakeScope("T1") });
    await runner.idle();
    const res = await api.app.request(`/v1/assessments/${assessment.id}`, { headers: bearer(C().admin) });
    expect(await res.text()).not.toContain("price-with-tax");
  });

  it("passes null routes for a Build registered without an inventory, and records an inconclusive run", async () => {
    assessor = fakeAssessor();
    runner = makeRunner();
    await runner.start();
    const { assessment } = await queue(A());
    const run = await within(assessor.run(0), 2_000, "the run");
    expect(run.input.build.routes).toBeNull();
    expect(run.input.build.canaries).toEqual([]);
    run.resolve({ results: inconclusiveResults(), scope: fakeScope("T1") });
    await runner.idle();
    const done = await read(A(), assessment.id);
    const score = scoreAssessment(inconclusiveResults(), "T1");
    expect(score.status).toBe("inconclusive");
    expect(done).toMatchObject({
      status: "inconclusive",
      rrs: null,
      inconclusive_code: "excluded_over_limit",
      inconclusive_reason: score.status === "inconclusive" ? score.reason : "",
    });
  });

  it("runs one Assessment per Organization and two at once in all", async () => {
    assessor = fakeAssessor();
    runner = makeRunner();
    await runner.start();
    // One millisecond apart, so that "oldest first" is the order queued.
    const at = (ms: number) => {
      clock.now = new Date(T0 + 500_000 + ms);
    };
    at(1);
    const a1 = await queue(A());
    at(2);
    const a2 = await queue(A());
    at(3);
    const b1 = await queue(B());
    at(4);
    const c1 = await queue(C());
    await within(assessor.run(1), 2_000, "the second run");
    await settle();
    expect(assessor.runs).toHaveLength(2);
    expect((await read(A(), a1.assessment.id)).status).toBe("running");
    expect((await read(A(), a2.assessment.id)).status).toBe("queued");
    expect((await read(B(), b1.assessment.id)).status).toBe("running");
    expect((await read(C(), c1.assessment.id)).status).toBe("queued");

    // A's first run ends: A's second may not start before C's (oldest first, one per Organization).
    assessor.runs[0]?.resolve({ results: scoredResults(), scope: fakeScope("T1") });
    await within(assessor.run(2), 2_000, "the third run");
    await settle();
    expect(assessor.runs).toHaveLength(3);
    expect((await read(A(), a2.assessment.id)).status).toBe("running");
    expect((await read(C(), c1.assessment.id)).status).toBe("queued");

    assessor.runs[1]?.resolve({ results: scoredResults(), scope: fakeScope("T1") });
    await within(assessor.run(3), 2_000, "the fourth run");
    expect((await read(C(), c1.assessment.id)).status).toBe("running");
    for (const run of assessor.runs.slice(2)) run.resolve({ results: scoredResults(), scope: fakeScope("T1") });
    await runner.idle();
  });

  it("marks a run failed when the Assessor rejects, keeping the results decided before", async () => {
    assessor = fakeAssessor();
    runner = makeRunner();
    await runner.start();
    const { assessment } = await queue(A());
    const run = await within(assessor.run(0), 2_000, "the run");
    const [w1, w2] = inconclusiveResults();
    run.input.onResult?.(w1 as never);
    run.input.onResult?.(w2 as never);
    run.reject(new Error("worker crashed reading ak_live_secret"));
    await runner.idle();
    const done = await read(A(), assessment.id);
    expect(done).toMatchObject({
      status: "failed",
      failure_reason: FAILURE_REASONS.engine,
      rrs: null,
      results: [w1, w2],
    });
    expect(JSON.stringify(done)).not.toContain("ak_live_secret");
    expect(api.logger.lines.join("\n")).not.toContain("ak_live_secret");
  });

  it("marks a run failed when the agent stopped with an error, keeping the verifiers' results as partial", async () => {
    assessor = fakeAssessor();
    runner = makeRunner();
    await runner.start();
    const { assessment } = await queue(A());
    const run = await within(assessor.run(0), 2_000, "the run");
    run.resolve({ results: inconclusiveResults(), scope: fakeScope("T1"), end: "agent_error" });
    await runner.idle();
    expect(await read(A(), assessment.id)).toMatchObject({
      status: "failed",
      failure_reason: FAILURE_REASONS.agent,
      rrs: null,
      inconclusive_reason: null,
      results: inconclusiveResults(),
    });
  });

  it("maps the engine's own deadline (TimeoutError) to timeout and its abort (AbortError) to interrupted", async () => {
    assessor = fakeAssessor();
    runner = makeRunner();
    await runner.start();
    const timed = await queue(A());
    const first = await within(assessor.run(0), 2_000, "the run");
    first.reject(new DOMException("over its deadline: ak_live_x", "TimeoutError"));
    await runner.idle();
    expect(await read(A(), timed.assessment.id)).toMatchObject({ failure_reason: FAILURE_REASONS.timeout });
    const aborted = await queue(A());
    const second = await within(assessor.run(1), 2_000, "the second run");
    second.reject(new DOMException("aborted", "AbortError"));
    await runner.idle();
    expect(await read(A(), aborted.assessment.id)).toMatchObject({ failure_reason: FAILURE_REASONS.interrupted });
    expect(api.logger.lines.join("\n")).not.toContain("ak_live_x");
  });

  it("marks a run failed when the Assessor returns results that cannot be scored", async () => {
    assessor = fakeAssessor();
    runner = makeRunner();
    await runner.start();
    const { assessment } = await queue(A());
    const run = await within(assessor.run(0), 2_000, "the run");
    run.resolve({ results: scoredResults().slice(0, 4), scope: fakeScope("T1") });
    await runner.idle();
    expect(await read(A(), assessment.id)).toMatchObject({ status: "failed", failure_reason: FAILURE_REASONS.invalid });

    const second = await queue(A());
    const again = await within(assessor.run(1), 2_000, "the second run");
    again.resolve({ results: scoredResults(), scope: fakeScope("T2") });
    await runner.idle();
    expect(await read(A(), second.assessment.id)).toMatchObject({
      status: "failed",
      failure_reason: FAILURE_REASONS.invalid,
    });
  });

  it("enforces the tier's time budget itself: aborts the run and marks it failed with its partial results", async () => {
    assessor = fakeAssessor();
    runner = makeRunner({ budgets: { T1: { calls: 150, seconds: 0.05 } }, graceMs: 0 });
    await runner.start();
    const { assessment } = await queue(A());
    const run = await within(assessor.run(0), 2_000, "the run");
    expect(run.input.budgets).toEqual({ T1: { calls: 150, seconds: 0.05 } });
    const [, w2] = inconclusiveResults();
    run.input.onResult?.(w2 as never);
    await within(
      new Promise<void>((resolve) => run.input.signal.addEventListener("abort", () => resolve())),
      2_000,
      "the abort",
    );
    await runner.idle();
    expect(await read(A(), assessment.id)).toMatchObject({
      status: "failed",
      failure_reason: FAILURE_REASONS.timeout,
      results: [w2],
    });
    // A late answer changes nothing.
    run.resolve({ results: scoredResults(), scope: fakeScope("T1") });
    await settle();
    expect((await read(A(), assessment.id)).status).toBe("failed");
  });

  it("on start marks running Assessments failed (interrupted) and resumes queued ones", async () => {
    assessor = fakeAssessor();
    const crashed = createAssessmentRunner({ db, assessor, now: () => clock.now, logger: api.logger });
    runner = crashed;
    await crashed.start();
    const first = await queue(A());
    await within(assessor.run(0), 2_000, "the first run");
    const second = await queue(A());
    expect((await read(A(), second.assessment.id)).status).toBe("queued");

    // The process "crashed": its runner is gone without stopping. A new one starts on the same database.
    clock.now = new Date(T0 + 2 * DAY);
    const before = assessor;
    assessor = fakeAssessor();
    runner = makeRunner();
    await runner.start();
    const interrupted = await read(A(), first.assessment.id);
    expect(interrupted).toMatchObject({
      status: "failed",
      failure_reason: FAILURE_REASONS.interrupted,
      results: [],
      finished_at: new Date(T0 + 2 * DAY).toISOString(),
    });
    const resumed = await within(assessor.run(0), 2_000, "the resumed run");
    expect((await read(A(), second.assessment.id)).status).toBe("running");
    resumed.resolve({ results: scoredResults(), scope: fakeScope("T1") });
    await runner.idle();
    expect((await read(A(), second.assessment.id)).status).toBe("scored");

    // The old runner's run answering late changes nothing.
    before.runs[0]?.resolve({ results: scoredResults(), scope: fakeScope("T1") });
    await settle();
    expect((await read(A(), first.assessment.id)).status).toBe("failed");
    runners.push(crashed);
    clock.now = new Date(T0);
  });

  it("on stop aborts running Assessments and marks them failed (interrupted)", async () => {
    assessor = fakeAssessor();
    runner = createAssessmentRunner({ db, assessor, now: () => clock.now, logger: api.logger });
    await runner.start();
    const { assessment } = await queue(B());
    const run = await within(assessor.run(0), 2_000, "the run");
    await runner.stop();
    expect(run.input.signal.aborted).toBe(true);
    expect(await read(B(), assessment.id)).toMatchObject({
      status: "failed",
      failure_reason: FAILURE_REASONS.interrupted,
    });
  });

  it("deletes an artifact 30 days after its last Assessment finished, never while one is queued", async () => {
    assessor = fakeAssessor();
    runner = makeRunner();
    clock.now = new Date(T0 + 10 * DAY);
    await runner.start();
    const { assessment } = await queue(C());
    const run = await within(assessor.run(0), 2_000, "the run");

    // Past the upload's own 30 days, but still running: kept (other tests' artifacts may expire here).
    clock.now = new Date(T0 + 41 * DAY);
    await runner.expireOnce();
    expect((await read(C(), assessment.id)).artifact_kept_until).toBe(new Date(T0 + 40 * DAY).toISOString());
    run.resolve({ results: scoredResults(), scope: fakeScope("T1") });
    await runner.idle();
    const finished = await read(C(), assessment.id);
    expect(finished.artifact_kept_until).toBe(new Date(T0 + 71 * DAY).toISOString());

    clock.now = new Date(T0 + 71 * DAY - 1);
    expect(await runner.expireOnce()).toBe(0);
    clock.now = new Date(T0 + 71 * DAY);
    expect(await runner.expireOnce()).toBe(1);
    const after = await read(C(), assessment.id);
    expect(after).toMatchObject({ status: "scored", artifact_kept_until: null });
    const { rows } = await db.tx({ organizationId: C().organizationId }, (q) =>
      q.query("SELECT 1 FROM artifact_files f JOIN artifacts a ON a.id = f.artifact_id WHERE a.build_id = $1", [
        after.build_id,
      ]),
    );
    expect(rows).toEqual([]);
    // With the artifact gone, a reassessment needs the files again.
    const res = await api.app.request(
      `/v1/apps/${C().appId}/builds/${after.build_id}/assessments`,
      json({ tier: "T1" }, bearer(C().admin)),
    );
    expect(res.status).toBe(409);
    clock.now = new Date(T0);
  });

  // --- Stored calls (fork 5: Jev "store_referenced_calls", 0.70) ---------------------------------------------

  async function detail(org: { admin: string }, id: string) {
    const res = await api.app.request(`/v1/assessments/${id}`, { headers: bearer(org.admin) });
    expect(res.status).toBe(200);
    const body = await res.text();
    return { body, parsed: AssessmentResponseSchema.parse(JSON.parse(body)) };
  }

  const logOf = (count: number, summary = (index: number) => `search: ${index} hits`) =>
    Array.from({ length: count }, (_, index) => ({
      index,
      tool: "search" as const,
      cost: { calls: index + 1, seconds: index / 100 },
      summary: summary(index),
    }));

  it("stores only the calls the evidence references, with the totals, and returns them on the detail only", async () => {
    assessor = fakeAssessor();
    runner = makeRunner();
    await runner.start();
    const { assessment, manifest } = await queue(B());
    const run = await within(assessor.run(0), 2_000, "the run");
    run.resolve({
      results: scoredResults(),
      scope: fakeScope("T1"),
      calls: logOf(10),
      cost: { calls: 12, seconds: 3.5 },
    });
    await runner.idle();
    const { parsed } = await detail(B(), assessment.id);
    expect(parsed.calls).toEqual(logOf(10).filter((call) => call.index === 1 || call.index === 2));
    expect(parsed.call_totals).toEqual({ count: 10, calls: 12, seconds: 3.5 });

    const list = await api.app.request(`/v1/apps/${B().appId}/builds/${manifest.build_id}/assessments`, {
      headers: bearer(B().admin),
    });
    const listed = (await list.json()) as { assessments: object[] };
    expect(Object.keys(listed)).toEqual(["assessments"]);
    for (const item of listed.assessments) {
      expect(item).not.toHaveProperty("calls");
      expect(item).not.toHaveProperty("call_totals");
    }
  });

  it("caps stored calls at 200 and drops the cut indexes from the evidence, so every index resolves", async () => {
    assessor = fakeAssessor();
    runner = makeRunner();
    await runner.start();
    const { assessment } = await queue(B());
    const run = await within(assessor.run(0), 2_000, "the run");
    const refs = (from: number) => Array.from({ length: 50 }, (_, offset) => from + offset * 2);
    const results = scoredResults().map((result, position) => ({
      ...result,
      evidence: { ...result.evidence, calls: refs(position * 100) },
    }));
    run.resolve({ results, scope: fakeScope("T1"), calls: logOf(600), cost: { calls: 600, seconds: 60 } });
    await runner.idle();
    const { parsed } = await detail(B(), assessment.id);
    const stored = parsed.calls ?? [];
    expect(stored).toHaveLength(200);
    expect(stored.map((call) => call.index)).toEqual([...refs(0), ...refs(100), ...refs(200), ...refs(300)]);
    const indexes = new Set(stored.map((call) => call.index));
    for (const result of parsed.assessment.results) {
      for (const index of result.evidence.calls) expect(indexes.has(index)).toBe(true);
    }
    expect(parsed.assessment.results.find((result) => result.objective === "W5")?.evidence.calls).toEqual([]);
    expect(parsed.call_totals).toEqual({ count: 600, calls: 600, seconds: 60 });
  });

  it("never stores a Canary value in a call, whatever the engine reported", async () => {
    assessor = fakeAssessor();
    runner = makeRunner();
    await runner.start();
    const planted = canaries();
    const { assessment } = await queue(B(), { manifest: { canaries: planted } });
    const run = await within(assessor.run(0), 2_000, "the run");
    const leaky = (index: number) => `read: ${planted[index % 2]?.value ?? ""} at ${index}`;
    run.resolve({
      results: scoredResults(),
      scope: fakeScope("T1"),
      calls: logOf(5, leaky),
      cost: { calls: 5, seconds: 1 },
    });
    await runner.idle();
    const { body, parsed } = await detail(B(), assessment.id);
    expect(parsed.calls?.map((call) => call.index)).toEqual([1, 2]);
    for (const canary of planted) expect(body).not.toContain(canary.value);
    const { rows } = await db.tx({ organizationId: B().organizationId }, (q) =>
      q.query<{ calls: unknown }>("SELECT calls FROM assessments WHERE id = $1", [assessment.id]),
    );
    for (const canary of planted) expect(JSON.stringify(rows)).not.toContain(canary.value);
  });
});

describe("runner grace (slice 12b, review F4)", () => {
  it("outlasts the engine's own deadline grace, so the engine's judging budget ends a run first", () => {
    expect(RUNNER_DEFAULTS.graceMs).toBeGreaterThan(ASSESS_WORKER_LIMITS.graceMs);
  });
});
