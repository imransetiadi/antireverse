import {
  ASSESSMENT_LIMITS,
  AssessmentResponseSchema,
  type BuildManifest,
  CreateAssessmentResponseSchema,
  ListAssessmentsResponseSchema,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { CONFLICT_DETAILS } from "../src/problem.ts";
import { ASSESSMENT_BODY_BYTES_MAX } from "../src/routes/assessments.ts";
import { expireArtifacts, LATEST_KEPT_ARTIFACT_SQL } from "../src/stores/assessments.ts";
import { artifactFor, type FakeAssessor, fakeAssessor, fakeScope, sha256 } from "./fake-assessor.ts";
import {
  bearer,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  type TestApi,
} from "./helpers.ts";

// Slice 12a: the Assessment routes. Proof of Ownership (the Organization's registered Build, every uploaded file's
// SHA-256 equal to the Manifest's entry for its path, every Manifest artifact present), reuse of the Build's most recent
// kept artifact, the list and the single read; admin key only.

const T0 = Date.parse("2026-11-13T08:00:00.000Z");

describe("Assessment routes", () => {
  let api: TestApi;
  let assessor: FakeAssessor;
  const clock = { now: new Date(T0) };
  let adminA: string;
  let adminB: string;
  let shieldA: string;
  let orgA: string;
  let appId: string;

  async function registerBuild(manifest: BuildManifest): Promise<void> {
    const res = await api.app.request(`/v1/apps/${appId}/builds`, json({ manifest }, bearer(adminA)));
    expect(res.status).toBe(201);
  }

  const assessPath = (buildId: string, app = appId) => `/v1/apps/${app}/builds/${buildId}/assessments`;
  const create = (buildId: string, body: unknown, key = adminA, app = appId) =>
    Promise.resolve(api.app.request(assessPath(buildId, app), json(body, bearer(key))));

  beforeAll(async () => {
    assessor = fakeAssessor();
    // The queue is never woken: these tests see Assessments as they are queued. The runner tests run them.
    api = await makeTestApi({ now: () => clock.now, assessments: { wake: () => {} }, assessor });
    const a = await createOrganization(api, "A");
    const b = await createOrganization(api, "B");
    adminA = a.admin_key.key;
    adminB = b.admin_key.key;
    orgA = a.organization.id;
    const created = await createAppFor(api, adminA, { name: "Shop" });
    appId = created.app.id;
    shieldA = created.shield_key.key;
  });
  afterAll(async () => {
    await api.close();
  });

  it("queues an Assessment of an uploaded artifact whose hashes match the Manifest (202)", async () => {
    clock.now = new Date(T0 + 1_000);
    const { manifest, files } = artifactFor(appId);
    await registerBuild(manifest);
    const res = await create(manifest.build_id, { tier: "T1", files });
    expect(res.status).toBe(202);
    const { assessment } = CreateAssessmentResponseSchema.parse(await res.json());
    expect(assessment).toMatchObject({
      build_id: manifest.build_id,
      app_id: appId,
      environment: manifest.environment,
      tier: "T1",
      status: "queued",
      results: [],
      rrs: null,
      inconclusive_reason: null,
      inconclusive_code: null,
      renormalised: false,
      scope: fakeScope("T1"),
      created_at: new Date(T0 + 1_000).toISOString(),
      started_at: null,
      finished_at: null,
      failure_reason: null,
      artifact_kept_until: new Date(T0 + 1_000 + 30 * 86_400_000).toISOString(),
    });
    expect(assessment.id).toMatch(/^asm_[0-9a-f]{24}$/);

    const { rows } = await api.db.tx({ organizationId: orgA }, (q) =>
      q.query<{ path: string; sha256: string }>(
        `SELECT f.path, f.sha256 FROM artifact_files f JOIN assessments a
           ON a.organization_id = f.organization_id AND a.artifact_id = f.artifact_id
         WHERE a.id = $1 ORDER BY f.path`,
        [assessment.id],
      ),
    );
    expect(rows).toEqual(manifest.artifacts.map(({ path, sha256 }) => ({ path, sha256 })));
  });

  it("refuses a file whose SHA-256 differs from the Manifest's with 400 and stores nothing", async () => {
    const { manifest, files } = artifactFor(appId);
    await registerBuild(manifest);
    const tampered = files.map((file, index) =>
      index === 1 ? { ...file, base64: Buffer.from("export const answer = 43;").toString("base64") } : file,
    );
    const problem = await expectProblem(await create(manifest.build_id, { tier: "T1", files: tampered }), 400);
    expect(problem.errors).toEqual([
      { path: "files.1.base64", message: "Its SHA-256 must equal the Manifest's for this path." },
    ]);
    const listed = await api.app.request(assessPath(manifest.build_id), { headers: bearer(adminA) });
    expect(ListAssessmentsResponseSchema.parse(await listed.json()).assessments).toEqual([]);
  });

  it("refuses a file the Manifest does not list, and a missing Manifest artifact, with 400", async () => {
    const { manifest, files } = artifactFor(appId);
    await registerBuild(manifest);
    const extra = [...files, { path: "dist/extra.js", base64: Buffer.from("1").toString("base64") }];
    const one = await expectProblem(await create(manifest.build_id, { tier: "T1", files: extra }), 400);
    expect(one.errors).toEqual([{ path: "files.2.path", message: "Must be an artifact of the Build's Manifest." }]);

    const missing = await expectProblem(await create(manifest.build_id, { tier: "T1", files: files.slice(0, 1) }), 400);
    expect(missing.errors).toEqual([
      { path: "files", message: "Must include every artifact of the Manifest (1 missing)." },
    ]);
  });

  it("refuses a malformed body with 400 (tier, base64)", async () => {
    const { manifest, files } = artifactFor(appId);
    await registerBuild(manifest);
    await expectProblem(await create(manifest.build_id, { tier: "T4", files }), 400);
    const bad = await expectProblem(
      await create(manifest.build_id, { tier: "T1", files: [{ path: "dist/index.js", base64: "abc" }] }),
      400,
    );
    expect(bad.errors?.[0]?.path).toBe("files.0.base64");
  });

  it("refuses a body over the artifact limit with 413", async () => {
    const { manifest } = artifactFor(appId);
    const big = "A".repeat(ASSESSMENT_BODY_BYTES_MAX);
    const res = await create(manifest.build_id, { tier: "T1", files: [{ path: "dist/index.js", base64: big }] });
    await expectProblem(res, 413);
  });

  it("reassesses the Build's most recent kept artifact when no files are sent", async () => {
    const { manifest, files } = artifactFor(appId);
    await registerBuild(manifest);
    clock.now = new Date(T0 + 2_000);
    const first = CreateAssessmentResponseSchema.parse(
      await (await create(manifest.build_id, { tier: "T1", files })).json(),
    ).assessment;
    clock.now = new Date(T0 + 3_000);
    const res = await create(manifest.build_id, { tier: "T2" });
    expect(res.status).toBe(202);
    const second = CreateAssessmentResponseSchema.parse(await res.json()).assessment;
    expect(second).toMatchObject({ tier: "T2", status: "queued", scope: fakeScope("T2") });
    const { rows } = await api.db.tx({ organizationId: orgA }, (q) =>
      q.query<{ id: string; artifact_id: string }>("SELECT id, artifact_id FROM assessments WHERE id = ANY($1)", [
        [first.id, second.id],
      ]),
    );
    expect(new Set(rows.map((row) => row.artifact_id)).size).toBe(1);
  });

  it("answers 409 artifact-required without files for a Build with no kept artifact", async () => {
    const { manifest } = artifactFor(appId);
    await registerBuild(manifest);
    const problem = await expectProblem(await create(manifest.build_id, { tier: "T1" }), 409);
    expect(problem.reason).toBe("artifact-required");
    expect(problem.detail).toBe(CONFLICT_DETAILS["artifact-required"]);
  });

  it("does not reuse an artifact whose retention has passed", async () => {
    const { manifest, files } = artifactFor(appId);
    await registerBuild(manifest);
    clock.now = new Date(T0 + 5_000);
    expect((await create(manifest.build_id, { tier: "T1", files })).status).toBe(202);
    clock.now = new Date(T0 + 5_000 + 31 * 86_400_000);
    await expectProblem(await create(manifest.build_id, { tier: "T1" }), 409);
    clock.now = new Date(T0 + 10_000);
  });

  // Review hardening: the expiry must never delete an artifact a reassessment picked. With one connection the order
  // is shown by call order at the boundary; the locking itself is checked in the SQL.
  it("keeps the artifact a reassessment picked just before its retention ended, through the expiry", async () => {
    const { manifest, files } = artifactFor(appId);
    await registerBuild(manifest);
    const uploaded = T0 + 7_000;
    clock.now = new Date(uploaded);
    expect((await create(manifest.build_id, { tier: "T1", files })).status).toBe(202);
    const keptUntil = uploaded + 30 * 86_400_000;
    clock.now = new Date(keptUntil - 1);
    const res = await create(manifest.build_id, { tier: "T1" });
    expect(res.status).toBe(202);
    const { assessment } = CreateAssessmentResponseSchema.parse(await res.json());
    expect(assessment.artifact_kept_until).toBe(new Date(keptUntil).toISOString());

    await api.db.tx("none", (q) => expireArtifacts(q, new Date(keptUntil)));
    const read = await api.app.request(`/v1/assessments/${assessment.id}`, { headers: bearer(adminA) });
    const after = AssessmentResponseSchema.parse(await read.json()).assessment;
    expect(after.artifact_kept_until).toBe(new Date(keptUntil).toISOString());
    const { rows } = await api.db.tx({ organizationId: orgA }, (q) =>
      q.query<{ files: number }>(
        `SELECT count(f.*)::int AS files FROM assessments a JOIN artifact_files f
           ON f.organization_id = a.organization_id AND f.artifact_id = a.artifact_id WHERE a.id = $1`,
        [assessment.id],
      ),
    );
    expect(rows).toEqual([{ files: files.length }]);
    clock.now = new Date(T0 + 10_000);
  });

  it("refuses a reassessment cleanly with 409 once the expiry ran at the retention's end", async () => {
    const { manifest, files } = artifactFor(appId);
    await registerBuild(manifest);
    const uploaded = T0 + 8_000;
    clock.now = new Date(uploaded);
    expect((await create(manifest.build_id, { tier: "T1", files })).status).toBe(202);
    // Its only Assessment ends (as the runner would), so nothing in flight holds the artifact.
    await api.db.tx({ organizationId: orgA }, (q) =>
      q.query(
        `UPDATE assessments SET status = 'failed', started_at = created_at, finished_at = created_at,
           failure_reason = 'test' WHERE build_id = $1`,
        [manifest.build_id],
      ),
    );
    const keptUntil = uploaded + 30 * 86_400_000;
    clock.now = new Date(keptUntil);
    expect(await api.db.tx("none", (q) => expireArtifacts(q, new Date(keptUntil)))).toBeGreaterThanOrEqual(1);
    const problem = await expectProblem(await create(manifest.build_id, { tier: "T1" }), 409);
    expect(problem.reason).toBe("artifact-required");
    clock.now = new Date(T0 + 10_000);
  });

  it("locks the picked artifact row and lets the expiry skip locked rows", async () => {
    const { rows } = await api.db.tx("none", (q) =>
      q.query<{ def: string }>(
        "SELECT pg_get_functiondef('assessment_artifacts_expire(timestamptz)'::regprocedure) AS def",
      ),
    );
    expect(rows[0]?.def).toMatch(/FOR UPDATE SKIP LOCKED/);
    expect(LATEST_KEPT_ARTIFACT_SQL).toMatch(/kept_until > \$4::timestamptz[\s\S]*FOR UPDATE/);
  });

  it("lists a Build's Assessments newest first, at most 50, and reads one by id", async () => {
    const { manifest, files } = artifactFor(appId);
    await registerBuild(manifest);
    const ids: string[] = [];
    for (let index = 0; index < ASSESSMENT_LIMITS.listed + 2; index++) {
      clock.now = new Date(T0 + 100_000 + index * 1_000);
      const body = index === 0 ? { tier: "T1", files } : { tier: "T1" };
      const res = await create(manifest.build_id, body);
      expect(res.status).toBe(202);
      ids.push(CreateAssessmentResponseSchema.parse(await res.json()).assessment.id);
    }
    const res = await api.app.request(assessPath(manifest.build_id), { headers: bearer(adminA) });
    expect(res.status).toBe(200);
    const { assessments } = ListAssessmentsResponseSchema.parse(await res.json());
    expect(assessments.map((assessment) => assessment.id)).toEqual(ids.reverse().slice(0, ASSESSMENT_LIMITS.listed));

    const one = await api.app.request(`/v1/assessments/${ids[0]}`, { headers: bearer(adminA) });
    expect(one.status).toBe(200);
    expect(AssessmentResponseSchema.parse(await one.json()).assessment.id).toBe(ids[0]);
  });

  it("answers 403 to a Shield key and 401 without a key", async () => {
    const { manifest, files } = artifactFor(appId);
    await registerBuild(manifest);
    await expectProblem(await create(manifest.build_id, { tier: "T1", files }, shieldA), 403);
    await expectProblem(await api.app.request(assessPath(manifest.build_id), { headers: bearer(shieldA) }), 403);
    await expectProblem(await api.app.request(`/v1/assessments/asm_${"0".repeat(24)}`), 401);
  });

  it("answers 404 for another Organization's Build and Assessment, and for unknown or malformed ids", async () => {
    const { manifest, files } = artifactFor(appId);
    await registerBuild(manifest);
    const res = await create(manifest.build_id, { tier: "T1", files });
    const { assessment } = CreateAssessmentResponseSchema.parse(await res.json());

    await expectProblem(await create(manifest.build_id, { tier: "T1", files }, adminB), 404);
    await expectProblem(await create(manifest.build_id, { tier: "T1" }, adminB), 404);
    await expectProblem(await api.app.request(assessPath(manifest.build_id), { headers: bearer(adminB) }), 404);
    await expectProblem(await api.app.request(`/v1/assessments/${assessment.id}`, { headers: bearer(adminB) }), 404);
    await expectProblem(await create(newId("bld"), { tier: "T1", files }), 404);
    await expectProblem(await create("bld_nope", { tier: "T1", files }), 404);
    await expectProblem(await create(manifest.build_id, { tier: "T1", files }, adminA, "app_nope"), 404);
    await expectProblem(await api.app.request("/v1/assessments/asm_nope", { headers: bearer(adminA) }), 404);
    await expectProblem(
      await api.app.request(`/v1/assessments/asm_${"f".repeat(24)}`, { headers: bearer(adminA) }),
      404,
    );
  });

  it("never returns or logs artifact bytes, Canary values or keys", async () => {
    const { manifest, files, contents } = artifactFor(appId);
    await registerBuild(manifest);
    const res = await create(manifest.build_id, { tier: "T1", files });
    const text = await res.text();
    for (const content of contents.values()) expect(text).not.toContain(content);
    for (const file of files) expect(text).not.toContain(file.base64);
    expect(api.logger.lines.join("\n")).not.toContain(sha256(files[0]?.base64 ?? ""));
    expectNoKeyLogged(api);
  });
});
