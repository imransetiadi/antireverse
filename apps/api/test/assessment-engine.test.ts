import { fileURLToPath } from "node:url";
import {
  AssessmentResponseSchema,
  type Canary,
  CreateAssessmentResponseSchema,
  STAND_IN_MODEL,
} from "@antireverse/protocol";
import { newId, routesDigest } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { proveAssessor } from "../src/assess/prove-assessor.ts";
import { type AssessmentRunner, createAssessmentRunner, FAILURE_REASONS } from "../src/assess/runner.ts";
import { type OwnedDb, openDb } from "../src/db/db.ts";
import { artifactFor, sha256 } from "./fake-assessor.ts";
import { bearer, createAppFor, createOrganization, json, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 12a: the real engine (`packages/prove`, stand-in agent) end to end through the API's queue and runner: register
// a Build with a planted Canary and a route inventory, upload its artifact, and read the finished Assessment.

describe("Assessment through the real engine", () => {
  let db: OwnedDb;
  let api: TestApi;
  let runner: AssessmentRunner;

  beforeAll(async () => {
    db = await openDb();
    runner = createAssessmentRunner({ db, assessor: proveAssessor() });
    api = await makeTestApi({ db, assessor: proveAssessor(), assessments: runner });
    await runner.start();
  });
  afterAll(async () => {
    await runner.stop();
    await api.close();
  });

  it("runs a T1 Assessment of an unprotected artifact: W2 achieved on the planted Canary, inconclusive", async () => {
    const org = await createOrganization(api, "A");
    const admin = org.admin_key.key;
    const appId = (await createAppFor(api, admin, { name: "Shop" })).app.id;
    const canary: Canary = {
      id: newId("cny"),
      kind: "key",
      value: `ak_live_${"R".repeat(24)}${newId("cny").slice(-8)}`,
    };
    const routes = ["GET /api/products", "POST /api/cart", "POST /api/checkout"];
    const text = `const key = "${canary.value}";fetch("/api/products");fetch("/api/cart",{method:"POST"});`;
    const base = artifactFor(appId);
    const manifest = {
      ...base.manifest,
      artifacts: [{ path: "dist/index.js", sha256: sha256(text), bytes: Buffer.byteLength(text) }],
      canaries: [canary],
      route_count: routes.length,
      routes_digest: routesDigest(routes),
    };
    expect((await api.app.request(`/v1/apps/${appId}/builds`, json({ manifest, routes }, bearer(admin)))).status).toBe(
      201,
    );
    const files = [{ path: "dist/index.js", base64: Buffer.from(text).toString("base64") }];
    const res = await api.app.request(
      `/v1/apps/${appId}/builds/${manifest.build_id}/assessments`,
      json({ tier: "T1", files }, bearer(admin)),
    );
    expect(res.status).toBe(202);
    const { assessment } = CreateAssessmentResponseSchema.parse(await res.json());
    await runner.idle();

    const read = await api.app.request(`/v1/assessments/${assessment.id}`, { headers: bearer(admin) });
    const body = await read.text();
    expect(body).not.toContain(canary.value);
    expect(body).not.toContain("POST /api/checkout");
    const done = AssessmentResponseSchema.parse(JSON.parse(body)).assessment;
    expect(done.status).toBe("inconclusive");
    expect(done.inconclusive_code).toBe("excluded_over_limit");
    expect(done.scope).toMatchObject({ model: STAND_IN_MODEL, tier: "T1" });
    const by = Object.fromEntries(done.results.map((result) => [result.objective, result]));
    expect(by.W2).toMatchObject({ result: "achieved", tier: "T1" });
    expect(by.W2?.evidence.recovered).toContainEqual({ kind: "canary", canary_id: canary.id });
    // Slice 12b: no logic designated, so W3 is excluded (0.25 > 20 %); W4 is judged by the tamper verifier.
    expect(by.W3).toMatchObject({ result: "not_attempted", reason: "not_designated" });
    expect(by.W4?.result).not.toBe("not_attempted");
    expect(by.W1?.result).not.toBe("not_attempted");
    expect(by.W5?.result).not.toBe("achieved");
    // The referenced calls are stored and returned on the detail, never with a Canary value.
    const detail = AssessmentResponseSchema.parse(JSON.parse(body));
    expect(detail.calls?.length).toBeGreaterThan(0);
    expect(detail.call_totals?.count).toBeGreaterThanOrEqual(detail.calls?.length ?? 0);
    expect(JSON.stringify(detail.calls)).not.toContain(canary.value);
  });

  it("answers API requests promptly while an Assessment's agent blocks its worker, and stops it at once", async () => {
    const own = await openDb();
    const agents = fileURLToPath(new URL("./fixtures/agents.ts", import.meta.url));
    const blocking = proveAssessor({
      agent: { module: agents, export: "blocking" },
      identity: { name: "blocking", version: "0.0.1", model: "test-model" },
    });
    const busy = createAssessmentRunner({ db: own, assessor: blocking });
    const local = await makeTestApi({ db: own, assessor: blocking, assessments: busy });
    try {
      await busy.start();
      const org = await createOrganization(local, "Busy");
      const admin = org.admin_key.key;
      const appId = (await createAppFor(local, admin, { name: "Shop" })).app.id;
      const { manifest, files } = artifactFor(appId);
      expect((await local.app.request(`/v1/apps/${appId}/builds`, json({ manifest }, bearer(admin)))).status).toBe(201);
      const res = await local.app.request(
        `/v1/apps/${appId}/builds/${manifest.build_id}/assessments`,
        json({ tier: "T1", files }, bearer(admin)),
      );
      const { assessment } = CreateAssessmentResponseSchema.parse(await res.json());
      const status = async () =>
        AssessmentResponseSchema.parse(
          await (await local.app.request(`/v1/assessments/${assessment.id}`, { headers: bearer(admin) })).json(),
        ).assessment;
      for (let tries = 0; (await status()).status !== "running" && tries < 100; tries++) {
        await new Promise((resolve) => setTimeout(resolve, 20));
      }
      await new Promise((resolve) => setTimeout(resolve, 300));
      const asked = performance.now();
      expect((await local.app.request("/healthz")).status).toBe(200);
      expect((await status()).status).toBe("running");
      expect(performance.now() - asked).toBeLessThan(1_000);

      const stopping = performance.now();
      await busy.stop();
      expect(performance.now() - stopping).toBeLessThan(2_000);
      expect(await status()).toMatchObject({ status: "failed", failure_reason: FAILURE_REASONS.interrupted });
    } finally {
      await busy.stop();
      await local.close();
    }
  });
});
