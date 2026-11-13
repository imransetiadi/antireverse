import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AssessmentResponseSchema,
  CreateAppResponseSchema,
  CreateAssessmentResponseSchema,
  CreateOrganizationResponseSchema,
} from "@antireverse/protocol";
import { afterAll, describe, expect, it } from "vitest";
import { FAILURE_REASONS } from "../src/assess/runner.ts";
import { startApi } from "../src/server.ts";
import { artifactFor, fakeAssessor, fakeScope, scoredResults } from "./fake-assessor.ts";
import { captureLogger, within } from "./helpers.ts";

// Slice 12a: `startApi` starts the Assessment runner and stops it on close; a restart on the same data directory fails
// the Assessments the stopped process left running and resumes the queued ones.

describe("Assessments in a running API", () => {
  const root = mkdtempSync(join(tmpdir(), "ar-api-assess-"));
  const dataDir = join(root, "pg");
  afterAll(() => rmSync(root, { recursive: true, force: true }));

  it("runs Assessments, fails running ones on close, and resumes queued ones after a restart", async () => {
    const first = fakeAssessor();
    let api = await startApi({ dataDir, smtp: null, logger: captureLogger(), assessor: first });
    const post = (path: string, body: unknown, key?: string) =>
      fetch(`${api.url}${path}`, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          ...(key === undefined ? {} : { authorization: `Bearer ${key}` }),
        },
        body: JSON.stringify(body),
      });
    const get = async (id: string, key: string) =>
      AssessmentResponseSchema.parse(
        await (await fetch(`${api.url}/v1/assessments/${id}`, { headers: { authorization: `Bearer ${key}` } })).json(),
      ).assessment;

    const org = CreateOrganizationResponseSchema.parse(await (await post("/v1/organizations", { name: "A" })).json());
    const admin = org.admin_key.key;
    const app = CreateAppResponseSchema.parse(await (await post("/v1/apps", { name: "Shop" }, admin)).json());
    const queue = async () => {
      const { manifest, files } = artifactFor(app.app.id);
      expect((await post(`/v1/apps/${app.app.id}/builds`, { manifest }, admin)).status).toBe(201);
      const res = await post(
        `/v1/apps/${app.app.id}/builds/${manifest.build_id}/assessments`,
        { tier: "T1", files },
        admin,
      );
      expect(res.status).toBe(202);
      return CreateAssessmentResponseSchema.parse(await res.json()).assessment;
    };

    const running = await queue();
    const run = await within(first.run(0), 5_000, "the first run");
    expect(run.input.tier).toBe("T1");
    const queued = await queue();
    expect((await get(queued.id, admin)).status).toBe("queued");
    await api.close();
    expect(run.input.signal.aborted).toBe(true);

    const second = fakeAssessor();
    api = await startApi({ dataDir, smtp: null, logger: captureLogger(), assessor: second });
    expect(await get(running.id, admin)).toMatchObject({
      status: "failed",
      failure_reason: FAILURE_REASONS.interrupted,
    });
    const resumed = await within(second.run(0), 5_000, "the resumed run");
    resumed.resolve({ results: scoredResults(), scope: fakeScope("T1") });
    await api.assessments.idle();
    expect((await get(queued.id, admin)).status).toBe("scored");
    await api.close();
  });
});
