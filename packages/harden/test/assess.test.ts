// Slice 12a — the assessment client: the upload limits checked before sending (25 MB decoded, 1,000 files), the
// POST of the protected files to /v1/apps/:appId/builds/:buildId/assessments, and the Console link.
import {
  ASSESSMENT_LIMITS,
  type Assessment,
  CreateAssessmentRequestSchema,
  EXAMPLE_ASSESSMENT,
  EXAMPLE_BUILD,
} from "@antireverse/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";
import { assessmentUploadProblem, consoleBuildUrl, requestAssessment } from "../src/assess.ts";

const KEY = "aro_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const ENDPOINT = "https://api.example.test/";
const APP = EXAMPLE_BUILD.app_id;
const BUILD = EXAMPLE_BUILD.build_id;

/** The example Assessment as the API returns it right after the request: queued. */
const QUEUED: Assessment = {
  ...EXAMPLE_ASSESSMENT,
  build_id: BUILD,
  app_id: APP,
  status: "queued",
  results: [],
  rrs: null,
  inconclusive_reason: null,
  inconclusive_code: null,
  renormalised: false,
  started_at: null,
  finished_at: null,
  failure_reason: null,
};

afterEach(() => {
  vi.unstubAllGlobals();
});

function stub(status: number, body: unknown): Array<{ url: string; init: RequestInit }> {
  const calls: Array<{ url: string; init: RequestInit }> = [];
  vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
    calls.push({ url, init });
    return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
  });
  return calls;
}

const FILES = [
  { path: "a.mjs", code: "export const a = 1;\n" },
  { path: "lib/b.mjs", code: "export const b = 'é';\n" },
];

describe("assessmentUploadProblem", () => {
  it("accepts files within the limits", () => {
    expect(assessmentUploadProblem(FILES)).toBeNull();
  });

  it("refuses more than 1,000 files, naming the limit", () => {
    const files = Array.from({ length: ASSESSMENT_LIMITS.filesMax + 1 }, (_, i) => ({ path: `f${i}.mjs`, code: "1" }));
    expect(assessmentUploadProblem(files)).toMatch(/1,001 files.*at most 1,000/);
    expect(assessmentUploadProblem(files.slice(1))).toBeNull();
  });

  it("refuses more than 25 MB in total (UTF-8 bytes), naming the limit", () => {
    const half = "x".repeat(ASSESSMENT_LIMITS.artifactBytesMax / 2);
    expect(
      assessmentUploadProblem([
        { path: "a.mjs", code: half },
        { path: "b.mjs", code: half },
      ]),
    ).toBeNull();
    const problem = assessmentUploadProblem([
      { path: "a.mjs", code: half },
      { path: "b.mjs", code: `${half}x` },
    ]);
    expect(problem).toMatch(/26,214,401 bytes.*at most 25 MB/);
  });

  it("refuses a path the request schema refuses (over 256 characters)", () => {
    expect(assessmentUploadProblem([{ path: `${"p".repeat(300)}.mjs`, code: "1" }])).toMatch(/path/i);
  });
});

describe("requestAssessment", () => {
  it("POSTs { tier, files: [{ path, base64 }] } with a Bearer key and returns the Assessment", async () => {
    const calls = stub(202, { assessment: QUEUED });
    const result = await requestAssessment({
      endpoint: ENDPOINT,
      key: KEY,
      appId: APP,
      buildId: BUILD,
      tier: "T2",
      files: FILES,
    });
    expect(result).toEqual({ assessment: QUEUED });
    expect(calls.length).toBe(1);
    expect(calls[0]?.url).toBe(`https://api.example.test/v1/apps/${APP}/builds/${BUILD}/assessments`);
    expect(calls[0]?.init.method).toBe("POST");
    expect(new Headers(calls[0]?.init.headers).get("authorization")).toBe(`Bearer ${KEY}`);
    const body = JSON.parse(String(calls[0]?.init.body));
    expect(body).toEqual({
      tier: "T2",
      files: FILES.map((f) => ({ path: f.path, base64: Buffer.from(f.code, "utf8").toString("base64") })),
    });
    expect(CreateAssessmentRequestSchema.safeParse(body).success).toBe(true);
    expect(JSON.stringify(body)).not.toContain(KEY);
  });

  it("returns the API's problem detail (never throws) when the request is refused", async () => {
    stub(400, { type: "about:blank", title: "Bad Request", status: 400, detail: "The artifact does not match." });
    const result = await requestAssessment({
      endpoint: ENDPOINT,
      key: KEY,
      appId: APP,
      buildId: BUILD,
      tier: "T1",
      files: FILES,
    });
    expect(result).toEqual({ error: "The artifact does not match." });
  });

  it("returns an error on a response that is not an Assessment", async () => {
    stub(202, { assessment: { id: "nope" } });
    const result = await requestAssessment({
      endpoint: ENDPOINT,
      key: KEY,
      appId: APP,
      buildId: BUILD,
      tier: "T1",
      files: FILES,
    });
    expect(result).toEqual({ error: "the API returned a response that was not an Assessment" });
  });

  it("returns an error on a network failure, without the key", async () => {
    vi.stubGlobal("fetch", async () => {
      throw Object.assign(new Error(`boom ${KEY}`), { code: "ECONNREFUSED" });
    });
    const result = await requestAssessment({
      endpoint: ENDPOINT,
      key: KEY,
      appId: APP,
      buildId: BUILD,
      tier: "T1",
      files: FILES,
    });
    expect(result).toEqual({ error: "the API could not be reached (ECONNREFUSED)" });
  });

  it("never sends when the files are over a limit", async () => {
    const calls = stub(202, { assessment: QUEUED });
    const files = Array.from({ length: 1001 }, (_, i) => ({ path: `f${i}.mjs`, code: "1" }));
    const result = await requestAssessment({
      endpoint: ENDPOINT,
      key: KEY,
      appId: APP,
      buildId: BUILD,
      tier: "T1",
      files,
    });
    expect("error" in result).toBe(true);
    expect(calls.length).toBe(0);
  });
});

describe("consoleBuildUrl", () => {
  it("is the Build page under the Console base, without a doubled slash", () => {
    expect(consoleBuildUrl("http://127.0.0.1:3000/", APP, BUILD)).toBe(
      `http://127.0.0.1:3000/apps/${APP}/builds/${BUILD}`,
    );
    expect(consoleBuildUrl("https://console.example.test", APP, BUILD)).toBe(
      `https://console.example.test/apps/${APP}/builds/${BUILD}`,
    );
  });
});
