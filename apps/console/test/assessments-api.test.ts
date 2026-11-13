// @vitest-environment node
import { EXAMPLE_ASSESSMENT } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  ConflictError,
  createAssessment,
  getAssessment,
  listAssessments,
  NotFoundError,
  UnauthorizedError,
} from "@/lib/api.ts";

// Slice 12a: the Console reads a Build's Reverse Assessments and one Assessment by its id.

const key = generateKey("admin").key;
const appId = EXAMPLE_ASSESSMENT.app_id;
const buildId = EXAMPLE_ASSESSMENT.build_id;
const fetchMock = vi.fn<typeof fetch>();

function json(status: number, body: unknown, contentType = "application/json"): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": contentType } });
}
function problem(status: number, extra: Record<string, unknown> = {}): Response {
  return json(status, { type: "about:blank", title: "Problem", status, ...extra }, "application/problem+json");
}
function lastCall(): { url: string; init: RequestInit; headers: Headers } {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  const init = (call[1] ?? {}) as RequestInit;
  return { url: String(call[0]), init, headers: new Headers(init.headers) };
}
async function caught(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected a rejection");
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("AR_API_URL", "http://api.test:9999");
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("api client — Assessments", () => {
  it("lists the Assessments of a Build with the session key, without caching", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { assessments: [EXAMPLE_ASSESSMENT] }));
    expect(await listAssessments(key, appId, buildId)).toEqual({ assessments: [EXAMPLE_ASSESSMENT] });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`http://api.test:9999/v1/apps/${appId}/builds/${buildId}/assessments`);
    expect(init.method ?? "GET").toBe("GET");
    expect(init.cache).toBe("no-store");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("reads one Assessment by its id, encoding the identifiers", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { assessment: EXAMPLE_ASSESSMENT }));
    expect(await getAssessment(key, EXAMPLE_ASSESSMENT.id)).toEqual({ assessment: EXAMPLE_ASSESSMENT });
    expect(lastCall().url).toBe(`http://api.test:9999/v1/assessments/${EXAMPLE_ASSESSMENT.id}`);

    fetchMock.mockResolvedValueOnce(json(200, { assessments: [] }));
    await listAssessments(key, "app/../x", "bld x");
    expect(lastCall().url).toBe("http://api.test:9999/v1/apps/app%2F..%2Fx/builds/bld%20x/assessments");
  });

  it("maps 404 and 401, and refuses a score that the results do not give", async () => {
    fetchMock.mockResolvedValueOnce(problem(404));
    expect(await caught(getAssessment(key, EXAMPLE_ASSESSMENT.id))).toBeInstanceOf(NotFoundError);
    fetchMock.mockResolvedValueOnce(problem(401));
    expect(await caught(listAssessments(key, appId, buildId))).toBeInstanceOf(UnauthorizedError);

    // An inconclusive run that carries a number breaks the contract: the Console never shows it.
    fetchMock.mockResolvedValueOnce(json(200, { assessments: [{ ...EXAMPLE_ASSESSMENT, rrs: 40 }] }));
    const error = await caught(listAssessments(key, appId, buildId));
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(502);
  });

  it("asks for a new Assessment of the kept artifact with the tier alone, and reads the queued one", async () => {
    const queued = {
      ...EXAMPLE_ASSESSMENT,
      status: "queued",
      results: [],
      rrs: null,
      inconclusive_reason: null,
      inconclusive_code: null,
      started_at: null,
      finished_at: null,
    };
    fetchMock.mockResolvedValueOnce(json(202, { assessment: queued }));
    expect(await createAssessment(key, appId, buildId, { tier: "T2" })).toEqual({ assessment: queued });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`http://api.test:9999/v1/apps/${appId}/builds/${buildId}/assessments`);
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ tier: "T2" });
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("carries the reason of a 409 when no artifact is kept", async () => {
    fetchMock.mockResolvedValueOnce(problem(409, { reason: "artifact-required" }));
    const error = await caught(createAssessment(key, appId, buildId, { tier: "T1" }));
    expect(error).toBeInstanceOf(ConflictError);
    expect((error as ConflictError).reason).toBe("artifact-required");
  });
});
