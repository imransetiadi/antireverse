// @vitest-environment node
import { EXAMPLE_BUILD, EXAMPLE_CANARIES } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, getBuild, listBuilds, NotFoundError, UnauthorizedError, ValidationError } from "@/lib/api.ts";

const admin = generateKey("admin");
const key = admin.key;
const appId = EXAMPLE_BUILD.app_id;
const buildId = EXAMPLE_BUILD.build_id;
const base = `http://api.test:9999/v1/apps/${appId}/builds`;

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

describe("api client — Build requests", () => {
  it("lists the Builds of an App with the session key, without caching", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { builds: [EXAMPLE_BUILD] }));
    expect(await listBuilds(key, appId)).toEqual({ builds: [EXAMPLE_BUILD] });
    const { url, init, headers } = lastCall();
    expect(url).toBe(base);
    expect(init.method ?? "GET").toBe("GET");
    expect(init.cache).toBe("no-store");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("reads one Build by its id", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { build: EXAMPLE_BUILD }));
    expect(await getBuild(key, appId, buildId)).toEqual({ build: EXAMPLE_BUILD });
    expect(lastCall().url).toBe(`${base}/${buildId}`);
  });

  it("encodes the identifiers in the path", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { build: EXAMPLE_BUILD }));
    await getBuild(key, "app/../x", "bld weird");
    expect(lastCall().url).toBe("http://api.test:9999/v1/apps/app%2F..%2Fx/builds/bld%20weird");
  });

  it("maps 404 to NotFoundError for an unknown or foreign Build", async () => {
    fetchMock.mockResolvedValueOnce(problem(404));
    const error = await caught(getBuild(key, appId, buildId));
    expect(error).toBeInstanceOf(NotFoundError);
    expect((error as ApiError).status).toBe(404);

    fetchMock.mockResolvedValueOnce(problem(404));
    expect(await caught(listBuilds(key, appId))).toBeInstanceOf(NotFoundError);
  });

  it("maps 401 to UnauthorizedError", async () => {
    fetchMock.mockResolvedValueOnce(problem(401));
    expect(await caught(listBuilds(key, appId))).toBeInstanceOf(UnauthorizedError);
  });

  it("turns a response that fails the schema into ApiError, not a Validation or NotFound error", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { builds: [{ ...EXAMPLE_BUILD, format: 2 }] }));
    const listError = await caught(listBuilds(key, appId));
    expect(listError).toBeInstanceOf(ApiError);
    expect(listError).not.toBeInstanceOf(ValidationError);
    expect((listError as ApiError).status).toBe(502);

    fetchMock.mockResolvedValueOnce(json(200, { build: { ...EXAMPLE_BUILD, costs: { size_overhead_pct: "huge" } } }));
    const buildError = await caught(getBuild(key, appId, buildId));
    expect(buildError).toBeInstanceOf(ApiError);
    expect((buildError as ApiError).status).toBe(502);
  });

  it("accepts a Build with a leak-scan summary and value-less Canaries (id and kind)", async () => {
    const canaries = EXAMPLE_CANARIES.map(({ id, kind }) => ({ id, kind }));
    const build = { ...EXAMPLE_BUILD, leak_scan: { status: "suppressed", suppressed: 2 }, canaries };
    fetchMock.mockResolvedValueOnce(json(200, { build }));
    expect(await getBuild(key, appId, buildId)).toEqual({ build });

    fetchMock.mockResolvedValueOnce(json(200, { builds: [build, EXAMPLE_BUILD] }));
    expect(await listBuilds(key, appId)).toEqual({ builds: [build, EXAMPLE_BUILD] });
  });

  it("drops a Canary value should the API ever send one", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { build: { ...EXAMPLE_BUILD, canaries: EXAMPLE_CANARIES } }));
    const { build } = await getBuild(key, appId, buildId);
    expect(build.canaries).toEqual(EXAMPLE_CANARIES.map(({ id, kind }) => ({ id, kind })));
    expect(JSON.stringify(build)).not.toContain("ak_live_");
  });

  it("never puts a key into a thrown message, even when the API echoes one", async () => {
    const echo = `The key ${key} was refused`;
    for (const response of [problem(404, { title: echo, detail: echo }), problem(500, { title: echo })]) {
      fetchMock.mockResolvedValueOnce(response);
      const error = await caught(getBuild(key, appId, buildId));
      const visible = JSON.stringify([error.message, error.stack]);
      expect(visible).not.toContain(key);
      expect(visible).not.toContain(key.slice(4));
    }
  });
});
