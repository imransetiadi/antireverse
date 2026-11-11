// @vitest-environment node
import { EXAMPLE_FINDING, EXAMPLE_VIRTUAL_PATCH } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  ConflictError,
  listPatches,
  NotFoundError,
  setPatchMode,
  UnauthorizedError,
  ValidationError,
} from "@/lib/api.ts";

// Slice 20: the patch endpoints of the API client. Every response is validated against the contract.
const { key } = generateKey("admin");
const API = "http://api.test:9999";
const appId = EXAMPLE_FINDING.app_id;
const PATCH = {
  id: EXAMPLE_VIRTUAL_PATCH.id,
  title: EXAMPLE_VIRTUAL_PATCH.title,
  advisories: [...EXAMPLE_VIRTUAL_PATCH.advisories],
  package: EXAMPLE_VIRTUAL_PATCH.package,
  mode: "monitor",
  active: true,
  shipped: true,
  findings: [EXAMPLE_FINDING.id],
  hits_24h: 4,
  last_hit: "2026-11-11T14:05:00.000Z",
};

const fetchMock = vi.fn<typeof fetch>();
const json = (status: number, body: unknown, contentType = "application/json"): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": contentType } });
const problem = (status: number, extra: Record<string, unknown> = {}): Response =>
  json(status, { type: "about:blank", title: "Problem", status, ...extra }, "application/problem+json");
function lastCall(): { url: string; init: RequestInit; headers: Headers; body: unknown } {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  const init = (call[1] ?? {}) as RequestInit;
  const body = typeof init.body === "string" ? JSON.parse(init.body) : undefined;
  return { url: String(call[0]), init, headers: new Headers(init.headers), body };
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
  vi.stubEnv("AR_API_URL", API);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("api client — virtual patches", () => {
  it("lists the patches of an App and Environment with the session key, without caching", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { patches: [PATCH] }));
    expect(await listPatches(key, appId, "production")).toEqual({ patches: [PATCH] });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/apps/${appId}/patches?environment=production`);
    expect(init.method ?? "GET").toBe("GET");
    expect(init.cache).toBe("no-store");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("refuses a response outside the contract", async () => {
    for (const bad of [
      { ...PATCH, mode: "block" },
      { ...PATCH, id: "not-a-patch" },
      { ...PATCH, hits_24h: -1 },
      { ...PATCH, shipped: undefined },
      { ...PATCH, findings: ["nope"] },
    ]) {
      fetchMock.mockResolvedValueOnce(json(200, { patches: [bad] }));
      const error = await caught(listPatches(key, appId, "production"));
      expect(error).toBeInstanceOf(ApiError);
      expect((error as ApiError).status).toBe(502);
    }
  });

  it("sets the mode with POST, the Environment and the confirmation, and ignores the response body", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { patch: { anything: true } }));
    await setPatchMode(key, appId, PATCH.id, { environment: "staging", mode: "enforce", confirm: PATCH.id });
    const { url, init, body } = lastCall();
    expect(url).toBe(`${API}/v1/apps/${appId}/patches/${PATCH.id}/mode`);
    expect(init.method).toBe("POST");
    expect(body).toEqual({ environment: "staging", mode: "enforce", confirm: PATCH.id });
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));
    await setPatchMode(key, appId, PATCH.id, { environment: "staging", mode: "monitor" });
    expect(lastCall().body).toEqual({ environment: "staging", mode: "monitor" });
  });

  it("encodes the identifiers in the path", async () => {
    fetchMock.mockResolvedValue(json(200, { patches: [] }));
    await listPatches(key, "app/../x", "production");
    expect(lastCall().url).toBe(`${API}/v1/apps/app%2F..%2Fx/patches?environment=production`);
    await setPatchMode(key, appId, "vp/../x", { environment: "production", mode: "monitor" });
    expect(lastCall().url).toBe(`${API}/v1/apps/${appId}/patches/vp%2F..%2Fx/mode`);
  });

  it("maps 404, 409, 401 and 400 to their errors", async () => {
    fetchMock.mockResolvedValueOnce(problem(404));
    expect(await caught(listPatches(key, appId, "production"))).toBeInstanceOf(NotFoundError);
    fetchMock.mockResolvedValueOnce(problem(409));
    expect(
      await caught(setPatchMode(key, appId, PATCH.id, { environment: "production", mode: "monitor" })),
    ).toBeInstanceOf(ConflictError);
    fetchMock.mockResolvedValueOnce(problem(401));
    expect(await caught(listPatches(key, appId, "production"))).toBeInstanceOf(UnauthorizedError);
    fetchMock.mockResolvedValueOnce(problem(400, { errors: [{ path: "confirm", message: "required" }] }));
    const error = await caught(setPatchMode(key, appId, PATCH.id, { environment: "production", mode: "enforce" }));
    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ValidationError).errors).toEqual([{ path: "confirm", message: "required" }]);
  });
});
