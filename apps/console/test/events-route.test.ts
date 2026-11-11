// @vitest-environment node
// The list proxy the live feed reads when its stream opens (review finding F5).
import { EXAMPLE_STORED_EVENT } from "@antireverse/protocol";
import { generateKey, newId } from "@antireverse/protocol/server";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as route from "@/app/api/apps/[appId]/events/route.ts";

const key = generateKey("admin").key;
const appId = newId("app");
const fetchMock = vi.fn<typeof fetch>();

const get = (id: string, cookie?: string) =>
  route.GET(new NextRequest(`http://127.0.0.1:3000/api/apps/${id}/events`, { headers: cookie ? { cookie } : {} }), {
    params: Promise.resolve({ appId: id }),
  });

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("AR_API_URL", "http://api.test:9999");
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("GET /api/apps/[appId]/events", () => {
  it("exports the GET handler only", () => {
    expect(Object.keys(route)).toEqual(["GET"]);
  });

  it("answers 404 for a value that is not an App identifier, without calling the API", async () => {
    const response = await get("..%2F..%2Fv1%2Forganization", `ar_admin=${key}`);
    expect(response.status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("answers 401 without a session, without calling the API", async () => {
    const response = await get(appId);
    expect(response.status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns the API's list with the session's key and never caches it", async () => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ events: [EXAMPLE_STORED_EVENT] }), {
        status: 200,
        headers: { "content-type": "application/json" },
      }),
    );
    const response = await get(appId, `ar_admin=${key}`);

    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({ events: [EXAMPLE_STORED_EVENT] });
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).toBe(`http://api.test:9999/v1/apps/${appId}/events`);
    expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${key}`);
  });

  it.each([401, 404])("passes the API's %i through", async (status) => {
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ type: "about:blank", title: "x", status }), {
        status,
        headers: { "content-type": "application/problem+json" },
      }),
    );
    const response = await get(appId, `ar_admin=${key}`);
    expect(response.status).toBe(status);
    expect(response.headers.get("content-type")).toBe("application/problem+json");
  });

  it("answers 502 when the API cannot be reached, without quoting the error", async () => {
    fetchMock.mockRejectedValue(new TypeError(`fetch failed for Bearer ${key}`));
    const response = await get(appId, `ar_admin=${key}`);
    expect(response.status).toBe(502);
    expect(await response.text()).not.toContain(key);
  });
});
