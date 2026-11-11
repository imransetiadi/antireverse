// @vitest-environment node
import { generateKey, newId } from "@antireverse/protocol/server";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as route from "@/app/api/apps/[appId]/events/stream/route.ts";

const key = generateKey("admin").key;
const appId = newId("app");
const fetchMock = vi.fn<typeof fetch>();

function request(id: string, options: { cookie?: string; signal?: AbortSignal } = {}): NextRequest {
  const init: { headers: Record<string, string>; signal?: AbortSignal } = { headers: {} };
  if (options.cookie !== undefined) init.headers.cookie = options.cookie;
  if (options.signal !== undefined) init.signal = options.signal;
  return new NextRequest(`http://127.0.0.1:3000/api/apps/${id}/events/stream`, init);
}
const context = (id: string) => ({ params: Promise.resolve({ appId: id }) });
const get = (id: string, options?: { cookie?: string; signal?: AbortSignal }) =>
  route.GET(request(id, options), context(id));
const session = { cookie: `ar_admin=${key}` };

function sse(...chunks: string[]): Response {
  const encoder = new TextEncoder();
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk));
      controller.close();
    },
  });
  return new Response(body, { status: 200, headers: { "content-type": "text/event-stream", "x-upstream": "1" } });
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

describe("GET /api/apps/[appId]/events/stream", () => {
  it("exports the GET and HEAD handlers only — no segment config", () => {
    expect(Object.keys(route).sort()).toEqual(["GET", "HEAD"]);
  });

  it("answers HEAD with 405 and never opens an upstream stream (review finding F4)", async () => {
    const response = await route.HEAD();
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toBe("GET");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it.each([
    ["a word", "nope"],
    ["an uppercase identifier", `app_${"A".repeat(24)}`],
    ["a short identifier", "app_0123"],
    ["another kind of identifier", newId("org")],
    ["a path that tries to leave", "app_0123456789abcdef01234567%2F..%2F..%2Fv1%2Forganization"],
  ])("answers 404 for %s without calling the API", async (_label, id) => {
    const response = await get(id, session);
    expect(response.status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("answers 404 for a malformed appId even without a session", async () => {
    expect((await get("nope")).status).toBe(404);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("answers 401 without a session, without calling the API", async () => {
    for (const options of [{}, { cookie: "other=1" }, { cookie: "ar_admin=" }]) {
      const response = await get(appId, options);
      expect(response.status).toBe(401);
      expect(response.headers.get("content-type")).toContain("application/problem+json");
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("asks the API for the App's stream with the session's key, uncached", async () => {
    fetchMock.mockResolvedValueOnce(sse());
    await get(appId, session);
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).toBe(`http://api.test:9999/v1/apps/${appId}/events/stream`);
    const headers = new Headers(init?.headers);
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
    expect(headers.get("accept")).toBe("text/event-stream");
    expect(init?.cache).toBe("no-store");
  });

  it("hands the request's abort signal to the upstream fetch", async () => {
    fetchMock.mockResolvedValueOnce(sse());
    const controller = new AbortController();
    const incoming = request(appId, { ...session, signal: controller.signal });
    await route.GET(incoming, context(appId));
    const signal = fetchMock.mock.calls[0]?.[1]?.signal;
    expect(signal).toBe(incoming.signal);
    expect(signal?.aborted).toBe(false);
    controller.abort();
    expect(signal?.aborted).toBe(true);
  });

  it("forwards the upstream body as an uncached, untransformed event stream", async () => {
    const message = 'id: 1\nevent: security-event\ndata: {"a":1}\n\n';
    fetchMock.mockResolvedValueOnce(sse(": hello\n\n", message));
    const response = await get(appId, session);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("text/event-stream");
    expect(response.headers.get("cache-control")).toBe("no-cache, no-transform");
    expect(response.headers.has("x-upstream")).toBe(false);
    expect(await response.text()).toBe(`: hello\n\n${message}`);
  });

  it("passes an upstream 404 through", async () => {
    const problem = { type: "about:blank", title: "Not Found", status: 404 };
    fetchMock.mockResolvedValueOnce(
      new Response(JSON.stringify(problem), { status: 404, headers: { "content-type": "application/problem+json" } }),
    );
    const response = await get(appId, session);
    expect(response.status).toBe(404);
    expect(response.headers.get("content-type")).toBe("application/problem+json");
    expect(await response.json()).toEqual(problem);
  });

  it.each([
    [401, "application/problem+json"],
    [429, "application/problem+json"],
    [500, "text/plain; charset=utf-8"],
  ])("keeps the status and content type of an upstream %i", async (status, contentType) => {
    fetchMock.mockResolvedValueOnce(
      new Response("upstream says no", { status, headers: { "content-type": contentType } }),
    );
    const response = await get(appId, session);
    expect(response.status).toBe(status);
    expect(response.headers.get("content-type")).toBe(contentType);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.text()).toBe("upstream says no");
  });

  it("answers 502 without the key when the API cannot be reached", async () => {
    fetchMock.mockRejectedValueOnce(new TypeError(`fetch failed for Bearer ${key}`));
    const response = await get(appId, session);
    expect(response.status).toBe(502);
    expect(response.headers.get("content-type")).toContain("application/problem+json");
    expect(await response.text()).not.toContain(key);
  });
});
