// @vitest-environment node
// Slice 18a: the export of the audit log goes through the Console, which checks the session and forwards the API's
// NDJSON as a download. The admin key never reaches the browser.
import { EXAMPLE_AUDIT_ENTRY } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as route from "@/app/api/audit/export/route.ts";

const key = generateKey("admin").key;
const fetchMock = vi.fn<typeof fetch>();
const get = (cookie?: string, headers: Record<string, string> = {}) =>
  route.GET(
    new NextRequest("http://127.0.0.1:3000/api/audit/export", {
      headers: { host: "127.0.0.1:3000", ...(cookie ? { cookie } : {}), ...headers },
    }),
  );

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("AR_API_URL", "http://api.test:9999");
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("GET /api/audit/export", () => {
  it("exports the GET handler only", () => {
    expect(Object.keys(route)).toEqual(["GET"]);
  });

  it("refuses a cross-site request with 403 and no API call (review 18b, L3)", async () => {
    for (const headers of <Record<string, string>[]>[
      { "sec-fetch-site": "cross-site" },
      { origin: "https://evil.example" },
    ]) {
      const response = await get(`ar_admin=${key}`, headers);
      expect(response.status).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
    fetchMock.mockResolvedValue(new Response("", { status: 200 }));
    expect(
      (await get(`ar_admin=${key}`, { "sec-fetch-site": "same-origin", origin: "http://127.0.0.1:3000" })).status,
    ).toBe(200);
  });

  it("sends a browser without a session home, without calling the API", async () => {
    const response = await get();
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("streams the API's NDJSON as an attachment, with the session's key, never cached", async () => {
    const line = `${JSON.stringify(EXAMPLE_AUDIT_ENTRY)}\n`;
    fetchMock.mockResolvedValue(
      new Response(line, { status: 200, headers: { "content-type": "application/x-ndjson" } }),
    );
    const response = await get(`ar_admin=${key}`);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/x-ndjson");
    expect(response.headers.get("content-disposition")).toBe('attachment; filename="airverse-audit.ndjson"');
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.text()).toBe(line);
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).toBe("http://api.test:9999/v1/audit/export");
    expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${key}`);
  });

  const refusal = (status: number, headers: Record<string, string> = {}) =>
    new Response(JSON.stringify({ type: "about:blank", title: "Refused", status }), {
      status,
      headers: { "content-type": "application/problem+json", ...headers },
    });

  it("goes back to the Audit log with a notice when the export was asked for too often, never as a download", async () => {
    fetchMock.mockResolvedValue(refusal(429, { "retry-after": "30" }));
    let response = await get(`ar_admin=${key}`);
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/settings/audit?export=limited&retry=30");
    expect(response.headers.get("content-disposition")).toBeNull();
    fetchMock.mockResolvedValue(refusal(429, { "retry-after": "soon" }));
    response = await get(`ar_admin=${key}`);
    expect(response.headers.get("location")).toBe("/settings/audit?export=limited");
  });

  it("sends a key the API no longer accepts to sign in, and any other failure back with a notice", async () => {
    fetchMock.mockResolvedValue(refusal(401));
    let response = await get(`ar_admin=${key}`);
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/sign-in?reason=expired");
    fetchMock.mockResolvedValue(refusal(500));
    response = await get(`ar_admin=${key}`);
    expect(response.headers.get("location")).toBe("/settings/audit?export=failed");
    fetchMock.mockRejectedValue(new Error(`connect ECONNREFUSED with ${key}`));
    response = await get(`ar_admin=${key}`);
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/settings/audit?export=failed");
    expect(await response.text()).not.toContain(key);
  });
});
