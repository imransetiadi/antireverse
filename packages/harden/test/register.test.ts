import {
  EXAMPLE_BUILD,
  EXAMPLE_BUILD_MANIFEST,
  EXAMPLE_FINDINGS_SUMMARY,
  EXAMPLE_INVENTORY,
  EXAMPLE_ROUTE_INVENTORY,
} from "@antireverse/protocol";
import { afterEach, describe, expect, it, vi } from "vitest";
import { registerBuild } from "../src/register.ts";

const KEY = "aro_abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQ";
const ENDPOINT = "https://api.example.test";
const APP = EXAMPLE_BUILD_MANIFEST.app_id;

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("registerBuild", () => {
  it("POSTs the manifest and nothing else to the right URL with a Bearer key", async () => {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    vi.stubGlobal("fetch", async (url: string, init: RequestInit) => {
      calls.push({ url, init });
      return new Response(JSON.stringify({ build: EXAMPLE_BUILD }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    });

    const result = await registerBuild({ endpoint: ENDPOINT, key: KEY, appId: APP, manifest: EXAMPLE_BUILD_MANIFEST });
    expect("build" in result).toBe(true);
    if ("build" in result) expect(result.build.build_id).toBe(EXAMPLE_BUILD.build_id);

    expect(calls.length).toBe(1);
    const call = calls[0];
    expect(call?.url).toBe(`${ENDPOINT}/v1/apps/${APP}/builds`);
    expect(call?.init.method).toBe("POST");
    const headers = new Headers(call?.init.headers);
    expect(headers.get("authorization")).toBe(`Bearer ${KEY}`);
    // The body is exactly { manifest } — no key, no extra fields.
    const body = JSON.parse(String(call?.init.body));
    expect(Object.keys(body)).toEqual(["manifest"]);
    expect(body.manifest).toEqual(EXAMPLE_BUILD_MANIFEST);
    expect(JSON.stringify(body)).not.toContain(KEY);
  });

  it("returns an error (never throws) when the server rejects", async () => {
    vi.stubGlobal(
      "fetch",
      async () =>
        new Response(JSON.stringify({ type: "about:blank", title: "conflict", status: 409 }), {
          status: 409,
          headers: { "content-type": "application/problem+json" },
        }),
    );
    const result = await registerBuild({ endpoint: ENDPOINT, key: KEY, appId: APP, manifest: EXAMPLE_BUILD_MANIFEST });
    expect("error" in result).toBe(true);
    if ("error" in result) expect(result.error).toMatch(/conflict|409/i);
  });

  it("returns an error (never throws) on a network failure, and never leaks the key", async () => {
    vi.stubGlobal("fetch", async () => {
      throw new Error("ECONNREFUSED");
    });
    const result = await registerBuild({ endpoint: ENDPOINT, key: KEY, appId: APP, manifest: EXAMPLE_BUILD_MANIFEST });
    expect("error" in result).toBe(true);
    if ("error" in result) expect(result.error).not.toContain(KEY);
  });
});

describe("registerBuild — components and findings (slice 19)", () => {
  it("sends components beside the Manifest and returns the findings summary", async () => {
    let body: unknown;
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      body = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ build: EXAMPLE_BUILD, findings: EXAMPLE_FINDINGS_SUMMARY }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    });
    const components = [...EXAMPLE_INVENTORY.components];
    const result = await registerBuild({
      endpoint: ENDPOINT,
      key: KEY,
      appId: APP,
      manifest: EXAMPLE_BUILD_MANIFEST,
      components,
    });
    expect(body).toEqual({ manifest: EXAMPLE_BUILD_MANIFEST, components });
    expect("build" in result && result.findings).toEqual(EXAMPLE_FINDINGS_SUMMARY);
  });

  it("returns no findings when the response has none", async () => {
    vi.stubGlobal(
      "fetch",
      async () =>
        new Response(JSON.stringify({ build: EXAMPLE_BUILD }), {
          status: 201,
          headers: { "content-type": "application/json" },
        }),
    );
    const result = await registerBuild({ endpoint: ENDPOINT, key: KEY, appId: APP, manifest: EXAMPLE_BUILD_MANIFEST });
    expect("build" in result && result.findings).toBeUndefined();
  });
});

describe("registerBuild — route inventory (slice 12a)", () => {
  it("sends the routes beside the Manifest (and the components when given)", async () => {
    let body: unknown;
    vi.stubGlobal("fetch", async (_url: string, init: RequestInit) => {
      body = JSON.parse(String(init.body));
      return new Response(JSON.stringify({ build: EXAMPLE_BUILD }), {
        status: 201,
        headers: { "content-type": "application/json" },
      });
    });
    const routes = [...EXAMPLE_ROUTE_INVENTORY];
    const components = [...EXAMPLE_INVENTORY.components];
    await registerBuild({ endpoint: ENDPOINT, key: KEY, appId: APP, manifest: EXAMPLE_BUILD_MANIFEST, routes });
    expect(body).toEqual({ manifest: EXAMPLE_BUILD_MANIFEST, routes });
    await registerBuild({
      endpoint: ENDPOINT,
      key: KEY,
      appId: APP,
      manifest: EXAMPLE_BUILD_MANIFEST,
      components,
      routes,
    });
    expect(body).toEqual({ manifest: EXAMPLE_BUILD_MANIFEST, components, routes });
  });
});
