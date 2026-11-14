// @vitest-environment node
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { OPS_TOKEN } from "./helpers/slo.ts";

// Slice 18d: the operator session — its own cookie, apart from the tenant session: httpOnly, SameSite=Strict, scoped to
// `/ops`, Secure in production as the tenant cookie is. A tenant session never stands in for it.

const store = vi.hoisted(() => ({ get: vi.fn(), set: vi.fn(), delete: vi.fn() }));
const requestHeaders = vi.hoisted(() => ({ value: new Headers() }));
vi.mock("next/headers", () => ({ cookies: async () => store, headers: async () => requestHeaders.value }));

import { GET as expired } from "@/app/ops/expired/route.ts";
import {
  clearOpsSession,
  isCrossSiteForm,
  OPS_COOKIE,
  OPS_COOKIE_PATH,
  OPS_SESSION_MAX_AGE_SECONDS,
  OPS_TOKEN_PATTERN,
  readOpsSession,
  writeOpsSession,
} from "@/lib/ops-session.ts";

beforeEach(() => {
  store.get.mockReset();
  store.set.mockReset();
  store.delete.mockReset();
});
afterEach(() => vi.unstubAllEnvs());

describe("operator session", () => {
  it("is the cookie ar_ops on /ops, apart from the tenant cookie ar_admin", () => {
    expect(OPS_COOKIE).toBe("ar_ops");
    expect(OPS_COOKIE_PATH).toBe("/ops");
    expect(OPS_SESSION_MAX_AGE_SECONDS).toBe(28_800);
  });

  it("writes the token httpOnly, SameSite=Strict, on /ops only, Secure only in production", async () => {
    vi.stubEnv("NODE_ENV", "development");
    await writeOpsSession(OPS_TOKEN);
    expect(store.set).toHaveBeenCalledWith("ar_ops", OPS_TOKEN, {
      httpOnly: true,
      sameSite: "strict",
      path: "/ops",
      secure: false,
      maxAge: 28_800,
    });
    vi.stubEnv("NODE_ENV", "production");
    await writeOpsSession(OPS_TOKEN);
    expect(store.set.mock.calls[1]?.[2]).toMatchObject({ secure: true });
  });

  it("reads the token from ar_ops only: a tenant session does not grant it", async () => {
    store.get.mockImplementation((name: string) =>
      name === "ar_admin" ? { name, value: "aro_tenantkey" } : undefined,
    );
    expect(await readOpsSession()).toBeUndefined();
    expect(store.get).toHaveBeenCalledWith("ar_ops");
    store.get.mockImplementation((name: string) => (name === "ar_ops" ? { name, value: OPS_TOKEN } : undefined));
    expect(await readOpsSession()).toBe(OPS_TOKEN);
  });

  it("treats an empty or malformed cookie as no session", async () => {
    store.get.mockReturnValueOnce({ name: "ar_ops", value: "" });
    expect(await readOpsSession()).toBeUndefined();
    store.get.mockReturnValueOnce({ name: "ar_ops", value: "short" });
    expect(await readOpsSession()).toBeUndefined();
    store.get.mockReturnValueOnce({ name: "ar_ops", value: `${"x".repeat(40)} y` });
    expect(await readOpsSession()).toBeUndefined();
  });

  it("clears the cookie on its own path", async () => {
    await clearOpsSession();
    expect(store.delete).toHaveBeenCalledWith({ name: "ar_ops", path: "/ops" });
  });

  it("accepts tokens shaped as the API requires them: 32 to 512 printable characters without spaces", () => {
    expect(OPS_TOKEN_PATTERN.test(OPS_TOKEN)).toBe(true);
    expect(OPS_TOKEN_PATTERN.test("x".repeat(31))).toBe(false);
    expect(OPS_TOKEN_PATTERN.test("x".repeat(512))).toBe(true);
    expect(OPS_TOKEN_PATTERN.test("x".repeat(513))).toBe(false);
    expect(OPS_TOKEN_PATTERN.test(`${"x".repeat(32)}\r\nX-Evil: 1`)).toBe(false);
  });
});

describe("cross-site forms", () => {
  const withHeaders = (entries: Record<string, string>) => new Headers(entries);
  it("refuses a form another site sent", () => {
    expect(isCrossSiteForm(withHeaders({ host: "console.test", "sec-fetch-site": "cross-site" }))).toBe(true);
    expect(isCrossSiteForm(withHeaders({ host: "console.test", "sec-fetch-site": "same-site" }))).toBe(true);
    expect(isCrossSiteForm(withHeaders({ host: "console.test", origin: "https://evil.test" }))).toBe(true);
  });
  it("lets the Console's own forms through", () => {
    expect(isCrossSiteForm(withHeaders({ host: "console.test", "sec-fetch-site": "same-origin" }))).toBe(false);
    expect(
      isCrossSiteForm(
        withHeaders({ host: "console.test", "sec-fetch-site": "same-origin", origin: "http://console.test" }),
      ),
    ).toBe(false);
    expect(
      isCrossSiteForm(
        withHeaders({ host: "internal:3000", "x-forwarded-host": "console.test", origin: "https://console.test" }),
      ),
    ).toBe(false);
    expect(isCrossSiteForm(withHeaders({ host: "console.test" }))).toBe(false);
  });
});

describe("GET /ops/expired", () => {
  const request = (headers: Record<string, string> = {}) =>
    new NextRequest("http://console.test/ops/expired", { headers: { host: "console.test", ...headers } });

  it("clears the operator cookie and sends the operator to sign in again", async () => {
    vi.stubEnv("NODE_ENV", "development");
    const response = await expired(request({ "sec-fetch-site": "same-origin" }));
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/ops/sign-in?reason=expired");
    const cookie = response.headers.get("set-cookie") ?? "";
    expect(cookie).toMatch(/^ar_ops=;/);
    expect(cookie).toContain("Path=/ops");
    expect(cookie).toContain("Max-Age=0");
    expect(cookie).toContain("HttpOnly");
    expect(cookie).toContain("SameSite=Strict");
    expect(cookie).not.toContain("Secure");
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("marks the clearing cookie Secure in production", async () => {
    vi.stubEnv("NODE_ENV", "production");
    const response = await expired(request());
    expect(response.headers.get("set-cookie")).toContain("Secure");
  });

  it("refuses a request another site made", async () => {
    const response = await expired(request({ "sec-fetch-site": "cross-site" }));
    expect(response.status).toBe(403);
    expect(response.headers.get("set-cookie")).toBeNull();
  });
});
