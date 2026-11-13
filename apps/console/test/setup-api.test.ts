// @vitest-environment node
// Slice 16: the API client of the set-up endpoint, the proxy the Set up page polls, and the pure set-up state.
import type { AppSetup } from "@antireverse/protocol";
import { generateKey, newId } from "@antireverse/protocol/server";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as route from "@/app/api/apps/[appId]/setup/route.ts";
import { loadSetupDone } from "@/features/setup/load.ts";
import { currentStep, doneCount, mergeSetup } from "@/features/setup/setup-state.ts";
import { ApiError, getAppSetup, NotFoundError } from "@/lib/api.ts";
import { ROUTES } from "@/lib/routes.ts";

const key = generateKey("admin").key;
const appId = newId("app");
const fetchMock = vi.fn<typeof fetch>();

const SETUP: AppSetup = {
  environment: "staging",
  shield: { done_at: "2026-11-13T09:00:00.000Z" },
  guard: { done_at: null },
  harden: { done_at: null },
};
const json = (status: number, body: unknown, type = "application/json"): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": type } });

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("AR_API_URL", "http://api.test:9999");
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("getAppSetup", () => {
  it("asks for the App's set-up with the admin key, for the Environment when one is given", async () => {
    fetchMock.mockImplementation(async () => json(200, { setup: SETUP }));
    expect(await getAppSetup(key, appId, "staging")).toEqual({ setup: SETUP });
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).toBe(`http://api.test:9999/v1/apps/${appId}/setup?environment=staging`);
    expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${key}`);

    await getAppSetup(key, appId);
    expect(String(fetchMock.mock.calls[1]?.[0])).toBe(`http://api.test:9999/v1/apps/${appId}/setup`);
  });

  it("rejects an answer outside the contract and maps 404", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { setup: { ...SETUP, shield: { done_at: "yesterday" } } }));
    expect(await getAppSetup(key, appId).catch((error) => error)).toBeInstanceOf(ApiError);
    fetchMock.mockResolvedValueOnce(json(404, { type: "about:blank", title: "Not Found", status: 404 }));
    expect(await getAppSetup(key, appId).catch((error) => error)).toBeInstanceOf(NotFoundError);
  });
});

describe("GET /api/apps/[appId]/setup", () => {
  const get = (id: string, search = "", cookie?: string) =>
    route.GET(
      new NextRequest(`http://127.0.0.1:3000/api/apps/${id}/setup${search}`, { headers: cookie ? { cookie } : {} }),
      { params: Promise.resolve({ appId: id }) },
    );

  it("exports the GET handler only", () => {
    expect(Object.keys(route)).toEqual(["GET"]);
  });

  it("answers 404 for a value that is not an App identifier and 401 without a session, without calling the API", async () => {
    expect((await get("..%2Fv1%2Forganization", "", `ar_admin=${key}`)).status).toBe(404);
    expect((await get(appId)).status).toBe(401);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("answers 400 for an Environment that does not exist, without calling the API", async () => {
    expect((await get(appId, "?environment=moon", `ar_admin=${key}`)).status).toBe(400);
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("returns the API's answer with the session's key and never caches it", async () => {
    fetchMock.mockResolvedValue(json(200, { setup: SETUP }));
    const response = await get(appId, "?environment=staging", `ar_admin=${key}`);
    expect(response.status).toBe(200);
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(await response.json()).toEqual({ setup: SETUP });
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).toBe(`http://api.test:9999/v1/apps/${appId}/setup?environment=staging`);
    expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${key}`);
  });

  it("passes the API's 401 through and answers 502 when the API cannot be reached", async () => {
    fetchMock.mockResolvedValueOnce(json(401, { type: "about:blank", title: "Unauthorized", status: 401 }));
    expect((await get(appId, "", `ar_admin=${key}`)).status).toBe(401);
    fetchMock.mockRejectedValueOnce(new TypeError(`connect ECONNREFUSED with ${key}`));
    const failed = await get(appId, "", `ar_admin=${key}`);
    expect(failed.status).toBe(502);
    expect(await failed.text()).not.toContain(key);
  });
});

describe("routes", () => {
  it("has the Set up page and its poll address, never with a key", () => {
    expect(ROUTES.setup(appId)).toBe(`/apps/${appId}/setup`);
    expect(ROUTES.setupApi(appId, "production")).toBe(`/api/apps/${appId}/setup?environment=production`);
  });
});

describe("set-up state", () => {
  const none: AppSetup = { ...SETUP, shield: { done_at: null } };

  it("counts the steps done and names the first one not done", () => {
    expect(doneCount(none)).toBe(0);
    expect(currentStep(none)).toBe("shield");
    expect(doneCount(SETUP)).toBe(1);
    expect(currentStep(SETUP)).toBe("guard");
    // Harden can be done before Guard: the current step is still the first one not done.
    const hardened = { ...SETUP, harden: { done_at: "2026-11-13T08:00:00.000Z" } };
    expect(currentStep(hardened)).toBe("guard");
    const all = { ...hardened, guard: { done_at: "2026-11-13T09:01:00.000Z" } };
    expect(doneCount(all)).toBe(3);
    expect(currentStep(all)).toBeNull();
  });

  it("merges by keeping the earliest time of each step and never forgets one", () => {
    const later = {
      ...SETUP,
      shield: { done_at: "2026-11-13T10:00:00.000Z" },
      guard: { done_at: "2026-11-13T10:00:01.000Z" },
    };
    expect(mergeSetup(SETUP, later)).toEqual({ ...SETUP, guard: later.guard });
    expect(mergeSetup(later, none).shield.done_at).toBe("2026-11-13T10:00:00.000Z");
  });
});

describe("loadSetupDone", () => {
  it("counts the done steps of the App's own Environment", async () => {
    fetchMock.mockImplementation(async () => json(200, { setup: SETUP }));
    expect(await loadSetupDone(key, appId)).toBe(1);
    expect(String(fetchMock.mock.calls[0]?.[0])).toBe(`http://api.test:9999/v1/apps/${appId}/setup`);
  });

  it("is null, never an error, when the API cannot say", async () => {
    fetchMock.mockImplementationOnce(async () => json(500, { type: "about:blank", title: "Error", status: 500 }));
    expect(await loadSetupDone(key, appId)).toBeNull();
    fetchMock.mockImplementationOnce(async () => json(404, { type: "about:blank", title: "Not Found", status: 404 }));
    expect(await loadSetupDone(key, appId)).toBeNull();
    fetchMock.mockRejectedValueOnce(new TypeError("fetch failed"));
    expect(await loadSetupDone(key, appId)).toBeNull();
  });

  it("goes to sign-in when the API no longer accepts the key", async () => {
    fetchMock.mockImplementation(async () => json(401, { type: "about:blank", title: "Unauthorized", status: 401 }));
    const error = await loadSetupDone(key, appId).catch((caught: unknown) => caught);
    expect(String((error as { digest?: string }).digest)).toContain("/sign-in?reason=expired");
  });
});
