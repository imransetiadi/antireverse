// @vitest-environment node
import { generateKey, newId } from "@antireverse/protocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

const requestHeaders = vi.hoisted(() => ({ current: new Headers() }));
vi.mock("next/headers", () => ({ headers: async () => requestHeaders.current }));
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  getOrganization: vi.fn(),
}));
vi.mock("@/lib/session.ts", () => ({ SESSION_COOKIE: "ar_admin", readSession: vi.fn() }));
vi.mock("next/navigation", () => ({
  redirect: vi.fn((url: string) => {
    throw new Error(`REDIRECT ${url}`);
  }),
}));

import * as api from "@/lib/api.ts";
import { currentOrganization, isActionRequest, requireSession } from "@/lib/guard.ts";
import * as session from "@/lib/session.ts";

const key = generateKey("admin").key;
const organization = { id: newId("org"), name: "Acme", created_at: "2026-11-10T08:00:00.000Z" };

beforeEach(() => {
  requestHeaders.current = new Headers();
  vi.mocked(api.getOrganization).mockReset();
  vi.mocked(session.readSession).mockReset();
});

describe("requireSession", () => {
  it("goes to / without a session and does not call the API", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(undefined);
    await expect(requireSession()).rejects.toThrow("REDIRECT /");
    expect(api.getOrganization).not.toHaveBeenCalled();
  });

  it("returns the key and the Organization it belongs to", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(key);
    vi.mocked(api.getOrganization).mockResolvedValueOnce({ organization });
    expect(await requireSession()).toEqual({ key, organization });
    expect(api.getOrganization).toHaveBeenCalledWith(key);
  });

  it("goes to sign-in, with no key in the address, when the API no longer accepts the key", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(key);
    vi.mocked(api.getOrganization).mockRejectedValueOnce(new api.UnauthorizedError("no"));
    await expect(requireSession()).rejects.toThrow("REDIRECT /sign-in?reason=expired");
  });

  it("lets any other failure reach the error screen", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(key);
    const down = new api.ApiError("unreachable", 0);
    vi.mocked(api.getOrganization).mockRejectedValueOnce(down);
    await expect(requireSession()).rejects.toBe(down);
  });
});

describe("currentOrganization", () => {
  it("is null without a session and when the key is no longer accepted", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(undefined);
    expect(await currentOrganization()).toBeNull();

    vi.mocked(session.readSession).mockResolvedValueOnce(key);
    vi.mocked(api.getOrganization).mockRejectedValueOnce(new api.UnauthorizedError("no"));
    expect(await currentOrganization()).toBeNull();
  });

  it("is the Organization of an accepted key", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(key);
    vi.mocked(api.getOrganization).mockResolvedValueOnce({ organization });
    expect(await currentOrganization()).toEqual(organization);
  });
});

describe("isActionRequest", () => {
  it("is false for a plain page request", async () => {
    requestHeaders.current = new Headers({ accept: "text/html" });
    expect(await isActionRequest()).toBe(false);
  });

  it("is true while a Server Action is being answered, with or without JavaScript", async () => {
    requestHeaders.current = new Headers({ "next-action": "40c1f5a0" });
    expect(await isActionRequest()).toBe(true);
    requestHeaders.current = new Headers({ "content-type": "multipart/form-data; boundary=----x" });
    expect(await isActionRequest()).toBe(true);
    requestHeaders.current = new Headers({ "content-type": "application/x-www-form-urlencoded" });
    expect(await isActionRequest()).toBe(true);
  });
});
