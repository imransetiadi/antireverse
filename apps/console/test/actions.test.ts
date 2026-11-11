// @vitest-environment node
import { generateKey, newId } from "@antireverse/protocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";

// The actions are exercised through their interface with the API client and the session replaced by fakes.
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  createOrganization: vi.fn(),
  getOrganization: vi.fn(),
  createApp: vi.fn(),
}));
vi.mock("@/lib/session.ts", () => ({
  SESSION_COOKIE: "ar_admin",
  readSession: vi.fn(),
  writeSession: vi.fn(),
  clearSession: vi.fn(),
}));
// redirect() never returns: the real one throws a control-flow signal, and so does this one.
vi.mock("next/navigation", () => ({
  redirect: vi.fn((url: string) => {
    throw new Error(`REDIRECT ${url}`);
  }),
}));

import { redirect } from "next/navigation";
import { createAppAction, createOrganizationAction, signInAction, signOutAction } from "@/app/actions.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const shield = generateKey("shield", "production");
const organization = { id: newId("org"), name: "Acme", created_at: "2026-11-10T08:00:00.000Z" };
const app = { id: newId("app"), name: "shop-web", created_at: "2026-11-10T08:01:00.000Z" };

function form(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) data.set(name, value);
  return data;
}

beforeEach(() => {
  vi.mocked(api.createOrganization).mockReset();
  vi.mocked(api.getOrganization).mockReset();
  vi.mocked(api.createApp).mockReset();
  vi.mocked(session.readSession).mockReset();
  vi.mocked(session.writeSession).mockReset();
  vi.mocked(session.clearSession).mockReset();
  vi.mocked(redirect).mockClear();
});

describe("createOrganizationAction", () => {
  it("creates the Organization, stores the admin key in the session and returns the key once", async () => {
    vi.mocked(api.createOrganization).mockResolvedValueOnce({ organization, admin_key: admin });
    const state = await createOrganizationAction(null, form({ name: "  Acme  " }));
    expect(api.createOrganization).toHaveBeenCalledWith({ name: "Acme" });
    expect(session.writeSession).toHaveBeenCalledTimes(1);
    expect(session.writeSession).toHaveBeenCalledWith(admin.key);
    expect(state).toEqual({ ok: true, organization, adminKey: admin.key });
    // The key travels in the action state only — never in a redirect URL.
    expect(redirect).not.toHaveBeenCalled();
  });

  it("refuses an empty name without calling the API and stores nothing", async () => {
    const state = await createOrganizationAction(null, form({ name: "   " }));
    expect(state).toEqual({ ok: false, errors: [{ path: "name", message: "Enter a name." }], values: { name: "" } });
    expect(api.createOrganization).not.toHaveBeenCalled();
    expect(session.writeSession).not.toHaveBeenCalled();
  });

  it("refuses a missing name field", async () => {
    const state = await createOrganizationAction(null, new FormData());
    expect(state).toMatchObject({ ok: false, errors: [{ path: "name", message: "Enter a name." }] });
    expect(session.writeSession).not.toHaveBeenCalled();
  });

  it("refuses a name of 81 characters and gives the typed value back", async () => {
    const name = "a".repeat(81);
    const state = await createOrganizationAction(null, form({ name }));
    expect(state).toEqual({
      ok: false,
      errors: [{ path: "name", message: "Use 80 characters or fewer." }],
      values: { name },
    });
    expect(api.createOrganization).not.toHaveBeenCalled();
  });

  it("reports a refusal by the API next to the field and stores nothing", async () => {
    vi.mocked(api.createOrganization).mockRejectedValueOnce(
      new api.ValidationError("refused", [{ path: "name", message: "Too big" }]),
    );
    const state = await createOrganizationAction(null, form({ name: "Acme" }));
    expect(state).toEqual({
      ok: false,
      errors: [{ path: "name", message: "The API did not accept this value. Change it and try again." }],
      values: { name: "Acme" },
    });
    expect(session.writeSession).not.toHaveBeenCalled();
  });

  it("says what failed and what to do when the API does not answer", async () => {
    vi.mocked(api.createOrganization).mockRejectedValueOnce(new api.ApiError("unreachable", 0));
    const state = await createOrganizationAction(null, form({ name: "Acme" }));
    expect(state).toEqual({
      ok: false,
      errors: [
        {
          path: "",
          message:
            "The Anti Reverse API did not answer, so nothing was saved. Check that it is running, then try again.",
        },
      ],
      values: { name: "Acme" },
    });
    expect(session.writeSession).not.toHaveBeenCalled();
  });
});

describe("signInAction", () => {
  it("stores the key when the API accepts it and goes to the Apps", async () => {
    vi.mocked(api.getOrganization).mockResolvedValueOnce({ organization });
    await expect(signInAction(null, form({ key: `  ${admin.key}\n` }))).rejects.toThrow("REDIRECT /apps");
    expect(api.getOrganization).toHaveBeenCalledWith(admin.key);
    expect(session.writeSession).toHaveBeenCalledWith(admin.key);
  });

  it("stores nothing and says the key was not accepted when the API refuses it", async () => {
    vi.mocked(api.getOrganization).mockRejectedValueOnce(new api.UnauthorizedError("no"));
    const state = await signInAction(null, form({ key: admin.key }));
    expect(state).toEqual({ ok: false, message: "That key was not accepted." });
    expect(session.writeSession).not.toHaveBeenCalled();
    expect(redirect).not.toHaveBeenCalled();
  });

  it.each([
    ["an empty value", ""],
    ["a malformed key", "aro_short"],
    ["a Shield key", shield.key],
  ])("refuses %s without calling the API", async (_label, key) => {
    const state = await signInAction(null, form({ key }));
    expect(state).toEqual({ ok: false, message: "That key was not accepted." });
    expect(api.getOrganization).not.toHaveBeenCalled();
    expect(session.writeSession).not.toHaveBeenCalled();
  });

  it("does not blame the key when the API does not answer", async () => {
    vi.mocked(api.getOrganization).mockRejectedValueOnce(new api.ApiError("unreachable", 0));
    const state = await signInAction(null, form({ key: admin.key }));
    expect(state).toEqual({
      ok: false,
      message:
        "The Anti Reverse API did not answer, so the key could not be checked. Check that it is running, then try again.",
    });
    expect(session.writeSession).not.toHaveBeenCalled();
  });

  it("never returns the key in its state", async () => {
    vi.mocked(api.getOrganization).mockRejectedValueOnce(new api.UnauthorizedError("no"));
    expect(JSON.stringify(await signInAction(null, form({ key: admin.key })))).not.toContain(admin.key);
    expect(JSON.stringify(await signInAction(null, form({ key: `${admin.key}x` })))).not.toContain(admin.key);
  });
});

describe("createAppAction", () => {
  it("creates the App with the session's key and returns the Shield key once", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(admin.key);
    vi.mocked(api.createApp).mockResolvedValueOnce({ app, shield_key: { ...shield, environment: "production" } });
    const state = await createAppAction(null, form({ name: " shop-web ", environment: "production" }));
    expect(api.createApp).toHaveBeenCalledWith(admin.key, { name: "shop-web", environment: "production" });
    expect(state).toEqual({ ok: true, app, shieldKey: shield.key, environment: "production" });
    expect(redirect).not.toHaveBeenCalled();
    expect(JSON.stringify(state)).not.toContain(admin.key);
  });

  it("defaults the Environment to development", async () => {
    const dev = generateKey("shield", "development");
    vi.mocked(session.readSession).mockResolvedValueOnce(admin.key);
    vi.mocked(api.createApp).mockResolvedValueOnce({ app, shield_key: { ...dev, environment: "development" } });
    const state = await createAppAction(null, form({ name: "shop-web" }));
    expect(api.createApp).toHaveBeenCalledWith(admin.key, { name: "shop-web", environment: "development" });
    expect(state).toMatchObject({ ok: true, environment: "development" });
  });

  it("requires a session: without one it goes to / and never calls the API", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(undefined);
    await expect(createAppAction(null, form({ name: "shop-web" }))).rejects.toThrow("REDIRECT /");
    expect(redirect).toHaveBeenCalledWith("/");
    expect(api.createApp).not.toHaveBeenCalled();
  });

  it("goes to sign-in when the API no longer accepts the session's key", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(admin.key);
    vi.mocked(api.createApp).mockRejectedValueOnce(new api.UnauthorizedError("no"));
    await expect(createAppAction(null, form({ name: "shop-web" }))).rejects.toThrow("REDIRECT /sign-in");
  });

  it("refuses an empty name and an unknown Environment without calling the API", async () => {
    vi.mocked(session.readSession).mockResolvedValue(admin.key);
    expect(await createAppAction(null, form({ name: "", environment: "production" }))).toEqual({
      ok: false,
      errors: [{ path: "name", message: "Enter a name." }],
      values: { name: "", environment: "production" },
    });
    expect(await createAppAction(null, form({ name: "shop-web", environment: "moon" }))).toEqual({
      ok: false,
      errors: [{ path: "environment", message: "Choose Production, Staging or Development." }],
      values: { name: "shop-web", environment: "moon" },
    });
    expect(api.createApp).not.toHaveBeenCalled();
  });

  it("says what failed and what to do when the API does not answer", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(admin.key);
    vi.mocked(api.createApp).mockRejectedValueOnce(new api.ApiError("unreachable", 0));
    const state = await createAppAction(null, form({ name: "shop-web", environment: "staging" }));
    expect(state).toMatchObject({
      ok: false,
      errors: [{ path: "" }],
      values: { name: "shop-web", environment: "staging" },
    });
  });
});

describe("signOutAction", () => {
  it("clears the session and goes to /", async () => {
    await expect(signOutAction()).rejects.toThrow("REDIRECT /");
    expect(session.clearSession).toHaveBeenCalledTimes(1);
    expect(redirect).toHaveBeenCalledWith("/");
  });
});
