// @vitest-environment node
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const store = vi.hoisted(() => ({ get: vi.fn(), set: vi.fn(), delete: vi.fn() }));
vi.mock("next/headers", () => ({ cookies: async () => store }));

import { clearSession, readSession, SESSION_COOKIE, writeSession } from "@/lib/session.ts";

const key = generateKey("admin").key;

beforeEach(() => {
  store.get.mockReset();
  store.set.mockReset();
  store.delete.mockReset();
});
afterEach(() => vi.unstubAllEnvs());

describe("session", () => {
  it("names the cookie ar_admin", () => {
    expect(SESSION_COOKIE).toBe("ar_admin");
  });

  it("writes the admin key with exactly the options of contract C6", async () => {
    vi.stubEnv("NODE_ENV", "development");
    await writeSession(key);
    expect(store.set).toHaveBeenCalledTimes(1);
    expect(store.set).toHaveBeenCalledWith("ar_admin", key, {
      httpOnly: true,
      sameSite: "lax",
      path: "/",
      secure: false,
      maxAge: 604_800,
    });
  });

  it("marks the cookie secure only in production", async () => {
    vi.stubEnv("NODE_ENV", "production");
    await writeSession(key);
    expect(store.set.mock.calls[0]?.[2]).toMatchObject({ secure: true });

    vi.stubEnv("NODE_ENV", "test");
    await writeSession(key);
    expect(store.set.mock.calls[1]?.[2]).toMatchObject({ secure: false });
  });

  it("reads the key from the cookie and returns undefined when there is none", async () => {
    store.get.mockReturnValueOnce({ name: "ar_admin", value: key });
    expect(await readSession()).toBe(key);
    expect(store.get).toHaveBeenCalledWith("ar_admin");

    store.get.mockReturnValueOnce(undefined);
    expect(await readSession()).toBeUndefined();
  });

  it("treats an empty cookie as no session", async () => {
    store.get.mockReturnValueOnce({ name: "ar_admin", value: "" });
    expect(await readSession()).toBeUndefined();
  });

  it("clears the cookie", async () => {
    await clearSession();
    expect(store.delete).toHaveBeenCalledWith("ar_admin");
  });
});
