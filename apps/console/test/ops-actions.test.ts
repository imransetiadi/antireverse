// @vitest-environment node
import { beforeEach, describe, expect, it, vi } from "vitest";
import { OPS_TOKEN, sloReport } from "./helpers/slo.ts";

// Slice 18d: operator sign-in and sign-out. The token is checked by reading the report with it; it is stored only when
// the API accepts it, and never returned, redirected with or logged. A form another site sent is refused.

vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  getSloReport: vi.fn(),
}));
const requestHeaders = vi.hoisted(() => ({
  value: new Headers({ host: "console.test", "sec-fetch-site": "same-origin" }),
}));
vi.mock("@/lib/ops-session.ts", async (original) => ({
  ...(await original<typeof import("@/lib/ops-session.ts")>()),
  writeOpsSession: vi.fn(),
  clearOpsSession: vi.fn(),
}));
vi.mock("next/headers", () => ({ headers: async () => requestHeaders.value }));
vi.mock("next/navigation", () => ({
  redirect: vi.fn((url: string) => {
    throw new Error(`REDIRECT ${url}`);
  }),
}));

import { redirect } from "next/navigation";
import { opsSignInAction, opsSignOutAction } from "@/app/ops/actions.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/ops-session.ts";

const form = (token: string): FormData => {
  const data = new FormData();
  data.set("token", token);
  return data;
};
const logged = (): string =>
  [console.log, console.info, console.warn, console.error]
    .flatMap((fn) => vi.mocked(fn).mock.calls.flat())
    .map(String)
    .join("\n");

beforeEach(() => {
  vi.mocked(api.getSloReport).mockReset();
  vi.mocked(session.writeOpsSession).mockReset();
  vi.mocked(session.clearOpsSession).mockReset();
  vi.mocked(redirect).mockClear();
  requestHeaders.value = new Headers({ host: "console.test", "sec-fetch-site": "same-origin" });
  for (const name of ["log", "info", "warn", "error"] as const) vi.spyOn(console, name).mockImplementation(() => {});
});

describe("opsSignInAction", () => {
  it("checks the token against the API, stores it and opens /ops", async () => {
    vi.mocked(api.getSloReport).mockResolvedValueOnce(sloReport());
    await expect(opsSignInAction(null, form(`  ${OPS_TOKEN}  `))).rejects.toThrow(/^REDIRECT \/ops$/);
    expect(api.getSloReport).toHaveBeenCalledWith(OPS_TOKEN);
    expect(session.writeOpsSession).toHaveBeenCalledWith(OPS_TOKEN);
    expect(vi.mocked(redirect).mock.calls[0]?.[0]).not.toContain(OPS_TOKEN);
    expect(logged()).not.toContain(OPS_TOKEN);
  });

  it("says a refused token was not accepted, and stores nothing", async () => {
    vi.mocked(api.getSloReport).mockRejectedValueOnce(
      new api.UnauthorizedError("GET /v1/ops/slo failed with status 401"),
    );
    expect(await opsSignInAction(null, form(OPS_TOKEN))).toEqual({
      ok: false,
      message: "That token was not accepted.",
    });
    expect(session.writeOpsSession).not.toHaveBeenCalled();
  });

  it("never sends a value that cannot be a token", async () => {
    for (const value of ["", "short", `${"x".repeat(40)} with space`]) {
      expect(await opsSignInAction(null, form(value))).toEqual({ ok: false, message: "That token was not accepted." });
    }
    expect(api.getSloReport).not.toHaveBeenCalled();
  });

  it("says operator access is off when the API answers 404", async () => {
    vi.mocked(api.getSloReport).mockRejectedValueOnce(new api.NotFoundError("GET /v1/ops/slo failed with status 404"));
    expect(await opsSignInAction(null, form(OPS_TOKEN))).toEqual({
      ok: false,
      message: "Operator access is not enabled on this API.",
    });
    expect(session.writeOpsSession).not.toHaveBeenCalled();
  });

  it("says the API failed for any other error", async () => {
    vi.mocked(api.getSloReport).mockRejectedValueOnce(new api.ApiError("unreachable", 0));
    expect(await opsSignInAction(null, form(OPS_TOKEN))).toEqual({
      ok: false,
      message: "The API could not be reached. Try again in a moment.",
    });
  });

  it("says the API answered in an unexpected way when its answer breaks the contract (502)", async () => {
    vi.mocked(api.getSloReport).mockRejectedValueOnce(new api.ApiError("contract", 502));
    expect(await opsSignInAction(null, form(OPS_TOKEN))).toEqual({
      ok: false,
      message: "The API answered in an unexpected way. Try again in a moment.",
    });
    expect(session.writeOpsSession).not.toHaveBeenCalled();
  });

  it("refuses a form another site sent, before the API is called", async () => {
    requestHeaders.value = new Headers({ host: "console.test", "sec-fetch-site": "cross-site" });
    expect(await opsSignInAction(null, form(OPS_TOKEN))).toEqual({
      ok: false,
      message: "This form was not sent from this Console, so it was refused.",
    });
    expect(api.getSloReport).not.toHaveBeenCalled();
    expect(session.writeOpsSession).not.toHaveBeenCalled();
  });
});

describe("opsSignOutAction", () => {
  it("clears the operator cookie and returns to operator sign-in", async () => {
    await expect(opsSignOutAction()).rejects.toThrow("REDIRECT /ops/sign-in");
    expect(session.clearOpsSession).toHaveBeenCalledTimes(1);
  });

  it("refuses a sign-out another site sent", async () => {
    requestHeaders.value = new Headers({ host: "console.test", origin: "https://evil.test" });
    await expect(opsSignOutAction()).rejects.toThrow(/^REDIRECT \/ops$/);
    expect(session.clearOpsSession).not.toHaveBeenCalled();
  });
});
