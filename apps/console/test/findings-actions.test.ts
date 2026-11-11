// @vitest-environment node
import { EXAMPLE_FINDING, type Finding } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// The Finding actions (slice 19), exercised through their interface with the API client, the session, the
// cache and the navigation replaced by fakes.
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  ignoreFinding: vi.fn(),
  reopenFinding: vi.fn(),
}));
vi.mock("@/lib/session.ts", () => ({
  SESSION_COOKIE: "ar_admin",
  readSession: vi.fn(),
  writeSession: vi.fn(),
  clearSession: vi.fn(),
}));
vi.mock("next/cache", () => ({ revalidatePath: vi.fn() }));
vi.mock("next/navigation", () => ({
  redirect: vi.fn((url: string) => {
    throw new Error(`REDIRECT ${url}`);
  }),
}));

import { revalidatePath } from "next/cache";
import { ignoreFindingAction, reopenFindingAction } from "@/app/actions.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const findingId = EXAMPLE_FINDING.id;
const PAGE = `/findings/${findingId}`;
// 2026-11-11 15:30 UTC: the ignore window is 2026-11-12 to 2027-02-09.
const NOW = Date.UTC(2026, 10, 11, 15, 30);
const IGNORED: Finding = {
  ...EXAMPLE_FINDING,
  status: "ignored",
  ignore: { reason: "Not reachable", until: "2026-12-11T00:00:00.000Z", by: "key_0123456789abcdef01234567" },
};

const STALE = "This Finding changed since the page was loaded, so nothing was saved. Reload the page and try again.";
const UNCONFIRMED = "Nothing was changed. Confirm the change first.";
const REASON_REQUIRED = "Enter a reason.";
const REASON_LONG = "Use 200 characters or fewer.";
const UNTIL = "Choose a date from tomorrow up to 90 days ahead.";
const API_DOWN = "The Airverse API did not answer, so nothing was saved. Check that it is running, then try again.";
const FIELD = "The API did not accept this value. Change it and try again.";

function form(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) data.append(name, value);
  return data;
}
const ignoreForm = (overrides: Record<string, string> = {}) =>
  form({ findingId, confirm: findingId, reason: "  Not reachable  ", until: "2026-12-11", ...overrides });

beforeEach(() => {
  vi.useFakeTimers({ toFake: ["Date"] });
  vi.setSystemTime(NOW);
  vi.mocked(api.ignoreFinding).mockReset();
  vi.mocked(api.reopenFinding).mockReset();
  vi.mocked(session.readSession).mockReset();
  vi.mocked(session.readSession).mockResolvedValue(admin.key);
  vi.mocked(revalidatePath).mockReset();
});
afterEach(() => {
  vi.useRealTimers();
});

describe("ignoreFindingAction", () => {
  it("ignores with the trimmed reason until the start of the chosen day (UTC), then goes back to the page", async () => {
    vi.mocked(api.ignoreFinding).mockResolvedValue({ finding: IGNORED });
    await expect(ignoreFindingAction(null, ignoreForm())).rejects.toThrow(`REDIRECT ${PAGE}`);
    expect(api.ignoreFinding).toHaveBeenCalledWith(admin.key, findingId, {
      reason: "Not reachable",
      until: "2026-12-11T00:00:00.000Z",
    });
    expect(revalidatePath).toHaveBeenCalledWith(PAGE);
    expect(revalidatePath).toHaveBeenCalledWith("/findings");
    expect(revalidatePath).toHaveBeenCalledWith(`/apps/${EXAMPLE_FINDING.app_id}/findings`);
  });

  it("refuses without the confirmation and never calls the API", async () => {
    expect(await ignoreFindingAction(null, ignoreForm({ confirm: "" }))).toEqual({
      ok: false,
      errors: [{ path: "confirm", message: UNCONFIRMED }],
      values: { reason: "Not reachable", until: "2026-12-11" },
    });
    expect(api.ignoreFinding).not.toHaveBeenCalled();
  });

  it("requires a reason of at most 200 characters and a date inside the window, and keeps what was typed", async () => {
    expect(await ignoreFindingAction(null, ignoreForm({ reason: "   ", until: "2027-02-10" }))).toEqual({
      ok: false,
      errors: [
        { path: "reason", message: REASON_REQUIRED },
        { path: "until", message: UNTIL },
      ],
      values: { reason: "", until: "2027-02-10" },
    });
    const long = "x".repeat(201);
    expect(await ignoreFindingAction(null, ignoreForm({ reason: long, until: "2026-11-11" }))).toEqual({
      ok: false,
      errors: [
        { path: "reason", message: REASON_LONG },
        { path: "until", message: UNTIL },
      ],
      values: { reason: long, until: "2026-11-11" },
    });
    expect(api.ignoreFinding).not.toHaveBeenCalled();
  });

  it("accepts exactly 200 characters and the last day of the window", async () => {
    vi.mocked(api.ignoreFinding).mockResolvedValue({ finding: IGNORED });
    const reason = "y".repeat(200);
    await expect(ignoreFindingAction(null, ignoreForm({ reason, until: "2027-02-09" }))).rejects.toThrow(/REDIRECT/);
    expect(api.ignoreFinding).toHaveBeenCalledWith(admin.key, findingId, {
      reason,
      until: "2027-02-09T00:00:00.000Z",
    });
  });

  it("says the Finding changed when the id is malformed, the API answers 409 or 404", async () => {
    expect(await ignoreFindingAction(null, ignoreForm({ findingId: "fnd_x", confirm: "fnd_x" }))).toMatchObject({
      ok: false,
      errors: [{ path: "", message: STALE }],
    });
    vi.mocked(api.ignoreFinding).mockRejectedValueOnce(new api.ConflictError("POST failed with status 409"));
    expect(await ignoreFindingAction(null, ignoreForm())).toMatchObject({ errors: [{ path: "", message: STALE }] });
    vi.mocked(api.ignoreFinding).mockRejectedValueOnce(new api.NotFoundError("POST failed with status 404"));
    expect(await ignoreFindingAction(null, ignoreForm())).toMatchObject({ errors: [{ path: "", message: STALE }] });
  });

  it("puts a field the API refused next to that field, and an unreachable API in the summary", async () => {
    vi.mocked(api.ignoreFinding).mockRejectedValueOnce(
      new api.ValidationError("POST failed with status 400", [{ path: "until", message: "too far" }]),
    );
    expect(await ignoreFindingAction(null, ignoreForm())).toEqual({
      ok: false,
      errors: [{ path: "until", message: FIELD }],
      values: { reason: "Not reachable", until: "2026-12-11" },
    });
    vi.mocked(api.ignoreFinding).mockRejectedValueOnce(new api.ApiError("failed: unreachable", 0));
    expect(await ignoreFindingAction(null, ignoreForm())).toMatchObject({ errors: [{ path: "", message: API_DOWN }] });
  });

  it("sends a person whose key is no longer accepted to sign in, and one without a session home", async () => {
    vi.mocked(api.ignoreFinding).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(ignoreFindingAction(null, ignoreForm())).rejects.toThrow("REDIRECT /sign-in?reason=expired");
    vi.mocked(session.readSession).mockResolvedValueOnce(undefined);
    await expect(ignoreFindingAction(null, ignoreForm())).rejects.toThrow("REDIRECT /");
  });
});

describe("reopenFindingAction", () => {
  it("reopens at once and goes back to the page", async () => {
    vi.mocked(api.reopenFinding).mockResolvedValue({ finding: EXAMPLE_FINDING });
    await expect(reopenFindingAction(null, form({ findingId }))).rejects.toThrow(`REDIRECT ${PAGE}`);
    expect(api.reopenFinding).toHaveBeenCalledWith(admin.key, findingId);
    expect(revalidatePath).toHaveBeenCalledWith(PAGE);
    expect(revalidatePath).toHaveBeenCalledWith("/findings");
  });

  it("says the Finding changed for a malformed id or a 409", async () => {
    expect(await reopenFindingAction(null, form({ findingId: "nope" }))).toEqual({
      ok: false,
      errors: [{ path: "", message: STALE }],
    });
    expect(api.reopenFinding).not.toHaveBeenCalled();
    vi.mocked(api.reopenFinding).mockRejectedValueOnce(new api.ConflictError("409"));
    expect(await reopenFindingAction(null, form({ findingId }))).toEqual({
      ok: false,
      errors: [{ path: "", message: STALE }],
    });
  });
});
