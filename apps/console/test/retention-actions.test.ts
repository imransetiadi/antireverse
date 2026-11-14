// @vitest-environment node
import { generateKey } from "@antireverse/protocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { RETENTION } from "./helpers/retention.ts";

// Slice 18c: the Server Action that changes the Event retention. Lengthening needs no reason; shortening is sent from
// the confirmation step with a reason, forwarded as the reason header. A shortening sent without one (a tab that still
// shows a shorter period than the API holds) comes back asking for the confirmation step.
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  updateRetention: vi.fn(),
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
import { updateRetentionAction } from "@/app/actions.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const REASON = "Storage policy: keep request metadata one week";
const REMOVED_BEFORE = "2026-11-07T09:00:00.000Z";
const PENDING_MESSAGE =
  "This Organization is scheduled for deletion, so nothing was saved. Cancel the deletion in Settings → Data controls to make changes again.";
function form(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) data.append(name, value);
  return data;
}
const answer = (days: 7 | 30 | 90 | 180 | 395) => ({
  retention: { ...RETENTION, event_retention_days: days },
  last_run: null,
  events_removed_before: REMOVED_BEFORE,
});

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(session.readSession).mockResolvedValue(admin.key);
});

describe("updateRetentionAction", () => {
  it("lengthens without a reason and says from when older Events go", async () => {
    vi.mocked(api.updateRetention).mockResolvedValueOnce(answer(90));
    const state = await updateRetentionAction(null, form({ event_retention_days: "90" }));
    expect(state).toEqual({ ok: true, days: 90, eventsRemovedBefore: REMOVED_BEFORE });
    expect(api.updateRetention).toHaveBeenCalledWith(admin.key, { event_retention_days: 90 }, {});
    expect(revalidatePath).toHaveBeenCalledWith("/settings/data");
  });

  it("refuses a period that is not one of the choices before anything is sent", async () => {
    for (const value of ["14", "", "7.5", "seven", "-30"]) {
      const state = await updateRetentionAction(null, form({ event_retention_days: value }));
      expect(state).toEqual({
        ok: false,
        errors: [{ path: "event_retention_days", message: "Choose one of the offered periods." }],
      });
    }
    expect(api.updateRetention).not.toHaveBeenCalled();
  });

  it("from the confirmation step: needs a reason, checks it, then forwards it", async () => {
    let state = await updateRetentionAction(null, form({ event_retention_days: "7", confirm: "shorten", reason: " " }));
    expect(state).toEqual({
      ok: false,
      errors: [
        {
          path: "reason",
          message: "Nothing was saved. Give a reason for this change; it is recorded in the audit log.",
        },
      ],
      confirm: 7,
    });
    state = await updateRetentionAction(
      null,
      form({ event_retention_days: "7", confirm: "shorten", reason: `key ${admin.key}` }),
    );
    expect(state).toMatchObject({ ok: false, errors: [{ path: "reason" }], confirm: 7 });
    expect(api.updateRetention).not.toHaveBeenCalled();

    vi.mocked(api.updateRetention).mockResolvedValueOnce(answer(7));
    state = await updateRetentionAction(null, form({ event_retention_days: "7", confirm: "shorten", reason: REASON }));
    expect(state).toEqual({ ok: true, days: 7, eventsRemovedBefore: REMOVED_BEFORE });
    expect(api.updateRetention).toHaveBeenCalledWith(admin.key, { event_retention_days: 7 }, { reason: REASON });
  });

  it("a shortening the API calls one (reason-required) opens the confirmation step for that period", async () => {
    // A stale tab: it showed 7 days, the API now holds 90, and 30 is a shortening.
    vi.mocked(api.updateRetention).mockRejectedValueOnce(new api.ReasonRequiredError("400"));
    expect(await updateRetentionAction(null, form({ event_retention_days: "30" }))).toEqual({
      ok: false,
      errors: [],
      confirm: 30,
    });
    expect(revalidatePath).toHaveBeenCalledWith("/settings/data");
    // From the step itself (the reason was lost on the way): the reason field says so.
    vi.mocked(api.updateRetention).mockRejectedValueOnce(new api.ReasonRequiredError("400"));
    expect(
      await updateRetentionAction(null, form({ event_retention_days: "30", confirm: "shorten", reason: REASON })),
    ).toEqual({
      ok: false,
      errors: [
        {
          path: "reason",
          message: "Nothing was saved. Give a reason for this change; it is recorded in the audit log.",
        },
      ],
      reason: REASON,
      confirm: 30,
    });
  });

  it("explains a reason the API refused and a period it refused", async () => {
    vi.mocked(api.updateRetention).mockRejectedValueOnce(
      new api.ValidationError("400", [{ path: "x-airverse-reason", message: "bad" }], "reason-holds-secret"),
    );
    expect(
      await updateRetentionAction(null, form({ event_retention_days: "7", confirm: "shorten", reason: REASON })),
    ).toMatchObject({ ok: false, errors: [{ path: "reason" }], reason: REASON, confirm: 7 });
    vi.mocked(api.updateRetention).mockRejectedValueOnce(
      new api.ValidationError("400", [{ path: "event_retention_days", message: "Invalid input" }]),
    );
    expect(await updateRetentionAction(null, form({ event_retention_days: "90" }))).toEqual({
      ok: false,
      errors: [{ path: "event_retention_days", message: "Choose one of the offered periods." }],
    });
  });

  it("a tab opened before the deletion says the deletion is pending; a failure keeps the reason", async () => {
    vi.mocked(api.updateRetention).mockRejectedValueOnce(new api.DeletionPendingError("403"));
    expect(await updateRetentionAction(null, form({ event_retention_days: "90" }))).toEqual({
      ok: false,
      errors: [{ path: "", message: PENDING_MESSAGE }],
    });
    vi.mocked(api.updateRetention).mockRejectedValueOnce(new api.ApiError("500", 500));
    expect(
      await updateRetentionAction(null, form({ event_retention_days: "7", confirm: "shorten", reason: REASON })),
    ).toEqual({
      ok: false,
      errors: [
        { path: "", message: "The Airverse API reported a problem, so nothing was saved. Try again in a moment." },
      ],
      reason: REASON,
      confirm: 7,
    });
  });

  it("goes home without a session and to sign-in for a key no longer accepted", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(undefined);
    await expect(updateRetentionAction(null, form({ event_retention_days: "90" }))).rejects.toThrow("REDIRECT /");
    vi.mocked(api.updateRetention).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(updateRetentionAction(null, form({ event_retention_days: "90" }))).rejects.toThrow(
      "REDIRECT /sign-in?reason=expired",
    );
  });
});
