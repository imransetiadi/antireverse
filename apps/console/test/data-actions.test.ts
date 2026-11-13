// @vitest-environment node
import { generateKey, newId } from "@antireverse/protocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { ERASE_REPORT, IP_HASH, PENDING } from "./helpers/deletion.ts";

// Slice 18b: the Server Actions of Settings → Data controls (request and cancel the deletion, erase a subject), the
// session guard while a deletion is pending, and the message every other action shows for that refusal.
const requestHeaders = vi.hoisted(() => ({ current: new Headers() }));
vi.mock("next/headers", () => ({ headers: async () => requestHeaders.current }));
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  getOrganization: vi.fn(),
  getDeletionStatus: vi.fn(),
  requestDeletion: vi.fn(),
  cancelDeletion: vi.fn(),
  eraseSubject: vi.fn(),
  createApp: vi.fn(),
  getPolicy: vi.fn(),
  simulatePolicy: vi.fn(),
  testAlertChannel: vi.fn(),
  resendConfirmation: vi.fn(),
  verifyTarget: vi.fn(),
  listAudit: vi.fn(),
  verifyAudit: vi.fn(),
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

import { EXAMPLE_POLICY } from "@antireverse/protocol";
import {
  cancelDeletionAction,
  createAppAction,
  eraseSubjectAction,
  loadMoreAuditAction,
  requestDeletionAction,
  resendConfirmationAction,
  signInAction,
  simulatePolicyAction,
  testAlertChannelAction,
  verifyAuditChainAction,
  verifyTargetAction,
} from "@/app/actions.ts";
import * as api from "@/lib/api.ts";
import { currentOrganization, requireSession, requireSessionDuringDeletion } from "@/lib/guard.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const organization = { id: newId("org"), name: "Acme", created_at: "2026-11-10T08:00:00.000Z" };
const REASON = "Contract ended — customer asked for deletion";
const PENDING_MESSAGE =
  "This Organization is scheduled for deletion, so nothing was saved. Cancel the deletion in Settings → Data controls to make changes again.";

const PENDING_READ =
  "This Organization is scheduled for deletion, so this could not be read. Cancel the deletion in Settings → Data controls to use this page again.";
const pendingError = () => new api.DeletionPendingError("GET /v1/organization failed with status 403");
function form(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) data.append(name, value);
  return data;
}

beforeEach(() => {
  vi.clearAllMocks();
  vi.mocked(session.readSession).mockResolvedValue(admin.key);
});

describe("session guard while a deletion is pending", () => {
  it("requireSession sends every page to Data controls, which says why", async () => {
    vi.mocked(api.getOrganization).mockRejectedValueOnce(pendingError());
    await expect(requireSession()).rejects.toThrow("REDIRECT /settings/data?blocked=1");
  });

  it("requireSessionDuringDeletion gives the Organization and no deletion when none is pending, with one call", async () => {
    vi.mocked(api.getOrganization).mockResolvedValueOnce({ organization });
    expect(await requireSessionDuringDeletion()).toEqual({ key: admin.key, organization, deletion: null });
    expect(api.getDeletionStatus).not.toHaveBeenCalled();
  });

  it("requireSessionDuringDeletion gives the pending deletion and no Organization while pending", async () => {
    vi.mocked(api.getOrganization).mockRejectedValueOnce(pendingError());
    vi.mocked(api.getDeletionStatus).mockResolvedValueOnce({ deletion: PENDING });
    expect(await requireSessionDuringDeletion()).toEqual({ key: admin.key, organization: null, deletion: PENDING });
  });

  it("requireSessionDuringDeletion goes home without a session and to sign-in for a key no longer accepted", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(undefined);
    await expect(requireSessionDuringDeletion()).rejects.toThrow("REDIRECT /");
    vi.mocked(api.getOrganization).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(requireSessionDuringDeletion()).rejects.toThrow("REDIRECT /sign-in?reason=expired");
  });

  it("currentOrganization (the `/` page) sends a session pending deletion to Data controls, not to the error screen", async () => {
    vi.mocked(api.getOrganization).mockRejectedValueOnce(pendingError());
    await expect(currentOrganization()).rejects.toThrow("REDIRECT /settings/data?blocked=1");
  });

  it("sign-in with the key of an Organization pending deletion opens Data controls", async () => {
    vi.mocked(api.getOrganization).mockRejectedValueOnce(pendingError());
    await expect(signInAction(null, form({ key: admin.key }))).rejects.toThrow("REDIRECT /settings/data?blocked=1");
    expect(session.writeSession).toHaveBeenCalledWith(admin.key);
  });

  it("an action refused for the pending deletion says so instead of a generic failure", async () => {
    vi.mocked(api.createApp).mockRejectedValueOnce(pendingError());
    const state = await createAppAction(null, form({ name: "shop-web", environment: "development" }));
    expect(state).toEqual({
      ok: false,
      errors: [{ path: "", message: PENDING_MESSAGE }],
      values: { name: "shop-web", environment: "development" },
    });
  });
});

describe("requestDeletionAction", () => {
  const valid = { confirm_name: "Acme", reason: REASON };

  it("asks for the typed name and a reason before anything is sent", async () => {
    let state = await requestDeletionAction(null, form({ confirm_name: "", reason: REASON }));
    expect(state).toEqual({
      ok: false,
      errors: [{ path: "confirm_name", message: "Type the Organization's name exactly as it is shown." }],
      reason: REASON,
    });
    state = await requestDeletionAction(null, form({ confirm_name: "Acme", reason: " " }));
    expect(state).toEqual({
      ok: false,
      errors: [
        {
          path: "reason",
          message: "Nothing was saved. Give a reason for this change; it is recorded in the audit log.",
        },
      ],
    });
    state = await requestDeletionAction(null, form({ confirm_name: "Acme", reason: `key ${admin.key}` }));
    expect(state?.errors[0]?.path).toBe("reason");
    expect(api.requestDeletion).not.toHaveBeenCalled();
  });

  it("sends the name and the reason, then opens Data controls with the deletion requested", async () => {
    vi.mocked(api.requestDeletion).mockResolvedValueOnce({ deletion: PENDING });
    await expect(requestDeletionAction(null, form(valid))).rejects.toThrow("REDIRECT /settings/data?done=requested");
    expect(api.requestDeletion).toHaveBeenCalledWith(admin.key, { confirm_name: "Acme" }, { reason: REASON });
  });

  it("explains a name the API refused and a reason it refused, keeping the reason", async () => {
    vi.mocked(api.requestDeletion).mockRejectedValueOnce(
      new api.ValidationError("400", [{ path: "confirm_name", message: "Must be the name" }]),
    );
    expect(await requestDeletionAction(null, form(valid))).toEqual({
      ok: false,
      errors: [{ path: "confirm_name", message: "Type the Organization's name exactly as it is shown." }],
      reason: REASON,
    });
    vi.mocked(api.requestDeletion).mockRejectedValueOnce(new api.ReasonRequiredError("400"));
    expect((await requestDeletionAction(null, form(valid)))?.errors[0]?.path).toBe("reason");
  });

  it("a deletion already pending (409 or 403) opens Data controls, which shows it", async () => {
    vi.mocked(api.requestDeletion).mockRejectedValueOnce(new api.ConflictError("409"));
    await expect(requestDeletionAction(null, form(valid))).rejects.toThrow("REDIRECT /settings/data");
    vi.mocked(api.requestDeletion).mockRejectedValueOnce(pendingError());
    await expect(requestDeletionAction(null, form(valid))).rejects.toThrow("REDIRECT /settings/data");
  });

  it("goes home without a session and to sign-in for a key no longer accepted", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(undefined);
    await expect(requestDeletionAction(null, form(valid))).rejects.toThrow("REDIRECT /");
    vi.mocked(api.requestDeletion).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(requestDeletionAction(null, form(valid))).rejects.toThrow("REDIRECT /sign-in?reason=expired");
  });
});

describe("cancelDeletionAction", () => {
  it("asks for a reason before anything is sent", async () => {
    const state = await cancelDeletionAction(null, form({ reason: "" }));
    expect(state?.errors[0]?.path).toBe("reason");
    expect(api.cancelDeletion).not.toHaveBeenCalled();
  });

  it("cancels with the reason, then opens Data controls with the deletion cancelled", async () => {
    vi.mocked(api.cancelDeletion).mockResolvedValueOnce({
      deletion: { ...PENDING, status: "cancelled", cancelled_at: "2026-11-14T09:00:00.000Z" },
    });
    await expect(cancelDeletionAction(null, form({ reason: REASON }))).rejects.toThrow(
      "REDIRECT /settings/data?done=cancelled",
    );
    expect(api.cancelDeletion).toHaveBeenCalledWith(admin.key, { reason: REASON });
  });

  it("a deletion no longer pending (404) opens Data controls; a failure keeps the reason", async () => {
    vi.mocked(api.cancelDeletion).mockRejectedValueOnce(new api.NotFoundError("404"));
    await expect(cancelDeletionAction(null, form({ reason: REASON }))).rejects.toThrow("REDIRECT /settings/data");
    vi.mocked(api.cancelDeletion).mockRejectedValueOnce(new api.ApiError("500", 500));
    expect(await cancelDeletionAction(null, form({ reason: REASON }))).toEqual({
      ok: false,
      errors: [
        { path: "", message: "The Airverse API reported a problem, so nothing was saved. Try again in a moment." },
      ],
      reason: REASON,
    });
  });
});

describe("eraseSubjectAction", () => {
  it("refuses a value that is not an actor hash, and a missing confirmation, before anything is sent", async () => {
    let state = await eraseSubjectAction(
      null,
      form({ ip_hash: "203.0.113.7", confirm: "203.0.113.7", reason: REASON }),
    );
    expect(state).toMatchObject({ ok: false, errors: [{ path: "ip_hash" }] });
    state = await eraseSubjectAction(null, form({ ip_hash: IP_HASH, confirm: "", reason: REASON }));
    expect(state).toMatchObject({ ok: false, errors: [{ path: "" }] });
    state = await eraseSubjectAction(null, form({ ip_hash: IP_HASH, confirm: IP_HASH, reason: "" }));
    expect(state).toMatchObject({ ok: false, errors: [{ path: "reason" }] });
    expect(api.eraseSubject).not.toHaveBeenCalled();
  });

  it("erases with the reason and gives the report back", async () => {
    vi.mocked(api.eraseSubject).mockResolvedValueOnce({ report: ERASE_REPORT });
    const state = await eraseSubjectAction(null, form({ ip_hash: IP_HASH, confirm: IP_HASH, reason: REASON }));
    expect(state).toEqual({ ok: true, report: ERASE_REPORT });
    expect(api.eraseSubject).toHaveBeenCalledWith(admin.key, IP_HASH, { reason: REASON });
  });

  it("explains a refused reason and a pending deletion, keeping the reason", async () => {
    vi.mocked(api.eraseSubject).mockRejectedValueOnce(new api.ReasonRequiredError("400"));
    const fields = { ip_hash: IP_HASH, confirm: IP_HASH, reason: REASON };
    expect(await eraseSubjectAction(null, form(fields))).toMatchObject({
      ok: false,
      errors: [{ path: "reason" }],
      reason: REASON,
    });
    vi.mocked(api.eraseSubject).mockRejectedValueOnce(pendingError());
    expect(await eraseSubjectAction(null, form(fields))).toEqual({
      ok: false,
      errors: [{ path: "", message: PENDING_MESSAGE }],
      reason: REASON,
    });
  });
});

// Review 18b: a tab opened before the deletion was requested still submits its forms. Every action says why the API
// refused, through one helper, instead of its own generic failure.
describe("actions from a tab opened before the deletion", () => {
  const ids = {
    channelId: "chn_0123456789abcdef01234567",
    recipientId: "rcp_0123456789abcdef01234567",
    targetId: "tgt_0123456789abcdef01234567",
  };

  it("a simulation says the deletion is pending", async () => {
    vi.mocked(api.getPolicy).mockResolvedValueOnce({ policy: { ...EXAMPLE_POLICY, version: 4 } });
    vi.mocked(api.simulatePolicy).mockRejectedValueOnce(pendingError());
    const state = await simulatePolicyAction(
      null,
      form({ appId: EXAMPLE_POLICY.app_id, environment: "development", expectedVersion: "4" }),
    );
    expect(state).toMatchObject({ ok: false, errors: [{ path: "", message: PENDING_MESSAGE }] });
  });

  it("a test alert, a resent confirmation and a target check say the deletion is pending", async () => {
    vi.mocked(api.testAlertChannel).mockRejectedValueOnce(pendingError());
    expect(await testAlertChannelAction(null, form({ channelId: ids.channelId }))).toEqual({
      ok: false,
      message: PENDING_MESSAGE,
    });
    vi.mocked(api.resendConfirmation).mockRejectedValueOnce(pendingError());
    expect(
      await resendConfirmationAction(null, form({ channelId: ids.channelId, recipientId: ids.recipientId })),
    ).toEqual({ ok: false, message: PENDING_MESSAGE });
    vi.mocked(api.verifyTarget).mockRejectedValueOnce(pendingError());
    expect(await verifyTargetAction(null, form({ targetId: ids.targetId }))).toEqual({
      ok: false,
      message: PENDING_MESSAGE,
    });
  });

  it("reading more of the audit log or verifying its chain says the deletion is pending", async () => {
    vi.mocked(api.listAudit).mockRejectedValueOnce(pendingError());
    expect(await loadMoreAuditAction({}, "5")).toEqual({ ok: false, message: PENDING_READ });
    vi.mocked(api.verifyAudit).mockRejectedValueOnce(pendingError());
    expect(await verifyAuditChainAction()).toEqual({ ok: false, message: PENDING_READ });
  });
});
