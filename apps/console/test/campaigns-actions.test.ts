// @vitest-environment node
import type { ConflictReason } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { campaignId, completed, queued, stopped } from "./helpers/campaigns.ts";

// Slice 15a: launching and stopping a Campaign, exercised through the actions' interface with the API client, the
// session, the cache and the navigation replaced by fakes. Every problem of the API has a field or a clear message.
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  createCampaign: vi.fn(),
  stopCampaign: vi.fn(),
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
import { createCampaignAction, stopCampaignAction } from "@/app/actions.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const REASON = "Quarterly test of the staging shop";
const PHRASE = `I authorise a test of ${completed.host}`;
const values = { target: completed.target_id, intensity: "safe-active" };
const good = { ...values, confirm: PHRASE, staging: "on", reason: REASON };

function form(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) data.set(name, value);
  return data;
}
async function redirectOf(promise: Promise<unknown>): Promise<string> {
  try {
    await promise;
  } catch (error) {
    const match = /^REDIRECT (.+)$/.exec((error as Error).message);
    if (match) return match[1] as string;
    throw error;
  }
  throw new Error("expected a redirect");
}
const refusedWith = async (error: Error) => {
  vi.mocked(api.createCampaign).mockRejectedValueOnce(error);
  return createCampaignAction(null, form(good));
};

beforeEach(() => {
  vi.mocked(api.createCampaign).mockReset();
  vi.mocked(api.stopCampaign).mockReset();
  vi.mocked(session.readSession).mockReset();
  vi.mocked(session.readSession).mockResolvedValue(admin.key);
  vi.mocked(revalidatePath).mockReset();
});

describe("createCampaignAction", () => {
  it("sends the target, the intensity, the phrase as typed, the declaration and the reason, then opens the Campaign", async () => {
    vi.mocked(api.createCampaign).mockResolvedValue({ campaign: queued });
    expect(await redirectOf(createCampaignAction(null, form({ ...good, confirm: `  ${PHRASE} ` })))).toBe(
      `/prove/campaigns/${queued.id}`,
    );
    expect(api.createCampaign).toHaveBeenCalledWith(
      admin.key,
      { target_id: completed.target_id, intensity: "safe-active", confirm: PHRASE, staging: true },
      { reason: REASON },
    );
    expect(revalidatePath).toHaveBeenCalledWith("/prove/campaigns");
  });

  it("names every field that is missing at once, in form order, before anything is sent", async () => {
    expect(await createCampaignAction(null, form({ target: "", intensity: "full", confirm: " " }))).toEqual({
      ok: false,
      errors: [
        { path: "target", message: "Nothing was launched. Choose a target." },
        { path: "intensity", message: "Nothing was launched. Choose one of the offered intensities." },
        {
          path: "confirm",
          message: "Nothing was launched. Type the phrase of the chosen target exactly as it is shown.",
        },
        { path: "staging", message: "Nothing was launched. Declare that the target is a staging or test system." },
        {
          path: "reason",
          message: "Nothing was saved. Give a reason for this change; it is recorded in the audit log.",
        },
      ],
      values: { target: "", intensity: "full" },
    });
    // The declaration must be the checkbox itself: any other value is not a declaration.
    const state = await createCampaignAction(null, form({ ...good, staging: "false" }));
    expect(state?.errors.map((error) => error.path)).toEqual(["staging"]);
    expect(api.createCampaign).not.toHaveBeenCalled();
  });

  it("gives back the target, the intensity and the reason after a refusal, never the phrase", async () => {
    const state = await refusedWith(
      new api.ValidationError("refused", [{ path: "confirm", message: "Type the exact phrase." }]),
    );
    expect(state).toEqual({
      ok: false,
      errors: [
        {
          path: "confirm",
          message: "Nothing was launched. Type the phrase of the chosen target exactly as it is shown.",
        },
      ],
      values,
      reason: REASON,
    });
    expect(JSON.stringify(state)).not.toContain(PHRASE);
  });

  it("maps each field the API refuses to that field", async () => {
    const cases: Array<[string, string, string]> = [
      ["target_id", "target", "Nothing was launched. This target is no longer one of the Organization."],
      ["intensity", "intensity", "Nothing was launched. Choose one of the offered intensities."],
      ["staging", "staging", "Nothing was launched. Declare that the target is a staging or test system."],
    ];
    for (const [apiPath, path, message] of cases) {
      const state = await refusedWith(new api.ValidationError("refused", [{ path: apiPath, message: "x" }]));
      expect(state?.errors).toEqual([{ path, message }]);
    }
    const other = await refusedWith(new api.ValidationError("refused", [{ path: "elsewhere", message: "x" }]));
    expect(other?.errors).toEqual([
      { path: "", message: "The Airverse API reported a problem, so nothing was saved. Try again in a moment." },
    ]);
  });

  it("maps a missing or refused reason to the reason field", async () => {
    expect((await refusedWith(new api.ReasonRequiredError("refused")))?.errors).toEqual([
      { path: "reason", message: "Nothing was saved. Give a reason for this change; it is recorded in the audit log." },
    ]);
    const secret = await refusedWith(new api.ValidationError("refused", [], "reason-holds-secret"));
    expect(secret?.errors[0]?.path).toBe("reason");
  });

  it("maps each conflict to its field or to a clear message", async () => {
    const cases: Array<[ConflictReason | undefined, string, string]> = [
      [
        "campaign-active",
        "",
        "Nothing was launched. This Organization already has a queued or running Campaign. Wait for it to end, or stop it.",
      ],
      [
        "campaign-target-not-verified",
        "target",
        "Nothing was launched. This target is not verified, or its last check is older than 26 hours. Verify it again first.",
      ],
      ["campaign-no-rules", "", "Nothing was launched. There are no signed Rules of Engagement."],
      [
        "campaign-target-out-of-scope",
        "target",
        "Nothing was launched. This target is not in the scope of the current Rules of Engagement.",
      ],
      [
        "campaign-rules-too-old",
        "",
        "Nothing was launched. The current Rules of Engagement were signed more than 90 days ago. Sign them again first.",
      ],
      [
        "campaign-intensity-exceeds",
        "intensity",
        "Nothing was launched. The current Rules of Engagement allow less than this intensity.",
      ],
      [
        "campaign-verification-path-excluded",
        "",
        "Nothing was launched. The current Rules of Engagement exclude /.well-known/airverse-verification.txt, the ownership file every Campaign reads at its start. Sign Rules that do not exclude it.",
      ],
      [
        undefined,
        "",
        "Nothing was launched. The request conflicts with what the API holds. Reload the page and try again.",
      ],
      [
        "target-limit",
        "",
        "Nothing was launched. The request conflicts with what the API holds. Reload the page and try again.",
      ],
    ];
    for (const [reason, path, message] of cases) {
      const state = await refusedWith(new api.ConflictError("refused", reason));
      expect(state?.errors).toEqual([{ path, message }]);
      expect(state?.values).toEqual(values);
    }
  });

  it("says why Campaigns cannot be created at all", async () => {
    const cases = [
      ["disabled", "Nothing was launched. Campaigns are switched off on this API."],
      ["stopped", "Nothing was launched. The operator has stopped all Campaigns."],
      ["suspended", "Nothing was launched. The operator has suspended Campaigns for this Organization."],
    ] as const;
    for (const [kind, message] of cases) {
      const state = await refusedWith(new api.CampaignsUnavailableError("refused", kind));
      expect(state?.errors).toEqual([{ path: "", message }]);
    }
  });

  it("says when to try again after too many Campaigns in 24 hours", async () => {
    const start =
      "Nothing was launched. At most 5 Campaigns per Organization and 3 per target can be created in 24 hours.";
    expect((await refusedWith(new api.RateLimitedError("refused", 5400)))?.errors).toEqual([
      { path: "", message: `${start} Try again in about 2 hours.` },
    ]);
    expect((await refusedWith(new api.RateLimitedError("refused", 90)))?.errors).toEqual([
      { path: "", message: `${start} Try again in about 2 minutes.` },
    ]);
    expect((await refusedWith(new api.RateLimitedError("refused", undefined)))?.errors).toEqual([
      { path: "", message: `${start} Try again later.` },
    ]);
  });

  it("goes to sign-in for a key that stopped working, and explains a pending deletion or an API that is down", async () => {
    expect(await redirectOf(refusedWith(new api.UnauthorizedError("refused")))).toBe("/sign-in?reason=expired");
    expect((await refusedWith(new api.DeletionPendingError("refused")))?.errors[0]?.message).toContain(
      "scheduled for deletion",
    );
    expect((await refusedWith(new api.ApiError("down", 0)))?.errors).toEqual([
      {
        path: "",
        message: "The Airverse API did not answer, so nothing was saved. Check that it is running, then try again.",
      },
    ]);
    vi.mocked(session.readSession).mockResolvedValue(undefined);
    expect(await redirectOf(createCampaignAction(null, form(good)))).toBe("/");
  });
});

describe("stopCampaignAction", () => {
  const stop = { campaignId, confirm: campaignId, reason: "Wrong window" };

  it("stops with the reason and opens the Campaign again", async () => {
    vi.mocked(api.stopCampaign).mockResolvedValue({ campaign: stopped });
    expect(await redirectOf(stopCampaignAction(null, form(stop)))).toBe(`/prove/campaigns/${campaignId}`);
    expect(api.stopCampaign).toHaveBeenCalledWith(admin.key, campaignId, { reason: "Wrong window" });
    expect(revalidatePath).toHaveBeenCalledWith(`/prove/campaigns/${campaignId}`);
    expect(revalidatePath).toHaveBeenCalledWith("/prove/campaigns");
  });

  it("needs the confirmation and a reason, and keeps the reason after a refusal", async () => {
    expect(await stopCampaignAction(null, form({ campaignId, reason: "Wrong window" }))).toEqual({
      ok: false,
      errors: [{ path: "confirm", message: "Nothing was stopped. Confirm the stop first." }],
      reason: "Wrong window",
    });
    expect(await stopCampaignAction(null, form({ campaignId, confirm: campaignId, reason: " " }))).toEqual({
      ok: false,
      errors: [
        {
          path: "reason",
          message: "Nothing was saved. Give a reason for this change; it is recorded in the audit log.",
        },
      ],
    });
    expect(
      (await stopCampaignAction(null, form({ campaignId: "nope", confirm: "nope", reason: "x" })))?.errors,
    ).toEqual([{ path: "", message: "This Campaign no longer exists." }]);
    expect(api.stopCampaign).not.toHaveBeenCalled();
  });

  it("handles a Campaign that had already ended calmly: the page says so, nothing is reported as an error", async () => {
    vi.mocked(api.stopCampaign).mockRejectedValueOnce(new api.ConflictError("refused", "campaign-ended"));
    expect(await redirectOf(stopCampaignAction(null, form(stop)))).toBe(`/prove/campaigns/${campaignId}?notice=ended`);
    expect(revalidatePath).toHaveBeenCalledWith(`/prove/campaigns/${campaignId}`);
  });

  it("maps the other refusals: the reason, a Campaign that is gone, an expired key, an API that is down", async () => {
    vi.mocked(api.stopCampaign).mockRejectedValueOnce(new api.ReasonRequiredError("refused"));
    expect((await stopCampaignAction(null, form(stop)))?.errors[0]?.path).toBe("reason");
    vi.mocked(api.stopCampaign).mockRejectedValueOnce(new api.NotFoundError("refused"));
    expect((await stopCampaignAction(null, form(stop)))?.errors).toEqual([
      { path: "", message: "This Campaign no longer exists." },
    ]);
    vi.mocked(api.stopCampaign).mockRejectedValueOnce(new api.ConflictError("refused"));
    expect((await stopCampaignAction(null, form(stop)))?.errors[0]?.path).toBe("");
    vi.mocked(api.stopCampaign).mockRejectedValueOnce(new api.UnauthorizedError("refused"));
    expect(await redirectOf(stopCampaignAction(null, form(stop)))).toBe("/sign-in?reason=expired");
    vi.mocked(api.stopCampaign).mockRejectedValueOnce(new api.ApiError("down", 0));
    expect((await stopCampaignAction(null, form(stop)))?.errors[0]?.message).toContain("did not answer");
  });
});
