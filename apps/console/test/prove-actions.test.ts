// @vitest-environment node
import {
  EXAMPLE_RULES_OF_ENGAGEMENT,
  EXAMPLE_TARGET,
  type Target,
  verificationInstructions,
} from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { dropReason } from "./helpers/reason.ts";

// Slice 14: the Prove actions, exercised through their interface with the API client, the session, the cache and
// the navigation replaced by fakes.
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  createTarget: vi.fn(),
  deleteTarget: vi.fn(),
  verifyTarget: vi.fn(),
  signRulesOfEngagement: vi.fn(),
  checkAuthorization: vi.fn(),
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
import {
  checkAuthorizationAction,
  createTargetAction,
  deleteTargetAction,
  signRulesOfEngagementAction,
  verifyTargetAction,
} from "@/app/actions.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE";
const targetId = EXAMPLE_TARGET.id;
/** Slice 18a: removing a target and signing Rules of Engagement carry a reason. */
const REASON = "Scope review of 2026-11-13";
const CONFLICT = "This change conflicts with what the API holds, so nothing was saved. Reload the page and try again.";
const API_DOWN = "The Airverse API did not answer, so nothing was saved. Check that it is running, then try again.";
const HOST_INVALID =
  "Enter a public DNS name such as shop.acme.io. IP addresses and private names such as localhost are not accepted.";

function form(fields: Record<string, string | string[]>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) {
    for (const one of Array.isArray(value) ? value : [value]) data.append(name, one);
  }
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

const ALL = [api.createTarget, api.deleteTarget, api.verifyTarget, api.signRulesOfEngagement, api.checkAuthorization];

beforeEach(() => {
  for (const fn of ALL) vi.mocked(fn).mockReset();
  vi.mocked(session.readSession).mockReset();
  vi.mocked(session.readSession).mockResolvedValue(admin.key);
  vi.mocked(revalidatePath).mockReset();
});

describe("createTargetAction", () => {
  it("adds the host as typed (trimmed) and opens its page with the instructions", async () => {
    const pending: Target = { ...EXAMPLE_TARGET, status: "pending", method: null, verified_at: null };
    vi.mocked(api.createTarget).mockResolvedValue({
      target: pending,
      verification: verificationInstructions(pending.host, TOKEN),
    });
    expect(await redirectOf(createTargetAction(null, form({ host: "  shop.acme-shop.io " })))).toBe(
      `/prove/targets/${targetId}`,
    );
    expect(api.createTarget).toHaveBeenCalledWith(admin.key, { host: "shop.acme-shop.io" });
    expect(revalidatePath).toHaveBeenCalledWith("/prove/targets");
  });

  it("asks for a host, and refuses an address or a private name before sending anything", async () => {
    expect(await createTargetAction(null, form({ host: "" }))).toEqual({
      ok: false,
      errors: [{ path: "host", message: "Enter a host, for example shop.acme.io." }],
      values: { host: "" },
    });
    for (const host of ["203.0.113.7", "printer.local", "localhost", "https://shop.acme-shop.io/"]) {
      expect(await createTargetAction(null, form({ host }))).toEqual({
        ok: false,
        errors: [{ path: "host", message: HOST_INVALID }],
        values: { host },
      });
    }
    expect(api.createTarget).not.toHaveBeenCalled();
  });

  it("shows the API's refusal of the host below the field", async () => {
    vi.mocked(api.createTarget).mockRejectedValue(
      new api.ValidationError("400", [{ path: "host", message: "already a target" }]),
    );
    expect(await createTargetAction(null, form({ host: "shop.acme-shop.io" }))).toEqual({
      ok: false,
      errors: [
        {
          path: "host",
          message: "The API did not accept this host. It may already be a target, or it is not a public DNS name.",
        },
      ],
      values: { host: "shop.acme-shop.io" },
    });
  });

  it("maps each 409 reason exactly: the 50 cap, a host already added, and a generic conflict otherwise", async () => {
    const create = async () => (await createTargetAction(null, form({ host: "shop.acme-shop.io" })))?.errors;
    vi.mocked(api.createTarget).mockRejectedValueOnce(new api.ConflictError("409", "target-limit"));
    expect(await create()).toEqual([
      { path: "", message: "Your organization already has 50 targets. Remove one first." },
    ]);
    vi.mocked(api.createTarget).mockRejectedValueOnce(new api.ConflictError("409", "target-duplicate"));
    expect(await create()).toEqual([{ path: "host", message: "This host is already a target of your organization." }]);
    // No reason, or one that is not about creating a target: never guessed.
    vi.mocked(api.createTarget).mockRejectedValueOnce(new api.ConflictError("409"));
    expect(await create()).toEqual([{ path: "", message: CONFLICT }]);
    vi.mocked(api.createTarget).mockRejectedValueOnce(new api.ConflictError("409", "target-in-scope"));
    expect(await create()).toEqual([{ path: "", message: CONFLICT }]);
  });

  it("says when the API did not answer", async () => {
    vi.mocked(api.createTarget).mockRejectedValueOnce(new api.ApiError("down", 0));
    expect((await createTargetAction(null, form({ host: "shop.acme-shop.io" })))?.errors).toEqual([
      { path: "", message: API_DOWN },
    ]);
  });

  it("sends a signed out person home and an expired key to sign in", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(undefined);
    expect(await redirectOf(createTargetAction(null, form({ host: "shop.acme-shop.io" })))).toBe("/");
    vi.mocked(api.createTarget).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    expect(await redirectOf(createTargetAction(null, form({ host: "shop.acme-shop.io" })))).toBe(
      "/sign-in?reason=expired",
    );
  });
});

describe("verifyTargetAction", () => {
  it("returns the outcome and refreshes the target and the list", async () => {
    const result = { verified: true as const, method: "file" as const, checked_at: "2026-11-12T08:05:00.000Z" };
    vi.mocked(api.verifyTarget).mockResolvedValue({ target: EXAMPLE_TARGET, result });
    expect(await verifyTargetAction(null, form({ targetId }))).toEqual({ ok: true, result });
    expect(api.verifyTarget).toHaveBeenCalledWith(admin.key, targetId);
    expect(revalidatePath).toHaveBeenCalledWith(`/prove/targets/${targetId}`);
    expect(revalidatePath).toHaveBeenCalledWith("/prove/targets");
  });

  it("explains both hourly limits (per host and per organization) with the minutes to wait", async () => {
    vi.mocked(api.verifyTarget).mockRejectedValueOnce(new api.RateLimitedError("429", 1201));
    expect(await verifyTargetAction(null, form({ targetId }))).toEqual({
      ok: false,
      message:
        "Each host can be checked 10 times per hour, and each organization 60 times per hour. Try again in 21 min.",
    });
    vi.mocked(api.verifyTarget).mockRejectedValueOnce(new api.RateLimitedError("429", undefined));
    expect(await verifyTargetAction(null, form({ targetId }))).toEqual({
      ok: false,
      message: "Each host can be checked 10 times per hour, and each organization 60 times per hour. Try again later.",
    });
  });

  it("refuses a malformed id without calling the API, and says when the target is gone", async () => {
    expect(await verifyTargetAction(null, form({ targetId: "tgt_x" }))).toEqual({
      ok: false,
      message: "This target no longer exists. Reload the page.",
    });
    expect(api.verifyTarget).not.toHaveBeenCalled();
    vi.mocked(api.verifyTarget).mockRejectedValueOnce(new api.NotFoundError("404"));
    expect(await verifyTargetAction(null, form({ targetId }))).toEqual({
      ok: false,
      message: "This target no longer exists. Reload the page.",
    });
  });
});

describe("deleteTargetAction", () => {
  it("removes the target named in the confirmation and goes back to the list", async () => {
    vi.mocked(api.deleteTarget).mockResolvedValue(undefined);
    expect(await redirectOf(deleteTargetAction(null, form({ targetId, confirm: targetId, reason: REASON })))).toBe(
      "/prove/targets",
    );
    expect(api.deleteTarget).toHaveBeenCalledWith(admin.key, targetId, { reason: REASON });
    expect(revalidatePath).toHaveBeenCalledWith("/prove/targets");
  });

  it("refuses without the confirmation", async () => {
    expect(dropReason(await deleteTargetAction(null, form({ targetId })))).toEqual({
      ok: false,
      errors: [{ path: "confirm", message: "Nothing was removed. Confirm the change first." }],
    });
    expect(api.deleteTarget).not.toHaveBeenCalled();
  });

  it("explains that a target in the current scope cannot be removed, on the reason target-in-scope only", async () => {
    vi.mocked(api.deleteTarget).mockRejectedValueOnce(new api.ConflictError("409"));
    expect(dropReason(await deleteTargetAction(null, form({ targetId, confirm: targetId, reason: REASON })))).toEqual({
      ok: false,
      errors: [{ path: "", message: CONFLICT }],
    });
    vi.mocked(api.deleteTarget).mockRejectedValueOnce(new api.ConflictError("409", "target-limit"));
    expect((await deleteTargetAction(null, form({ targetId, confirm: targetId, reason: REASON })))?.errors).toEqual([
      { path: "", message: CONFLICT },
    ]);
    vi.mocked(api.deleteTarget).mockRejectedValueOnce(new api.ConflictError("409", "target-in-scope"));
    expect(dropReason(await deleteTargetAction(null, form({ targetId, confirm: targetId, reason: REASON })))).toEqual({
      ok: false,
      errors: [
        {
          path: "",
          message:
            "This host is in the current Rules of Engagement, so it was not removed. Sign a new version without it first.",
        },
      ],
    });
  });

  it("treats a target that is already gone as removed", async () => {
    vi.mocked(api.deleteTarget).mockRejectedValueOnce(new api.NotFoundError("404"));
    expect(await redirectOf(deleteTargetAction(null, form({ targetId, confirm: targetId, reason: REASON })))).toBe(
      "/prove/targets",
    );
  });
});

describe("signRulesOfEngagementAction", () => {
  const fields = {
    scope: [targetId],
    exclusions: " /admin \r\n\r\n/checkout\n",
    intensity: "safe-active",
    days: ["mon", "tue", "wed", "thu", "fri"],
    from: "09:00",
    to: "17:00",
    contacts: "security@acme-shop.io\noncall@acme-shop.io",
    confirm: "I authorise safe-active testing",
    reason: REASON,
  };
  const values = {
    scope: [targetId],
    exclusions: fields.exclusions,
    intensity: "safe-active",
    days: fields.days,
    allDay: false,
    from: "09:00",
    to: "17:00",
    contacts: fields.contacts,
  };

  it("signs the version with one exclusion and one contact per line, and opens the Rules of Engagement", async () => {
    vi.mocked(api.signRulesOfEngagement).mockResolvedValue({ version: EXAMPLE_RULES_OF_ENGAGEMENT });
    expect(await redirectOf(signRulesOfEngagementAction(null, form(fields)))).toBe("/prove/rules-of-engagement");
    expect(api.signRulesOfEngagement).toHaveBeenCalledWith(
      admin.key,
      {
        scope: [targetId],
        exclusions: ["/admin", "/checkout"],
        intensity: "safe-active",
        window: { days: ["mon", "tue", "wed", "thu", "fri"], from: "09:00", to: "17:00" },
        contacts: ["security@acme-shop.io", "oncall@acme-shop.io"],
        confirm: "I authorise safe-active testing",
      },
      { reason: REASON },
    );
    expect(revalidatePath).toHaveBeenCalledWith("/prove/rules-of-engagement");
  });

  it("sends the whole day, 00:00 to 24:00, for All day", async () => {
    vi.mocked(api.signRulesOfEngagement).mockResolvedValue({ version: EXAMPLE_RULES_OF_ENGAGEMENT });
    await redirectOf(signRulesOfEngagementAction(null, form({ ...fields, allDay: "on", from: "", to: "" })));
    expect(vi.mocked(api.signRulesOfEngagement).mock.calls[0]?.[1].window).toEqual({
      days: ["mon", "tue", "wed", "thu", "fri"],
      from: "00:00",
      to: "24:00",
    });
  });

  it("refuses without the exact phrase for the chosen intensity, and keeps what was written", async () => {
    expect(
      dropReason(await signRulesOfEngagementAction(null, form({ ...fields, confirm: "I authorise full testing" }))),
    ).toEqual({
      ok: false,
      errors: [{ path: "confirm", message: "Nothing was signed. Type the phrase exactly as shown." }],
      values,
    });
    expect(api.signRulesOfEngagement).not.toHaveBeenCalled();
  });

  it("explains every malformed field before sending anything", async () => {
    const state = dropReason(
      await signRulesOfEngagementAction(
        null,
        form({
          exclusions: "admin\n/a/../b",
          intensity: "loud",
          from: "9",
          to: "17:00",
          contacts: "nobody",
          confirm: "",
        }),
      ),
    );
    expect(state && !state.ok ? state.errors : []).toEqual([
      { path: "scope", message: "Choose at least one verified target." },
      {
        path: "exclusions",
        message: "Write each excluded path on its own line, starting with /, without a trailing /, such as /admin.",
      },
      { path: "intensity", message: "Choose an intensity." },
      { path: "days", message: "Choose at least one day." },
      { path: "from", message: "Enter a start time as HH:MM, from 00:00 to 23:59." },
      { path: "contacts", message: "Enter 1 to 5 email addresses, one per line." },
    ]);
    expect(api.signRulesOfEngagement).not.toHaveBeenCalled();
  });

  it("refuses an end time equal to the start", async () => {
    const state = dropReason(await signRulesOfEngagementAction(null, form({ ...fields, to: "09:00" })));
    expect(state && !state.ok ? state.errors : []).toEqual([
      { path: "to", message: "Enter an end time as HH:MM, from 00:00 to 24:00, different from the start." },
    ]);
  });

  it("answers a 409 on signing with the generic conflict message, never a guess", async () => {
    vi.mocked(api.signRulesOfEngagement).mockRejectedValueOnce(new api.ConflictError("409"));
    const state = dropReason(await signRulesOfEngagementAction(null, form(fields)));
    expect(state && !state.ok ? state.errors : []).toEqual([{ path: "", message: CONFLICT }]);
  });

  it("says when a chosen target is no longer verified", async () => {
    vi.mocked(api.signRulesOfEngagement).mockRejectedValueOnce(
      new api.ValidationError("400", [{ path: "scope.0", message: "not verified" }]),
    );
    const state = dropReason(await signRulesOfEngagementAction(null, form(fields)));
    expect(state && !state.ok ? state.errors : []).toEqual([
      {
        path: "scope",
        message:
          "A chosen target is no longer verified or no longer exists, so nothing was signed. Reload the page and choose again.",
      },
    ]);
  });
});

describe("checkAuthorizationAction", () => {
  const fields = { host: "shop.acme-shop.io", path: "/products", intensity: "passive", at: "2026-11-12T10:30" };

  it("checks the test at the time given in UTC and returns the answer with what was typed", async () => {
    vi.mocked(api.checkAuthorization).mockResolvedValue({ allowed: false, reason: "path_excluded" });
    expect(await checkAuthorizationAction(null, form(fields))).toEqual({
      ok: true,
      result: { allowed: false, reason: "path_excluded" },
      values: fields,
    });
    expect(api.checkAuthorization).toHaveBeenCalledWith(admin.key, {
      host: "shop.acme-shop.io",
      path: "/products",
      intensity: "passive",
      at: "2026-11-12T10:30:00.000Z",
    });
  });

  it("explains malformed fields before asking", async () => {
    const state = await checkAuthorizationAction(
      null,
      form({ host: "10.0.0.1", path: "products", intensity: "x", at: "soon" }),
    );
    expect(state && !state.ok ? state.errors : []).toEqual([
      { path: "host", message: HOST_INVALID },
      { path: "path", message: "Enter a path starting with /, such as /products." },
      { path: "intensity", message: "Choose an intensity." },
      { path: "at", message: "Enter a date and time in UTC." },
    ]);
    expect(api.checkAuthorization).not.toHaveBeenCalled();
  });
});
