// @vitest-environment node
import { type AlertChannel, EXAMPLE_EMAIL_CHANNEL } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

// Slice 06b: the email channel actions (create with recipients, resend a confirmation, the test alert's refusals)
// and the server-side confirmation of a link, exercised through their interface with the API client, the session,
// the cache and the navigation replaced by fakes.
vi.mock("@/lib/api.ts", async (original) => ({
  ...(await original<typeof import("@/lib/api.ts")>()),
  createAlertChannel: vi.fn(),
  testAlertChannel: vi.fn(),
  resendConfirmation: vi.fn(),
  confirmAlertRecipient: vi.fn(),
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
  confirmRecipientAction,
  createAlertChannelAction,
  resendConfirmationAction,
  testAlertChannelAction,
} from "@/app/actions.ts";
import { confirmRecipientToken } from "@/features/alerts/confirm.ts";
import * as api from "@/lib/api.ts";
import * as session from "@/lib/session.ts";

const admin = generateKey("admin");
const email = EXAMPLE_EMAIL_CHANNEL as Extract<AlertChannel, { kind: "email" }>;
const channelId = email.id;
const recipientId = email.recipients[1]?.id ?? "";
const TOKEN = `${"a".repeat(42)}Z`;

const SMTP_OFF = "Email alerts are not set up on this Airverse server.";
const CAP = "An organization holds at most 10 alert channels. Remove one before adding another.";

function form(fields: Record<string, string>): FormData {
  const data = new FormData();
  for (const [name, value] of Object.entries(fields)) data.append(name, value);
  return data;
}

beforeEach(() => {
  for (const fn of [api.createAlertChannel, api.testAlertChannel, api.resendConfirmation, api.confirmAlertRecipient]) {
    vi.mocked(fn).mockReset();
  }
  vi.mocked(session.readSession).mockReset();
  vi.mocked(session.readSession).mockResolvedValue(admin.key);
  vi.mocked(revalidatePath).mockReset();
});

describe("createAlertChannelAction — email", () => {
  it("sends the recipients one per line, trimmed and lower-cased, blank lines dropped, and no URL", async () => {
    vi.mocked(api.createAlertChannel).mockResolvedValue({ channel: email });
    const state = await createAlertChannelAction(
      null,
      form({ kind: "email", name: " On-call email ", recipients: "  OnCall@Example.com \r\n\n lead@example.com\n" }),
    );
    expect(api.createAlertChannel).toHaveBeenCalledWith(admin.key, {
      kind: "email",
      name: "On-call email",
      recipients: ["oncall@example.com", "lead@example.com"],
    });
    expect(state).toEqual({ ok: true, channel: email });
    expect(revalidatePath).toHaveBeenCalledWith("/settings/alerts");
  });

  it("needs no URL for an email channel", async () => {
    vi.mocked(api.createAlertChannel).mockResolvedValue({ channel: email });
    const state = await createAlertChannelAction(
      null,
      form({ kind: "email", name: "Mail", recipients: "a@example.com" }),
    );
    expect(state).toMatchObject({ ok: true });
  });

  it("checks the recipients with the protocol's rules before calling the API, in the Console's words", async () => {
    const refused = async (recipients: string) =>
      createAlertChannelAction(null, form({ kind: "email", name: "Mail", recipients }));
    expect(await refused(" \n \n")).toEqual({
      ok: false,
      errors: [{ path: "recipients", message: "Enter at least one email address, one per line." }],
      values: { kind: "email", name: "Mail", recipients: " \n \n" },
    });
    expect(
      await refused("a@example.com\nb@example.com\nc@example.com\nd@example.com\ne@example.com\nf@example.com"),
    ).toMatchObject({ errors: [{ path: "recipients", message: "Enter at most 5 email addresses." }] });
    expect(await refused("a@example.com\n\nnot an address")).toMatchObject({
      errors: [{ path: "recipients", message: "Line 3 is not a valid email address." }],
    });
    expect(await refused(`${"x".repeat(65)}@example.com`)).toMatchObject({
      errors: [{ path: "recipients", message: "Line 1 is not a valid email address." }],
    });
    expect(await refused("a@example.com\nb@example.com\nA@Example.com")).toMatchObject({
      errors: [{ path: "recipients", message: "Line 3 repeats an address given above." }],
    });
    expect(api.createAlertChannel).not.toHaveBeenCalled();
  });

  it("checks the name of an email channel too", async () => {
    expect(await createAlertChannelAction(null, form({ kind: "email", name: "", recipients: "" }))).toMatchObject({
      errors: [
        { path: "name", message: "Enter a name." },
        { path: "recipients", message: "Enter at least one email address, one per line." },
      ],
    });
  });

  it("refuses an unknown kind, naming all three", async () => {
    expect(await createAlertChannelAction(null, form({ kind: "pager", name: "x", url: "" }))).toMatchObject({
      errors: [{ path: "kind", message: "Choose Webhook, Slack or Email." }, { path: "url" }],
    });
  });

  it("maps 409 smtp-not-configured to the set-up message, and any other 409 to the cap", async () => {
    vi.mocked(api.createAlertChannel).mockRejectedValueOnce(new api.ConflictError("409", "smtp-not-configured"));
    const fields = { kind: "email", name: "Mail", recipients: "a@example.com" };
    expect(await createAlertChannelAction(null, form(fields))).toEqual({
      ok: false,
      errors: [{ path: "kind", message: SMTP_OFF }],
      values: { kind: "email", name: "Mail", recipients: "a@example.com" },
    });
    vi.mocked(api.createAlertChannel).mockRejectedValueOnce(new api.ConflictError("409"));
    expect(await createAlertChannelAction(null, form(fields))).toMatchObject({ errors: [{ path: "", message: CAP }] });
  });

  it("explains recipients the API refused without repeating its text", async () => {
    vi.mocked(api.createAlertChannel).mockRejectedValueOnce(
      new api.ValidationError("400", [{ path: "recipients.0", message: "Must be a valid email address." }]),
    );
    expect(
      await createAlertChannelAction(null, form({ kind: "email", name: "Mail", recipients: "a@example.com" })),
    ).toMatchObject({
      errors: [
        {
          path: "recipients",
          message: "These addresses were refused. Use 1 to 5 valid email addresses, each on its own line.",
        },
      ],
    });
  });
});

describe("resendConfirmationAction", () => {
  const fields = { channelId, recipientId };

  it("asks the API for a new confirmation email by ids and refreshes the list", async () => {
    vi.mocked(api.resendConfirmation).mockResolvedValue({ recipient: email.recipients[1] as never });
    expect(await resendConfirmationAction(null, form(fields))).toEqual({ ok: true });
    expect(api.resendConfirmation).toHaveBeenCalledWith(admin.key, channelId, recipientId);
    expect(revalidatePath).toHaveBeenCalledWith("/settings/alerts");
  });

  it("says the daily cap was reached on 429", async () => {
    vi.mocked(api.resendConfirmation).mockRejectedValue(new api.RateLimitedError("429", 3600));
    expect(await resendConfirmationAction(null, form(fields))).toEqual({
      ok: false,
      message: "This address already got 3 confirmation emails today. Try again tomorrow.",
    });
  });

  it("says an address that confirmed meanwhile is already confirmed, and refreshes the list", async () => {
    vi.mocked(api.resendConfirmation).mockRejectedValue(new api.ConflictError("409", "recipient-confirmed"));
    expect(await resendConfirmationAction(null, form(fields))).toEqual({
      ok: false,
      message: "This address has already confirmed. Reload the page to see its status.",
    });
    expect(revalidatePath).toHaveBeenCalledWith("/settings/alerts");
  });

  it("explains no SMTP settings, a recipient that is gone and an API that failed", async () => {
    vi.mocked(api.resendConfirmation).mockRejectedValueOnce(new api.ConflictError("409", "smtp-not-configured"));
    expect(await resendConfirmationAction(null, form(fields))).toEqual({ ok: false, message: SMTP_OFF });
    vi.mocked(api.resendConfirmation).mockRejectedValueOnce(new api.NotFoundError("404"));
    expect(await resendConfirmationAction(null, form(fields))).toEqual({
      ok: false,
      message: "This recipient no longer exists. Reload the page to see the current list.",
    });
    vi.mocked(api.resendConfirmation).mockRejectedValueOnce(new api.ApiError("boom", 500));
    expect(await resendConfirmationAction(null, form(fields))).toEqual({
      ok: false,
      message: "The Airverse API reported a problem, so no confirmation email was sent. Try again in a moment.",
    });
    vi.mocked(api.resendConfirmation).mockRejectedValueOnce(new api.ApiError("down", 0));
    expect(await resendConfirmationAction(null, form(fields))).toEqual({
      ok: false,
      message:
        "The Airverse API did not answer, so no confirmation email was sent. Check that it is running, then try again.",
    });
  });

  it("refuses malformed ids without calling the API", async () => {
    expect(await resendConfirmationAction(null, form({ channelId, recipientId: "rcp_x" }))).toMatchObject({
      ok: false,
    });
    expect(await resendConfirmationAction(null, form({ channelId: "chn_x", recipientId }))).toMatchObject({
      ok: false,
    });
    expect(api.resendConfirmation).not.toHaveBeenCalled();
  });

  it("requires a session, and sends an expired one to sign in", async () => {
    vi.mocked(session.readSession).mockResolvedValueOnce(undefined);
    await expect(resendConfirmationAction(null, form(fields))).rejects.toThrow("REDIRECT /");
    vi.mocked(api.resendConfirmation).mockRejectedValueOnce(new api.UnauthorizedError("401"));
    await expect(resendConfirmationAction(null, form(fields))).rejects.toThrow("REDIRECT /sign-in?reason=expired");
  });
});

describe("testAlertChannelAction — email", () => {
  it("says no recipient has confirmed yet on 409 no-confirmed-recipients", async () => {
    vi.mocked(api.testAlertChannel).mockRejectedValueOnce(new api.ConflictError("409", "no-confirmed-recipients"));
    expect(await testAlertChannelAction(null, form({ channelId }))).toEqual({
      ok: false,
      message: "No recipient has confirmed yet.",
    });
  });

  it("says email is not set up on 409 smtp-not-configured", async () => {
    vi.mocked(api.testAlertChannel).mockRejectedValueOnce(new api.ConflictError("409", "smtp-not-configured"));
    expect(await testAlertChannelAction(null, form({ channelId }))).toEqual({ ok: false, message: SMTP_OFF });
  });
});

describe("confirmRecipientToken", () => {
  const consoleSpies: Array<ReturnType<typeof vi.spyOn>> = [];
  beforeEach(() => {
    for (const method of ["log", "info", "warn", "error", "debug"] as const) {
      consoleSpies.push(vi.spyOn(console, method).mockImplementation(() => undefined));
    }
  });
  afterEach(() => {
    for (const spy of consoleSpies.splice(0)) {
      expect(spy).not.toHaveBeenCalled();
      spy.mockRestore();
    }
  });

  it("posts a well-formed token and reports confirmed or invalid as the API says", async () => {
    vi.mocked(api.confirmAlertRecipient).mockResolvedValueOnce({ confirmed: true });
    expect(await confirmRecipientToken(TOKEN)).toBe("confirmed");
    expect(api.confirmAlertRecipient).toHaveBeenCalledWith(TOKEN);
    vi.mocked(api.confirmAlertRecipient).mockResolvedValueOnce({ confirmed: false });
    expect(await confirmRecipientToken(TOKEN)).toBe("invalid");
  });

  it("calls nothing for a missing, repeated or malformed token", async () => {
    for (const token of [undefined, "", [TOKEN, TOKEN], "short", `${TOKEN}x`, `${"a".repeat(42)}=`]) {
      expect(await confirmRecipientToken(token)).toBe("invalid");
    }
    expect(api.confirmAlertRecipient).not.toHaveBeenCalled();
  });

  it("maps 429 to busy, 400 to invalid and any other failure to unavailable", async () => {
    vi.mocked(api.confirmAlertRecipient).mockRejectedValueOnce(new api.RateLimitedError("429", 60));
    expect(await confirmRecipientToken(TOKEN)).toBe("busy");
    vi.mocked(api.confirmAlertRecipient).mockRejectedValueOnce(new api.ValidationError("400", []));
    expect(await confirmRecipientToken(TOKEN)).toBe("invalid");
    vi.mocked(api.confirmAlertRecipient).mockRejectedValueOnce(new api.ApiError("down", 0));
    expect(await confirmRecipientToken(TOKEN)).toBe("unavailable");
    vi.mocked(api.confirmAlertRecipient).mockRejectedValueOnce(new api.ApiError("boom", 500));
    expect(await confirmRecipientToken(TOKEN)).toBe("unavailable");
  });
});

describe("confirmRecipientAction", () => {
  it("confirms the token of the posted form, needs no session, and redirects to a result without the token", async () => {
    vi.mocked(session.readSession).mockResolvedValue(undefined);
    vi.mocked(api.confirmAlertRecipient).mockResolvedValueOnce({ confirmed: true });
    const error = await confirmRecipientAction(form({ token: TOKEN })).catch((thrown: Error) => thrown);
    expect((error as Error).message).toBe("REDIRECT /alerts/confirm/done?result=confirmed");
    expect((error as Error).message).not.toContain(TOKEN);
    expect(api.confirmAlertRecipient).toHaveBeenCalledWith(TOKEN);
    expect(session.readSession).not.toHaveBeenCalled();
  });

  it.each([
    ["invalid", () => vi.mocked(api.confirmAlertRecipient).mockResolvedValueOnce({ confirmed: false })],
    ["busy", () => vi.mocked(api.confirmAlertRecipient).mockRejectedValueOnce(new api.RateLimitedError("429", 60))],
    ["unavailable", () => vi.mocked(api.confirmAlertRecipient).mockRejectedValueOnce(new api.ApiError("x", 0))],
  ] as const)("redirects to result=%s", async (result, arrange) => {
    arrange();
    await expect(confirmRecipientAction(form({ token: TOKEN }))).rejects.toThrow(
      `REDIRECT /alerts/confirm/done?result=${result}`,
    );
  });

  it("redirects a malformed token to invalid without calling the API", async () => {
    await expect(confirmRecipientAction(form({ token: "short" }))).rejects.toThrow(
      "REDIRECT /alerts/confirm/done?result=invalid",
    );
    await expect(confirmRecipientAction(new FormData())).rejects.toThrow(
      "REDIRECT /alerts/confirm/done?result=invalid",
    );
    expect(api.confirmAlertRecipient).not.toHaveBeenCalled();
  });
});
