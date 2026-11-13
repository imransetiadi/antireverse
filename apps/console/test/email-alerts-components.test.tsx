import { type AlertChannel, EXAMPLE_ALERT_CHANNEL, EXAMPLE_EMAIL_CHANNEL } from "@antireverse/protocol";
import { act, fireEvent, render, screen, within } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

// Slice 06b: the email channel on the alert settings screen (form, recipients with their status, resend) and the
// public confirmation page. The Server Actions, the confirmation call and the session guard are replaced by fakes.
vi.mock("@/app/actions.ts", () => ({
  createAlertChannelAction: vi.fn(),
  deleteAlertChannelAction: vi.fn(),
  testAlertChannelAction: vi.fn(),
  resendConfirmationAction: vi.fn(),
  confirmRecipientAction: vi.fn(),
  signOutAction: vi.fn(),
}));
vi.mock("@/features/alerts/confirm.ts", () => ({ confirmRecipientToken: vi.fn() }));
vi.mock("@/lib/guard.ts", () => ({
  requireSession: vi.fn(() => {
    throw new Error("the confirmation page must not require a session");
  }),
  currentOrganization: vi.fn(() => {
    throw new Error("the confirmation page must not read a session");
  }),
}));

import * as actions from "@/app/actions.ts";
import AlertConfirmDonePage from "@/app/alerts/confirm/done/page.tsx";
import AlertConfirmPage from "@/app/alerts/confirm/page.tsx";
import { AddChannelForm } from "@/features/alerts/add-channel-form.tsx";
import { ChannelList } from "@/features/alerts/channel-list.tsx";
import { confirmRecipientToken } from "@/features/alerts/confirm.ts";
import { ConfirmOutcome } from "@/features/alerts/confirm-outcome.tsx";

const email = EXAMPLE_EMAIL_CHANNEL as Extract<AlertChannel, { kind: "email" }>;
const [confirmed, pending] = email.recipients as [(typeof email.recipients)[0], (typeof email.recipients)[0]];
const TOKEN = `${"T".repeat(40)}_-k`;
const SMTP_OFF = "Email alerts are not set up on this Airverse server.";

const sent = (action: unknown): Record<string, string[]> => {
  const data = vi.mocked(action as (previous: unknown, data: FormData) => unknown).mock.calls.at(-1)?.[1];
  if (!data) throw new Error("the action was not called");
  const values: Record<string, string[]> = {};
  for (const [name, value] of data.entries()) values[name] = [...(values[name] ?? []), String(value)];
  return values;
};
const submit = async (control: HTMLElement): Promise<void> => {
  await act(async () => {
    fireEvent.click(control);
  });
};
const recipientRow = (id: string): HTMLElement => {
  const found = screen.getAllByTestId("recipient").find((element) => element.getAttribute("data-recipient-id") === id);
  if (!found) throw new Error(`no recipient ${id}`);
  return found;
};

beforeEach(() => {
  for (const action of Object.values(actions)) vi.mocked(action).mockReset();
  vi.mocked(confirmRecipientToken).mockReset();
});

describe("AddChannelForm — email", () => {
  it("offers Email as a kind and asks for recipients one per line instead of a URL", () => {
    render(<AddChannelForm smtpConfigured />);
    const kind = screen.getByLabelText("Kind") as HTMLSelectElement;
    expect(Array.from(kind.options).map((option) => [option.value, option.textContent, option.disabled])).toEqual([
      ["webhook", "Webhook", false],
      ["slack", "Slack", false],
      ["email", "Email", false],
    ]);
    expect(screen.queryByLabelText("Recipients")).toBeNull();
    fireEvent.change(kind, { target: { value: "email" } });
    expect(screen.queryByLabelText("URL")).toBeNull();
    const recipients = screen.getByLabelText("Recipients") as HTMLTextAreaElement;
    expect(recipients.tagName).toBe("TEXTAREA");
    expect(document.getElementById("channel-recipients-help")?.textContent).toBe(
      "One email address per line, up to 5. Each address gets a link to confirm and receives alerts only after confirming.",
    );
    expect(document.getElementById("channel-kind-help")).toBeNull();
  });

  it("sends kind, name and recipients, and says each recipient must confirm", async () => {
    vi.mocked(actions.createAlertChannelAction).mockResolvedValue({ ok: true, channel: email });
    render(<AddChannelForm smtpConfigured />);
    fireEvent.change(screen.getByLabelText("Kind"), { target: { value: "email" } });
    fireEvent.change(screen.getByLabelText("Channel name"), { target: { value: "On-call email" } });
    fireEvent.change(screen.getByLabelText("Recipients"), {
      target: { value: "oncall@example.com\nlead@example.com" },
    });
    await submit(screen.getByTestId("channel-add"));
    expect(sent(actions.createAlertChannelAction)).toEqual({
      kind: ["email"],
      name: ["On-call email"],
      recipients: ["oncall@example.com\nlead@example.com"],
    });
    expect(screen.getByTestId("channel-created").textContent).toBe("On-call email was added");
    expect(screen.getByTestId("channel-confirmation-note").textContent).toBe(
      "Each recipient gets an email with a link to confirm. Alerts go only to recipients who confirmed.",
    );
    expect(screen.queryByTestId("signing-secret")).toBeNull();
  });

  it("shows Email disabled with the reason when SMTP is not configured", () => {
    render(<AddChannelForm smtpConfigured={false} />);
    const kind = screen.getByLabelText("Kind") as HTMLSelectElement;
    const option = Array.from(kind.options).find((one) => one.value === "email");
    expect(option?.disabled).toBe(true);
    expect(document.getElementById("channel-kind-help")?.textContent).toBe(SMTP_OFF);
    expect(kind.getAttribute("aria-describedby")).toContain("channel-kind-help");
  });

  it("shows a refusal of the recipients below the field and keeps what was typed", async () => {
    vi.mocked(actions.createAlertChannelAction).mockResolvedValue({
      ok: false,
      errors: [{ path: "recipients", message: "Line 2 is not a valid email address." }],
      values: { kind: "email", name: "Mail", recipients: "a@example.com\nnope" },
    });
    render(<AddChannelForm smtpConfigured />);
    fireEvent.change(screen.getByLabelText("Kind"), { target: { value: "email" } });
    await submit(screen.getByTestId("channel-add"));
    const recipients = screen.getByLabelText("Recipients") as HTMLTextAreaElement;
    expect(recipients.value).toBe("a@example.com\nnope");
    expect(recipients.getAttribute("aria-invalid")).toBe("true");
    expect(screen.getByTestId("channel-recipients-error").textContent).toBe("Line 2 is not a valid email address.");
    expect(screen.getByTestId("error-summary").textContent).toContain("Line 2 is not a valid email address.");
    expect((screen.getByLabelText("Kind") as HTMLSelectElement).value).toBe("email");
  });

  it("shows the API's smtp-not-configured refusal next to the kind", async () => {
    vi.mocked(actions.createAlertChannelAction).mockResolvedValue({
      ok: false,
      errors: [{ path: "kind", message: SMTP_OFF }],
      values: { kind: "email", name: "Mail", recipients: "a@example.com" },
    });
    render(<AddChannelForm smtpConfigured />);
    await submit(screen.getByTestId("channel-add"));
    expect(screen.getByTestId("channel-kind-error").textContent).toBe(SMTP_OFF);
  });
});

describe("ChannelList — email", () => {
  it("lists each recipient with its status chip and last sent time, never a token", () => {
    render(<ChannelList channels={[EXAMPLE_ALERT_CHANNEL, email]} confirmRemoveId={undefined} />);
    const row = screen
      .getAllByTestId("channel-row")
      .find((element) => element.getAttribute("data-channel-id") === email.id) as HTMLElement;
    expect(within(row).getByTestId("channel-kind").textContent).toBe("Email");
    const addresses = within(row)
      .getAllByTestId("recipient-address")
      .map((element) => element.textContent);
    expect(addresses).toEqual(["oncall@example.com", "lead@example.com"]);

    const yes = within(recipientRow(confirmed.id)).getByTestId("recipient-status");
    expect(yes.textContent).toBe("Confirmed");
    expect(yes.getAttribute("data-status")).toBe("confirmed");
    expect(yes.querySelector("svg")).not.toBeNull();
    expect(yes.className).toContain("text-primary");
    const no = within(recipientRow(pending.id)).getByTestId("recipient-status");
    expect(no.textContent).toBe("Pending");
    expect(no.getAttribute("data-status")).toBe("pending");
    expect(no.querySelector("svg")).not.toBeNull();
    expect(no.className).toContain("text-sev-medium");
    // Own glyph each: the state reads in greyscale.
    expect(yes.querySelector("svg")?.innerHTML).not.toBe(no.querySelector("svg")?.innerHTML);

    const sentAt = within(recipientRow(confirmed.id)).getByTestId("recipient-last-sent");
    expect(sentAt.textContent).toBe("Last sent 2026-11-10 08:05:00 UTC");
    expect(sentAt.querySelector("time")?.getAttribute("dateTime")).toBe("2026-11-10T08:05:00.000Z");
    expect(document.body.innerHTML).not.toMatch(/token/i);
  });

  it("says when nothing was sent to a recipient yet", () => {
    const fresh = { ...email, recipients: [{ ...pending, last_sent_at: null }] };
    render(<ChannelList channels={[fresh]} confirmRemoveId={undefined} />);
    expect(screen.getByTestId("recipient-last-sent").textContent).toBe("Nothing sent yet");
  });

  it("offers Resend confirmation for pending recipients only, and sends the ids", async () => {
    vi.mocked(actions.resendConfirmationAction).mockResolvedValue({ ok: true });
    render(<ChannelList channels={[email]} confirmRemoveId={undefined} />);
    expect(within(recipientRow(confirmed.id)).queryByRole("button", { name: "Resend confirmation" })).toBeNull();
    const resend = within(recipientRow(pending.id)).getByRole("button", { name: "Resend confirmation" });
    expect(resend.getAttribute("data-testid")).toBe("recipient-resend");
    await submit(resend);
    expect(sent(actions.resendConfirmationAction)).toEqual({ channelId: [email.id], recipientId: [pending.id] });
    const outcome = within(recipientRow(pending.id)).getByTestId("recipient-resend-outcome");
    expect(outcome.textContent).toBe("Confirmation email sent.");
    expect(outcome.getAttribute("role")).toBe("status");
  });

  it("shows the daily cap refusal of a resend", async () => {
    vi.mocked(actions.resendConfirmationAction).mockResolvedValue({
      ok: false,
      message: "This address already got 3 confirmation emails today. Try again tomorrow.",
    });
    render(<ChannelList channels={[email]} confirmRemoveId={undefined} />);
    await submit(within(recipientRow(pending.id)).getByTestId("recipient-resend"));
    expect(screen.getByTestId("recipient-resend-outcome").textContent).toBe(
      "This address already got 3 confirmation emails today. Try again tomorrow.",
    );
  });

  it("asks before removing an email channel, naming its addresses", () => {
    render(<ChannelList channels={[email]} confirmRemoveId={email.id} />);
    expect(screen.getByTestId("confirm-question").textContent).toBe(
      "Remove the alert channel On-call email? New Incidents will no longer be sent to oncall@example.com, lead@example.com.",
    );
  });

  it("names email in the empty state", () => {
    render(<ChannelList channels={[]} confirmRemoveId={undefined} />);
    expect(screen.getByTestId("channels-empty").textContent).toBe(
      "No alert channels yet. Add a webhook, Slack or email channel to be told when an Incident opens.",
    );
  });
});

describe("ConfirmOutcome", () => {
  it.each([
    ["confirmed", "Email confirmed. You will receive Airverse alerts for this channel."],
    ["invalid", "This link is invalid or has expired. Ask your team to resend it."],
    ["busy", "Too many attempts. Try again in a minute."],
    ["unavailable", "Airverse could not check this link right now. Try again in a few minutes."],
  ] as const)("says %s in words", (outcome, text) => {
    render(<ConfirmOutcome outcome={outcome} />);
    const shown = screen.getByTestId("confirm-outcome");
    expect(shown.textContent).toBe(text);
    expect(shown.getAttribute("data-outcome")).toBe(outcome);
  });
});

describe("/alerts/confirm", () => {
  const page = async (searchParams: Record<string, string | string[] | undefined>) =>
    render(await AlertConfirmPage({ searchParams: Promise.resolve(searchParams) }));

  it("never confirms on load: it asks for a click, carrying the token in a hidden field of a POST form", async () => {
    await page({ token: TOKEN });
    expect(confirmRecipientToken).not.toHaveBeenCalled();
    expect(actions.confirmRecipientAction).not.toHaveBeenCalled();
    expect(screen.getByRole("heading", { level: 1 }).textContent).toBe("Email confirmation");
    expect(screen.getByTestId("confirm-lead").textContent).toBe(
      "Confirm this email address to receive Airverse alerts for the channel that added it.",
    );
    const button = screen.getByRole("button", { name: "Confirm email" });
    expect(button.getAttribute("data-testid")).toBe("confirm-submit");
    const formElement = button.closest("form") as HTMLFormElement;
    const hidden = formElement.querySelector('input[name="token"]') as HTMLInputElement;
    expect(hidden.type).toBe("hidden");
    expect(hidden.value).toBe(TOKEN);
    expect(screen.queryByTestId("confirm-outcome")).toBeNull();
    // A page for anyone with the link: the brand only, no navigation of the Console, no sign-out.
    expect(screen.queryByRole("navigation")).toBeNull();
    expect(screen.queryByRole("button", { name: /sign out/i })).toBeNull();
  });

  it("sends the click to the confirmation action", async () => {
    await page({ token: TOKEN });
    await submit(screen.getByTestId("confirm-submit"));
    const data = vi.mocked(actions.confirmRecipientAction).mock.calls.at(-1)?.[0] as FormData;
    expect(data.get("token")).toBe(TOKEN);
  });

  it.each([[undefined], [""], ["short"], [[TOKEN, TOKEN]], [`${TOKEN}x`]])(
    "shows the invalid sentence and no button for the token %j",
    async (token) => {
      await page({ token });
      expect(screen.getByTestId("confirm-outcome").textContent).toBe(
        "This link is invalid or has expired. Ask your team to resend it.",
      );
      expect(screen.queryByRole("button", { name: "Confirm email" })).toBeNull();
      expect(document.body.innerHTML).not.toContain(TOKEN);
    },
  );
});

describe("/alerts/confirm/done", () => {
  const page = async (searchParams: Record<string, string | string[] | undefined>) =>
    render(await AlertConfirmDonePage({ searchParams: Promise.resolve(searchParams) }));

  it.each([
    ["confirmed", "Email confirmed. You will receive Airverse alerts for this channel."],
    ["invalid", "This link is invalid or has expired. Ask your team to resend it."],
    ["busy", "Too many attempts. Try again in a minute."],
    ["unavailable", "Airverse could not check this link right now. Try again in a few minutes."],
  ] as const)("shows the %s outcome without a button", async (result, text) => {
    await page({ result });
    expect(screen.getByTestId("confirm-outcome").textContent).toBe(text);
    expect(screen.queryByRole("button", { name: "Confirm email" })).toBeNull();
    expect(screen.queryByRole("navigation")).toBeNull();
  });

  it("treats an unknown or repeated result as invalid", async () => {
    for (const result of [undefined, "yes", ["confirmed", "confirmed"]]) {
      const { unmount } = await page({ result });
      expect(screen.getByTestId("confirm-outcome").getAttribute("data-outcome")).toBe("invalid");
      unmount();
    }
  });
});
