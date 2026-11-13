// Ticket 06b in a real browser: an email channel is added in the Console; its recipient opens the confirmation link
// from the mail the e2e API's local SMTP server received (fixtures/api-fixture-patches.ts writes those mails to
// E2E_FAKE_MAIL_FILE). Opening the link confirms nothing (mail link scanners open links): the API still says pending
// until "Confirm email" is clicked; then the browser lands on the done page without the token, and the channel list
// shows the recipient as Confirmed.
import { readFileSync } from "node:fs";
import { decodeQuotedPrintable } from "@antireverse/api";
import { ListAlertChannelsResponseSchema } from "@antireverse/protocol";
import { expect, test } from "@playwright/test";
import { API_URL, CONSOLE_URL, FAKE_MAIL_FILE } from "./playwright.config.ts";

const MAIL_BUDGET_MS = 15_000;
const RECIPIENT = "ivy@example.com";

interface Mail {
  from: string;
  to: string[];
  data: string;
  overTls: boolean;
}

function mailsTo(address: string): Mail[] {
  let mails: Mail[];
  try {
    mails = JSON.parse(readFileSync(FAKE_MAIL_FILE as string, "utf8")) as Mail[];
  } catch {
    return [];
  }
  return mails.filter((mail) => mail.to.includes(address));
}

async function recipientStatus(adminKey: string): Promise<string | undefined> {
  const response = await fetch(`${API_URL}/v1/alert-channels`, { headers: { authorization: `Bearer ${adminKey}` } });
  expect(response.status).toBe(200);
  const { channels, smtp_configured } = ListAlertChannelsResponseSchema.parse(await response.json());
  expect(smtp_configured).toBe(true);
  const channel = channels.find((c) => c.kind === "email");
  return channel?.kind === "email" ? channel.recipients.find((r) => r.address === RECIPIENT)?.status : undefined;
}

test("an email recipient confirms by the mailed link and shows as Confirmed", async ({ page, browser }) => {
  await page.goto("/");
  await page.getByLabel("Organization name").fill("Acme");
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByTestId("organization-created")).toBeVisible();
  const adminKey = (await page.getByTestId("admin-key").textContent()) ?? "";
  expect(adminKey).toMatch(/^aro_[A-Za-z0-9_-]{43}$/);
  await page.getByRole("link", { name: "Continue" }).click();

  await page.getByTestId("nav-alerts").click();
  await expect(page).toHaveURL(/\/settings\/alerts$/);
  await expect(page.getByTestId("channels-empty")).toBeVisible();

  await page.locator("#channel-kind").selectOption("email");
  await page.locator("#channel-name").fill("On-call mail");
  await page.locator("#channel-recipients").fill(RECIPIENT);
  await page.getByTestId("channel-add").click();
  await expect(page.getByTestId("channel-created")).toBeVisible();
  await expect(page.getByTestId("channel-confirmation-note")).toBeVisible();

  const row = page.getByTestId("channel-row").filter({ hasText: "On-call mail" });
  await expect(row).toHaveAttribute("data-kind", "email");
  const recipient = row.getByTestId("recipient").filter({ hasText: RECIPIENT });
  await expect(recipient.getByTestId("recipient-status")).toHaveAttribute("data-status", "pending");

  // The confirmation mail, from the local SMTP server: exactly one, over TLS, with one link.
  await expect.poll(() => mailsTo(RECIPIENT).length, { timeout: MAIL_BUDGET_MS }).toBe(1);
  const [mail] = mailsTo(RECIPIENT) as [Mail];
  expect(mail.overTls).toBe(true);
  const body = decodeQuotedPrintable(mail.data.slice(mail.data.indexOf("\r\n\r\n") + 4));
  const link = /https?:\/\/\S+/.exec(body)?.[0] ?? "";
  expect(link).toMatch(new RegExp(`^${CONSOLE_URL}/alerts/confirm\\?token=[A-Za-z0-9_-]{43}$`));
  const token = new URL(link).searchParams.get("token") ?? "";

  // The recipient opens it in a browser without a Console session.
  const context = await browser.newContext();
  try {
    const inbox = await context.newPage();
    await inbox.goto(link);
    const confirmButton = inbox.getByRole("button", { name: "Confirm email" });
    await expect(confirmButton).toBeVisible();
    await expect(inbox.getByTestId("confirm-lead")).toBeVisible();
    // Opening the page confirmed nothing.
    expect(await recipientStatus(adminKey)).toBe("pending");

    await confirmButton.click();
    await inbox.waitForURL(/\/alerts\/confirm\/done/);
    expect(inbox.url()).toBe(`${CONSOLE_URL}/alerts/confirm/done?result=confirmed`);
    expect(inbox.url()).not.toContain(token);
    await expect(inbox.getByTestId("confirm-outcome")).toHaveAttribute("data-outcome", "confirmed");
    await expect(inbox.getByTestId("confirm-outcome")).toContainText("Email confirmed");
    // The form and its token are gone from the page. (The document keeps the framework's inline data of the page it
    // started on, the link page, because the redirect after the action is a client-side navigation: not checked.)
    await expect(inbox.locator('input[name="token"]')).toHaveCount(0);
    expect(await inbox.locator("main").textContent()).not.toContain(token);
    // Reloading the done page (a fresh request to its address) carries no token either.
    await inbox.reload();
    await expect(inbox.getByTestId("confirm-outcome")).toHaveAttribute("data-outcome", "confirmed");
    expect(await inbox.content()).not.toContain(token);
  } finally {
    await context.close();
  }
  expect(await recipientStatus(adminKey)).toBe("confirmed");

  // The channel list shows it Confirmed.
  await page.reload();
  const confirmed = page
    .getByTestId("channel-row")
    .filter({ hasText: "On-call mail" })
    .getByTestId("recipient")
    .filter({ hasText: RECIPIENT });
  await expect(confirmed.getByTestId("recipient-status")).toHaveAttribute("data-status", "confirmed");
  await expect(confirmed.getByTestId("recipient-status")).toHaveText("Confirmed");
  // One mail in all: confirming sends nothing more.
  expect(mailsTo(RECIPIENT)).toHaveLength(1);
});
