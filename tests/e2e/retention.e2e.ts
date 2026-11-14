// Ticket 18c in a real browser: Settings → Data controls → Retention. The table of what is kept and for how long and
// the last run; lengthening the Event retention saves at once without a reason; shortening opens the confirmation step
// in place (focused, reason required) that says what goes, then the outcome is announced with the date the API gave,
// the API holds the new period, and the audit log has the change with its reason.
import { ListAuditResponseSchema, RetentionResponseSchema, UpdateRetentionResponseSchema } from "@antireverse/protocol";
import { expect, test } from "@playwright/test";
import { API_URL } from "./playwright.config.ts";

const REASON = "Storage policy: keep request metadata one week";

const utcTime = (iso: string): string => `${iso.slice(0, 10)} ${iso.slice(11, 19)} UTC`;

test("retention: see what is kept, lengthen without a reason, shorten with one", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Organization name").fill("Retention e2e");
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByTestId("organization-created")).toBeVisible();
  const adminKey = (await page.getByTestId("admin-key").textContent()) ?? "";
  await page.getByRole("link", { name: "Continue" }).click();
  const auth = { authorization: `Bearer ${adminKey}` };
  const read = async () =>
    RetentionResponseSchema.parse(
      await (await fetch(`${API_URL}/v1/organization/retention`, { headers: auth })).json(),
    );

  // 1. The table, the choice (30 days for a new Organization) and the last run.
  await page.goto("/settings/data");
  await expect(page.getByRole("heading", { level: 2, name: "Retention" })).toBeVisible();
  const table = page.getByTestId("retention-table");
  const rows = table.getByTestId("retention-row");
  await expect(rows.first()).toContainText("Events (request metadata)");
  await expect(rows.first()).toContainText("30 days — set below");
  await expect(table).toContainText("Events carrying a Guard report");
  await expect(table).toContainText("395 days after they were last seen; kept while a block still names them");
  await expect(table).toContainText("30 days after their last Assessment");
  await expect(rows.filter({ hasText: "Audit log" })).toContainText("The Organization's lifetime");
  await expect(rows.filter({ hasText: "Builds" })).toContainText("The Organization's lifetime");
  const select = page.getByLabel("Keep Events for");
  await expect(select).toHaveValue("30");
  const before = await read();
  expect(before.retention.event_retention_days).toBe(30);
  const lastRun = page.getByTestId("retention-last-run");
  if (before.last_run === null) await expect(lastRun).toContainText("No run yet.");
  else await expect(lastRun).toContainText(`Last run: ${utcTime(before.last_run.ran_at)}`);

  // 2. Lengthen: saved at once, no confirmation step, no reason.
  await select.selectOption("90");
  await page.getByTestId("retention-save").click();
  const done = page.getByTestId("retention-done");
  await expect(done).toContainText("Event retention set to 90 days.");
  await expect(done).toBeFocused();
  await expect(page.getByTestId("retention-confirm")).toHaveCount(0);
  expect((await read()).retention.event_retention_days).toBe(90);
  await expect(page.getByTestId("retention-row").first()).toContainText("90 days — set below");
  const lengthened = ListAuditResponseSchema.parse(
    await (await fetch(`${API_URL}/v1/audit?action=organization.retention.update`, { headers: auth })).json(),
  );
  expect(lengthened.entries[0]?.summary).toBe("Changed the Event retention from 30 to 90 days.");
  expect(lengthened.entries[0]?.reason ?? null).toBeNull();

  // 3. Shorten: the step opens in place, focused, says what goes and needs a reason.
  await select.selectOption("7");
  await page.getByTestId("retention-save").click();
  await expect(page).toHaveURL(/\/settings\/data$/);
  const step = page.getByTestId("retention-confirm");
  await expect(step).toBeFocused();
  await expect(step.getByTestId("confirm-question")).toHaveText("Shorten the Event retention to 7 days?");
  await expect(step).toContainText("Events received before about");
  await expect(step).toContainText("are removed at the next daily run");
  const reason = step.getByLabel("Reason");
  await expect(reason).toHaveAttribute("required", "");
  // Held back by the browser while the reason is empty: nothing is sent.
  await step.getByTestId("confirm-submit").click();
  await expect(step).toBeVisible();
  expect((await read()).retention.event_retention_days).toBe(90);
  // Cancel closes it and returns to Save.
  await step.getByTestId("confirm-cancel").click();
  await expect(step).toHaveCount(0);
  await expect(page.getByTestId("retention-save")).toBeFocused();

  await page.getByTestId("retention-save").click();
  await expect(step).toBeFocused();
  await reason.fill(REASON);
  const [response] = await Promise.all([
    page.waitForResponse((answer) => answer.request().method() === "POST" && answer.url().includes("/settings/data")),
    step.getByTestId("confirm-submit").click(),
  ]);
  expect(response.ok()).toBe(true);
  await expect(step).toHaveCount(0);
  await expect(done).toContainText("Event retention set to 7 days.");
  await expect(done).toBeFocused();

  // The API holds 7 days; the notice names the date it answered (the change time less 7 days, to the second).
  const after = await read();
  expect(after.retention.event_retention_days).toBe(7);
  const shortened = ListAuditResponseSchema.parse(
    await (await fetch(`${API_URL}/v1/audit?action=organization.retention.update`, { headers: auth })).json(),
  );
  const entry = shortened.entries[0];
  expect(entry?.summary).toBe("Changed the Event retention from 90 to 7 days.");
  expect(entry?.reason).toBe(REASON);
  const removedBefore = new Date(Date.parse(entry?.at ?? "") - 7 * 86_400_000).toISOString();
  await expect(done).toContainText(
    `Events received before about ${utcTime(removedBefore)} are removed at the next daily run, and from then on every Event older than 7 days.`,
  );

  // Keeping the same period is not a shortening: no reason needed.
  const unchanged = await fetch(`${API_URL}/v1/organization/retention`, {
    method: "PUT",
    headers: { ...auth, "content-type": "application/json" },
    body: JSON.stringify({ event_retention_days: 7 }),
  });
  expect(unchanged.status).toBe(200);
  expect(UpdateRetentionResponseSchema.parse(await unchanged.json()).retention.event_retention_days).toBe(7);

  // 4. A reload keeps the period.
  await page.reload();
  await expect(page.getByLabel("Keep Events for")).toHaveValue("7");
  await expect(page.getByTestId("retention-row").first()).toContainText("7 days — set below");
});
