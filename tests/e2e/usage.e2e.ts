// Ticket 17a in a real browser: Settings → Usage against the real API. Events sent with two Apps' Shield keys (one batch
// sent twice) are metered as protected requests; the page shows the totals, each App, the day's bar and its table row,
// and says the month is in progress. The month picker (a GET form) switches to the previous, closed month, which is
// empty; a month the API refuses is named in its words.
import { randomBytes } from "node:crypto";
import { CreateAppResponseSchema, usageMonthOf } from "@antireverse/protocol";
import { SDK_NAME, SDK_VERSION } from "@antireverse/shield-node";
import { expect, test } from "@playwright/test";
import { API_URL } from "./playwright.config.ts";

const MONTHS = [
  "January",
  "February",
  "March",
  "April",
  "May",
  "June",
  "July",
  "August",
  "September",
  "October",
  "November",
  "December",
];
const monthName = (month: string): string => `${MONTHS[Number(month.slice(5, 7)) - 1]} ${month.slice(0, 4)}`;

/** A UUID version 7 (RFC 9562) for `ms`, as Shield stamps its Events. */
function uuidv7(ms: number): string {
  const hex = ms.toString(16).padStart(12, "0") + randomBytes(10).toString("hex");
  const variant = ((Number.parseInt(hex.slice(16, 17), 16) & 0x3) | 0x8).toString(16);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-7${hex.slice(13, 16)}-${variant}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

/** A batch of `count` allowed requests, as Shield sends it. */
function batchOf(count: number) {
  const now = Date.now();
  const events = Array.from({ length: count }, (_, i) => ({
    event_id: uuidv7(now + i),
    ts: new Date(now + i).toISOString(),
    type: "request.decision",
    surface: "api",
    request: { method: "GET", route: "/api/products/:id", status: 200, latency_ms: 1 },
    decision: { action: "allow", mode: "enforce", rule_id: null, policy_version: 1 },
    actor: { ip_prefix: "198.51.100.0/24" },
    signals: [],
  }));
  return { protocol: 1, sdk: { name: SDK_NAME, version: SDK_VERSION }, events };
}

async function send(shieldKey: string, batch: ReturnType<typeof batchOf>): Promise<unknown> {
  const response = await fetch(`${API_URL}/v1/events`, {
    method: "POST",
    headers: { authorization: `Bearer ${shieldKey}`, "content-type": "application/json" },
    body: JSON.stringify(batch),
  });
  expect(response.status).toBe(202);
  return response.json();
}

test("usage: protected requests per App and per day, and the month picker", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Organization name").fill("Usage e2e");
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByTestId("organization-created")).toBeVisible();
  const adminKey = (await page.getByTestId("admin-key").textContent()) ?? "";
  await page.getByRole("link", { name: "Continue" }).click();

  // Two Apps, created with the admin key; 7 requests to the first (its batch sent twice) and 5 to the second.
  const shieldKeys: string[] = [];
  for (const [name, environment] of [
    ["Storefront", "production"],
    ["Back office", "staging"],
  ] as const) {
    const created = await fetch(`${API_URL}/v1/apps`, {
      method: "POST",
      headers: { authorization: `Bearer ${adminKey}`, "content-type": "application/json" },
      body: JSON.stringify({ name, environment }),
    });
    expect(created.status).toBe(201);
    shieldKeys.push(CreateAppResponseSchema.parse(await created.json()).shield_key.key);
  }
  const first = batchOf(7);
  expect(await send(shieldKeys[0] ?? "", first)).toEqual({ accepted: 7, duplicates: 0 });
  expect(await send(shieldKeys[0] ?? "", first)).toEqual({ accepted: 0, duplicates: 7 });
  expect(await send(shieldKeys[1] ?? "", batchOf(5))).toEqual({ accepted: 5, duplicates: 0 });

  // 1. Settings → Usage: the current month, in progress.
  const now = new Date();
  const month = usageMonthOf(now);
  const today = now.toISOString().slice(0, 10);
  await page.getByTestId("nav-usage").click();
  await expect(page).toHaveURL(/\/settings\/usage$/);
  await expect(page.getByTestId("nav-usage")).toHaveAttribute("aria-current", "page");
  await expect(page.getByRole("heading", { level: 1, name: "Usage" })).toBeVisible();
  await expect(page.getByTestId("usage-status")).toHaveText(
    `${monthName(month)} so far — the month is in progress (UTC). Counts grow until it ends.`,
  );
  await expect(page.locator("#usage-month")).toHaveValue(month);

  const totals = page.getByTestId("usage-total-value");
  await expect(totals).toHaveText(["12", "0", "0"]);
  await expect(page.getByTestId("usage-totals")).toContainText(
    "Requests that Shield drops before they reach Airverse (a full buffer, or giving up after retries) and batches the API refuses are not counted.",
  );
  const rows = page.getByTestId("usage-app-row");
  await expect(rows).toHaveCount(2);
  await expect(rows.nth(0).locator("th, td")).toHaveText(["Storefront", "7", "0", "0"]);
  await expect(rows.nth(1).locator("th, td")).toHaveText(["Back office", "5", "0", "0"]);
  await expect(page.getByTestId("usage-apps-count")).toHaveText("2");
  await expect(page.getByTestId("usage-retention")).toContainText("30 days");
  await expect(page.getByTestId("usage-seats")).toHaveText("Not applicable — no member accounts yet");

  // The chart: an image named by its summary; today's bar is the busiest; its table row says 12.
  await expect(page.getByTestId("usage-chart").getByRole("img")).toHaveAttribute(
    "aria-label",
    `Daily protected requests, ${monthName(month)} so far: 12 in all. Busiest day: ${today}, with 12.`,
  );
  await expect(page.getByTestId("usage-chart-max")).toHaveText("12");
  await page.getByText("Show daily requests as a table").click();
  const todayRow = page.getByTestId("usage-daily-row").filter({ hasText: today });
  await expect(todayRow.locator("th, td")).toHaveText([today, "12"]);

  // 2. The picker: the previous month, closed and empty, through the GET form.
  const previous = usageMonthOf(new Date(Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 1, 1)));
  await page.locator("#usage-month").selectOption(previous);
  await page.getByRole("button", { name: "Show" }).click();
  await expect(page).toHaveURL(new RegExp(`/settings/usage\\?month=${previous}$`));
  await expect(page.getByTestId("usage-status")).toHaveText(`${monthName(previous)} — the month has ended (UTC).`);
  await expect(page.locator("#usage-month")).toHaveValue(previous);
  await expect(totals).toHaveText(["0", "0", "0"]);
  await expect(page.getByTestId("usage-daily-empty")).toHaveText(`No protected requests in ${monthName(previous)}.`);
  await expect(page.getByTestId("usage-chart")).toHaveCount(0);

  // 3. A month the API refuses: its reason, and the picker back on the current month.
  await page.goto(`/settings/usage?month=${now.getUTCFullYear() + 1}-01`);
  await expect(page.getByTestId("usage-invalid")).toHaveText(
    "This month cannot be shown: The month is in the future. Choose one of the listed months.",
  );
  await expect(page.locator("#usage-month")).toHaveValue(month);
  await expect(page.getByTestId("usage-totals")).toHaveCount(0);
});
