// Ticket 06 in a real browser: a burst of enforced blocks opens a High Incident that the Console lists; the
// analyst opens it, acknowledges and resolves it. Alert settings: add a webhook channel (signing secret shown
// once), send a test alert to a local receiver, remove the channel.
// The API of playwright.config.ts runs with AR_ALLOW_PRIVATE_ALERT_URLS=1 so that a loopback http receiver is allowed.
import { randomBytes } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { verifyWebhookSignature } from "@antireverse/protocol/server";
import { SDK_NAME, SDK_VERSION } from "@antireverse/shield-node";
import { expect, type Page, test } from "@playwright/test";
import { API_URL } from "./playwright.config.ts";

/** PB-14: a Detection is recorded within 10 s of the Event that completes it. */
const DETECTION_BUDGET_MS = 10_000;

async function createOrganizationAndApp(page: Page): Promise<{ shieldKey: string }> {
  await page.goto("/");
  await page.getByLabel("Organization name").fill("Acme");
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByTestId("organization-created")).toBeVisible();
  await page.getByRole("link", { name: "Continue" }).click();
  await page.getByRole("link", { name: "New App" }).first().click();
  await page.getByLabel("App name").fill("shop-web");
  await page.getByRole("button", { name: "Create App" }).click();
  await expect(page.getByTestId("app-created")).toHaveText("shop-web is ready");
  const shieldKey = (await page.getByTestId("shield-key").textContent()) ?? "";
  expect(shieldKey).toMatch(/^ark_dev_[A-Za-z0-9_-]{43}$/);
  return { shieldKey };
}

/** A UUID version 7 (RFC 9562) for `ms`, as Shield stamps its Events. */
function uuidv7(ms: number): string {
  const hex = ms.toString(16).padStart(12, "0") + randomBytes(10).toString("hex");
  const variant = ((Number.parseInt(hex.slice(16, 17), 16) & 0x3) | 0x8).toString(16);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-7${hex.slice(13, 16)}-${variant}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

/** Posts `count` enforced blocks from one network prefix with the Shield key, as Shield would after a burst. */
async function postBlockedEvents(shieldKey: string, count: number): Promise<void> {
  const now = Date.now();
  const events = Array.from({ length: count }, (_, i) => ({
    event_id: uuidv7(now + i),
    ts: new Date(now + i).toISOString(),
    type: "request.decision",
    surface: "api",
    request: { method: "GET", route: "/api/admin/**", status: 403, latency_ms: 1 },
    decision: { action: "block", mode: "enforce", rule_id: "rul_0123456789abcdef01234567", policy_version: 1 },
    actor: { ip_prefix: "203.0.113.0/24" },
    signals: [],
  }));
  const response = await fetch(`${API_URL}/v1/events`, {
    method: "POST",
    headers: { authorization: `Bearer ${shieldKey}`, "content-type": "application/json" },
    body: JSON.stringify({ protocol: 1, sdk: { name: SDK_NAME, version: SDK_VERSION }, events }),
  });
  expect(response.status).toBe(202);
  expect(await response.json()).toEqual({ accepted: count, duplicates: 0 });
}

test("a burst of enforced blocks opens a High Incident that is acknowledged and resolved in the Console", async ({
  page,
}) => {
  const { shieldKey } = await createOrganizationAndApp(page);

  await page.getByTestId("nav-incidents").click();
  await expect(page).toHaveURL(/\/incidents$/);
  await expect(page.getByTestId("incidents-empty")).toBeVisible();

  // 20 enforced blocks from 203.0.113.0/24: the threshold of "Blocked burst".
  await postBlockedEvents(shieldKey, 20);

  const row = page.getByTestId("incident-row").filter({ hasText: "Blocked burst" });
  await expect(async () => {
    await page.reload();
    await expect(row).toHaveCount(1, { timeout: 1_000 });
  }).toPass({ timeout: DETECTION_BUDGET_MS });
  await expect(row).toHaveAttribute("data-severity", "high");
  await expect(row).toHaveAttribute("data-status", "open");
  await expect(row.getByTestId("incident-app")).toHaveText("shop-web");
  await expect(row.getByTestId("incident-status")).toHaveText("Open");

  await row.getByTestId("incident-link").click();
  await expect(page).toHaveURL(/\/incidents\/inc_[0-9a-f]{24}$/);
  await expect(page.getByTestId("incident-severity")).toHaveAttribute("data-severity", "high");
  await expect(page.getByTestId("incident-severity")).toContainText("High");
  await expect(page.getByTestId("incident-status")).toHaveAttribute("data-status", "open");
  await expect(page.getByTestId("incident-facts")).toContainText("203.0.113.0/24");
  await expect(page.getByTestId("incident-timeline")).toBeVisible();
  await expect(page.getByTestId("incident-evidence")).toContainText("/api/admin/**");

  // Acknowledge: sent at once.
  await page.getByTestId("incident-acknowledge").click();
  await expect(page.getByTestId("incident-status")).toHaveAttribute("data-status", "acknowledged");
  await expect(page.getByTestId("incident-status")).toHaveText("Acknowledged");
  await expect(page.getByTestId("incident-acknowledge")).toHaveCount(0);

  // Resolve: never one click — a confirmation first.
  await page.getByTestId("incident-resolve").click();
  const dialog = page.getByTestId("incident-confirm");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByTestId("confirm-question")).toContainText("Blocked burst");
  await dialog.getByTestId("confirm-submit").click();
  await expect(page.getByTestId("incident-resolved-note")).toBeVisible();
  await expect(page.getByTestId("incident-status")).toHaveAttribute("data-status", "resolved");
  await expect(page.getByTestId("incident-confirm")).toHaveCount(0);

  // The list shows it resolved.
  await page.getByTestId("nav-incidents").click();
  await expect(page.getByTestId("incident-row").filter({ hasText: "Blocked burst" })).toHaveAttribute(
    "data-status",
    "resolved",
  );
});

test("a webhook channel is added with its secret shown once, test-sent to a receiver, and removed", async ({
  page,
}) => {
  const received: { signature: string; rawBody: string }[] = [];
  const receiver = http.createServer((req, res) => {
    const chunks: Buffer[] = [];
    req.on("data", (chunk: Buffer) => chunks.push(chunk));
    req.on("end", () => {
      received.push({
        signature: String(req.headers["ar-signature"] ?? ""),
        rawBody: Buffer.concat(chunks).toString("utf8"),
      });
      res.writeHead(200).end();
    });
  });
  await new Promise<void>((resolve) => receiver.listen(0, "127.0.0.1", resolve));
  const hookUrl = `http://127.0.0.1:${(receiver.address() as AddressInfo).port}/hooks/antireverse-e2e`;

  try {
    await createOrganizationAndApp(page);
    await page.getByTestId("nav-alerts").click();
    await expect(page).toHaveURL(/\/settings\/alerts$/);
    await expect(page.getByTestId("channels-empty")).toBeVisible();

    await page.locator("#channel-kind").selectOption("webhook");
    await page.locator("#channel-name").fill("Ops webhook");
    await page.locator("#channel-url").fill(hookUrl);
    await page.getByTestId("channel-add").click();
    await expect(page.getByTestId("channel-created")).toBeVisible();
    const secretEl = page.getByTestId("signing-secret");
    await expect(secretEl).toHaveText(/^whsec_[A-Za-z0-9_-]{43}$/);
    const secret = (await secretEl.textContent()) ?? "";

    const row = page.getByTestId("channel-row").filter({ hasText: "Ops webhook" });
    await expect(row).toHaveCount(1);
    await expect(row.getByTestId("channel-destination")).toContainText("127.0.0.1");
    // The URL is never shown back, only its host and last 4 characters.
    expect(await page.content()).not.toContain("/hooks/antireverse-e2e");

    await row.getByTestId("channel-test").click();
    await expect(row.getByTestId("channel-test-outcome")).toHaveAttribute("data-outcome", "delivered");
    expect(received).toHaveLength(1);
    const [alert] = received;
    expect(JSON.parse(alert?.rawBody ?? "{}")).toMatchObject({ type: "test", incident: null, console_url: null });
    expect(
      verifyWebhookSignature(secret, alert?.signature ?? "", alert?.rawBody ?? "", Math.floor(Date.now() / 1000)),
    ).toBe(true);
    expect(alert?.rawBody).not.toContain(secret);

    // Shown once: after a reload the secret is nowhere on the page.
    await page.reload();
    await expect(page.getByTestId("signing-secret")).toHaveCount(0);
    expect(await page.content()).not.toContain(secret);

    await page.getByTestId("channel-row").filter({ hasText: "Ops webhook" }).getByTestId("channel-remove").click();
    const dialog = page.getByTestId("channel-confirm");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByTestId("confirm-question")).toContainText("Ops webhook");
    await dialog.getByTestId("confirm-submit").click();
    await expect(page.getByTestId("channel-row")).toHaveCount(0);
    await expect(page.getByTestId("channels-empty")).toBeVisible();
  } finally {
    receiver.closeAllConnections();
    await new Promise<void>((resolve) => receiver.close(() => resolve()));
  }
});
