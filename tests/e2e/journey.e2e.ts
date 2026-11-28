// Ticket 01 in a real browser: create an Organization and an App in the Console, run a customer server
// with Shield using the key the Console shows, send a request, and see it in the live feed within 5 s.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { createShield } from "@antireverse/shield-node";
import { expect, test } from "@playwright/test";
import express from "express";
import { API_URL } from "./playwright.config.ts";

/** PB-13: an Event is visible within five seconds. */
const VISIBLE_BUDGET_MS = 5_000;

test("a request to a server running Shield appears in the Console live feed", async ({ page, context }) => {
  const visitedUrls: string[] = [];
  page.on("framenavigated", (frame) => visitedUrls.push(frame.url()));

  // 1. Create the Organization; the admin key is shown once.
  await page.goto("/");
  await page.getByLabel("Organization name").fill("Acme");
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByTestId("organization-created")).toHaveText("Acme is ready");
  await expect(page.getByTestId("admin-key")).toHaveText(/^aro_[A-Za-z0-9_-]{43}$/);
  const adminKey = (await page.getByTestId("admin-key").textContent()) ?? "";

  const cookies = await context.cookies();
  const session = cookies.find((cookie) => cookie.name === "ar_admin");
  expect(session, "the session cookie exists").toBeDefined();
  expect(session?.httpOnly).toBe(true);
  expect(session?.sameSite).toBe("Lax");
  expect(await page.evaluate<string>("document.cookie")).not.toContain("aro_");

  // 2. Create the App; the Shield key is shown once, with the monitor-mode sentence.
  await page.getByRole("link", { name: "Continue" }).click();
  await expect(page).toHaveURL(/\/apps$/);
  // Shown once: after leaving the page the admin key is nowhere in the document.
  expect((await page.content()).includes(adminKey)).toBe(false);
  await expect(page.getByText("No Apps yet. Create one to get a Shield key.")).toBeVisible();
  await page.getByRole("link", { name: "New App" }).first().click();
  await page.getByLabel("App name").fill("shop-web");
  await page.getByRole("button", { name: "Create App" }).click();
  await expect(page.getByTestId("app-created")).toHaveText("shop-web is ready");
  const shieldKey = (await page.getByTestId("shield-key").textContent()) ?? "";
  expect(shieldKey).toMatch(/^ark_dev_[A-Za-z0-9_-]{43}$/);
  // The copyable set-up snippet for Express is on the same screen.
  await expect(page.getByText(/^npm install --save-exact @antireverse\/shield-node@\d+\.\d+\.\d+$/)).toBeVisible();
  await expect(page.getByText("app.use(shield.express());")).toBeVisible();
  await expect(page.getByRole("button", { name: "Copy" }).first()).toBeVisible();
  await expect(page.getByTestId("monitor-note")).toHaveText(
    "Shield starts in monitor mode — it observes and cannot block anything yet.",
  );

  // 3. Open the live feed: nothing yet, connection live.
  await page.getByTestId("live-link").click();
  await expect(page).toHaveURL(/\/apps\/app_[0-9a-f]{24}\/live$/);
  await expect(page.getByTestId("feed-waiting")).toContainText("Waiting for the first event from shop-web");
  await expect(page.getByTestId("live-indicator")).toHaveText("Live");

  // 4. The customer's server, with Shield and the key from the Console.
  const shield = createShield({ key: shieldKey, endpoint: API_URL, flushIntervalMs: 200 });
  expect(shield.stats().disabledReason).toBeNull();
  const customerApp = express();
  customerApp.use(shield.express());
  customerApp.get("/api/products/:id", (req, res) => {
    res.json({ id: req.params.id });
  });
  const customer = http.createServer(customerApp);
  await new Promise<void>((resolve) => customer.listen(0, "127.0.0.1", resolve));
  const customerUrl = `http://127.0.0.1:${(customer.address() as AddressInfo).port}`;

  try {
    // 5. One request; it must appear without a reload, inside the budget.
    const startedAt = Date.now();
    const response = await fetch(`${customerUrl}/api/products/4711?token=secret-value`);
    expect(response.status).toBe(200);

    const row = page.getByTestId("event-row").filter({ hasText: "/api/products/:id" });
    await expect(row).toHaveCount(1, { timeout: VISIBLE_BUDGET_MS });
    const visibleMs = Date.now() - startedAt;
    expect(visibleMs).toBeLessThanOrEqual(VISIBLE_BUDGET_MS);
    test.info().annotations.push({ type: "event-visible-ms", description: String(visibleMs) });

    await expect(row).toContainText("Allowed");
    await expect(row).toContainText("Monitor");
    await expect(row).toContainText("GET");
    await expect(row).toContainText("200");
    await expect(page.getByTestId("feed-waiting")).toHaveCount(0);
    await expect(page.getByTestId("live-indicator")).toHaveText("Live");

    // Nothing from the concrete URL reaches the Console.
    const feedText = (await page.locator("main").textContent()) ?? "";
    expect(feedText).not.toContain("4711");
    expect(feedText).not.toContain("secret-value");
  } finally {
    await shield.close();
    customer.closeAllConnections();
    await new Promise<void>((resolve) => customer.close(() => resolve()));
  }

  // 6. No key ever appeared in a URL.
  for (const url of visitedUrls) {
    expect(url).not.toContain("aro_");
    expect(url).not.toContain("ark_");
  }

  // 7. After a reload the feed is served from storage and the key is gone from the page.
  await page.reload();
  await expect(page.getByTestId("event-row").filter({ hasText: "/api/products/:id" })).toHaveCount(1);
  expect((await page.content()).includes(shieldKey)).toBe(false);
});
