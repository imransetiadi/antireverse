// Ticket 08 in a real browser: the admin adds a Rule for /login with the "Login protection" preset (POST, 10 failed
// responses per 5 minutes per address; a new Rule is always monitor), sees the limit in the Rule list, promotes it
// to enforce through the confirmation that says requests over the limit will be refused, and — with a real Express
// app behind Shield answering ten failed logins and Shield refusing the eleventh — sees "Throttled" in the live feed.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { RATE_LIMITED_RESPONSE_BODY } from "@antireverse/protocol";
import { createShield, type Shield } from "@antireverse/shield-node";
import { expect, type Page, test } from "@playwright/test";
import express from "express";
import { API_URL } from "./playwright.config.ts";

/** What the preset fills in. */
const FAILURES = 10;

async function createOrganizationAndApp(page: Page): Promise<{ shieldKey: string; publicKey: string }> {
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
  const publicKey = (await page.getByTestId("policy-public-key").first().textContent()) ?? "";
  expect(publicKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
  return { shieldKey, publicKey };
}

test("a Login protection Rule added and promoted in the Console throttles failed logins, shown as Throttled", async ({
  page,
}) => {
  test.setTimeout(120_000);
  const { shieldKey, publicKey } = await createOrganizationAndApp(page);

  // 1. The Rule form: name and path are the admin's, the preset fills the rest and sends nothing.
  await page.getByTestId("policy-link").click();
  await expect(page).toHaveURL(/\/policy\?environment=development$/);
  await expect(page.getByTestId("policy-empty")).toBeVisible();
  await expect(page.getByTestId("rule-limit-fields")).toHaveCount(0);
  await page.getByLabel("Rule name").fill("Login protection");
  await page.getByLabel("Path pattern").fill("/login");
  await page.getByTestId("rule-preset-login").click();
  await expect(page.getByTestId("policy-empty")).toBeVisible();
  const fields = page.getByTestId("rule-limit-fields");
  await expect(fields).toBeVisible();
  await expect(page.locator("#rule-action-throttle")).toBeChecked();
  await expect(page.locator("#rule-methods-POST")).toBeChecked();
  await expect(page.locator("#rule-limit-requests")).toHaveValue(String(FAILURES));
  await expect(page.locator("#rule-limit-window")).toHaveValue("300");
  await expect(page.locator("#rule-limit-key-ip")).toBeChecked();
  await expect(page.locator("#rule-limit-count-failures")).toBeChecked();
  // A limit and a signature requirement never go together.
  await expect(page.getByTestId("rule-requires-signature")).toBeDisabled();

  await page.getByRole("button", { name: "Add Rule" }).click();
  const row = page.getByTestId("rule-row").filter({ hasText: "/login" });
  await expect(row).toHaveCount(1);
  await expect(row).toHaveAttribute("data-mode", "monitor");
  await expect(row).toHaveAttribute("data-action", "throttle");
  await expect(row.getByTestId("rule-limit")).toHaveText("10 failed responses / 5 min per address");
  await expect(row.getByTestId("rule-methods")).toHaveText("POST");
  await expect(row.getByTestId("rule-limit-note")).toHaveCount(0);
  await expect(page.getByTestId("policy-version")).toHaveText("Version 1");

  // 2. Promote, through the confirmation: a limit Rule refuses the requests over the limit, not every one.
  await row.getByTestId("rule-promote").click();
  const dialog = page.getByTestId("policy-confirm");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByTestId("confirm-question")).toHaveText(
    /^Promote to enforce in development\? Requests matching \/login over the limit will be refused\.$/,
  );
  // Nothing is enforced before the confirmation.
  await expect(row).toHaveAttribute("data-mode", "monitor");
  // Slice 18a: promoting is a sensitive change, recorded in the audit log with its reason.
  await dialog.getByTestId("confirm-reason").fill("Credential stuffing on /login");
  await dialog.getByTestId("confirm-submit").click();
  await expect(page.getByTestId("policy-confirm")).toHaveCount(0);
  await expect(row).toHaveAttribute("data-mode", "enforce");
  await expect(page.getByTestId("policy-version")).toHaveText("Version 2");
  await expect(row.getByTestId("rule-limit")).toHaveText("10 failed responses / 5 min per address");
  await expect(row.getByTestId("rule-limit-note")).toHaveText("Counted per Shield instance.");

  // 3. The customer's server: a real Express app behind Shield whose login refuses every password.
  const shield: Shield = createShield({
    key: shieldKey,
    endpoint: API_URL,
    policyPublicKey: publicKey,
    flushIntervalMs: 200,
    logger: { warn() {} },
  });
  let handlerCalls = 0;
  const app = express();
  app.use(shield.express());
  app.post("/login", (_req, res) => {
    handlerCalls += 1;
    res.status(401).json({ error: "invalid_credentials" });
  });
  const customer = http.createServer(app);
  await new Promise<void>((resolve) => customer.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(customer.address() as AddressInfo).port}/login`;
  const attempt = () => fetch(url, { method: "POST" });

  try {
    await shield.refreshPolicy();
    expect(shield.stats()).toMatchObject({ policyVersion: 2, policyRules: 1, lastPolicyError: null });

    // 4. Ten failed logins are the app's own 401; the eleventh is refused before the handler.
    await page.getByTestId("app-nav-live").click();
    await expect(page.getByTestId("live-indicator")).toHaveText("Live");
    for (let i = 0; i < FAILURES; i++) {
      const response = await attempt();
      expect(response.status, `login ${i + 1}`).toBe(401);
      await response.text();
    }
    expect(handlerCalls).toBe(FAILURES);
    // A failure is counted when its response has closed on the server: a moment after the client has read it.
    await page.waitForTimeout(100);
    const refused = await attempt();
    expect(refused.status).toBe(429);
    expect(refused.headers.get("retry-after")).toMatch(/^[1-9][0-9]*$/);
    expect(await refused.text()).toBe(RATE_LIMITED_RESPONSE_BODY);
    expect(handlerCalls).toBe(FAILURES);

    // 5. The live feed: one Throttled row for the limited route, enforced, with the 429; the ten failures are
    //    plain rows of the app's own 401.
    const rows = page.getByTestId("event-row").filter({ hasText: "/login" });
    const throttled = rows.filter({
      has: page.locator('[data-testid="decision-chip"][data-decision="throttle"][data-mode="enforce"]'),
    });
    await expect(throttled).toHaveCount(1, { timeout: 5_000 });
    await expect(throttled.getByTestId("decision-chip")).toHaveText("Throttled");
    await expect(throttled).toContainText("429");
    await expect(throttled.getByTestId("mode-tag")).toHaveCount(0);
    await expect(rows).toHaveCount(FAILURES + 1);
    await expect(rows.locator('[data-testid="decision-chip"][data-decision="block"]')).toHaveCount(0);
  } finally {
    await shield.close();
    customer.closeAllConnections();
    await new Promise<void>((resolve) => customer.close(() => resolve()));
  }
});
