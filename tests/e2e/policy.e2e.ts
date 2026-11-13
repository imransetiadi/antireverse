// Ticket 02 in a real browser: add a Rule, promote it with the confirmation, see a Blocked row;
// roll back to the Monitor version and see the request served and marked as would-have-blocked.
import http from "node:http";
import type { AddressInfo } from "node:net";
import { createShield, type Shield } from "@antireverse/shield-node";
import { expect, type Page, test } from "@playwright/test";
import express from "express";
import { API_URL } from "./playwright.config.ts";

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
  const publicKey = (await page.getByTestId("policy-public-key").first().textContent()) ?? "";
  expect(publicKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
  return { shieldKey, publicKey };
}

/** `reason`: the reason a sensitive change requires (slice 18a); typed into the step when given. */
async function confirm(page: Page, question: RegExp, reason?: string): Promise<void> {
  const dialog = page.getByTestId("policy-confirm");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByTestId("confirm-question")).toHaveText(question);
  if (reason !== undefined) await dialog.getByTestId("confirm-reason").fill(reason);
  await dialog.getByTestId("confirm-submit").click();
  await expect(page.getByTestId("policy-confirm")).toHaveCount(0);
}

test("a Rule promoted in the Console blocks a request, and a rollback lifts the block", async ({ page }) => {
  const { shieldKey, publicKey } = await createOrganizationAndApp(page);

  // The signing key the Console shows is the one the API signs with.
  const signingKey = (await (await fetch(`${API_URL}/v1/signing-key`)).json()) as { public_key: string };
  expect(publicKey).toBe(signingKey.public_key);

  // 1. Add a Rule: it starts in Monitor mode (version 1).
  await page.getByTestId("policy-link").click();
  await expect(page).toHaveURL(/\/policy\?environment=development$/);
  await expect(page.getByTestId("policy-empty")).toBeVisible();
  await page.getByLabel("Rule name").fill("Admin area");
  await page.getByLabel("Path pattern").fill("/api/admin/**");
  await page.getByRole("button", { name: "Add Rule" }).click();
  const row = page.getByTestId("rule-row").filter({ hasText: "/api/admin/**" });
  await expect(row).toHaveAttribute("data-mode", "monitor");
  await expect(row.getByTestId("mode-tag")).toHaveText("Monitor");
  await expect(page.getByTestId("policy-version")).toHaveText("Version 1");

  // 2. Promote it, with the confirmation naming Environment and pattern (version 2).
  await row.getByTestId("rule-promote").click();
  await confirm(
    page,
    /^Promote to enforce in development\? Requests matching \/api\/admin\/\*\* will be blocked\.$/,
    "Admin area must not be reachable",
  );
  await expect(row).toHaveAttribute("data-mode", "enforce");
  await expect(page.getByTestId("policy-version")).toHaveText("Version 2");

  // 3. The customer's server, with the key and the public key from the Console.
  const shield: Shield = createShield({
    key: shieldKey,
    endpoint: API_URL,
    policyPublicKey: publicKey,
    flushIntervalMs: 200,
    logger: { warn() {} },
  });
  const app = express();
  app.use(shield.express());
  app.get("/api/admin/reports", (_req, res) => {
    res.json({ reports: [] });
  });
  const customer = http.createServer(app);
  await new Promise<void>((resolve) => customer.listen(0, "127.0.0.1", resolve));
  const url = `http://127.0.0.1:${(customer.address() as AddressInfo).port}/api/admin/reports`;

  try {
    await shield.refreshPolicy();
    expect(shield.stats()).toMatchObject({ policyVersion: 2, policyRules: 1, lastPolicyError: null });

    // 4. Blocked, and visible as an enforced block in the live feed.
    await page.getByTestId("app-nav-live").click();
    await expect(page.getByTestId("live-indicator")).toHaveText("Live");
    expect((await fetch(url)).status).toBe(403);
    const blockedRow = page.getByTestId("event-row").filter({ hasText: "/api/admin/**" });
    await expect(blockedRow).toHaveCount(1, { timeout: 5_000 });
    await expect(
      blockedRow.locator('[data-testid="decision-chip"][data-decision="block"][data-mode="enforce"]'),
    ).toHaveText("Blocked");
    await expect(blockedRow.getByTestId("mode-tag")).toHaveCount(0);
    await expect(blockedRow).toContainText("403");

    // 5. Roll back to version 1 (the Rule in Monitor mode), with its confirmation (version 3).
    await page.getByTestId("app-nav-policy").click();
    await page.locator('[data-testid="version-row"][data-version="1"]').getByTestId("version-rollback").click();
    await confirm(page, /^Roll back development to the Rules of version 1\?$/);
    await expect(page.getByTestId("policy-version")).toHaveText("Version 3");
    await expect(page.getByTestId("rule-row").filter({ hasText: "/api/admin/**" })).toHaveAttribute(
      "data-mode",
      "monitor",
    );

    await shield.refreshPolicy();
    expect(shield.stats().policyVersion).toBe(3);

    // 6. Served again, and marked as would-have-blocked.
    await page.getByTestId("app-nav-live").click();
    await expect(page.getByTestId("live-indicator")).toHaveText("Live");
    expect((await fetch(url)).status).toBe(200);
    const markedRow = page.getByTestId("event-row").filter({ hasText: "/api/admin/reports" });
    await expect(markedRow).toHaveCount(1, { timeout: 5_000 });
    await expect(
      markedRow.locator('[data-testid="decision-chip"][data-decision="block"][data-mode="monitor"]'),
    ).toBeVisible();
    await expect(markedRow.getByTestId("mode-tag")).toHaveText("Monitor");
    await expect(markedRow).toContainText("200");
  } finally {
    await shield.close();
    customer.closeAllConnections();
    await new Promise<void>((resolve) => customer.close(() => resolve()));
  }
});

test("enforcing a broad Rule needs the stronger confirmation with the Environment typed", async ({ page }) => {
  await createOrganizationAndApp(page);
  await page.getByTestId("policy-link").click();
  await page.getByLabel("Rule name").fill("Everything below the root");
  await page.getByLabel("Path pattern").fill("/*/**");
  await page.getByRole("button", { name: "Add Rule" }).click();
  const row = page.getByTestId("rule-row").filter({ hasText: "/*/**" });
  await expect(row).toHaveAttribute("data-mode", "monitor");

  await row.getByTestId("rule-promote").click();
  const dialog = page.getByTestId("policy-confirm");
  await expect(dialog.getByTestId("confirm-broad")).toHaveText(
    "This pattern matches most of the App's requests. Enforcing it can take the App offline for its users.",
  );
  await expect(dialog.getByTestId("confirm-typed-label")).toHaveText("Type development to confirm");

  // A wrong value is not accepted: the browser holds the form back and nothing is published.
  await dialog.getByTestId("confirm-reason").fill("Lock the App down during the incident");
  await dialog.getByTestId("confirm-typed").fill("Development");
  await dialog.getByTestId("confirm-submit").click();
  await expect(page.getByTestId("policy-version")).toHaveText("Version 1");
  await expect(row).toHaveAttribute("data-mode", "monitor");

  // The exact Environment name enforces it.
  await dialog.getByTestId("confirm-typed").fill("development");
  await dialog.getByTestId("confirm-submit").click();
  await expect(page.getByTestId("policy-confirm")).toHaveCount(0);
  await expect(page.getByTestId("policy-version")).toHaveText("Version 2");
  await expect(row).toHaveAttribute("data-mode", "enforce");
});
