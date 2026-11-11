// Ticket 09 in a real browser: an attack through Shield opens an Incident; the analyst opens it, blocks its Actor
// from the containment bar (1 hour by default) after a confirmation that names App, Environment, duration and
// expiry; the attacker's next request through the running Shield is blocked within 30 s while another client of
// the same /24 is not; the App's Containment tab lists the block; Lift (confirmed) lets the attacker through again.
// Settings › Never block: add a range, see it, remove it with a confirmation.
//
// Two clients in one /24: only 127.0.0.1 exists on macOS loopback, so the customer's Shield reads the client
// address from X-Forwarded-For through its public `clientAddress` option (as behind a trusted reverse proxy), and
// the test sends two documentation addresses of 198.51.100.0/24.
import { randomBytes } from "node:crypto";
import http, { type IncomingMessage } from "node:http";
import type { AddressInfo } from "node:net";
import { BLOCK_RESPONSE_BODY } from "@antireverse/protocol";
import { actorHash } from "@antireverse/protocol/server";
import { createRangeServer } from "@antireverse/range";
import { createShield, type Shield } from "@antireverse/shield-node";
import { expect, type Page, test } from "@playwright/test";
import { API_URL } from "./playwright.config.ts";

/** PB-14: a Detection is recorded within 10 s of the Event that completes it. */
const DETECTION_BUDGET_MS = 10_000;
/** PB-15: a containment is enforced by every Shield of the App and Environment within 30 s. */
const ENFORCE_BUDGET_MS = 30_000;
const BURST = 20;
/** The customer-held actor key Shield hashes addresses with (owner decision on review finding F1). */
const ACTOR_KEY = randomBytes(32).toString("base64url");
const ATTACKER = "198.51.100.7";
const BYSTANDER = "198.51.100.9";

function forwardedFor(req: unknown): string | undefined {
  const request = req as IncomingMessage;
  const forwarded = request.headers["x-forwarded-for"];
  return typeof forwarded === "string" && forwarded !== "" ? forwarded : request.socket?.remoteAddress;
}

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

/** Adds the Rule for the admin area and promotes it to Enforce, as the slice 02 journey does. */
async function enforceAdminRule(page: Page): Promise<void> {
  await page.getByTestId("policy-link").click();
  await expect(page).toHaveURL(/\/policy\?environment=development$/);
  await page.getByLabel("Rule name").fill("Admin area");
  await page.getByLabel("Path pattern").fill("/api/admin/**");
  await page.getByRole("button", { name: "Add Rule" }).click();
  const row = page.getByTestId("rule-row").filter({ hasText: "/api/admin/**" });
  await expect(row).toHaveAttribute("data-mode", "monitor");
  await row.getByTestId("rule-promote").click();
  const dialog = page.getByTestId("policy-confirm");
  await expect(dialog).toBeVisible();
  await dialog.getByTestId("confirm-submit").click();
  await expect(row).toHaveAttribute("data-mode", "enforce");
}

test("an Actor blocked from the Incident is enforced by Shield within 30 s, listed, and lifted again", async ({
  page,
}) => {
  test.setTimeout(150_000);
  const { shieldKey, publicKey } = await createOrganizationAndApp(page);
  await enforceAdminRule(page);
  const policyUrl = page.url();
  const attackerHash = actorHash(ACTOR_KEY, ATTACKER) ?? "";
  expect(attackerHash).not.toBe(actorHash(shieldKey, ATTACKER));

  // The customer's server: Shield with its default poll interval (5 s) in front of the reference target.
  // Built apart from the call so that the test compiles before and after `actorKey` joins ShieldConfig.
  const config = {
    key: shieldKey,
    endpoint: API_URL,
    policyPublicKey: publicKey,
    clientAddress: forwardedFor,
    actorKey: ACTOR_KEY,
    flushIntervalMs: 200,
    logger: { warn() {} },
  };
  const shield: Shield = createShield(config);
  const customer = http.createServer(createRangeServer({ shield }));
  await new Promise<void>((resolve) => customer.listen(0, "127.0.0.1", resolve));
  const base = `http://127.0.0.1:${(customer.address() as AddressInfo).port}`;
  const visit = async (client: string, path = "/") => {
    const response = await fetch(`${base}${path}`, { headers: { "x-forwarded-for": client } });
    return { status: response.status, body: await response.text() };
  };
  const contained = { status: 403, body: BLOCK_RESPONSE_BODY };

  try {
    await shield.refreshPolicy();
    expect(shield.stats()).toMatchObject({ policyRules: 1, lastPolicyError: null });

    // 1. The attack: 20 requests to the enforced admin area, all blocked by the Rule.
    for (let i = 0; i < BURST; i++) expect(await visit(ATTACKER, "/api/admin/reports")).toEqual(contained);
    expect((await visit(BYSTANDER)).status).toBe(200);

    // 2. The Incident, with its Actor.
    await page.getByTestId("nav-incidents").click();
    await expect(page).toHaveURL(/\/incidents$/);
    const row = page.getByTestId("incident-row").filter({ hasText: "Blocked burst" });
    await expect(async () => {
      await page.reload();
      await expect(row).toHaveCount(1, { timeout: 1_000 });
    }).toPass({ timeout: DETECTION_BUDGET_MS });
    await row.getByTestId("incident-link").click();
    await expect(page).toHaveURL(/\/incidents\/inc_[0-9a-f]{24}$/);
    const incidentUrl = page.url();
    const actors = page.getByTestId("incident-actors");
    await expect(actors.getByTestId("actor-row")).toHaveCount(1);
    await expect(actors.getByTestId("actor-hash-full")).toContainText(attackerHash);
    await expect(actors.getByTestId("actor-requests")).toHaveText(String(BURST));
    await expect(page.getByTestId("incident-contained")).toHaveCount(0);

    // 3. Block actor: the top Actor and 1 hour are preselected; the confirmation names target, scope and expiry.
    const bar = page.getByTestId("containment-bar");
    await expect(bar.getByTestId("containment-actor")).toHaveValue(attackerHash);
    await expect(bar.getByTestId("containment-duration")).toHaveValue("3600");
    await bar.getByTestId("containment-block-actor").click();
    const dialog = page.getByTestId("containment-confirm");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByTestId("confirm-question")).toHaveText(
      /^Blocks 1 Actor \(iph_[^)]+\) in development of shop-web for 1 hour, until (?:\d{4}-\d{2}-\d{2} )?\d{2}:\d{2} UTC\.$/,
    );
    await dialog.getByTestId("confirm-submit").click();
    const blockedAt = Date.now();
    const block = page.getByTestId("block-row");
    await expect(block).toHaveCount(1);
    await expect(block).toHaveAttribute("data-status", "active");
    await expect(block).toHaveAttribute("data-kind", "actor");
    await expect(page.getByTestId("incident-contained")).toBeVisible();

    // 4. The running Shield enforces it within 30 s; the other client of the same /24 is served.
    await expect(async () => {
      expect(await visit(ATTACKER)).toEqual(contained);
    }).toPass({ timeout: ENFORCE_BUDGET_MS, intervals: [100] });
    const containMs = Date.now() - blockedAt;
    expect(containMs).toBeLessThanOrEqual(ENFORCE_BUDGET_MS);
    expect((await visit(BYSTANDER)).status).toBe(200);

    // 5. The App's Containment tab lists the active block in its Environment.
    await page.goto(policyUrl);
    await page.getByTestId("app-nav-containment").click();
    const section = page.getByTestId("app-containment");
    await expect(section).toBeVisible();
    await expect(section.getByTestId("containment-environment").getByTestId("block-row")).toHaveAttribute(
      "data-status",
      "active",
    );

    // 6. Lift, confirmed, from the Incident: the attacker is served again within 30 s.
    await page.goto(incidentUrl);
    await page.getByTestId("block-row").getByTestId("block-lift").click();
    const lift = page.getByTestId("lift-confirm");
    await expect(lift).toBeVisible();
    await lift.getByTestId("confirm-submit").click();
    const liftedAt = Date.now();
    await expect(page.getByTestId("block-row")).toHaveAttribute("data-status", "lifted");
    await expect(page.getByTestId("block-row").getByTestId("block-status")).toHaveText("Lifted");
    await expect(page.getByTestId("incident-contained")).toHaveCount(0);
    await expect(async () => {
      expect((await visit(ATTACKER)).status).toBe(200);
    }).toPass({ timeout: ENFORCE_BUDGET_MS, intervals: [100] });
    const liftMs = Date.now() - liftedAt;
    console.info(`containment browser e2e: confirm -> attacker blocked ${containMs} ms; lift -> passes ${liftMs} ms`);
  } finally {
    await shield.close();
    customer.closeAllConnections();
    await new Promise<void>((resolve) => customer.close(() => resolve()));
  }
});

test("a range is added to the never-block list and removed with a confirmation", async ({ page }) => {
  await createOrganizationAndApp(page);
  await page.getByTestId("nav-allowlist").click();
  await expect(page).toHaveURL(/\/settings\/allowlist$/);
  await expect(page.getByTestId("allowlist-empty")).toBeVisible();

  await page.getByTestId("allowlist-cidr-input").fill("203.0.113.0/24");
  await page.getByTestId("allowlist-note-input").fill("Office");
  await page.getByTestId("allowlist-add").click();
  const row = page.getByTestId("allowlist-row");
  await expect(row).toHaveCount(1);
  await expect(row.getByTestId("allowlist-cidr")).toHaveText("203.0.113.0/24");
  await expect(row.getByTestId("allowlist-note")).toHaveText("Office");

  await row.getByTestId("allowlist-remove").click();
  const dialog = page.getByTestId("allowlist-confirm");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByTestId("confirm-question")).toContainText("203.0.113.0/24");
  await dialog.getByTestId("confirm-submit").click();
  await expect(page.getByTestId("allowlist-row")).toHaveCount(0);
  await expect(page.getByTestId("allowlist-empty")).toBeVisible();
});
