// Ticket 11 in a real browser: the admin adds a Rule (monitor), sends known traffic through a real Express app
// behind Shield, clicks "Simulate" on the Policy page and reads the estimate panel: its caption, the Rule's figures
// and the notes. The promote-to-enforce confirmation then shows what promoting that Rule would refuse, dated with
// the time of the run (plan A5). "Simulate with this Rule" on the add-Rule form replays the current Rules plus the Rule being typed:
// its row is tagged "Not published", nothing is published (the version, the Rule list and Shield are as before),
// and the promote confirmation shows no estimate from that run, because it was not a simulation of the Rules the
// Policy holds.
import { randomBytes } from "node:crypto";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { SIMULATION_NOT_SIMULATED } from "@antireverse/protocol";
import { createShield, type Shield } from "@antireverse/shield-node";
import { expect, type Page, test } from "@playwright/test";
import express from "express";
import { API_URL } from "./playwright.config.ts";

/** The traffic: admin reads the Rule would block, and searches over the limit of the Rule being typed. */
const ADMIN_READS = 5;
const SEARCHES = 12;
const SEARCH_LIMIT = 10;

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

test("Simulate shows the estimate per Rule, the promote confirmation shows it, and a typed Rule is simulated without publishing", async ({
  page,
}) => {
  test.setTimeout(120_000);
  const { shieldKey, publicKey } = await createOrganizationAndApp(page);

  // 1. One Rule, in monitor (version 1). Without a Rule there is nothing to simulate.
  await page.getByTestId("policy-link").click();
  await expect(page).toHaveURL(/\/policy\?environment=development$/);
  await expect(page.getByTestId("policy-empty")).toBeVisible();
  await expect(page.getByTestId("simulate")).toHaveCount(0);
  await page.getByLabel("Rule name").fill("Admin area");
  await page.getByLabel("Path pattern").fill("/api/admin/**");
  await page.getByRole("button", { name: "Add Rule" }).click();
  const rule = page.getByTestId("rule-row").filter({ hasText: "/api/admin/**" });
  await expect(rule).toHaveAttribute("data-mode", "monitor");
  await expect(page.getByTestId("policy-version")).toHaveText("Version 1");

  // 2. Before any request was recorded: the estimate says there is nothing to estimate.
  const panel = page.getByTestId("simulation-result");
  await expect(panel).toHaveCount(0);
  await page.getByTestId("simulate").click();
  await expect(panel).toBeVisible();
  await expect(panel.getByTestId("simulation-caption")).toHaveText(
    "Estimate from the last 24 hours of recorded requests",
  );
  await expect(panel.getByTestId("simulation-events")).toHaveText("0 requests replayed");
  await expect(panel.getByTestId("simulation-empty")).toBeVisible();
  await expect(panel.getByTestId("simulation-row")).toHaveCount(0);

  // 3. The customer's server: a real Express app behind Shield, with an actor key so that clients are told apart.
  const shield: Shield = createShield({
    key: shieldKey,
    endpoint: API_URL,
    policyPublicKey: publicKey,
    actorKey: randomBytes(32).toString("base64url"),
    flushIntervalMs: 200,
    logger: { warn() {} },
  });
  const app = express();
  app.use(shield.express());
  app.get("/api/admin/users", (_req, res) => {
    res.json({ users: [] });
  });
  app.get("/api/search", (_req, res) => {
    res.json({ results: [] });
  });
  const customer = http.createServer(app);
  await new Promise<void>((resolve) => customer.listen(0, "127.0.0.1", resolve));
  const origin = `http://127.0.0.1:${(customer.address() as AddressInfo).port}`;
  const get = async (path: string): Promise<number> => {
    const response = await fetch(`${origin}${path}`);
    await response.text();
    return response.status;
  };

  try {
    await shield.refreshPolicy();
    expect(shield.stats()).toMatchObject({ policyVersion: 1, policyRules: 1, lastPolicyError: null });

    // 4. The traffic, all served (the Rule is in monitor), and all of it recorded: the live feed shows every row.
    await page.getByTestId("app-nav-live").click();
    await expect(page.getByTestId("live-indicator")).toHaveText("Live");
    for (let i = 0; i < ADMIN_READS; i++) expect(await get("/api/admin/users"), `admin read ${i + 1}`).toBe(200);
    for (let i = 0; i < SEARCHES; i++) expect(await get("/api/search"), `search ${i + 1}`).toBe(200);
    await expect(page.getByTestId("event-row")).toHaveCount(ADMIN_READS + SEARCHES, { timeout: 10_000 });

    // 5. Simulate the Rules as shown: the panel, labelled an estimate, with the Rule's figures.
    await page.getByTestId("app-nav-policy").click();
    await expect(page.getByTestId("policy-version")).toHaveText("Version 1");
    await expect(panel).toHaveCount(0); // a result lives in one page view only
    await page.getByTestId("simulate").click();
    await expect(panel).toBeVisible();
    await expect(panel.getByTestId("simulation-caption")).toHaveText(
      "Estimate from the last 24 hours of recorded requests",
    );
    await expect(panel.getByTestId("simulation-period")).toHaveText(
      /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} to \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$/,
    );
    await expect(panel.getByTestId("simulation-events")).toHaveText(`${ADMIN_READS + SEARCHES} requests replayed`);
    const ran = panel.getByTestId("simulation-ran");
    await expect(ran).toHaveText(/^Simulated at \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC$/);
    const ranAt = /(\d{2}:\d{2}):\d{2} UTC$/.exec((await ran.textContent()) ?? "")?.[1] ?? "";
    await expect(panel.getByRole("columnheader", { name: "Routes refused most" })).toBeVisible();
    const rows = panel.getByTestId("simulation-row");
    await expect(rows).toHaveCount(1);
    const adminRow = rows.first();
    await expect(adminRow.getByRole("rowheader")).toHaveText("Admin area");
    await expect(adminRow.getByTestId("simulation-draft")).toHaveCount(0);
    await expect(adminRow.getByTestId("simulation-refuse")).toHaveText(String(ADMIN_READS));
    await expect(adminRow.getByTestId("simulation-kind")).toHaveText([`${ADMIN_READS} blocked`]);
    await expect(adminRow.getByTestId("simulation-clients")).toHaveText("1");
    await expect(adminRow.getByTestId("simulation-undecidable")).toHaveText("0");
    await expect(adminRow.getByTestId("simulation-already")).toHaveText("0");
    await expect(adminRow.getByTestId("simulation-route")).toHaveText([`GET /api/admin/users ${ADMIN_READS}`]);
    await expect(panel.getByTestId("simulation-totals")).toHaveText(
      `In total these Rules would refuse ${ADMIN_READS} requests from 1 client.`,
    );
    // What the estimate leaves out: one note per value the API names, each explained in words — none falls back to
    // the raw value ("Not simulated: name"). The list comes from the protocol, so a value added there must be
    // explained by the Console before this passes.
    const notes = panel.getByTestId("simulation-note");
    await expect(notes).toHaveCount(SIMULATION_NOT_SIMULATED.length);
    const texts = await notes.allTextContents();
    expect(new Set(texts).size).toBe(SIMULATION_NOT_SIMULATED.length);
    for (const text of texts) {
      expect(text).not.toMatch(/^Not simulated: /);
      expect(text.trim()).not.toBe("");
    }
    // The explanations of the first five, as the panel words them.
    for (const known of [
      "Virtual patches are not simulated.",
      "Blocks on individual clients are not simulated.",
      "Requests whose path Shield decodes or resolves differently may be missed.",
      "Limits per device are a lower bound: recorded requests carry no device.",
      "Whether Shield checks request bodies on your routes is not known to the simulation.",
    ]) {
      expect(texts).toContain(known);
    }
    // Shield has an actor key: no request without a known client.
    await expect(panel.getByTestId("simulation-unknown-total")).toHaveCount(0);
    // Nothing was published by simulating.
    await expect(page.getByTestId("policy-version")).toHaveText("Version 1");
    await expect(rule).toHaveAttribute("data-mode", "monitor");

    // 6. The promote confirmation carries what promoting the Rule would refuse, from that simulation and dated with it.
    await rule.getByTestId("rule-promote").click();
    const dialog = page.getByTestId("policy-confirm");
    await expect(dialog).toBeVisible();
    await expect(dialog.getByTestId("confirm-question")).toHaveText(
      /^Promote to enforce in development\? Requests matching \/api\/admin\/\*\* will be blocked\.$/,
    );
    const estimate = dialog.getByTestId("confirm-estimate");
    expect(ranAt).toMatch(/^\d{2}:\d{2}$/);
    await expect(estimate).toHaveText(
      `Estimate from ${ranAt} UTC: promoting this Rule would refuse ${ADMIN_READS} requests from 1 client in the last 24 hours; 0 could not be judged.`,
    );
    // The result stays while the confirmation is open; cancelling enforces nothing.
    await expect(panel).toBeVisible();
    await dialog.getByTestId("confirm-cancel").click();
    await expect(page.getByTestId("policy-confirm")).toHaveCount(0);
    await expect(rule).toHaveAttribute("data-mode", "monitor");
    await expect(page.getByTestId("policy-version")).toHaveText("Version 1");

    // 7. A Rule being typed: a request limit on the search route, simulated with the current Rules.
    await page.getByLabel("Rule name").fill("Search limit");
    await page.getByLabel("Path pattern").fill("/api/search");
    await page.locator("#rule-methods-GET").check();
    await page.locator("#rule-action-throttle").check();
    await expect(page.getByTestId("rule-limit-fields")).toBeVisible();
    await page.locator("#rule-limit-requests").fill(String(SEARCH_LIMIT));
    await page.locator("#rule-limit-window").fill("60");
    await page.locator("#rule-limit-key-ip").check();
    await page.getByTestId("rule-simulate").click();

    await expect(rows).toHaveCount(2);
    await expect(rows.nth(0).getByRole("rowheader")).toHaveText("Admin area");
    await expect(rows.nth(0).getByTestId("simulation-draft")).toHaveCount(0);
    await expect(rows.nth(0).getByTestId("simulation-refuse")).toHaveText(String(ADMIN_READS));
    const draftRow = rows.nth(1);
    await expect(draftRow.getByRole("rowheader")).toContainText("Search limit");
    await expect(draftRow.getByTestId("simulation-draft")).toHaveText("Not published");
    await expect(draftRow.getByTestId("simulation-refuse")).toHaveText(String(SEARCHES - SEARCH_LIMIT));
    await expect(draftRow.getByTestId("simulation-kind")).toHaveText([`${SEARCHES - SEARCH_LIMIT} throttled`]);
    await expect(draftRow.getByTestId("simulation-clients")).toHaveText("1");
    await expect(draftRow.getByTestId("simulation-route")).toHaveText([`GET /api/search ${SEARCHES - SEARCH_LIMIT}`]);
    await expect(panel.getByTestId("simulation-caption")).toHaveText(
      "Estimate from the last 24 hours of recorded requests",
    );
    await expect(panel.getByTestId("simulation-totals")).toHaveText(
      `In total these Rules would refuse ${ADMIN_READS + SEARCHES - SEARCH_LIMIT} requests from 1 client.`,
    );

    // 8. Nothing was published: the version and the Rule list are as before, and the typed Rule is still in the form.
    await expect(page.getByTestId("policy-version")).toHaveText("Version 1");
    await expect(page.getByTestId("rule-row")).toHaveCount(1);
    await expect(page.getByTestId("rule-row").filter({ hasText: "/api/search" })).toHaveCount(0);
    await expect(page.getByLabel("Rule name")).toHaveValue("Search limit");
    await expect(page.getByLabel("Path pattern")).toHaveValue("/api/search");
    await shield.refreshPolicy();
    expect(shield.stats()).toMatchObject({ policyVersion: 1, policyRules: 1, lastPolicyError: null });
    // Shield still serves what the typed Rule would throttle and what the monitor Rule would block.
    expect(await get("/api/search")).toBe(200);
    expect(await get("/api/admin/users")).toBe(200);

    // 9. The promote confirmation shows no estimate from that run: it was not of the Rules the Policy holds.
    await rule.getByTestId("rule-promote").click();
    await expect(dialog).toBeVisible();
    await expect(dialog.getByTestId("confirm-question")).toHaveText(
      /^Promote to enforce in development\? Requests matching \/api\/admin\/\*\* will be blocked\.$/,
    );
    await expect(dialog.getByTestId("confirm-estimate")).toHaveCount(0);
    await expect(dialog).not.toContainText("promoting this Rule would refuse");
    // The run itself is still shown, with its "Not published" row.
    await expect(rows.nth(1).getByTestId("simulation-draft")).toHaveText("Not published");
    await dialog.getByTestId("confirm-cancel").click();
    await expect(page.getByTestId("policy-confirm")).toHaveCount(0);
    await expect(page.getByTestId("policy-version")).toHaveText("Version 1");

    // A reload asks the API again: still version 1 with the one Rule in monitor, and no result kept anywhere.
    await page.reload();
    await expect(page.getByTestId("policy-version")).toHaveText("Version 1");
    await expect(page.getByTestId("rule-row")).toHaveCount(1);
    await expect(rule).toHaveAttribute("data-mode", "monitor");
    await expect(panel).toHaveCount(0);
  } finally {
    await shield.close();
    customer.closeAllConnections();
    await new Promise<void>((resolve) => customer.close(() => resolve()));
  }
});
