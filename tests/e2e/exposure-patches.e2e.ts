// Ticket 20 in a real browser. The API of playwright.config.ts runs on the fixture advisories with the fixture
// Virtual patch catalog (fixtures/api-fixture-patches.ts). A Build whose components include vuln-range 2.0.5 (High
// fixture advisory GHSA-fx01-0001-rang) is registered through the API; its query-key patch ships in monitor. A real
// Express app with Shield, using the Shield key the Console showed, receives the exploit request and answers it
// normally; the Finding page shows the Virtual patch section in Monitor with the hit. Enforce goes through the typed
// confirmation of the patch id; the chip shows Enforce, the Policy page lists the patch, Shield refuses the exploit;
// Back to monitor restores it.

import { readFileSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { fileURLToPath } from "node:url";
import { buildManifest, harden } from "@antireverse/harden";
import {
  BLOCK_RESPONSE_BODY,
  type Component,
  ListFindingsResponseSchema,
  ListPatchesResponseSchema,
  type PatchSummary,
} from "@antireverse/protocol";
import { componentsDigest, newId } from "@antireverse/protocol/server";
import { createShield, type Shield } from "@antireverse/shield-node";
import { expect, type Page, test } from "@playwright/test";
import express from "express";
import { API_URL } from "./playwright.config.ts";

const webDir = fileURLToPath(new URL("../../apps/range/web", import.meta.url));
const read = (rel: string) => readFileSync(`${webDir}/${rel}`, "utf8");
const SOURCES = { "src/index.ts": read("src/index.ts"), "src/pricing.ts": read("src/pricing.ts") };

const PATCH = "vp_fixture_range_query";
const PATCH_TITLE = "vuln-range prototype pollution through query keys";
const ADVISORY = "GHSA-fx01-0001-rang";
const COMPONENTS: Component[] = [
  { name: "vuln-range", version: "2.0.5", dev: false },
  { name: "safe-pkg", version: "1.0.0", dev: false },
];
const EXPLOIT = "/search?q[__proto__][x]=1";
const BENIGN = "/search?q=__proto__";
/** PB-13: an Event is visible within five seconds. */
const VISIBLE_BUDGET_MS = 5_000;

async function createOrganizationAndApp(page: Page): Promise<{ adminKey: string; appId: string; shieldKey: string }> {
  await page.goto("/");
  await page.getByLabel("Organization name").fill("Acme");
  await page.getByRole("button", { name: "Create organization" }).click();
  const adminKey = (await page.getByTestId("admin-key").textContent()) ?? "";
  expect(adminKey).toMatch(/^aro_[A-Za-z0-9_-]{43}$/);
  await page.getByRole("link", { name: "Continue" }).click();
  await page.getByRole("link", { name: "New App" }).first().click();
  await page.getByLabel("App name").fill("shop-web");
  await page.getByRole("button", { name: "Create App" }).click();
  await expect(page.getByTestId("app-created")).toHaveText("shop-web is ready");
  const shieldKey = (await page.getByTestId("shield-key").textContent()) ?? "";
  expect(shieldKey).toMatch(/^ark_dev_[A-Za-z0-9_-]{43}$/);
  await page.getByTestId("live-link").click();
  await page.waitForURL(/\/apps\/app_[0-9a-f]{24}\/live/);
  const appId = (/\/apps\/(app_[0-9a-f]{24})/.exec(page.url()) ?? [])[1] ?? "";
  expect(appId).toMatch(/^app_/);
  return { adminKey, appId, shieldKey };
}

/** Hardens the reference bundle and registers the Build with the components, as `harden --register` does. */
async function registerBuild(adminKey: string, appId: string): Promise<void> {
  const seed = 11;
  const result = harden(SOURCES, { profile: "balanced", seed });
  const manifest = buildManifest({
    buildId: newId("bld"),
    appId,
    environment: "development",
    version: "4.0.0",
    profile: "balanced",
    seed,
    artifacts: result.files.map((f) => ({ path: f.path, code: f.code })),
    originals: SOURCES,
    transform: result.transform,
    equivalence: "skipped",
    components: { count: COMPONENTS.length, digest: componentsDigest(COMPONENTS) },
  });
  const registered = await fetch(`${API_URL}/v1/apps/${appId}/builds`, {
    method: "POST",
    headers: { authorization: `Bearer ${adminKey}`, "content-type": "application/json" },
    body: JSON.stringify({ manifest, components: COMPONENTS }),
  });
  expect(registered.status).toBe(201);
  const body = (await registered.json()) as { findings?: { open: { high: number } } };
  expect(body.findings?.open.high).toBe(1);
}

async function patchOf(adminKey: string, appId: string): Promise<PatchSummary | undefined> {
  const response = await fetch(`${API_URL}/v1/apps/${appId}/patches?environment=development`, {
    headers: { authorization: `Bearer ${adminKey}` },
  });
  expect(response.status).toBe(200);
  return ListPatchesResponseSchema.parse(await response.json()).patches.find((p) => p.id === PATCH);
}

test("a Finding's virtual patch: monitor with hits, enforce through the typed confirmation, back to monitor", async ({
  page,
}) => {
  const { adminKey, appId, shieldKey } = await createOrganizationAndApp(page);
  await registerBuild(adminKey, appId);
  const findings = await fetch(`${API_URL}/v1/findings?app_id=${appId}`, {
    headers: { authorization: `Bearer ${adminKey}` },
  });
  const finding = ListFindingsResponseSchema.parse(await findings.json()).findings.find(
    (f) => f.advisory_id === ADVISORY,
  );
  expect(finding).toBeDefined();
  const findingId = finding?.id ?? "";
  expect(await patchOf(adminKey, appId)).toMatchObject({ active: true, shipped: true, mode: "monitor" });

  // The customer's server with Shield, the key the Console showed and the API's signing key.
  const { public_key: policyPublicKey } = (await (await fetch(`${API_URL}/v1/signing-key`)).json()) as {
    public_key: string;
  };
  const shield: Shield = createShield({
    key: shieldKey,
    endpoint: API_URL,
    policyPublicKey,
    flushIntervalMs: 200,
    inventory: false,
    logger: { warn() {} },
  });
  const customerApp = express();
  customerApp.use(shield.express());
  customerApp.get("/search", (_req, res) => {
    res.json({ results: [] });
  });
  const customer = http.createServer(customerApp);
  await new Promise<void>((resolve) => customer.listen(0, "127.0.0.1", resolve));
  const customerUrl = `http://127.0.0.1:${(customer.address() as AddressInfo).port}`;
  const visit = async (path: string) => {
    const response = await fetch(`${customerUrl}${path}`);
    return { status: response.status, body: await response.text() };
  };

  try {
    await shield.refreshPolicy();
    expect(shield.stats().lastPolicyError).toBeNull();

    // Monitor: the exploit is answered normally and recorded as a hit.
    expect(await visit(EXPLOIT)).toEqual({ status: 200, body: JSON.stringify({ results: [] }) });
    await expect.poll(async () => (await patchOf(adminKey, appId))?.hits_24h, { timeout: VISIBLE_BUDGET_MS }).toBe(1);

    // 1. The Finding page: the Virtual patch section, in Monitor, with the hit.
    await page.goto(`/findings/${findingId}`);
    const section = page.getByTestId("finding-patch");
    await expect(section.getByRole("heading", { level: 2 })).toHaveText("Virtual patch");
    await expect(section.getByTestId("patch-note")).toHaveText(
      "A patch blocks known exploit requests. Upgrading is the fix.",
    );
    await expect(section.getByTestId("patch-title")).toHaveText(PATCH_TITLE);
    await expect(section.getByTestId("patch-id")).toHaveText(PATCH);
    await expect(section.getByTestId("patch-mode")).toHaveAttribute("data-mode", "monitor");
    await expect(section.getByTestId("patch-mode")).toHaveText("Monitor");
    await expect(section.getByTestId("patch-hits")).toHaveText("1");
    await expect(section.getByTestId("patch-last-hit")).toHaveAttribute("datetime", /^\d{4}-\d{2}-\d{2}T/);
    await expect(section.getByTestId("patch-not-shipped")).toHaveCount(0);

    // 2. Enforce is never one click: the confirmation step asks for the patch id, typed.
    await section.getByTestId("patch-enforce").click();
    await expect(page).toHaveURL(new RegExp(`/findings/${findingId}\\?confirm=enforce$`));
    const confirm = page.getByTestId("patch-confirm");
    await expect(confirm).toBeVisible();
    await expect(confirm.getByTestId("confirm-question")).toContainText(PATCH_TITLE);
    await expect(confirm.getByTestId("confirm-typed-label")).toContainText(PATCH);
    expect((await patchOf(adminKey, appId))?.mode).toBe("monitor");
    await confirm.getByTestId("confirm-typed").fill(PATCH);
    await confirm.getByTestId("confirm-submit").click();

    // 3. The chip shows Enforce; the API ships it enforced; Shield refuses the exploit, a benign request passes.
    await expect(page).toHaveURL(new RegExp(`/findings/${findingId}$`));
    await expect(section.getByTestId("patch-mode")).toHaveAttribute("data-mode", "enforce");
    await expect(section.getByTestId("patch-mode")).toHaveText("Enforce");
    await expect(page.getByTestId("patch-confirm")).toHaveCount(0);
    await expect(section.getByTestId("patch-monitor")).toBeVisible();
    expect((await patchOf(adminKey, appId))?.mode).toBe("enforce");
    await shield.refreshPolicy();
    expect(await visit(EXPLOIT)).toEqual({ status: 403, body: BLOCK_RESPONSE_BODY });
    expect((await visit(BENIGN)).status).toBe(200);
    await expect.poll(async () => (await patchOf(adminKey, appId))?.hits_24h, { timeout: VISIBLE_BUDGET_MS }).toBe(2);

    // 4. The App's Policy page lists the active patch with its mode and hits, read only.
    await page.goto(`/apps/${appId}/policy?environment=development`);
    const row = page.getByTestId("policy-patches").getByTestId("policy-patch-row");
    await expect(row).toHaveCount(1);
    await expect(row).toHaveAttribute("data-patch-id", PATCH);
    await expect(row.getByTestId("patch-title")).toHaveText(PATCH_TITLE);
    await expect(row.getByTestId("patch-mode")).toHaveAttribute("data-mode", "enforce");
    await expect(row.getByTestId("patch-hits")).toHaveText("2");
    await row.getByTestId("patch-finding-link").click();
    await expect(page).toHaveURL(new RegExp(`/findings/${findingId}$`));

    // 5. Back to monitor, in one action: the exploit passes again.
    await page.getByTestId("finding-patch").getByTestId("patch-monitor").click();
    await expect(page.getByTestId("finding-patch").getByTestId("patch-mode")).toHaveAttribute("data-mode", "monitor");
    await expect(page.getByTestId("finding-patch").getByTestId("patch-enforce")).toBeVisible();
    expect((await patchOf(adminKey, appId))?.mode).toBe("monitor");
    await shield.refreshPolicy();
    expect(await visit(EXPLOIT)).toEqual({ status: 200, body: JSON.stringify({ results: [] }) });
  } finally {
    await shield.close();
    customer.closeAllConnections();
    await new Promise<void>((resolve) => customer.close(() => resolve()));
  }
});
