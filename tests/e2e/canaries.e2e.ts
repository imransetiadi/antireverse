// Ticket 07 in a real browser: a Build hardened from the reference bundle (leak scan clean, Canaries planted) and
// registered through the API shows its leak-scan result and its Canaries in the Console; an Event carrying a
// Canary's signal opens a "Canary used" Incident whose page names the Canary and links to its Build.
import { randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildManifest, hardenBundle } from "@antireverse/harden";
import { newId } from "@antireverse/protocol/server";
import { SDK_NAME, SDK_VERSION } from "@antireverse/shield-node";
import { expect, test } from "@playwright/test";
import { API_URL } from "./playwright.config.ts";

/** PB-17 is 60 s; the detector answers in about a second here. */
const INCIDENT_BUDGET_MS = 15_000;

const webDir = fileURLToPath(new URL("../../apps/range/web", import.meta.url));
const read = (rel: string) => readFileSync(`${webDir}/${rel}`, "utf8");
const SOURCES = { "src/index.ts": read("src/index.ts"), "src/pricing.ts": read("src/pricing.ts") };

/** A UUID version 7 (RFC 9562) for `ms`, as Shield stamps its Events. */
function uuidv7(ms: number): string {
  const hex = ms.toString(16).padStart(12, "0") + randomBytes(10).toString("hex");
  const variant = ((Number.parseInt(hex.slice(16, 17), 16) & 0x3) | 0x8).toString(16);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-7${hex.slice(13, 16)}-${variant}${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

test("a Build shows its leak scan and Canaries, and a Canary Incident links to the Build", async ({ page }) => {
  // 1. Organization and App in the Console; capture the admin key, the Shield key and the App id.
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
  const appId = (/\/apps\/(app_[0-9a-f]{24})/.exec(page.url()) ?? [])[1] as string;
  expect(appId).toBeTruthy();

  // 2. Harden the reference bundle (leak scan, transforms, Canaries) and register the Build through the API.
  const seed = 1;
  const result = hardenBundle({ sources: SOURCES }, { profile: "balanced", seed });
  expect(result.leakScan.status).toBe("clean");
  expect(result.canaries).toHaveLength(3);
  const manifest = buildManifest({
    buildId: newId("bld"),
    appId,
    environment: "development",
    version: "3.0.0",
    profile: "balanced",
    seed,
    artifacts: result.files.map((f) => ({ path: f.path, code: f.code })),
    originals: SOURCES,
    transform: result.transform,
    equivalence: "skipped",
    leakScan: { status: "clean", suppressed: 0 },
    canaries: result.canaries,
  });
  const registered = await fetch(`${API_URL}/v1/apps/${appId}/builds`, {
    method: "POST",
    headers: { authorization: `Bearer ${adminKey}`, "content-type": "application/json" },
    body: JSON.stringify({ manifest }),
  });
  expect(registered.status).toBe(201);
  const keyCanary = result.canaries.find((c) => c.kind === "key");
  expect(keyCanary).toBeDefined();

  // 3. The Build list shows the Canary count; the Build page shows the Markers.
  await page.getByTestId("app-nav-builds").click();
  await expect(page).toHaveURL(new RegExp(`/apps/${appId}/builds$`));
  const row = page.getByTestId("build-row").filter({ hasText: "3.0.0" });
  await expect(row).toHaveCount(1);
  await expect(row.getByTestId("build-canaries")).toHaveText("3");
  await row.getByTestId("build-link").click();
  await expect(page).toHaveURL(new RegExp(`/apps/${appId}/builds/${manifest.build_id}$`));
  const markers = page.getByTestId("build-markers");
  await expect(markers.getByTestId("build-leak-scan")).toHaveAttribute("data-status", "clean");
  await expect(markers.getByTestId("build-leak-scan-value")).toHaveText("Clean");
  await expect(markers.getByTestId("canary-count")).toHaveText("3 Canaries");
  const canaryRows = markers.getByTestId("canary-row");
  await expect(canaryRows).toHaveCount(3);
  for (const canary of result.canaries) {
    const canaryRow = markers.locator(`[data-testid="canary-row"][data-canary-id="${canary.id}"]`);
    await expect(canaryRow).toHaveAttribute("data-kind", canary.kind);
    await expect(canaryRow.getByTestId("canary-id")).toHaveText(canary.id);
    await expect(canaryRow.getByTestId("canary-kind")).toHaveText(canary.kind === "key" ? "Decoy key" : "Decoy route");
  }
  // Values are never shown: the API does not return them.
  const html = await page.content();
  for (const canary of result.canaries) expect(html).not.toContain(canary.value);

  // 4. An Event with the decoy key's signal, as Shield sends it after a request carrying the key.
  const now = Date.now();
  const ingest = await fetch(`${API_URL}/v1/events`, {
    method: "POST",
    headers: { authorization: `Bearer ${shieldKey}`, "content-type": "application/json" },
    body: JSON.stringify({
      protocol: 1,
      sdk: { name: SDK_NAME, version: SDK_VERSION },
      events: [
        {
          event_id: uuidv7(now),
          ts: new Date(now).toISOString(),
          type: "request.decision",
          surface: "api",
          request: { method: "GET", route: "/api/products/:id", status: 200, latency_ms: 1 },
          decision: { action: "allow", mode: "monitor", rule_id: null, policy_version: 0 },
          actor: { ip_prefix: "203.0.113.0/24" },
          signals: [{ id: `canary.touched:${keyCanary?.id}`, confidence: 1 }],
        },
      ],
    }),
  });
  expect(ingest.status).toBe(202);

  // 5. Incidents → "Canary used" → the Canary and its Build → the Build page.
  await page.getByTestId("nav-incidents").click();
  await expect(page).toHaveURL(/\/incidents$/);
  const incidentRow = page.getByTestId("incident-row").filter({ hasText: "Canary used" });
  await expect(async () => {
    await page.reload();
    await expect(incidentRow).toHaveCount(1, { timeout: 1_000 });
  }).toPass({ timeout: INCIDENT_BUDGET_MS });
  await expect(incidentRow).toHaveAttribute("data-severity", "high");
  await expect(incidentRow.getByTestId("incident-link")).toHaveText("Canary used");
  await incidentRow.getByTestId("incident-link").click();
  await expect(page).toHaveURL(/\/incidents\/inc_[0-9a-f]{24}$/);
  await expect(page.getByTestId("incident-severity")).toHaveAttribute("data-severity", "high");
  await expect(page.getByTestId("fact-canary-id")).toHaveText(keyCanary?.id ?? "");
  await expect(page.getByTestId("fact-canary-kind")).toHaveText("Decoy key");
  const buildLink = page.getByTestId("fact-build-link");
  await expect(buildLink).toHaveAttribute("href", `/apps/${appId}/builds/${manifest.build_id}`);
  await expect(buildLink).toHaveText("Build 3.0.0");
  await expect(page.getByTestId("fact-build-id")).toHaveText(manifest.build_id);
  await buildLink.click();
  await expect(page).toHaveURL(new RegExp(`/apps/${appId}/builds/${manifest.build_id}$`));
  await expect(page.getByTestId("build-id")).toHaveText(manifest.build_id);
});
