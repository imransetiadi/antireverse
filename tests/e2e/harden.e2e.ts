// Ticket 05 in a real browser: a Build hardened from the reference bundle and registered through the API
// appears on the App in the Console, and its detail shows the profile, cost, transforms and artifacts.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildManifest, checkEquivalence, harden } from "@antireverse/harden";
import { newId } from "@antireverse/protocol/server";
import { expect, test } from "@playwright/test";
import { API_URL } from "./playwright.config.ts";

const webDir = fileURLToPath(new URL("../../apps/range/web", import.meta.url));
const read = (rel: string) => readFileSync(`${webDir}/${rel}`, "utf8");
const SOURCES = { "src/index.ts": read("src/index.ts"), "src/pricing.ts": read("src/pricing.ts") };

test("a hardened Build registered through the API shows on the App in the Console", async ({ page }) => {
  // 1. Create the Organization and App in the Console; capture the admin key and App id.
  await page.goto("/");
  await page.getByLabel("Organization name").fill("Acme");
  await page.getByRole("button", { name: "Create organization" }).click();
  const adminKey = (await page.getByTestId("admin-key").textContent()) ?? "";
  expect(adminKey).toMatch(/^aro_[A-Za-z0-9_-]{43}$/);
  await page.getByRole("link", { name: "Continue" }).click();
  await page.getByRole("link", { name: "New App" }).first().click();
  await page.getByLabel("App name").fill("shop-web");
  await page.getByRole("button", { name: "Create App" }).click();
  await page.getByTestId("live-link").click();
  await page.waitForURL(/\/apps\/app_[0-9a-f]{24}\/live/);
  const appId = (/\/apps\/(app_[0-9a-f]{24})/.exec(page.url()) ?? [])[1];
  expect(appId).toBeTruthy();

  // 2. Harden the reference bundle and register the Build through the API (as the CLI would in CI).
  const seed = 5;
  const result = harden(SOURCES, { profile: "balanced", seed });
  const files = Object.fromEntries(result.files.map((f) => [f.path, f.code]));
  const equivalence = (
    await checkEquivalence({
      dir: webDir,
      testCommand: "node --experimental-strip-types check.ts",
      protectedFiles: files,
    })
  ).passed
    ? "passed"
    : "skipped";
  expect(equivalence).toBe("passed");
  const manifest = buildManifest({
    buildId: newId("bld"),
    appId: appId as string,
    environment: "development",
    version: "2.1.0",
    profile: "balanced",
    seed,
    artifacts: result.files.map((f) => ({ path: f.path, code: f.code })),
    originals: SOURCES,
    transform: result.transform,
    equivalence,
  });
  const registered = await fetch(`${API_URL}/v1/apps/${appId}/builds`, {
    method: "POST",
    headers: { authorization: `Bearer ${adminKey}`, "content-type": "application/json" },
    body: JSON.stringify({ manifest }),
  });
  expect(registered.status).toBe(201);

  // 3. In the Console, open the App's Builds tab and find the Build.
  await page.getByTestId("app-nav-builds").click();
  await expect(page).toHaveURL(new RegExp(`/apps/${appId}/builds$`));
  const row = page.getByTestId("build-row").filter({ hasText: "2.1.0" });
  await expect(row).toHaveCount(1);
  await expect(row.getByTestId("build-profile")).toHaveText("balanced");
  await expect(row.getByTestId("build-equivalence")).toHaveText("Passed");

  // 4. Open the Build detail and check its facts.
  await row.getByTestId("build-link").click();
  await expect(page).toHaveURL(new RegExp(`/apps/${appId}/builds/${manifest.build_id}$`));
  await expect(page.getByRole("heading", { level: 1 })).toContainText("2.1.0");
  await expect(page.getByTestId("build-id")).toHaveText(manifest.build_id);
  await expect(page.getByTestId("cost-size")).toHaveAttribute("data-overbudget", "false");
  await expect(page.getByTestId("build-transform")).toBeVisible();
  await expect(page.getByTestId("artifact-row")).toHaveCount(result.files.length);
});
