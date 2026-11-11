// Ticket 19 in a real browser: a Build hardened from the reference bundle is registered through the API with a
// lockfile's components, one of which a Critical fixture advisory affects (the API of playwright.config.ts starts
// on a data directory the real `vulns:sync --fixture` filled). The Console's Findings page lists the Finding with
// its severity badge, CVE and fixed version; the Finding page shows the fix; Ignore with a reason and an end date
// works, and Reopen puts it back.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildManifest, harden } from "@antireverse/harden";
import { type Component, FindingResponseSchema } from "@antireverse/protocol";
import { componentsDigest, newId } from "@antireverse/protocol/server";
import { expect, type Page, test } from "@playwright/test";
import { API_URL } from "./playwright.config.ts";

const webDir = fileURLToPath(new URL("../../apps/range/web", import.meta.url));
const read = (rel: string) => readFileSync(`${webDir}/${rel}`, "utf8");
const SOURCES = { "src/index.ts": read("src/index.ts"), "src/pricing.ts": read("src/pricing.ts") };

/** Fixture advisory GHSA-fx01-0005-scop: `@fixture/vuln-scoped` < 5.0.0, CRITICAL, alias CVE-2026-90005. */
const ADVISORY = "GHSA-fx01-0005-scop";
const CVE = "CVE-2026-90005";
const PACKAGE = "@fixture/vuln-scoped";
const COMPONENTS: Component[] = [
  { name: PACKAGE, version: "4.2.0", dev: false },
  { name: "safe-pkg", version: "1.0.0", dev: false },
];
const REASON = "Not reachable: only used by the offline export job";
const DAY_MS = 86_400_000;

async function createOrganizationAndApp(page: Page): Promise<{ adminKey: string; appId: string }> {
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
  await page.getByTestId("live-link").click();
  await page.waitForURL(/\/apps\/app_[0-9a-f]{24}\/live/);
  const appId = (/\/apps\/(app_[0-9a-f]{24})/.exec(page.url()) ?? [])[1] ?? "";
  expect(appId).toMatch(/^app_/);
  return { adminKey, appId };
}

/** Hardens the reference bundle and registers the Build with the components, as `harden --register` does. */
async function registerBuild(adminKey: string, appId: string): Promise<string> {
  const seed = 9;
  const result = harden(SOURCES, { profile: "balanced", seed });
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
    components: { count: COMPONENTS.length, digest: componentsDigest(COMPONENTS) },
  });
  const registered = await fetch(`${API_URL}/v1/apps/${appId}/builds`, {
    method: "POST",
    headers: { authorization: `Bearer ${adminKey}`, "content-type": "application/json" },
    body: JSON.stringify({ manifest, components: COMPONENTS }),
  });
  expect(registered.status).toBe(201);
  const body = (await registered.json()) as { findings?: { open: { critical: number } } };
  expect(body.findings?.open.critical).toBe(1);
  return manifest.build_id;
}

/** The ISO date (UTC) `days` from now. */
const utcDate = (days: number) => new Date(Date.now() + days * DAY_MS).toISOString().slice(0, 10);

test("a vulnerable component shows as a Critical Finding; it is ignored with a reason and an end date, then reopened", async ({
  page,
}) => {
  const { adminKey, appId } = await createOrganizationAndApp(page);
  const buildId = await registerBuild(adminKey, appId);

  // 1. The Organization's Findings page.
  await page.getByTestId("nav-findings").click();
  await expect(page).toHaveURL(/\/findings$/);
  const row = page.getByTestId("finding-row");
  await expect(row).toHaveCount(1);
  await expect(row).toHaveAttribute("data-severity", "critical");
  await expect(row).toHaveAttribute("data-status", "open");
  await expect(row).toHaveAttribute("data-source", "build");
  await expect(row.getByTestId("severity-badge")).toHaveAttribute("data-severity", "critical");
  await expect(row.getByTestId("severity-badge")).toHaveText("Critical");
  await expect(row.getByTestId("finding-link")).toContainText(`${PACKAGE}@4.2.0`);
  await expect(row.getByTestId("finding-app")).toHaveText("shop-web");
  await expect(row.getByTestId("finding-advisory")).toHaveText(ADVISORY);
  await expect(row.getByTestId("finding-cve")).toHaveText(CVE);
  await expect(row.getByTestId("finding-fixed-in")).toHaveText("5.0.0");
  await expect(row.getByTestId("finding-status")).toHaveText("Open");
  // The package that no advisory names is not a Finding.
  await expect(page.getByText("safe-pkg")).toHaveCount(0);

  // 2. The Finding page: severity, CVE alias, where found, the fix.
  await row.getByTestId("finding-link").click();
  await expect(page).toHaveURL(/\/findings\/fnd_[0-9a-f]{24}$/);
  const findingId = (/\/findings\/(fnd_[0-9a-f]{24})/.exec(page.url()) ?? [])[1] ?? "";
  await expect(page.getByRole("heading", { level: 1 })).toContainText(ADVISORY);
  await expect(page.getByTestId("finding-severity")).toHaveAttribute("data-severity", "critical");
  await expect(page.getByTestId("finding-severity")).toHaveText("Critical");
  await expect(page.getByTestId("finding-status")).toHaveAttribute("data-status", "open");
  await expect(page.getByTestId("fact-package")).toContainText(`${PACKAGE}@4.2.0`);
  await expect(page.getByTestId("fact-alias")).toHaveText([CVE]);
  await expect(page.getByTestId("fact-build-id")).toHaveText(buildId);
  await expect(page.getByTestId("finding-fix-suggestion")).toHaveText("Upgrade to 5.0.0 or later");
  await expect(page.getByTestId("finding-fixed-version")).toHaveText(["5.0.0"]);

  // 3. Ignore: never one click — the confirmation step holds the reason and the end date.
  await page.getByTestId("finding-ignore").click();
  const confirm = page.getByTestId("finding-confirm");
  await expect(confirm).toBeVisible();
  await expect(confirm.getByTestId("confirm-question")).toContainText(ADVISORY);
  const until = utcDate(14);
  await page.getByTestId("finding-ignore-reason-input").fill(REASON);
  await page.getByTestId("finding-ignore-until-input").fill(until);
  await confirm.getByTestId("confirm-submit").click();

  await expect(page.getByTestId("finding-status")).toHaveAttribute("data-status", "ignored");
  await expect(page.getByTestId("finding-status")).toHaveText("Ignored");
  await expect(page.getByTestId("finding-ignore-reason")).toHaveText(REASON);
  await expect(page.getByTestId("finding-ignore-until")).toHaveAttribute("datetime", `${until}T00:00:00.000Z`);
  await expect(page.getByTestId("finding-confirm")).toHaveCount(0);
  await expect(page.getByTestId("finding-ignore")).toHaveCount(0);

  // The API agrees: ignored until the start of that UTC day, with the reason.
  const ignored = await fetch(`${API_URL}/v1/findings/${findingId}`, {
    headers: { authorization: `Bearer ${adminKey}` },
  });
  expect(ignored.status).toBe(200);
  const { finding } = FindingResponseSchema.parse(await ignored.json());
  expect(finding.status).toBe("ignored");
  expect(finding.ignore).toMatchObject({ reason: REASON, until: `${until}T00:00:00.000Z` });

  // The list shows it ignored.
  await page.getByTestId("finding-back").click();
  await expect(page.getByTestId("finding-row")).toHaveAttribute("data-status", "ignored");
  await expect(page.getByTestId("finding-row").getByTestId("finding-status")).toHaveText("Ignored");

  // 4. Reopen: sent at once.
  await page.getByTestId("finding-link").click();
  await page.getByTestId("finding-reopen").click();
  await expect(page.getByTestId("finding-status")).toHaveAttribute("data-status", "open");
  await expect(page.getByTestId("finding-ignore-facts")).toHaveCount(0);
  await expect(page.getByTestId("finding-ignore")).toBeVisible();

  // The App's Findings tab lists it open.
  await page.goto(`/apps/${appId}/findings`);
  const appRow = page.getByTestId("finding-row");
  await expect(appRow).toHaveCount(1);
  await expect(appRow).toHaveAttribute("data-status", "open");
  await expect(appRow.getByTestId("finding-fixed-in")).toHaveText("5.0.0");
});
