// TC-CON-001 (slice 16) in a real browser: signup → App → Shield on the reference server → first protected request on
// the Set up page, timed from signup (budget 15 minutes, expected seconds). Then Guard: a page served by the same
// server loads Guard from packages/guard/src (as attestation.e2e.ts does), attests, and calls the server with the
// token, so one Event with a valid attestation arrives. Then Harden: the real CLI registers a Build of the reference
// bundle. The Set up page turns each step done without a reload, and the App nav's "Set up: n of 3" goes away.
import { execFile } from "node:child_process";
import { cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { createRangeServer } from "@antireverse/range";
import { createShield, type Shield } from "@antireverse/shield-node";
import { expect, test } from "@playwright/test";
import express from "express";
import { API_URL } from "./playwright.config.ts";

/** TC-CON-001: signup to the first protected request on screen. */
const ONBOARDING_BUDGET_MS = 15 * 60_000;
/** The Set up page asks for Guard and Harden every 5 s; one poll plus margin. */
const POLL_BUDGET_MS = 15_000;

const root = fileURLToPath(new URL("../..", import.meta.url));
const guardDir = join(root, "packages/guard/src");
const webDir = join(root, "apps/range/web");
const cliPath = join(root, "packages/harden/src/cli.ts");
const tsxCli = join(root, "node_modules/tsx/dist/cli.mjs");
const KEY_ENV = "AR_E2E_ADMIN_KEY";

interface RunResult {
  token: string | null;
  status: number;
}

/** The shop's page: Guard from /guard/, attest, then one call to the shop's own API with the token. */
function shopPage(appId: string): string {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>shop-web</title></head>
  <body>
    <h1>shop-web</h1>
    <script type="module">
      import { createGuard } from "/guard/index.js";
      const guard = createGuard({ appId: ${JSON.stringify(appId)}, endpoint: ${JSON.stringify(API_URL)} });
      window.arRun = async (path) => {
        await guard.attest();
        const response = await fetch(path, { headers: guard.headers() });
        await response.text();
        return { token: guard.token(), status: response.status };
      };
      document.body.dataset.ready = "1";
    </script>
  </body>
</html>
`;
}

/** The customer's server: the shop page and Guard's files in front of ar-range, which Shield observes. */
async function serveShop(shield: Shield, appId: string): Promise<{ server: http.Server; url: string }> {
  const app = express();
  app.disable("x-powered-by");
  app.get("/shop", (_req, res) => {
    res.type("html").set("cache-control", "no-store").send(shopPage(appId));
  });
  app.get("/guard/:file", (req, res) => {
    const file = String(req.params.file);
    if (!/^[a-z]+\.js$/.test(file)) {
      res.status(404).end();
      return;
    }
    try {
      res
        .type("text/javascript")
        .set("cache-control", "no-store")
        .send(readFileSync(join(guardDir, file)));
    } catch {
      res.status(404).end();
    }
  });
  app.use(createRangeServer({ shield }));
  const server = http.createServer(app);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}` };
}

function harden(
  args: string[],
  cwd: string,
  adminKey: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [tsxCli, cliPath, "harden", ...args],
      { cwd, env: { ...process.env, [KEY_ENV]: adminKey }, maxBuffer: 16 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === "number" ? error.code : -1;
        resolve({ code, stdout: String(stdout), stderr: String(stderr) });
      },
    );
  });
}

let shield: Shield | undefined;
let server: http.Server | undefined;
const temps: string[] = [];

test.afterAll(async () => {
  await shield?.close();
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server?.close(() => resolve()));
  }
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

test("TC-CON-001: signup to the first protected request, then Guard and Harden turn done", async ({
  page,
  context,
}) => {
  test.setTimeout(180_000);

  // 1. The timer starts at signup: create the Organization, then the App.
  const startedAt = Date.now();
  await page.goto("/");
  await page.getByLabel("Organization name").fill("Acme");
  await page.getByRole("button", { name: "Create organization" }).click();
  await expect(page.getByTestId("organization-created")).toHaveText("Acme is ready");
  const adminKey = (await page.getByTestId("admin-key").textContent()) ?? "";
  expect(adminKey).toMatch(/^aro_[A-Za-z0-9_-]{43}$/);
  await page.getByRole("link", { name: "Continue" }).click();
  await page.getByRole("link", { name: "New App" }).first().click();
  await page.getByLabel("App name").fill("shop-web");
  await page.getByRole("button", { name: "Create App" }).click();
  await expect(page.getByTestId("app-created")).toHaveText("shop-web is ready");
  const shieldKey = (await page.getByTestId("shield-key").textContent()) ?? "";
  expect(shieldKey).toMatch(/^ark_dev_[A-Za-z0-9_-]{43}$/);
  const publicKey = (await page.getByTestId("policy-public-key").first().textContent()) ?? "";
  expect(publicKey).toMatch(/^[A-Za-z0-9_-]{43}$/);
  // The guide is already on the creation screen, waiting.
  await expect(page.getByTestId("setup-status")).toContainText("Waiting for the first event from shop-web");

  // The App's Set up page: step 1 of 3, waiting for Shield.
  await page.getByTestId("setup-link").click();
  await page.waitForURL(/\/apps\/app_[0-9a-f]{24}\/setup/);
  const appId = (/\/apps\/(app_[0-9a-f]{24})/.exec(page.url()) ?? [])[1] as string;
  const status = page.getByTestId("setup-status");
  await expect(status).toContainText("Waiting for the first event from shop-web…");
  await expect(page.getByText("Step 1 of 3")).toBeVisible();

  // 2. The reference server with Shield and the keys the Console showed; one request.
  shield = createShield({
    key: shieldKey,
    endpoint: API_URL,
    policyPublicKey: publicKey,
    flushIntervalMs: 200,
    logger: { warn() {} },
  });
  await shield.refreshPolicy();
  expect(shield.stats().lastPolicyError).toBeNull();
  const shop = await serveShop(shield, appId);
  server = shop.server;
  const response = await fetch(`${shop.url}/api/products/7`);
  expect(response.status).toBe(200);

  // 3. On screen without a reload.
  await expect(status).toContainText("First protected request received");
  // 4. Elapsed from signup, within the 15-minute budget.
  const elapsedMs = Date.now() - startedAt;
  test.info().annotations.push({ type: "signup-to-first-protected-request-ms", description: String(elapsedMs) });
  console.info(`TC-CON-001: signup to first protected request on screen ${(elapsedMs / 1000).toFixed(1)} s`);
  expect(elapsedMs).toBeLessThan(ONBOARDING_BUDGET_MS);
  await expect(status).toContainText("Waiting for the first request from shop-web with a Guard token…");
  await expect(page.getByText("Step 2 of 3")).toBeVisible();
  await expect(page.locator('button[data-step="shield"]')).toContainText("Done");

  // Elsewhere in the App, the nav counts one of three.
  const live = await context.newPage();
  await live.goto(`/apps/${appId}/live`);
  await expect(live.getByTestId("app-nav-setup")).toHaveText("Set up: 1 of 3");

  // 5a. Guard: the shop page attests and calls the server with the token: an Event with a valid attestation.
  const browserShop = await context.newPage();
  await browserShop.goto(`${shop.url}/shop`);
  await expect(browserShop.locator("body")).toHaveAttribute("data-ready", "1");
  const run = await browserShop.evaluate(() =>
    (globalThis as unknown as { arRun(path: string): Promise<RunResult> }).arRun("/api/products/8"),
  );
  expect(run.status).toBe(200);
  expect(run.token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  await browserShop.close();
  await expect(status).toContainText("First request with a Guard token received", { timeout: POLL_BUDGET_MS });
  await expect(page.locator('button[data-step="guard"]')).toContainText("Done");
  await expect(page.getByText("Step 3 of 3")).toBeVisible();

  // 5b. Harden: the real CLI registers a Build of the reference bundle.
  const bundleDir = join(mkdtempSync(join(tmpdir(), "antireverse-e2e-onboarding-bundle-")), "web");
  temps.push(join(bundleDir, ".."));
  cpSync(webDir, bundleDir, { recursive: true });
  const workDir = mkdtempSync(join(tmpdir(), "antireverse-e2e-onboarding-ci-"));
  temps.push(workDir);
  const registered = await harden(
    [
      bundleDir,
      "--profile",
      "balanced",
      "--register",
      "--endpoint",
      API_URL,
      "--key-env",
      KEY_ENV,
      "--app",
      appId,
      "--environment",
      "development",
      "--build-version",
      "1.0.0",
    ],
    workDir,
    adminKey,
  );
  expect(registered.code, registered.stderr).toBe(0);
  await expect(status).toContainText("First Build registered", { timeout: POLL_BUDGET_MS });
  await expect(status).toContainText("All three steps are done.");
  await expect(page.getByText("Set up complete")).toBeVisible();
  for (const step of ["shield", "guard", "harden"]) {
    await expect(page.locator(`button[data-step="${step}"]`)).toContainText("Done");
  }

  // The count is gone from the App nav and the Apps list says Done.
  await live.reload();
  await expect(live.getByTestId("app-nav-setup")).toHaveText("Set up");
  await expect(live.getByText(/Set up: \d of 3/)).toHaveCount(0);
  await live.goto("/apps");
  await expect(live.getByTestId("setup-progress")).toHaveText("Done");
  await live.close();
});
