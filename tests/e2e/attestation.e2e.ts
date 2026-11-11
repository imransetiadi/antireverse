// Ticket 03 in a real browser: a page served by the customer's server (ar-range with Shield) loads Guard straight
// from packages/guard/src (plain ES modules, no build step), attests against the API cross-origin (CORS *), and
// calls the server's API on its own origin with `guard.headers()`. The Console live feed shows that request's row
// with the verdict the browser actually earned and its risk, the Client note above the table, and a request sent
// without a token as "No token".
//
// The verdict is whatever Guard's signals in this Chromium give, computed with the protocol's verdict table:
// Playwright sets navigator.webdriver (automation.webdriver, Suspect 70 on its own); a headless shell whose user
// agent says HeadlessChrome, or that has no plugins, adds automation.headless; the "Desktop Chrome" device profile
// claims a Windows user agent, so on another OS env.inconsistent can join. Two or more signals are Hostile.

import { readFileSync } from "node:fs";
import http from "node:http";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { verdictFor } from "@antireverse/protocol";
import { createRangeServer } from "@antireverse/range";
import { createShield, type Shield } from "@antireverse/shield-node";
import { expect, type Page, test } from "@playwright/test";
import express from "express";
import { API_URL } from "./playwright.config.ts";

/** PB-13: an Event is visible within five seconds. */
const VISIBLE_BUDGET_MS = 5_000;
/** The customer's server (inside the e2e port range 39940-39959). */
const PAGE_PORT = Number(process.env.E2E_ATTEST_PAGE_PORT || 39_942);
const PAGE_ORIGIN = `http://127.0.0.1:${PAGE_PORT}`;
const guardDir = fileURLToPath(new URL("../../packages/guard/src", import.meta.url));

interface RunResult {
  token: string | null;
  signals: string[];
  userAgent: string;
  platform: string;
  plugins: number;
  webdriver: boolean;
  attestMs: number;
  status: number;
  sentAt: number;
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

/** The shop's page: Guard from /guard/, attest, then one call to the shop's own API with or without the token. */
function shopPage(appId: string): string {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>shop-web</title></head>
  <body>
    <h1>shop-web</h1>
    <script type="module">
      import { createGuard } from "/guard/index.js";
      const guard = createGuard({ appId: ${JSON.stringify(appId)}, endpoint: ${JSON.stringify(API_URL)} });
      window.arRun = async (path, withToken) => {
        let attestMs = 0;
        if (withToken) {
          const started = performance.now();
          await guard.attest();
          attestMs = Math.round(performance.now() - started);
        }
        const sentAt = Date.now();
        const response = await fetch(path, { headers: withToken ? guard.headers() : {} });
        await response.text();
        return {
          token: guard.token(),
          signals: guard.signals(),
          userAgent: navigator.userAgent,
          platform: navigator.platform,
          plugins: navigator.plugins ? navigator.plugins.length : -1,
          webdriver: navigator.webdriver === true,
          attestMs,
          status: response.status,
          sentAt,
        };
      };
      document.body.dataset.ready = "1";
    </script>
  </body>
</html>
`;
}

/** The customer's server: the page and Guard's files beside ar-range, which Shield observes. */
function serveShop(shield: Shield, appId: string): Promise<http.Server> {
  const app = express();
  app.disable("x-powered-by");
  // In front of ar-range (and so of Shield): static files are not API traffic.
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
      const body = readFileSync(join(guardDir, file));
      res.type("text/javascript").set("cache-control", "no-store").send(body);
    } catch {
      res.status(404).end();
    }
  });
  app.use(createRangeServer({ shield }));
  const server = http.createServer(app);
  return new Promise((resolve) => server.listen(PAGE_PORT, "127.0.0.1", () => resolve(server)));
}

let shield: Shield | undefined;
let server: http.Server | undefined;

test.afterAll(async () => {
  await shield?.close();
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server?.close(() => resolve()));
  }
});

test("a page with Guard attests in a real browser and the Console shows the request's verdict", async ({
  page,
  context,
}) => {
  test.setTimeout(120_000);
  const { shieldKey, publicKey } = await createOrganizationAndApp(page);
  await page.getByTestId("live-link").click();
  await page.waitForURL(/\/apps\/app_[0-9a-f]{24}\/live$/);
  const appId = (/\/apps\/(app_[0-9a-f]{24})/.exec(page.url()) ?? [])[1] as string;
  await expect(page.getByTestId("live-indicator")).toHaveText("Live");

  // Shield with the Console's keys and its default poll interval; the bundle carries the attestation keys.
  shield = createShield({
    key: shieldKey,
    endpoint: API_URL,
    policyPublicKey: publicKey,
    flushIntervalMs: 200,
    logger: { warn() {} },
  });
  await shield.refreshPolicy();
  expect(shield.stats().lastPolicyError).toBeNull();
  server = await serveShop(shield, appId);

  // The shop in the browser: Guard attests cross-origin, the API call goes to the shop's own origin.
  const shop = await context.newPage();
  const attestCalls: string[] = [];
  shop.on("request", (request) => {
    if (new URL(request.url()).pathname.startsWith("/v1/attest"))
      attestCalls.push(`${request.method()} ${request.url()}`);
  });
  await shop.goto(`${PAGE_ORIGIN}/shop`);
  await expect(shop.locator("body")).toHaveAttribute("data-ready", "1");
  const run = (path: string, withToken: boolean) =>
    shop.evaluate(
      ([p, w]) =>
        (globalThis as unknown as { arRun(path: string, withToken: boolean): Promise<RunResult> }).arRun(p, w),
      [path, withToken] as [string, boolean],
    );

  const withToken = await run("/api/products/7", true);
  expect(withToken.status).toBe(200);
  expect(withToken.token).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
  expect(attestCalls.filter((c) => c.startsWith("POST "))).toEqual([
    `POST ${API_URL}/v1/attest/challenge`,
    `POST ${API_URL}/v1/attest`,
  ]);
  // The verdict this browser earned: Playwright's Chromium always reports webdriver.
  expect(withToken.webdriver).toBe(true);
  expect(withToken.signals).toContain("automation.webdriver");
  expect(withToken.signals.includes("automation.headless")).toBe(
    /HeadlessChrome/.test(withToken.userAgent) || withToken.plugins === 0,
  );
  // The device profile's user agent claims Windows: inconsistent unless the browser really runs on Windows.
  expect(withToken.signals.includes("env.inconsistent")).toBe(
    /Windows/.test(withToken.userAgent) !== /^Win/.test(withToken.platform),
  );
  const expected = verdictFor(withToken.signals);
  test
    .info()
    .annotations.push(
      { type: "user-agent", description: withToken.userAgent },
      { type: "platform", description: `${withToken.platform}; plugins ${withToken.plugins}` },
      { type: "signals", description: withToken.signals.join(", ") },
      { type: "verdict", description: `${expected.verdict} ${expected.risk}` },
      { type: "attest-ms", description: String(withToken.attestMs) },
    );
  console.info(
    `attestation browser e2e: UA "${withToken.userAgent}", platform ${withToken.platform}, plugins ${withToken.plugins}; ` +
      `signals [${withToken.signals.join(", ")}] -> ${expected.verdict} ${expected.risk}; attest ${withToken.attestMs} ms`,
  );

  // The live feed: the request's row carries the verdict and risk; the note says what Client means.
  const row = page.getByTestId("event-row").filter({ hasText: "/api/products/:id" });
  await expect(row).toHaveCount(1, { timeout: VISIBLE_BUDGET_MS });
  const visibleMs = Date.now() - withToken.sentAt;
  test.info().annotations.push({ type: "token-to-row-ms", description: String(visibleMs) });
  console.info(`attestation browser e2e: request with token -> Console row ${visibleMs} ms`);
  const chip = row.getByTestId("attestation-chip");
  await expect(chip).toHaveAttribute("data-attestation", expected.verdict);
  await expect(chip).toHaveAttribute("data-status", "valid");
  await expect(chip).toHaveAttribute("data-verdict", expected.verdict);
  await expect(chip).toHaveText(expected.verdict === "hostile" ? "Hostile" : "Suspect");
  await expect(row.getByTestId("attestation-risk")).toHaveText(`risk ${expected.risk}`);
  await expect(page.getByTestId("client-note")).toHaveText(
    "Client shows the Guard attestation Shield verified for each request. It is evidence, not proof.",
  );

  // A request without a token: No token, no risk.
  const without = await run("/api/admin/reports", false);
  expect(without.status).toBe(200);
  const bare = page.getByTestId("event-row").filter({ hasText: "/api/admin/reports" });
  await expect(bare).toHaveCount(1, { timeout: VISIBLE_BUDGET_MS });
  const bareChip = bare.getByTestId("attestation-chip");
  await expect(bareChip).toHaveAttribute("data-attestation", "missing");
  await expect(bareChip).toHaveAttribute("data-status", "missing");
  await expect(bareChip).toHaveText("No token");
  await expect(bare.getByTestId("attestation-risk")).toHaveCount(0);

  // The token never reaches the Console, before or after a reload.
  const token = withToken.token ?? "";
  expect(await page.content()).not.toContain(token);
  await page.reload();
  await expect(
    page.getByTestId("event-row").filter({ hasText: "/api/products/:id" }).getByTestId("attestation-chip"),
  ).toHaveAttribute("data-attestation", expected.verdict);
  expect(await page.content()).not.toContain(token.split(".")[2] ?? token);
  await shop.close();
});
