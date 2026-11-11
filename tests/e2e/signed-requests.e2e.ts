// Ticket 04 in a real browser: the admin adds a Rule that requires a signed request in the Console and promotes it
// to Enforce with the usual confirmation. A page served by the customer's server loads Guard straight from
// packages/guard/src (plain ES modules, no build step) and calls `guard.fetch` for a JSON POST on that route: the
// request is signed with Guard's non-extractable session key and served. The very same request, captured from the
// browser and replayed from Node, is refused. The live feed shows the browser's request as Signed and the replay as
// Replayed.
//
// The customer's server is built here: Shield, then `express.json({ verify: shield.verifyBody })` (`bodyVerified`),
// then the route. ar-range has no body parser and no route that takes a body.

import { readFileSync } from "node:fs";
import http from "node:http";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { BLOCK_RESPONSE_BODY, CONTENT_HASH_HEADER, SIGNATURE_HEADER } from "@antireverse/protocol";
import { createShield, type Shield } from "@antireverse/shield-node";
import { expect, type Page, test } from "@playwright/test";
import express from "express";
import { API_URL } from "./playwright.config.ts";

/** PB-13: an Event is visible within five seconds. */
const VISIBLE_BUDGET_MS = 5_000;
/** The customer's server (inside the e2e port range 39940-39959). */
const PAGE_PORT = Number(process.env.E2E_SIGNED_PAGE_PORT || 39_943);
const PAGE_ORIGIN = `http://127.0.0.1:${PAGE_PORT}`;
const guardDir = fileURLToPath(new URL("../../packages/guard/src", import.meta.url));
const ORDER = { sku: "lantern", quantity: 2 };

interface RunResult {
  status: number;
  body: string;
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

/** The shop's page: Guard from /guard/, and one `guard.fetch` POST of a JSON order to the shop's own API. */
function shopPage(appId: string): string {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>shop-web</title></head>
  <body>
    <h1>shop-web</h1>
    <script type="module">
      import { createGuard } from "/guard/index.js";
      const guard = createGuard({ appId: ${JSON.stringify(appId)}, endpoint: ${JSON.stringify(API_URL)} });
      window.arOrder = async (order) => {
        await guard.attest();
        const sentAt = Date.now();
        const response = await guard.fetch("/api/orders", {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify(order),
        });
        return { status: response.status, body: await response.text(), sentAt };
      };
      document.body.dataset.ready = "1";
    </script>
  </body>
</html>
`;
}

/** The customer's server: the page and Guard's files, then Shield, the body parser with its hook, and the route. */
function serveShop(shield: Shield, appId: string, orders: unknown[]): Promise<http.Server> {
  const app = express();
  app.disable("x-powered-by");
  // In front of Shield: static files are not API traffic.
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
  app.use(shield.express());
  app.use(express.json({ verify: shield.verifyBody }));
  app.post("/api/orders", (req, res) => {
    orders.push(req.body);
    res.status(201).json({ ok: true });
  });
  const server = http.createServer(app);
  return new Promise((resolve) => server.listen(PAGE_PORT, "127.0.0.1", () => resolve(server)));
}

async function confirm(page: Page, question: RegExp): Promise<void> {
  const dialog = page.getByTestId("policy-confirm");
  await expect(dialog).toBeVisible();
  await expect(dialog.getByTestId("confirm-question")).toHaveText(question);
  await dialog.getByTestId("confirm-submit").click();
  await expect(page.getByTestId("policy-confirm")).toHaveCount(0);
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

test("Guard's signed request passes an enforced requirement; the same request replayed from a script is refused", async ({
  page,
  context,
}) => {
  test.setTimeout(120_000);
  const { shieldKey, publicKey } = await createOrganizationAndApp(page);
  await page.getByTestId("live-link").click();
  await page.waitForURL(/\/apps\/app_[0-9a-f]{24}\/live$/);
  const appId = (/\/apps\/(app_[0-9a-f]{24})/.exec(page.url()) ?? [])[1] as string;

  // 1. A Rule that requires a signed request on POST /api/orders: it starts in Monitor mode (version 1).
  await page.getByTestId("app-nav-policy").click();
  await expect(page).toHaveURL(/\/apps\/app_[0-9a-f]{24}\/policy/);
  await page.getByLabel("Rule name").fill("Orders");
  await page.getByLabel("Path pattern").fill("/api/orders");
  await page.locator("#rule-methods-POST").check();
  await page.getByTestId("rule-requires-signature").check();
  await page.getByRole("button", { name: "Add Rule" }).click();
  const row = page.getByTestId("rule-row").filter({ hasText: "/api/orders" });
  await expect(row).toHaveAttribute("data-mode", "monitor");
  await expect(row).toHaveAttribute("data-requires", "signature");
  await expect(row.getByTestId("rule-requires")).toHaveText("Signed requests required");
  await expect(row.getByTestId("rule-methods")).toHaveText("POST");
  await expect(page.getByTestId("policy-version")).toHaveText("Version 1");

  // 2. Promoted to Enforce with the confirmation naming Environment and pattern (version 2).
  await row.getByTestId("rule-promote").click();
  await confirm(page, /^Promote to enforce in development\? Requests matching \/api\/orders will be blocked\.$/);
  await expect(row).toHaveAttribute("data-mode", "enforce");
  await expect(row).toHaveAttribute("data-requires", "signature");
  await expect(page.getByTestId("policy-version")).toHaveText("Version 2");

  // 3. The customer's server with the Console's keys; it binds bodies through the parser's verify hook.
  shield = createShield({
    key: shieldKey,
    endpoint: API_URL,
    policyPublicKey: publicKey,
    flushIntervalMs: 200,
    bodyVerified: { types: ["application/json"] },
    logger: { warn() {} },
  });
  await shield.refreshPolicy();
  expect(shield.stats()).toMatchObject({ policyVersion: 2, policyRules: 1, lastPolicyError: null });
  const orders: unknown[] = [];
  server = await serveShop(shield, appId, orders);

  await page.getByTestId("app-nav-live").click();
  await expect(page.getByTestId("live-indicator")).toHaveText("Live");

  // 4. The shop in the browser: Guard attests cross-origin and signs the POST to the shop's own API.
  const shop = await context.newPage();
  const captured: { headers: Record<string, string>; body: string | null }[] = [];
  const capturing: Promise<void>[] = [];
  shop.on("request", (request) => {
    if (request.method() !== "POST" || new URL(request.url()).pathname !== "/api/orders") return;
    capturing.push(
      request.allHeaders().then((headers) => {
        captured.push({ headers, body: request.postData() });
      }),
    );
  });
  await shop.goto(`${PAGE_ORIGIN}/shop`);
  await expect(shop.locator("body")).toHaveAttribute("data-ready", "1");
  const result = await shop.evaluate(
    (order) => (globalThis as unknown as { arOrder(order: unknown): Promise<RunResult> }).arOrder(order),
    ORDER,
  );
  expect(result.status).toBe(201);
  expect(orders).toEqual([ORDER]);

  // The request as it went over the wire: signed, with the body's hash.
  await Promise.all(capturing);
  expect(captured).toHaveLength(1);
  const sent = captured[0] as { headers: Record<string, string>; body: string | null };
  expect(sent.body).toBe(JSON.stringify(ORDER));
  expect(sent.headers[SIGNATURE_HEADER]).toMatch(/^v1,t=\d+,n=[A-Za-z0-9_-]{22},s=[A-Za-z0-9_-]{86}$/);
  expect(sent.headers[CONTENT_HASH_HEADER]).toMatch(/^[A-Za-z0-9_-]{43}$/);
  expect(sent.headers["ar-attestation"]).toMatch(/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);

  const signedRows = page
    .getByTestId("event-row")
    .filter({ hasText: "/api/orders" })
    .filter({ has: page.locator('[data-testid="signature-chip"][data-signature="signed"]') });
  await expect(signedRows).toHaveCount(1, { timeout: VISIBLE_BUDGET_MS });
  const visibleMs = Date.now() - result.sentAt;
  test.info().annotations.push({ type: "signed-to-row-ms", description: String(visibleMs) });
  const signedChip = signedRows.getByTestId("signature-chip");
  await expect(signedChip).toHaveText("Signed");
  await expect(signedChip).toHaveAttribute("data-status", "valid");
  await expect(signedChip).toHaveAttribute("data-body", "checked");
  await expect(signedRows).toContainText("201");

  // 5. The captured request replayed from a script, byte for byte: refused before the handler.
  const replayHeaders: Record<string, string> = {};
  for (const name of ["ar-attestation", SIGNATURE_HEADER, CONTENT_HASH_HEADER, "content-type"]) {
    const value = sent.headers[name];
    if (value !== undefined) replayHeaders[name] = value;
  }
  const replay = await fetch(`${PAGE_ORIGIN}/api/orders`, {
    method: "POST",
    headers: replayHeaders,
    body: sent.body ?? "",
  });
  expect([replay.status, await replay.text()]).toEqual([403, BLOCK_RESPONSE_BODY]);
  expect(orders).toHaveLength(1);

  const replayRows = page
    .getByTestId("event-row")
    .filter({ hasText: "/api/orders" })
    .filter({ has: page.locator('[data-testid="signature-chip"][data-signature="replayed"]') });
  await expect(replayRows).toHaveCount(1, { timeout: VISIBLE_BUDGET_MS });
  await expect(replayRows.getByTestId("signature-chip")).toHaveText("Replayed");
  await expect(
    replayRows.locator('[data-testid="decision-chip"][data-decision="block"][data-mode="enforce"]'),
  ).toHaveText("Blocked");
  await expect(replayRows).toContainText("403");
  console.info(`signed-requests browser e2e: signed request -> Console row ${visibleMs} ms`);

  // Neither the signature nor the token reaches the Console.
  const content = await page.content();
  expect(content).not.toContain(sent.headers[SIGNATURE_HEADER]?.split(",s=")[1] ?? "unreachable");
  expect(content).not.toContain(sent.headers["ar-attestation"]?.split(".")[2] ?? "unreachable");
  await shop.close();
});
