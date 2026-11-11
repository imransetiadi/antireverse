// Ticket 10 in a real browser: a bundle hardened with `--origin http://shop.example:<port> --register` is served
// by one static server under two host names, which Chromium resolves to 127.0.0.1 (--host-resolver-rules). On
// the allowed name the page loads and sends nothing to Anti Reverse; on the clone name the planted beacon sends
// exactly one navigator.sendBeacon report, and the Console shows a High "Clone detected" Incident with the origin
// as plain text, a link to the Build and the clone note in place of the containment bar.
//
// Why a JavaScript bundle and not apps/range/web: the reference bundle is TypeScript, run by Node with type
// stripping; a browser cannot execute the protected .ts files, and no type stripper is a dependency of this
// workspace. So the test copies a browser-runnable storefront bundle (fixtures/storefront: plain ES modules,
// about 7.5 KB, with its own equivalence check) into a temp directory and hardens that with the real CLI. The reference bundle's beacon
// is covered over HTTP in clone-beacon.http.test.ts.
import { execFile } from "node:child_process";
import { copyFileSync, cpSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import http from "node:http";
import { tmpdir } from "node:os";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { ListIncidentsResponseSchema } from "@antireverse/protocol";
import { deriveBeaconToken } from "@antireverse/protocol/server";
import { expect, type Request, test } from "@playwright/test";
import { API_URL } from "./playwright.config.ts";

/** The ticket's budget is 60 s; the recorder answers in about a second here. */
const INCIDENT_BUDGET_MS = 15_000;
/** How long to watch for a beacon request that must not come. */
const QUIET_MS = 2_000;
/** The static server of the protected bundle (inside the e2e port range 39940-39959). */
const PAGE_PORT = Number(process.env.E2E_PAGE_PORT || 39_950);
const ALLOWED = `http://shop.example:${PAGE_PORT}`;
const CLONE = `http://clone.example:${PAGE_PORT}`;
const SEED = 11;
const VERSION = "11.0.0";

const root = fileURLToPath(new URL("../..", import.meta.url));
const cliPath = join(root, "packages/harden/src/cli.ts");
const tsxCli = join(root, "node_modules/tsx/dist/cli.mjs");
const KEY_ENV = "AR_E2E_ADMIN_KEY";
/** The storefront bundle (browser ES modules, its equivalence check and the page that loads it). */
const fixtureDir = fileURLToPath(new URL("./fixtures/storefront", import.meta.url));

test.use({
  launchOptions: { args: ["--host-resolver-rules=MAP shop.example 127.0.0.1, MAP clone.example 127.0.0.1"] },
});

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

/** Serves `dir` (the protected bundle) on 127.0.0.1, whatever the Host: both names reach the same files. */
function serve(dir: string): Promise<http.Server> {
  const types: Record<string, string> = {
    ".html": "text/html; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
  };
  const server = http.createServer((req, res) => {
    const path = new URL(req.url ?? "/", "http://localhost").pathname;
    const rel = normalize(path === "/" ? "index.html" : path.slice(1));
    const type = types[extname(rel)];
    if (rel.startsWith("..") || type === undefined) {
      res.writeHead(404).end();
      return;
    }
    try {
      const body = readFileSync(join(dir, rel));
      res.writeHead(200, { "content-type": type, "cache-control": "no-store" }).end(body);
    } catch {
      res.writeHead(404).end();
    }
  });
  return new Promise((resolve) => server.listen(PAGE_PORT, "127.0.0.1", () => resolve(server)));
}

let server: http.Server | undefined;
const temps: string[] = [];

test.afterAll(async () => {
  if (server) {
    server.closeAllConnections();
    await new Promise<void>((resolve) => server?.close(() => resolve()));
  }
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

test("a protected bundle on its allowed origin sends nothing; a clone reports itself and opens a Clone Incident", async ({
  page,
  context,
}) => {
  test.setTimeout(120_000);

  // 1. Organization and App in the Console; capture the admin key and the App id.
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
  const appId = (/\/apps\/(app_[0-9a-f]{24})/.exec(page.url()) ?? [])[1] as string;
  expect(appId).toBeTruthy();

  // 2. Write the storefront bundle and harden it with the real CLI: --origin the allowed name, --register.
  const work = mkdtempSync(join(tmpdir(), "antireverse-e2e-beacon-web-"));
  temps.push(work);
  const bundle = join(work, "web");
  const out = join(work, "protected");
  cpSync(fixtureDir, bundle, { recursive: true });
  const run = await harden(
    [
      bundle,
      "--profile",
      "balanced",
      "--seed",
      String(SEED),
      "--out",
      out,
      "--test",
      "node check.mjs",
      "--origin",
      ALLOWED,
      "--json",
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
      VERSION,
    ],
    work,
    adminKey,
  );
  expect(run.code, run.stderr).toBe(0);
  const report = JSON.parse(run.stdout) as {
    equivalence: string;
    beacon: { token: string; origins: string[]; planted_in: string };
    registered: { build_id: string };
  };
  expect(report.equivalence).toBe("passed");
  const token = deriveBeaconToken(SEED, { appId, version: VERSION });
  expect(report.beacon).toEqual({ token, origins: [ALLOWED], planted_in: "src/storefront.js" });
  const buildId = report.registered.build_id;
  copyFileSync(join(fixtureDir, "index.html"), join(out, "index.html"));
  server = await serve(out);

  const cloneIncidents = async () => {
    const response = await fetch(`${API_URL}/v1/incidents?app_id=${appId}`, {
      headers: { authorization: `Bearer ${adminKey}` },
    });
    expect(response.status).toBe(200);
    return ListIncidentsResponseSchema.parse(await response.json()).incidents.filter((i) => i.rule === "clone-origin");
  };

  // 3. The allowed name: the page runs (the protected modules executed) and no request goes to /v1/beacon.
  const shop = await context.newPage();
  const beacons: Request[] = [];
  shop.on("request", (request) => {
    if (new URL(request.url()).pathname === "/v1/beacon") beacons.push(request);
  });
  await shop.goto(`${ALLOWED}/`);
  await expect(shop.locator("body")).toHaveAttribute("data-ready", "1");
  expect(await shop.evaluate("location.origin")).toBe(ALLOWED);
  await expect(shop.locator("#cart")).toContainText("Shipping  free");
  await shop.waitForTimeout(QUIET_MS);
  expect(beacons).toHaveLength(0);
  expect(await cloneIncidents()).toEqual([]);

  // 4. The clone name: the same files report the copy exactly once.
  const sent = shop.waitForRequest((request) => new URL(request.url()).pathname === "/v1/beacon");
  const sentAt = Date.now();
  await shop.goto(`${CLONE}/`);
  await expect(shop.locator("body")).toHaveAttribute("data-ready", "1");
  const beacon = await sent;
  expect(beacon.method()).toBe("POST");
  expect(beacon.url()).toBe(`${API_URL}/v1/beacon`);
  expect(JSON.parse(beacon.postData() ?? "")).toEqual({ a: appId, t: token, o: CLONE });
  await shop.waitForTimeout(QUIET_MS);
  expect(beacons).toHaveLength(1);

  await expect.poll(async () => (await cloneIncidents()).length, { timeout: INCIDENT_BUDGET_MS }).toBe(1);
  const [incident] = await cloneIncidents();
  console.info(`clone-beacon browser e2e: beacon -> Incident ${Date.parse(incident?.created_at ?? "") - sentAt} ms`);
  expect(incident).toMatchObject({ origin: CLONE, build_id: buildId, severity: "high", ip_prefix: null });
  await shop.close();

  // 5. The Console: the Incident lists the origin; its page shows the origin as text, the Build, no containment.
  await page.getByTestId("nav-incidents").click();
  await expect(page).toHaveURL(/\/incidents$/);
  const row = page.getByTestId("incident-row").filter({ hasText: "Clone detected" });
  await expect(async () => {
    await page.reload();
    await expect(row).toHaveCount(1, { timeout: 1_000 });
  }).toPass({ timeout: INCIDENT_BUDGET_MS });
  await expect(row).toHaveAttribute("data-severity", "high");
  await expect(row.getByTestId("incident-origin")).toHaveText(CLONE);
  await row.getByTestId("incident-link").click();
  await expect(page).toHaveURL(new RegExp(`/incidents/${incident?.id}$`));
  await expect(page.getByTestId("incident-severity")).toHaveAttribute("data-severity", "high");
  await expect(page.getByTestId("fact-origin-value")).toHaveText(CLONE);
  // Plain text, never a link to the clone.
  await expect(page.getByTestId("fact-origin").locator("a")).toHaveCount(0);
  await expect(page.locator(`a[href*="clone.example"]`)).toHaveCount(0);
  const buildLink = page.getByTestId("fact-build-link");
  await expect(buildLink).toHaveAttribute("href", `/apps/${appId}/builds/${buildId}`);
  await expect(buildLink).toHaveText(`Build ${VERSION}`);
  await expect(page.getByTestId("detection-item")).toHaveCount(1);
  await expect(page.getByTestId("detection-reporter")).toHaveText("127.0.0.0/24");
  await expect(page.getByTestId("containment-bar")).toHaveCount(0);
  await expect(page.getByTestId("containment-clone-note")).toHaveText(
    "Containment does not apply to a clone. Take the copy down at its host.",
  );
  expect(await page.content()).not.toContain(token);

  // 6. The Build shows its Clone Beacon: on, with the allowed origin.
  await buildLink.click();
  await expect(page).toHaveURL(new RegExp(`/apps/${appId}/builds/${buildId}$`));
  await expect(page.getByTestId("build-beacon")).toHaveAttribute("data-status", "on");
  await expect(page.getByTestId("build-beacon-value")).toHaveText("On · 1 origin");
  await expect(page.getByTestId("beacon-origin")).toHaveText([ALLOWED]);
  expect(await page.content()).not.toContain(token);
});
