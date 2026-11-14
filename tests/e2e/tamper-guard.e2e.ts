// Ticket 21b in a real browser (QASUITE TC-GRD-002): the storefront bundle is hardened and registered by the real
// CLI, which plants the integrity marker; the page loads the protected modules and Guard (straight from
// packages/guard/src) and is served twice.
//
// 1. Untouched: about 30 s after its first token Guard hashes the Build's files and sends the report with one early
//    re-attest. The Build becomes watched and no Incident opens.
// 2. One byte of a protected file changed on disk, a second visitor (a new browser context: the first one's 24-hour
//    memo would keep it quiet): within 60 s of the page load the Console shows a High "Tampered Build" Incident with
//    the Build, the file and both hashes.
//
// Every /v1/attest body the two pages send is captured: it holds only the reviewed fields, and the first handshake
// of each page carries no report.
//
// The page lives at https://shop.example: the API does not judge a report from a local origin, and Guard needs a
// secure context for crypto.subtle. No server listens there: Playwright answers that origin's requests itself, from
// the files on disk (read on every request), so no certificate and no port is needed. The browser is allowed to
// call the loopback API from that public-looking page (the Local Network Access permission a user would grant).
// Nothing shortens Guard's 30 s: the test waits for it, twice.
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { extname, join, normalize } from "node:path";
import { fileURLToPath } from "node:url";
import { type Incident, ListIncidentsResponseSchema } from "@antireverse/protocol";
import { type BrowserContext, expect, type Page, test } from "@playwright/test";
import { API_URL } from "./playwright.config.ts";

/** The ticket's budget from the page load to the Incident in the Console; Guard waits 30 s of it. */
const INCIDENT_BUDGET_MS = 60_000;
/** From the page load to the report: Guard's 30 s, the collection and the handshake. */
const REPORT_BUDGET_MS = 45_000;
const ORIGIN = "https://shop.example";
const SEED = 21;
const VERSION = "21.2.0";

const root = fileURLToPath(new URL("../..", import.meta.url));
const cliPath = join(root, "packages/harden/src/cli.ts");
const tsxCli = join(root, "node_modules/tsx/dist/cli.mjs");
const KEY_ENV = "AR_E2E_ADMIN_KEY";
const fixtureDir = fileURLToPath(new URL("./fixtures/storefront", import.meta.url));
const guardDir = fileURLToPath(new URL("../../packages/guard/src", import.meta.url));

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

/** The shop's page: the protected storefront modules, and Guard attesting in idle time. */
function shopPage(appId: string): string {
  return `<!doctype html>
<html lang="en">
  <head><meta charset="utf-8"><title>Shop</title></head>
  <body>
    <h1>Your cart</h1>
    <pre id="cart"></pre>
    <script type="module" src="/src/main.js"></script>
    <script type="module">
      import { createGuard } from "/guard/index.js";
      const guard = createGuard({ appId: ${JSON.stringify(appId)}, endpoint: ${JSON.stringify(API_URL)} });
      guard.start();
    </script>
  </body>
</html>
`;
}

/**
 * Makes `context` a visitor of the shop: every request to its origin is answered with the page, the protected
 * bundle in `dir` (read from disk each time) or Guard's files; the page may call the loopback API.
 */
async function serveShop(context: BrowserContext, dir: string, appId: string): Promise<string[]> {
  /** Every request the shop's origin received, in order: the path and query. */
  const requests: string[] = [];
  await context.grantPermissions(["local-network-access"], { origin: ORIGIN });
  await context.route(`${ORIGIN}/**`, async (route) => {
    const url = new URL(route.request().url());
    const path = url.pathname;
    requests.push(path + url.search);
    const headers = { "cache-control": "no-store" };
    if (path === "/") {
      await route.fulfill({ status: 200, contentType: "text/html; charset=utf-8", headers, body: shopPage(appId) });
      return;
    }
    const guardFile = /^\/guard\/([a-z]+\.js)$/.exec(path)?.[1];
    const rel = normalize(path.slice(1));
    try {
      if (rel.startsWith("..") || extname(rel) !== ".js") throw new Error("not served");
      const body = readFileSync(guardFile === undefined ? join(dir, rel) : join(guardDir, guardFile));
      await route.fulfill({ status: 200, contentType: "text/javascript; charset=utf-8", headers, body });
    } catch {
      await route.fulfill({ status: 404, body: "" });
    }
  });
  return requests;
}

/**
 * What the shop's origin was asked for by one visit: the page and Guard's modules once, and each of the Build's
 * files the page loads twice, once by the page and once by Guard. Nothing else: no other file of the Build, no
 * other URL.
 */
function expectOnlyListedFilesRefetched(requests: string[], loaded: string[]) {
  const guardModules = readdirSync(guardDir)
    .filter((file) => file.endsWith(".js"))
    .map((file) => `/guard/${file}`);
  const expected = ["/", ...guardModules, ...loaded.flatMap((path) => [`/${path}`, `/${path}`])];
  expect([...requests].sort()).toEqual(expected.sort());
}

const sha256Hex = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("hex");
const sha256Wire = (bytes: Uint8Array) => createHash("sha256").update(bytes).digest("base64url");

interface Visit {
  page: Page;
  /** Every /v1/attest body the page sent, in order. */
  attests: Array<Record<string, unknown>>;
  /** The first attest body that carries an integrity report. */
  report: Promise<{ build: string; files: Array<{ i: number; h: string }>; skipped: number }>;
  loadedAt: number;
}

/** Opens the shop in `context` and records what its Guard sends to /v1/attest. */
async function visit(context: BrowserContext): Promise<Visit> {
  const page = await context.newPage();
  const attests: Visit["attests"] = [];
  let found: (report: Awaited<Visit["report"]>) => void = () => {};
  const report = new Promise<Awaited<Visit["report"]>>((resolve) => {
    found = resolve;
  });
  page.on("request", (request) => {
    if (request.url() !== `${API_URL}/v1/attest` || request.method() !== "POST") return;
    const body = JSON.parse(request.postData() ?? "{}") as Record<string, unknown>;
    attests.push(body);
    if (body.integrity !== undefined) found(body.integrity as Awaited<Visit["report"]>);
  });
  const loadedAt = Date.now();
  await page.goto(`${ORIGIN}/`);
  await expect(page.locator("body")).toHaveAttribute("data-ready", "1");
  await expect(page.locator("#cart")).toContainText("Shipping  free");
  expect(await page.evaluate("typeof crypto.subtle")).toBe("object");
  return { page, attests, report, loadedAt };
}

/** Rejects when `promise` has not settled within `ms`. */
function within<T>(promise: Promise<T>, ms: number, what: string): Promise<T> {
  return Promise.race([
    promise,
    new Promise<never>((_resolve, reject) => setTimeout(() => reject(new Error(`${what}: not within ${ms} ms`)), ms)),
  ]);
}

/** Only the reviewed fields: the handshake's own, and `{ build, files: [{ i, h }], skipped }`. */
function expectReviewedFields(attests: Visit["attests"], paths: string[]) {
  expect(attests.length).toBeGreaterThanOrEqual(2);
  // The first handshake carries no report.
  expect(Object.keys(attests[0] ?? {}).sort()).toEqual(["app_id", "cnf", "device", "nonce", "signals"]);
  for (const body of attests) {
    const { integrity, ...handshake } = body;
    expect(Object.keys(handshake).sort()).toEqual(["app_id", "cnf", "device", "nonce", "signals"]);
    if (integrity === undefined) continue;
    const report = integrity as { files: Array<Record<string, unknown>> };
    expect(Object.keys(report).sort()).toEqual(["build", "files", "skipped"]);
    for (const file of report.files) expect(Object.keys(file).sort()).toEqual(["h", "i"]);
    // No URL, path or origin.
    const wire = JSON.stringify(integrity);
    for (const secret of [...paths, "shop.example", "http", ".js", "/"]) expect(wire).not.toContain(secret);
  }
}

const temps: string[] = [];

test.afterAll(() => {
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

test("Guard reports the files a browser received: an untouched Build becomes watched, a changed file opens a Tampered Build Incident", async ({
  page,
  context,
  browser,
}) => {
  test.setTimeout(240_000);

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

  // 2. Harden the storefront bundle with the real CLI and register the Build: the marker is planted.
  const work = mkdtempSync(join(tmpdir(), "antireverse-e2e-tamper-guard-"));
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
      // The shop's own origin: with the Clone Beacon the planted statements go into src/storefront.js. Without it
      // the Canaries alone fit the tiny check.mjs, where the marker would find no room and not be planted.
      "--origin",
      ORIGIN,
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
  const hardened = JSON.parse(run.stdout) as {
    equivalence: string;
    integrity_marker: { files: string[] };
    registered: { build_id: string };
  };
  expect(hardened.equivalence).toBe("passed");
  const buildId = hardened.registered.build_id;
  const files = hardened.integrity_marker.files;
  // The two modules the page loads are listed; check.mjs is listed too and never loaded by a browser.
  expect(files).toEqual(expect.arrayContaining(["src/main.js", "src/storefront.js"]));
  const loaded = files.map((path, i) => ({ path, i })).filter(({ path }) => path.startsWith("src/"));
  expect(loaded).toHaveLength(2);
  const firstRequests = await serveShop(context, out, appId);

  const tamperIncidents = async (): Promise<Incident[]> => {
    const response = await fetch(`${API_URL}/v1/incidents?app_id=${appId}`, {
      headers: { authorization: `Bearer ${adminKey}` },
    });
    expect(response.status).toBe(200);
    return ListIncidentsResponseSchema.parse(await response.json()).incidents.filter(
      (incident) => incident.rule === "tampered-build",
    );
  };
  const onDisk = (path: string) => readFileSync(join(out, path));

  // 3. Untouched: the report names the Build and the hash of each loaded file as it is on disk.
  const first = await visit(context);
  const clean = await within(first.report, REPORT_BUDGET_MS, "the report of the untouched Build");
  console.info(`tamper-guard e2e: page load -> report ${Date.now() - first.loadedAt} ms`);
  expect(clean).toEqual({
    build: buildId,
    files: loaded.map(({ path, i }) => ({ i, h: sha256Wire(onDisk(path)) })),
    skipped: 0,
  });
  expectReviewedFields(first.attests, files);
  // Guard fetched nothing but the listed files it found on the page, each once.
  const refetched = await first.page.evaluate(() =>
    performance
      .getEntriesByType("resource")
      .filter((entry) => (entry as { initiatorType?: string }).initiatorType === "fetch")
      .map((entry) => new URL(entry.name).pathname)
      .filter((path) => !path.startsWith("/v1/")),
  );
  expect(refetched.sort()).toEqual(loaded.map(({ path }) => `/${path}`).sort());
  expectOnlyListedFilesRefetched(
    firstRequests,
    loaded.map(({ path }) => path),
  );
  // The device's memo: this App and Build, in first-party storage.
  expect(
    Object.keys(JSON.parse((await first.page.evaluate("localStorage.getItem('ar.integrity')")) as string)),
  ).toEqual([`${appId}/${buildId}`]);

  // The Build is watched since that report, and nothing was opened.
  await page.goto(`/apps/${appId}/builds/${buildId}`);
  await expect(async () => {
    await page.reload();
    await expect(page.getByTestId("build-integrity")).toHaveAttribute("data-status", "watched", { timeout: 1_000 });
  }).toPass({ timeout: 15_000 });
  expect(await tamperIncidents()).toEqual([]);
  await first.page.close();

  // 4. One byte of a protected file changes on disk; a second visitor loads the page.
  const target = "src/storefront.js";
  const registered = onDisk(target);
  const tampered = Buffer.from(registered);
  const last = tampered.length - 1;
  expect(tampered[last]).not.toBe(0x20);
  // The last byte (the end of the planted marker statement, or a line end) becomes a space: the module still runs.
  expect([0x0a, 0x3b]).toContain(tampered[last]);
  tampered[last] = 0x20;
  // The changed byte is not part of the Build id, which Guard looks for in this file (the marker's first) to know
  // that it is the Build's: the id is still there, before and after.
  expect(files[0]).toBe(target);
  expect(registered.includes(buildId)).toBe(true);
  expect(tampered.includes(buildId)).toBe(true);
  writeFileSync(join(out, target), tampered);
  expect(sha256Hex(tampered)).not.toBe(sha256Hex(registered));

  const visitor = await browser.newContext();
  try {
    const secondRequests = await serveShop(visitor, out, appId);
    const second = await visit(visitor);
    const dirty = await within(second.report, REPORT_BUDGET_MS, "the report of the changed Build");
    // The changed file has the hash of its new bytes; the untouched file still has its own; nothing was skipped.
    expect(dirty).toEqual({
      build: buildId,
      files: loaded.map(({ path, i }) => ({ i, h: sha256Wire(path === target ? tampered : onDisk(path)) })),
      skipped: 0,
    });
    expect(sha256Wire(onDisk("src/main.js"))).toBe(
      clean.files.find((file) => file.i === files.indexOf("src/main.js"))?.h,
    );
    expectReviewedFields(second.attests, files);
    expectOnlyListedFilesRefetched(
      secondRequests,
      loaded.map(({ path }) => path),
    );

    await expect.poll(async () => (await tamperIncidents()).length, { timeout: INCIDENT_BUDGET_MS }).toBe(1);
    const [incident] = await tamperIncidents();
    expect(incident).toMatchObject({
      build_id: buildId,
      severity: "high",
      title: "Tampered Build",
      artifact_path: target,
      observed_sha256: sha256Hex(tampered),
    });

    // 5. The Console shows it, within 60 s of the page load.
    await page.goto("/incidents");
    const row = page.getByTestId("incident-row").filter({ hasText: "Tampered Build" });
    await expect(async () => {
      await page.reload();
      await expect(row).toHaveCount(1, { timeout: 1_000 });
    }).toPass({ timeout: 15_000 });
    const shownAfterMs = Date.now() - second.loadedAt;
    console.info(`tamper-guard e2e: page load -> Incident in the Console ${shownAfterMs} ms`);
    expect(shownAfterMs).toBeLessThan(INCIDENT_BUDGET_MS);
    await expect(row).toHaveAttribute("data-severity", "high");
    await expect(row.getByTestId("incident-artifact")).toHaveText(target);
    await row.getByTestId("incident-link").click();
    await expect(page).toHaveURL(new RegExp(`/incidents/${incident?.id}$`));
    await expect(page.getByTestId("incident-severity")).toHaveAttribute("data-severity", "high");
    const buildLink = page.getByTestId("fact-build-link");
    await expect(buildLink).toHaveAttribute("href", `/apps/${appId}/builds/${buildId}`);
    await expect(buildLink).toHaveText(`Build ${VERSION}`);
    await expect(page.getByTestId("fact-file")).toHaveText(target);
    await expect(page.getByTestId("fact-registered-hash-value")).toHaveAttribute("title", sha256Hex(registered));
    await expect(page.getByTestId("fact-observed-hash-value")).toHaveAttribute("title", sha256Hex(tampered));
  } finally {
    await visitor.close();
  }
});
