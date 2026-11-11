// Browser journey of slice 01. Starts the API (fresh data directory) and the Console (next dev);
// the customer's Express server with Shield is started by the test itself, with the key the Console shows.
// One-time browser install: npx playwright install --only-shell --no-remove chromium
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { defineConfig, devices } from "@playwright/test";

const root = fileURLToPath(new URL("../..", import.meta.url));
// Overridable so that a run can avoid ports already in use (e.g. E2E_API_PORT=39940 E2E_CONSOLE_PORT=39941).
export const API_PORT = Number(process.env.E2E_API_PORT || 18_787);
export const CONSOLE_PORT = Number(process.env.E2E_CONSOLE_PORT || 13_000);
export const API_URL = `http://127.0.0.1:${API_PORT}`;
export const CONSOLE_URL = `http://127.0.0.1:${CONSOLE_PORT}`;

const dataDir = join(mkdtempSync(join(tmpdir(), "antireverse-e2e-")), "pg");

export default defineConfig({
  testDir: ".",
  testMatch: "**/*.e2e.ts",
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  outputDir: "./test-results",
  use: { baseURL: CONSOLE_URL, trace: "retain-on-failure" },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: [
    {
      name: "api",
      // The fixture advisories (slice 19) are imported into the fresh data directory with the real sync command
      // before the API takes it over (PGlite allows one owner at a time). Advisories are global, not tenant data.
      // The API is main.ts with the fixture Virtual patch catalog (slice 20): see fixtures/api-fixture-patches.ts.
      command:
        "npx tsx apps/api/src/vulns/cli.ts --fixture apps/api/test/fixtures/advisories.json && exec npx tsx tests/e2e/fixtures/api-fixture-patches.ts",
      cwd: root,
      // Alert channels may point at a receiver on loopback over http (slice 06): tests only.
      env: {
        HOST: "127.0.0.1",
        PORT: String(API_PORT),
        AR_DATA_DIR: dataDir,
        AR_ALLOW_PRIVATE_ALERT_URLS: "1",
        AR_CONSOLE_URL: CONSOLE_URL,
      },
      url: `${API_URL}/healthz`,
      reuseExistingServer: false,
      timeout: 30_000,
      stdout: "pipe",
      stderr: "pipe",
      gracefulShutdown: { signal: "SIGTERM", timeout: 3_000 },
    },
    {
      name: "console",
      command: "npm run dev -w @antireverse/console",
      cwd: root,
      // `next dev` allows one server per build directory: the e2e Console builds into its own folder so it can
      // run while a developer's Console dev server runs in this workspace.
      env: { PORT: String(CONSOLE_PORT), AR_API_URL: API_URL, AR_NEXT_DIST_DIR: ".next/e2e" },
      url: `${CONSOLE_URL}/sign-in`,
      reuseExistingServer: false,
      timeout: 120_000,
      stdout: "pipe",
      stderr: "pipe",
      gracefulShutdown: { signal: "SIGTERM", timeout: 3_000 },
    },
  ],
});
