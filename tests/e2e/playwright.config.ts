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
// The stand-in DNS of the e2e API (slice 14): a JSON file of TXT records the journey publishes and the API's resolver
// reads (fixtures/api-fixture-patches.ts). Set once by the runner, so that its workers, which inherit the environment
// and load this file again, use the same path.
process.env.E2E_FAKE_DNS_FILE ||= join(mkdtempSync(join(tmpdir(), "antireverse-e2e-dns-")), "dns-records.json");
export const FAKE_DNS_FILE = process.env.E2E_FAKE_DNS_FILE;
// The mails of the e2e API's local SMTP server (slice 06b), written by fixtures/api-fixture-patches.ts as they arrive.
process.env.E2E_FAKE_MAIL_FILE ||= join(mkdtempSync(join(tmpdir(), "antireverse-e2e-mail-")), "mails.json");
export const FAKE_MAIL_FILE = process.env.E2E_FAKE_MAIL_FILE;
// The hold of the e2e API's Assessment engine (slice 12a): while this file exists, a run waits before the real engine
// starts, so a journey can see an Assessment queued and running (fixtures/api-fixture-patches.ts). Absent: no wait.
process.env.E2E_ASSESS_HOLD_FILE ||= join(mkdtempSync(join(tmpdir(), "antireverse-e2e-hold-")), "assess-hold");
export const ASSESS_HOLD_FILE = process.env.E2E_ASSESS_HOLD_FILE;

// The operator token of the e2e API (slice 18d): it opens GET /v1/ops/slo and the Console's /ops dashboard. A test value
// for this local API only, at least 32 characters as the API requires.
export const OPS_TOKEN = "e2e-console-operator-token-".padEnd(48, "0");

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
      // The API is main.ts with the fixture Virtual patch catalog (slice 20) and a stand-in DNS resolver for Prove
      // (slice 14): see fixtures/api-fixture-patches.ts.
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
        E2E_FAKE_DNS_FILE: FAKE_DNS_FILE,
        E2E_FAKE_MAIL_FILE: FAKE_MAIL_FILE,
        E2E_ASSESS_HOLD_FILE: ASSESS_HOLD_FILE,
        AR_OPS_TOKEN: OPS_TOKEN,
        // Slice 15a: Pentest Campaigns are on for the e2e API. Its resolver never resolves a host (see
        // fixtures/api-fixture-patches.ts) and no test-only transport option is set here, so no Campaign of this API
        // ever sends a request: each is refused at its start checks, or stopped while it waits for them.
        AR_PROVE_CAMPAIGNS: "1",
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
