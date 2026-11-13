// Slice 12a in a real browser: the real harden CLI registers the reference bundle with a route inventory and requests
// a T1 Reverse Assessment from the e2e API (real prove engine, stand-in agent). While the run is held (the hold file of
// fixtures/api-fixture-patches.ts) the Build page shows it running, then a second one queued, and offers no
// "Assess again". Once both finish, the "Reverse resistance" section shows "Inconclusive: <reason>" with no number,
// the scope and stand-in note, and the five Objective rows (W2 achieved on the planted Canary, W3/W4 not attempted).
// "Assess again" then requests a new Assessment of the kept bundle, which runs and finishes too.
import { execFile } from "node:child_process";
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type Assessment,
  AssessmentResponseSchema,
  type Canary,
  EXAMPLE_ROUTE_INVENTORY,
  ListAssessmentsResponseSchema,
} from "@antireverse/protocol";
import { expect, test } from "@playwright/test";
import { API_URL, ASSESS_HOLD_FILE, CONSOLE_URL } from "./playwright.config.ts";

const root = fileURLToPath(new URL("../..", import.meta.url));
const webDir = join(root, "apps/range/web");
const cliPath = join(root, "packages/harden/src/cli.ts");
const tsxCli = join(root, "node_modules/tsx/dist/cli.mjs");
const KEY_ENV = "AR_E2E_ADMIN_KEY";
const FINISH_BUDGET_MS = 30_000;

interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
}

function harden(args: string[], cwd: string, adminKey: string): Promise<CliRun> {
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [tsxCli, cliPath, "harden", ...args],
      { cwd, env: { ...process.env, [KEY_ENV]: adminKey, AR_CONSOLE_URL: CONSOLE_URL }, maxBuffer: 16 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === "number" ? error.code : -1;
        resolve({ code, stdout: String(stdout), stderr: String(stderr) });
      },
    );
  });
}

function readTree(dir: string): Record<string, string> {
  const files: Record<string, string> = {};
  for (const entry of readdirSync(dir, { recursive: true, withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const full = join(entry.parentPath, entry.name);
    files[relative(dir, full).split(sep).join("/")] = readFileSync(full, "utf8");
  }
  return files;
}

async function getAssessment(adminKey: string, id: string): Promise<Assessment> {
  const response = await fetch(`${API_URL}/v1/assessments/${id}`, { headers: { authorization: `Bearer ${adminKey}` } });
  expect(response.status).toBe(200);
  return AssessmentResponseSchema.parse(await response.json()).assessment;
}

async function listAssessments(adminKey: string, appId: string, buildId: string): Promise<Assessment[]> {
  const response = await fetch(`${API_URL}/v1/apps/${appId}/builds/${buildId}/assessments`, {
    headers: { authorization: `Bearer ${adminKey}` },
  });
  expect(response.status).toBe(200);
  return ListAssessmentsResponseSchema.parse(await response.json()).assessments;
}

/** Polls an Assessment until its status is one of `statuses`. */
async function untilStatus(adminKey: string, id: string, statuses: readonly string[]): Promise<Assessment> {
  const started = Date.now();
  for (;;) {
    const assessment = await getAssessment(adminKey, id);
    if (statuses.includes(assessment.status)) return assessment;
    if (Date.now() - started > FINISH_BUDGET_MS) {
      throw new Error(`${id}: still ${assessment.status}, not ${statuses.join("/")} within ${FINISH_BUDGET_MS} ms`);
    }
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

const hold = () => writeFileSync(ASSESS_HOLD_FILE as string, "held");
const release = () => rmSync(ASSESS_HOLD_FILE as string, { force: true });

test.afterEach(() => release());

test("the Build page shows the Reverse resistance result, and Assess again only once a run has finished", async ({
  page,
}) => {
  test.setTimeout(180_000);
  expect(ASSESS_HOLD_FILE).toBeTruthy();
  const temps: string[] = [];
  const tempDir = (prefix: string) => {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    temps.push(dir);
    return dir;
  };

  try {
    // 1. Create the Organization and the App in the Console; capture the admin key and the App id.
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
    const appId = (/\/apps\/(app_[0-9a-f]{24})/.exec(page.url()) ?? [])[1] as string;
    expect(appId).toBeTruthy();

    // 2. Hold the engine, then harden, register with the route inventory and request a T1 Assessment (real CLI).
    hold();
    const bundleDir = join(tempDir("antireverse-e2e-asm-bundle-"), "web");
    cpSync(webDir, bundleDir, { recursive: true });
    const workDir = tempDir("antireverse-e2e-asm-ci-");
    const outDir = join(tempDir("antireverse-e2e-asm-out-"), "protected");
    writeFileSync(join(workDir, "routes.json"), JSON.stringify(EXAMPLE_ROUTE_INVENTORY));
    const run = await harden(
      [
        bundleDir,
        "--profile",
        "balanced",
        "--seed",
        "3",
        "--out",
        outDir,
        "--routes",
        "routes.json",
        "--assess",
        "T1",
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
        "12.1.0",
      ],
      workDir,
      adminKey,
    );
    expect(run.code, run.stderr).toBe(0);
    const report = JSON.parse(run.stdout) as {
      canaries: Canary[];
      registered: { build_id: string };
      assessment: { id: string; status: string };
    };
    const buildId = report.registered.build_id;
    const firstId = report.assessment.id;
    expect(firstId).toMatch(/^asm_[0-9a-f]{24}$/);
    const keyCanary = report.canaries.find((canary) => canary.kind === "key") as Canary;
    expect(keyCanary).toBeTruthy();

    // 3. Held, the runner has claimed it: the Build page shows it running and offers no "Assess again".
    await untilStatus(adminKey, firstId, ["running"]);
    await page.goto(`/apps/${appId}/builds/${buildId}`);
    const section = page.getByTestId("build-assessment");
    await expect(section.getByRole("heading", { name: "Reverse resistance" })).toBeVisible();
    await expect(section.getByTestId("assessment-latest")).toHaveAttribute("data-status", "running");
    await expect(section.getByTestId("assessment-progress")).toContainText("Running since");
    await expect(section.getByTestId("assess-again")).toHaveCount(0);

    // 4. A second request (with the same files) waits behind it, queued: still no "Assess again".
    const files = Object.entries(readTree(outDir)).map(([path, code]) => ({
      path,
      base64: Buffer.from(code, "utf8").toString("base64"),
    }));
    const second = await fetch(`${API_URL}/v1/apps/${appId}/builds/${buildId}/assessments`, {
      method: "POST",
      headers: { authorization: `Bearer ${adminKey}`, "content-type": "application/json" },
      body: JSON.stringify({ tier: "T1", files }),
    });
    expect(second.status).toBe(202);
    const secondId = ((await second.json()) as { assessment: { id: string } }).assessment.id;
    expect((await getAssessment(adminKey, secondId)).status).toBe("queued");
    await page.reload();
    await expect(section.getByTestId("assessment-latest")).toHaveAttribute("data-status", "queued");
    await expect(section.getByTestId("assessment-progress")).toContainText("Queued since");
    await expect(section.getByTestId("assess-again")).toHaveCount(0);
    await expect(section.getByTestId("history-row")).toHaveCount(2);

    // 5. Release the engine: both finish inconclusive.
    release();
    await untilStatus(adminKey, firstId, ["inconclusive"]);
    await untilStatus(adminKey, secondId, ["inconclusive"]);
    await page.reload();
    const latest = section.getByTestId("assessment-latest");
    await expect(latest).toHaveAttribute("data-status", "inconclusive");
    await expect(section.getByTestId("assessment-inconclusive")).toContainText(/^Inconclusive: \S/);
    await expect(section.getByTestId("rrs-meter")).toHaveCount(0);
    await expect(section.getByTestId("assessment-scope")).toContainText("stand-in");
    await expect(section.getByTestId("assessment-scope")).toContainText("tier T1");
    await expect(section.getByTestId("assessment-stand-in")).toBeVisible();

    // The Objective rows: W1–W5 in order; W2 achieved on the decoy key (by id, never its value); W3/W4 not attempted.
    const rows = section.getByTestId("objective-row");
    await expect(rows).toHaveCount(5);
    for (const [index, id] of ["W1", "W2", "W3", "W4", "W5"].entries()) {
      await expect(rows.nth(index)).toHaveAttribute("data-objective", id);
    }
    const w2 = section.locator('[data-testid="objective-row"][data-objective="W2"]');
    await expect(w2).toContainText("Achieved at T1");
    await expect(w2.locator('[data-testid="recovered-item"][data-kind="canary"]').first()).toBeVisible();
    await expect(w2).toContainText(keyCanary.id);
    await expect(w2.getByTestId("objective-fix")).toBeVisible();
    await expect(section.locator('[data-testid="objective-row"][data-objective="W1"]')).not.toContainText(
      "Not attempted",
    );
    for (const id of ["W3", "W4"]) {
      await expect(section.locator(`[data-testid="objective-row"][data-objective="${id}"]`)).toContainText(
        "Not attempted",
      );
    }
    await expect(section.locator('[data-testid="objective-row"][data-objective="W5"]')).toContainText("Not achieved");
    await expect(section).not.toContainText(keyCanary.value);

    // 6. "Assess again" is offered now and requests a new Assessment of the kept bundle (held, so it stays active).
    const again = section.getByTestId("assess-again");
    await expect(again).toBeVisible();
    hold();
    await again.getByLabel("Tier").selectOption("T1");
    await again.getByTestId("assess-again-submit").click();
    await expect
      .poll(async () => (await listAssessments(adminKey, appId, buildId)).length, { timeout: 15_000 })
      .toBe(3);
    const [third] = await listAssessments(adminKey, appId, buildId);
    expect(third?.id).not.toBe(secondId);
    expect(third?.tier).toBe("T1");
    expect(["queued", "running"]).toContain(third?.status);
    await page.reload();
    await expect(section.getByTestId("assessment-latest")).toHaveAttribute("data-status", /^(queued|running)$/);
    await expect(section.getByTestId("assess-again")).toHaveCount(0);

    // 7. Released, it finishes, and the page shows it with "Assess again" back.
    release();
    await untilStatus(adminKey, third?.id as string, ["inconclusive"]);
    await page.reload();
    await expect(section.getByTestId("assessment-latest")).toHaveAttribute("data-status", "inconclusive");
    await expect(section.getByTestId("history-row")).toHaveCount(3);
    await expect(section.getByTestId("history-row").first()).toHaveAttribute("data-assessment-id", third?.id as string);
    await expect(section.getByTestId("assess-again")).toBeVisible();
  } finally {
    release();
    for (const dir of temps) rmSync(dir, { recursive: true, force: true });
  }
});
