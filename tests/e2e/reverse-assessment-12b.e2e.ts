// Slice 12b in a real browser: the reference app, bundled into one ES module, is hardened by the real CLI with
// `--routes` and `--logic` (the reference logic file, written into the work directory at run time) and assessed at T1
// by the e2e API (real prove engine, stand-in agent). The Build page shows the RRS meter with the number, the scope
// line, and the W3/W4 rows: W3 judged against `discounted`'s hidden vectors, W4 achieved with its fix text. A Build
// hardened without `--logic` is inconclusive, and its W3 row shows how to add `--logic`.
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import {
  type Assessment,
  AssessmentResponseSchema,
  EXAMPLE_ROUTE_INVENTORY,
  LogicFileSchema,
  OBJECTIVES,
} from "@antireverse/protocol";
import { expect, test } from "@playwright/test";
import { buildSync } from "esbuild";
import { API_URL, ASSESS_HOLD_FILE, CONSOLE_URL } from "./playwright.config.ts";

const root = fileURLToPath(new URL("../..", import.meta.url));
const webDir = join(root, "apps/range/web");
const cliPath = join(root, "packages/harden/src/cli.ts");
const tsxCli = join(root, "node_modules/tsx/dist/cli.mjs");
const KEY_ENV = "AR_E2E_ADMIN_KEY";
const FINISH_BUDGET_MS = 30_000;
const LOGIC_TEXT = readFileSync(new URL("./fixtures/reference-logic.json", import.meta.url), "utf8");
const LOGIC = LogicFileSchema.parse(JSON.parse(LOGIC_TEXT));
const W4_FIX = OBJECTIVES.find((objective) => objective.id === "W4")?.fix as string;

function harden(
  args: string[],
  cwd: string,
  adminKey: string,
): Promise<{ code: number; stdout: string; stderr: string }> {
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

async function untilFinished(adminKey: string, id: string): Promise<Assessment> {
  const started = Date.now();
  for (;;) {
    const response = await fetch(`${API_URL}/v1/assessments/${id}`, {
      headers: { authorization: `Bearer ${adminKey}` },
    });
    expect(response.status).toBe(200);
    const { assessment } = AssessmentResponseSchema.parse(await response.json());
    if (assessment.status !== "queued" && assessment.status !== "running") return assessment;
    if (Date.now() - started > FINISH_BUDGET_MS) throw new Error(`${id}: not finished within ${FINISH_BUDGET_MS} ms`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

test("the Build page shows the RRS meter, the scope and the W3/W4 rows; without --logic, the --logic hint", async ({
  page,
}) => {
  test.setTimeout(180_000);
  // No hold left by another journey: these runs go straight through.
  rmSync(ASSESS_HOLD_FILE as string, { force: true });
  const temps: string[] = [];
  const tempDir = (prefix: string) => {
    const dir = mkdtempSync(join(tmpdir(), prefix));
    temps.push(dir);
    return dir;
  };

  try {
    // 1. Organization and App in the Console.
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

    // 2. The reference app as one ES module; routes.json and logic.json in the work directory, outside the bundle.
    const bundleDir = join(tempDir("antireverse-e2e-12b-bundle-"), "web");
    mkdirSync(bundleDir);
    buildSync({
      entryPoints: [join(webDir, "src/index.ts")],
      bundle: true,
      format: "esm",
      outfile: join(bundleDir, "bundle.mjs"),
      logLevel: "error",
    });
    const workDir = tempDir("antireverse-e2e-12b-ci-");
    writeFileSync(join(workDir, "routes.json"), JSON.stringify(EXAMPLE_ROUTE_INVENTORY));
    writeFileSync(join(workDir, "logic.json"), LOGIC_TEXT);

    const assess = async (extra: string[], version: string) => {
      const run = await harden(
        [
          bundleDir,
          "--profile",
          "balanced",
          "--seed",
          "6",
          "--routes",
          "routes.json",
          ...extra,
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
          version,
        ],
        workDir,
        adminKey,
      );
      expect(run.code, run.stderr).toBe(0);
      const report = JSON.parse(run.stdout) as { registered: { build_id: string }; assessment: { id: string } };
      return { buildId: report.registered.build_id, assessment: await untilFinished(adminKey, report.assessment.id) };
    };

    // 3. With --logic: scored. The page shows the meter with the API's number, the scope and the W3/W4 rows.
    const scored = await assess(["--logic", "logic.json"], "12.3.0");
    expect(scored.assessment.status, JSON.stringify(scored.assessment.results)).toBe("scored");
    const rrs = scored.assessment.rrs as number;
    await page.goto(`/apps/${appId}/builds/${scored.buildId}`);
    const section = page.getByTestId("build-assessment");
    await expect(section.getByTestId("assessment-latest")).toHaveAttribute("data-status", "scored");
    await expect(section.getByTestId("rrs-meter")).toBeVisible();
    await expect(section.getByTestId("rrs-value")).toHaveText(String(rrs));
    await expect(section.getByTestId("assessment-inconclusive")).toHaveCount(0);
    await expect(section.getByTestId("assessment-scope")).toContainText("stand-in");
    await expect(section.getByTestId("assessment-scope")).toContainText("tier T1");
    await expect(section.getByTestId("history-score").first()).toHaveText(String(rrs));

    const row = (id: string) => section.locator(`[data-testid="objective-row"][data-objective="${id}"]`);
    await expect(section.getByTestId("objective-row")).toHaveCount(5);
    await expect(row("W3")).toContainText("Not achieved");
    await expect(row("W3").getByTestId("objective-summary")).toContainText("discounted");
    await expect(row("W3").getByTestId("objective-summary")).toContainText(/\d+ of 15/);
    await expect(row("W4")).toContainText("Achieved at T1");
    await expect(row("W4").getByTestId("objective-fix")).toContainText(W4_FIX);
    for (const fn of LOGIC.functions) {
      for (const vector of fn.vectors) await expect(section).not.toContainText(JSON.stringify(vector.input));
    }

    // 4. Without --logic: inconclusive, and W3 says how to designate a function.
    const bare = await assess([], "12.3.1");
    expect(bare.assessment.status).toBe("inconclusive");
    await page.goto(`/apps/${appId}/builds/${bare.buildId}`);
    await expect(section.getByTestId("assessment-latest")).toHaveAttribute("data-status", "inconclusive");
    await expect(section.getByTestId("rrs-meter")).toHaveCount(0);
    await expect(row("W3")).toContainText("Not attempted");
    await expect(row("W3").getByTestId("objective-hint")).toContainText("--logic");
  } finally {
    for (const dir of temps) rmSync(dir, { recursive: true, force: true });
  }
});
