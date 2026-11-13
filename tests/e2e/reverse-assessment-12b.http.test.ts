// Slice 12b over HTTP/CLI: W3 Logic and W4 Tamper end to end. The reference app (apps/range/web) is bundled with the
// workspace's esbuild into one ES module, bundle.mjs (W4 takes .js/.mjs/.cjs files only, so the TypeScript sources
// would leave the stand-in nothing to tamper with). The real `antireverse harden` CLI hardens it with a route inventory
// (`--routes`) and the reference logic file (`--logic`, designating `discounted(cents, pct)` of
// apps/range/web/src/pricing.ts with 15 hidden vectors), registers it and requests a T1 Assessment from a real API
// (startApi, temporary data directory) running the real prove engine and stand-in agent. With every Objective decided
// the Assessment is scored: W3 judged (the stand-in's lookup over the public examples fails the hidden vectors), W4
// achieved (no tamper check; the ES module runs as a module). A classic-script build of the same app hardened with
// `--integrity` still loses W4 to the stand-in: the check is a signal, not
// tamper-proofing. Without `--logic`, W3 is not attempted (`not_designated`), which excludes 25 % and makes the
// Assessment inconclusive. No response ever carries a vector, and the Build read carries no logic.
import { execFile } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  type Assessment,
  AssessmentResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  EXAMPLE_ROUTE_INVENTORY,
  LogicFileSchema,
  type ObjectiveResult,
  STAND_IN_MODEL,
  scoreAssessment,
} from "@antireverse/protocol";
import { buildSync } from "esbuild";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const FINISH_BUDGET_MS = 60_000;

const root = fileURLToPath(new URL("../..", import.meta.url));
const webDir = join(root, "apps/range/web");
const cliPath = join(root, "packages/harden/src/cli.ts");
const tsxCli = join(root, "node_modules/tsx/dist/cli.mjs");
const KEY_ENV = "AR_E2E_ADMIN_KEY";

/** The reference logic file (fixtures/reference-logic.json): written into the work directory at run time only. */
const LOGIC_TEXT = readFileSync(new URL("./fixtures/reference-logic.json", import.meta.url), "utf8");
const LOGIC = LogicFileSchema.parse(JSON.parse(LOGIC_TEXT));
const DISCOUNTED = LOGIC.functions.find((fn) => fn.id === "discounted");

/**
 * The equivalence check of the ES module build: imports bundle.mjs from the equivalence runner's copy and checks the
 * app's behaviour through its exports. Kept outside the bundle folder.
 */
const ESM_CHECK = `import assert from "node:assert/strict";
import { pathToFileURL } from "node:url";
const web = await import(pathToFileURL("bundle.mjs").href);
assert.equal(web.quote("pro", 10), "€17.10");
assert.equal(web.quote("business"), "€49.00");
console.log("ok");
`;

/**
 * The equivalence check of the classic-script build: runs bundle.js as a script (no module system) and checks the
 * app's behaviour through the global the bundle defines. Kept outside the bundle folder.
 */
const CLASSIC_CHECK = `import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { runInThisContext } from "node:vm";
runInThisContext(readFileSync("bundle.js", "utf8"));
const web = globalThis.rangeWeb;
assert.equal(web.quote("pro", 10), "€17.10");
assert.equal(web.quote("business"), "€49.00");
console.log("ok");
`;

interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
}

interface HardenReport {
  equivalence: string;
  integrity: boolean;
  registered?: { build_id: string };
  routes: { count: number } | null;
  logic: { count: number } | null;
  assessment?: { id: string; status: string } | { error: string };
}

let api: RunningApi;
let adminKey: string;
let appId: string;
let workDir: string;
let bundleDir: string;
let esmCheck: string;
let classicDir: string;
let classicCheck: string;
const temps: string[] = [];
/** Every API response body this test read. */
const bodies: string[] = [];
/** The Build ids hardened with --logic. */
const logicBuilds: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

async function call(path: string, init: { method?: string; key?: string; body?: unknown } = {}): Promise<unknown> {
  const headers: Record<string, string> = {};
  if (init.key) headers.authorization = `Bearer ${init.key}`;
  if (init.body !== undefined) headers["content-type"] = "application/json";
  const response = await fetch(`${api.url}${path}`, {
    method: init.method ?? "GET",
    headers,
    ...(init.body === undefined ? {} : { body: JSON.stringify(init.body) }),
  });
  const text = await response.text();
  bodies.push(text);
  expect(response.status, `${path}: ${text.slice(0, 200)}`).toBeLessThan(300);
  return JSON.parse(text);
}

function harden(args: string[], cwd: string): Promise<CliRun> {
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

function registerArgs(version: string): string[] {
  return [
    "--register",
    "--endpoint",
    api.url,
    "--key-env",
    KEY_ENV,
    "--app",
    appId,
    "--environment",
    "development",
    "--build-version",
    version,
  ];
}

async function waitFinished(id: string): Promise<Assessment> {
  const started = Date.now();
  for (;;) {
    const { assessment } = AssessmentResponseSchema.parse(await call(`/v1/assessments/${id}`, { key: adminKey }));
    if (assessment.status !== "queued" && assessment.status !== "running") return assessment;
    if (Date.now() - started > FINISH_BUDGET_MS) throw new Error(`${id}: not finished within ${FINISH_BUDGET_MS} ms`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
}

/** Hardens `dir` with the given extra flags, requests a T1 Assessment, and returns the report and the finished run. */
async function hardenAndAssess(
  dir: string,
  extra: string[],
  version: string,
): Promise<{ report: HardenReport; assessment: Assessment }> {
  const run = await harden(
    [dir, "--profile", "balanced", "--seed", "1", ...extra, "--assess", "T1", "--json", ...registerArgs(version)],
    workDir,
  );
  expect(run.code, run.stderr).toBe(0);
  for (const fn of LOGIC.functions) {
    expect(run.stdout).not.toContain(fn.description);
    expect(run.stderr).not.toContain(fn.description);
  }
  const report = JSON.parse(run.stdout) as HardenReport;
  const requested = report.assessment as { id: string; status: string };
  expect(requested.id).toMatch(/^asm_[0-9a-f]{24}$/);
  return { report, assessment: await waitFinished(requested.id) };
}

const byObjective = (assessment: Assessment) =>
  Object.fromEntries(assessment.results.map((result) => [result.objective, result])) as Record<string, ObjectiveResult>;

/** The JSON texts of every hidden vector: as a whole, and its input arguments. */
const vectorTexts = () =>
  LOGIC.functions.flatMap((fn) => fn.vectors.flatMap((v) => [JSON.stringify(v), JSON.stringify(v.input)]));

beforeAll(async () => {
  expect(DISCOUNTED?.vectors).toHaveLength(15);
  // A temporary data directory: nothing is written to apps/api/.data.
  api = await startApi({ dataDir: join(tempDir("antireverse-e2e-12b-pg-"), "pg"), logger: { info() {}, warn() {} } });
  const organization = CreateOrganizationResponseSchema.parse(
    await call("/v1/organizations", { method: "POST", body: { name: "Acme" } }),
  );
  adminKey = organization.admin_key.key;
  appId = CreateAppResponseSchema.parse(
    await call("/v1/apps", { method: "POST", key: adminKey, body: { name: "shop-web" } }),
  ).app.id;

  // The bundle copies, and the CI working directory with the route inventory and the logic file beside each other.
  workDir = tempDir("antireverse-e2e-12b-ci-");
  writeFileSync(join(workDir, "routes.json"), JSON.stringify(EXAMPLE_ROUTE_INVENTORY));
  writeFileSync(join(workDir, "logic.json"), LOGIC_TEXT);
  classicCheck = join(workDir, "check-classic.mjs");
  writeFileSync(classicCheck, CLASSIC_CHECK);
  esmCheck = join(workDir, "check-esm.mjs");
  writeFileSync(esmCheck, ESM_CHECK);

  // The reference app as the browser gets it: one ES module (W4 takes .js, .mjs or .cjs files, so the TypeScript
  // sources themselves would leave the stand-in nothing to tamper with).
  bundleDir = join(tempDir("antireverse-e2e-12b-bundle-"), "web");
  mkdirSync(bundleDir);
  buildSync({
    entryPoints: [join(webDir, "src/index.ts")],
    bundle: true,
    format: "esm",
    outfile: join(bundleDir, "bundle.mjs"),
    logLevel: "error",
  });

  // The same app as one classic script (an IIFE that sets globalThis.rangeWeb): what --integrity can wrap.
  classicDir = join(tempDir("antireverse-e2e-12b-classic-"), "web");
  mkdirSync(classicDir);
  buildSync({
    entryPoints: [join(webDir, "src/index.ts")],
    bundle: true,
    format: "iife",
    globalName: "rangeWeb",
    footer: { js: "globalThis.rangeWeb = rangeWeb;" },
    outfile: join(classicDir, "bundle.js"),
    logLevel: "error",
  });
}, 60_000);

afterAll(async () => {
  await api?.close();
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("slice 12b W3 Logic and W4 Tamper over HTTP/CLI", () => {
  it("scores an ES module Build hardened with --logic and without --integrity: W3 judged, W4 achieved", async () => {
    const { report, assessment } = await hardenAndAssess(
      bundleDir,
      ["--test", `node ${esmCheck}`, "--routes", "routes.json", "--logic", "logic.json"],
      "12.2.0",
    );
    expect(report.equivalence).toBe("passed");
    expect(report.integrity).toBe(false);
    expect(report.logic).toEqual({ count: 1 });
    const buildId = report.registered?.build_id as string;
    logicBuilds.push(buildId);

    expect(assessment.status, JSON.stringify(assessment.results)).toBe("scored");
    expect(typeof assessment.rrs).toBe("number");
    expect(assessment.rrs).toBe(scoreAssessment(assessment.results, "T1").rrs);
    expect(assessment.inconclusive_reason).toBeNull();
    expect(assessment.renormalised).toBe(false);
    expect(assessment.scope).toMatchObject({ model: STAND_IN_MODEL, tier: "T1" });
    expect(assessment.results.map((result) => result.objective)).toEqual(["W1", "W2", "W3", "W4", "W5"]);
    for (const result of assessment.results) expect(result.result, result.objective).not.toBe("not_attempted");

    const results = byObjective(assessment);
    // W3: judged; the stand-in's lookup over the two public examples fails the hidden vectors.
    const w3 = results.W3 as ObjectiveResult;
    expect(w3.result).toBe("not_achieved");
    expect(w3.evidence.summary).toContain("discounted");
    expect(w3.evidence.summary).toMatch(/\b\d+ of 15\b/);
    for (const text of vectorTexts()) expect(w3.evidence.summary).not.toContain(text);
    // W4: no tamper check, so the stand-in's small marker edit runs.
    expect(results.W4?.result, results.W4?.evidence.summary).toBe("achieved");

    // The Build read carries the logic's count and digest at most, never the functions.
    const build = JSON.stringify(await call(`/v1/apps/${appId}/builds/${buildId}`, { key: adminKey }));
    expect(build).not.toContain("vectors");
    expect(build).not.toContain("examples");
    for (const fn of LOGIC.functions) expect(build).not.toContain(fn.description);
    for (const text of vectorTexts()) expect(build).not.toContain(text);
  }, 120_000);

  it("a classic-script build with --integrity still loses W4 to the stand-in (a signal, not tamper-proofing)", async () => {
    const { report, assessment } = await hardenAndAssess(
      classicDir,
      ["--integrity", "--test", `node ${classicCheck}`, "--routes", "routes.json", "--logic", "logic.json"],
      "12.2.1",
    );
    expect(report.integrity).toBe(true);
    expect(report.equivalence).toBe("passed");
    logicBuilds.push(report.registered?.build_id as string);

    expect(assessment.status, JSON.stringify(assessment.results)).toBe("scored");
    expect(assessment.rrs).toBe(scoreAssessment(assessment.results, "T1").rrs);
    const results = byObjective(assessment);
    const w4 = results.W4 as ObjectiveResult;
    expect(w4.result, w4.evidence.summary).toBe("achieved");
    // W4's evidence names the file it ran, never code.
    expect(w4.evidence.summary).toContain("bundle.js");
    expect(w4.evidence.summary).not.toContain("__payload");
    expect(results.W3?.result).toBe("not_achieved");
  }, 120_000);

  it("without --logic, W3 is not attempted (not_designated) and the Assessment is inconclusive", async () => {
    const { report, assessment } = await hardenAndAssess(bundleDir, ["--routes", "routes.json"], "12.2.2");
    expect(report.logic).toBeNull();
    const results = byObjective(assessment);
    expect(results.W3).toMatchObject({ result: "not_attempted", reason: "not_designated" });
    // W3 weighs 0.25, above the 20 % that may be excluded.
    expect(assessment).toMatchObject({ status: "inconclusive", rrs: null, inconclusive_code: "excluded_over_limit" });
    expect(results.W4?.result, results.W4?.evidence.summary).toBe("achieved");
  }, 120_000);

  it("never returns a hidden vector or a function description in any response body", () => {
    expect(logicBuilds).toHaveLength(2);
    expect(bodies.length).toBeGreaterThan(5);
    for (const body of bodies) {
      for (const text of vectorTexts()) expect(body).not.toContain(text);
      for (const fn of LOGIC.functions) expect(body).not.toContain(fn.description);
    }
  });
});
