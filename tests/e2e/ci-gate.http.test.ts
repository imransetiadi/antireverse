// Slice 13 over HTTP/CLI: the CI gate on the Reverse Resistance Score. The real `antireverse` CLI (harden and gate, in
// their own processes) runs against a real API (startApi, temporary data directory) whose Assessment runner uses a
// fixed-result Assessor: "scored" returns apps/api/test/fake-assessor.ts's scoredResults (every Objective decided, so
// the RRS is deterministic), "inconclusive" its inconclusiveResults (W3 and W4 not supported). A hold file stands in
// for a long run (like E2E_ASSESS_HOLD_FILE in fixtures/api-fixture-patches.ts): while it exists, a claimed run waits.
// Covered: `harden --register --assess T1 --min-rrs` at or above the score exits 0 (gate passed), below it exits 5
// naming the score, the threshold and the weakest Objectives; an inconclusive Assessment exits 6, or 0 with the gate
// skipped under `--on-no-score pass`; `antireverse gate --assessment <id>` gives the same exits for an Assessment
// queued earlier; a short `--wait` on a held Assessment exits 6; the admin key never appears in any output.
import { execFile } from "node:child_process";
import { cpSync, existsSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { type Assessor, type RunningApi, startApi } from "@antireverse/api";
import {
  type Assessment,
  AssessmentResponseSchema,
  CreateAppResponseSchema,
  CreateOrganizationResponseSchema,
  scoreAssessment,
} from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { fakeScope, inconclusiveResults, scoredResults } from "../../apps/api/test/fake-assessor.ts";

const FINISH_BUDGET_MS = 30_000;
/** A CLI run polls with a 2 s first backoff; a few polls at most. */
const RUN_TIMEOUT_MS = 60_000;

const root = fileURLToPath(new URL("../..", import.meta.url));
const webDir = join(root, "apps/range/web");
const cliPath = join(root, "packages/harden/src/cli.ts");
const tsxCli = join(root, "node_modules/tsx/dist/cli.mjs");
const KEY_ENV = "AR_E2E_ADMIN_KEY";

/** The fixed RRS of scoredResults() at T1. */
const SCORE = scoreAssessment(scoredResults(), "T1");
const RRS = SCORE.rrs as number;

type Mode = "scored" | "inconclusive";

interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
  /** Wall-clock milliseconds of the run. */
  ms: number;
}

interface WeakObjective {
  objective: string;
  name: string;
  result: string;
  tier?: string;
}

interface RrsGateReport {
  result: "passed" | "failed" | "no_score" | "skipped";
  rrs: number | null;
  threshold: number;
  status: string | null;
  reason: string | null;
  weakest: WeakObjective[];
}

interface HardenReport {
  registered?: { build_id: string };
  assessment?: { id: string; status: string } | { error: string };
  rrs_gate?: RrsGateReport | { result: "error"; reason: string };
}

interface GateReport {
  assessment: { id: string; status: string | null; tier: string | null; rrs: number | null };
  gate: RrsGateReport;
}

let api: RunningApi;
let adminKey: string;
let appId: string;
let bundleDir: string;
let workDir: string;
let holdFile: string;
/** What the next run returns; read when a run starts. */
let mode: Mode = "scored";
let versionCounter = 0;
const temps: string[] = [];
/** Every CLI run of this file, to prove the admin key is never printed. */
const runs: CliRun[] = [];
/** Assessments queued without a gate, for `antireverse gate`. */
const queued: Partial<Record<Mode, string>> = {};

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

/** The fixed-result Assessor: waits while the hold file exists, then returns the mode's results at the run's tier. */
function fixedAssessor(): Assessor {
  return {
    scope: fakeScope,
    async assess(input) {
      const results = mode === "scored" ? scoredResults() : inconclusiveResults();
      while (existsSync(holdFile) && !input.signal.aborted) {
        await new Promise((resolve) => setTimeout(resolve, 50));
      }
      return { results, scope: fakeScope(input.tier), end: "finished" };
    },
  };
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
  expect(response.status, `${path}: ${text.slice(0, 200)}`).toBeLessThan(300);
  return JSON.parse(text);
}

/** Runs the real CLI (`antireverse <command> …`) in its own process, the admin key only in the environment. */
function cli(command: "harden" | "gate", args: string[]): Promise<CliRun> {
  const started = Date.now();
  return new Promise((resolve) => {
    execFile(
      process.execPath,
      [tsxCli, cliPath, command, ...args],
      { cwd: workDir, env: { ...process.env, [KEY_ENV]: adminKey }, maxBuffer: 16 * 1024 * 1024 },
      (error, stdout, stderr) => {
        const code = error === null ? 0 : typeof error.code === "number" ? error.code : -1;
        const run = { code, stdout: String(stdout), stderr: String(stderr), ms: Date.now() - started };
        runs.push(run);
        resolve(run);
      },
    );
  });
}

/** `harden <bundle> --register … --assess T1` with the extra flags; a fresh Build version each time. */
function hardenAssess(extra: string[]): Promise<CliRun> {
  versionCounter += 1;
  return cli("harden", [
    bundleDir,
    "--profile",
    "balanced",
    "--seed",
    "1",
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
    `13.0.${versionCounter}`,
    "--assess",
    "T1",
    ...extra,
  ]);
}

function gate(id: string, extra: string[]): Promise<CliRun> {
  return cli("gate", ["--assessment", id, "--endpoint", api.url, "--key-env", KEY_ENV, ...extra]);
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

const hardenReport = (run: CliRun) => JSON.parse(run.stdout) as HardenReport;
const assessmentId = (report: HardenReport) => (report.assessment as { id: string }).id;
const rrsGate = (report: HardenReport) => report.rrs_gate as RrsGateReport;

/** The two weakest of scoredResults() at T1: W2 achieved at T1 (r = 0), then W1 not achieved (r = 0.4, first by order). */
const WEAKEST = [
  { objective: "W2", name: "Secrets", result: "achieved", tier: "T1" },
  { objective: "W1", name: "Map", result: "not_achieved" },
];

beforeAll(async () => {
  expect(SCORE.status).toBe("scored");
  // The thresholds below are RRS − 10 and RRS + 1: both must be valid --min-rrs values.
  expect(RRS).toBeGreaterThanOrEqual(10);
  expect(RRS).toBeLessThan(100);
  expect(Number.isInteger(RRS)).toBe(true);

  holdFile = join(tempDir("antireverse-e2e-13-hold-"), "assess-hold");
  // A temporary data directory and a free port: nothing is written to apps/api/.data.
  api = await startApi({
    dataDir: join(tempDir("antireverse-e2e-13-pg-"), "pg"),
    logger: { info() {}, warn() {} },
    assessor: fixedAssessor(),
  });
  const organization = CreateOrganizationResponseSchema.parse(
    await call("/v1/organizations", { method: "POST", body: { name: "Acme" } }),
  );
  adminKey = organization.admin_key.key;
  appId = CreateAppResponseSchema.parse(
    await call("/v1/apps", { method: "POST", key: adminKey, body: { name: "shop-web" } }),
  ).app.id;

  // A copy of the reference bundle (never hardened in place) and a CI working directory.
  bundleDir = join(tempDir("antireverse-e2e-13-bundle-"), "web");
  cpSync(webDir, bundleDir, { recursive: true });
  workDir = tempDir("antireverse-e2e-13-ci-");
}, 60_000);

afterAll(async () => {
  if (holdFile) rmSync(holdFile, { force: true });
  await api?.close();
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("slice 13 CI gate on the RRS over HTTP/CLI", () => {
  it(
    "harden --min-rrs below the score: waits for the scored Assessment, exits 0, gate passed",
    async () => {
      mode = "scored";
      const run = await hardenAssess(["--min-rrs", String(RRS - 10), "--json"]);
      expect(run.code, run.stderr).toBe(0);
      const report = hardenReport(run);
      expect(report.assessment).toMatchObject({ status: "scored" });
      expect(rrsGate(report)).toEqual({
        result: "passed",
        rrs: RRS,
        threshold: RRS - 10,
        status: "scored",
        reason: null,
        weakest: WEAKEST,
      });
      expect(run.stderr).not.toContain("RRS gate");
      // The score the gate read is the one the API stored.
      const stored = await waitFinished(assessmentId(report));
      expect(stored.rrs).toBe(RRS);
    },
    RUN_TIMEOUT_MS,
  );

  it(
    "harden --min-rrs equal to the score passes (at or above: exit 0)",
    async () => {
      mode = "scored";
      const run = await hardenAssess(["--min-rrs", String(RRS), "--json"]);
      expect(run.code, run.stderr).toBe(0);
      expect(rrsGate(hardenReport(run))).toMatchObject({ result: "passed", rrs: RRS, threshold: RRS });
    },
    RUN_TIMEOUT_MS,
  );

  it(
    "harden --min-rrs above the score exits 5 naming the score, the threshold and the weakest Objectives",
    async () => {
      mode = "scored";
      const json = await hardenAssess(["--min-rrs", String(RRS + 1), "--json"]);
      expect(json.code, json.stderr).toBe(5);
      expect(rrsGate(hardenReport(json))).toEqual({
        result: "failed",
        rrs: RRS,
        threshold: RRS + 1,
        status: "scored",
        reason: null,
        weakest: WEAKEST,
      });
      expect(json.stderr).toContain(`harden: RRS gate failed: ${RRS} is below ${RRS + 1}`);

      // The human output names the same.
      const human = await hardenAssess(["--min-rrs", String(RRS + 1)]);
      expect(human.code, human.stderr).toBe(5);
      expect(human.stdout).toMatch(
        new RegExp(`✗ RRS ${RRS} is below --min-rrs ${RRS + 1} — assessment asm_[0-9a-f]{24} scored \\(T1\\)`),
      );
      expect(human.stdout).toContain("weakest: W2 Secrets (achieved at T1), W1 Map (not achieved)");
      expect(human.stderr).toContain(`harden: RRS gate failed: ${RRS} is below ${RRS + 1}`);
      // Objective names and results only: never evidence.
      for (const result of scoredResults()) {
        expect(json.stdout).not.toContain(result.evidence.summary);
        expect(human.stdout).not.toContain(result.evidence.summary);
      }
    },
    RUN_TIMEOUT_MS * 2,
  );

  it(
    "an inconclusive Assessment exits 6; with --on-no-score pass it exits 0 and the gate is skipped",
    async () => {
      mode = "inconclusive";
      const failed = await hardenAssess(["--min-rrs", "10", "--json"]);
      expect(failed.code, failed.stderr).toBe(6);
      const gateFail = rrsGate(hardenReport(failed));
      expect(gateFail).toMatchObject({ result: "no_score", rrs: null, threshold: 10, status: "inconclusive" });
      expect(gateFail.reason).toEqual(expect.any(String));
      expect(failed.stderr).toContain("harden: RRS gate has no score:");

      const passed = await hardenAssess(["--min-rrs", "10", "--on-no-score", "pass", "--json"]);
      expect(passed.code, passed.stderr).toBe(0);
      expect(rrsGate(hardenReport(passed))).toMatchObject({
        result: "skipped",
        rrs: null,
        threshold: 10,
        status: "inconclusive",
        reason: gateFail.reason,
      });
      expect(passed.stderr).toContain("harden: warning: RRS gate skipped (--on-no-score pass): no score:");
    },
    RUN_TIMEOUT_MS * 2,
  );

  it(
    "queues Assessments without a gate for antireverse gate (scored and inconclusive)",
    async () => {
      for (const m of ["scored", "inconclusive"] as const) {
        mode = m;
        const run = await hardenAssess(["--json"]);
        expect(run.code, run.stderr).toBe(0);
        const report = hardenReport(run);
        expect(report.rrs_gate).toBeUndefined();
        const id = assessmentId(report);
        expect(id).toMatch(/^asm_[0-9a-f]{24}$/);
        expect((await waitFinished(id)).status).toBe(m);
        queued[m] = id;
      }
    },
    RUN_TIMEOUT_MS * 2,
  );

  it(
    "antireverse gate on an earlier scored Assessment: below the score exits 0, above exits 5",
    async () => {
      const id = queued.scored as string;
      expect(id).toBeDefined();

      const pass = await gate(id, ["--min-rrs", String(RRS - 10), "--json"]);
      expect(pass.code, pass.stderr).toBe(0);
      expect(JSON.parse(pass.stdout) as GateReport).toEqual({
        assessment: { id, status: "scored", tier: "T1", rrs: RRS },
        gate: { result: "passed", rrs: RRS, threshold: RRS - 10, status: "scored", reason: null, weakest: WEAKEST },
      });

      const fail = await gate(id, ["--min-rrs", String(RRS + 1), "--json"]);
      expect(fail.code, fail.stderr).toBe(5);
      expect((JSON.parse(fail.stdout) as GateReport).gate).toEqual({
        result: "failed",
        rrs: RRS,
        threshold: RRS + 1,
        status: "scored",
        reason: null,
        weakest: WEAKEST,
      });
      expect(fail.stderr).toContain(`gate: RRS gate failed: ${RRS} is below ${RRS + 1}`);

      const human = await gate(id, ["--min-rrs", String(RRS + 1)]);
      expect(human.code, human.stderr).toBe(5);
      expect(human.stdout).toContain(`✗ RRS ${RRS} is below --min-rrs ${RRS + 1} — assessment ${id} scored (T1)`);
      expect(human.stdout).toContain("weakest: W2 Secrets (achieved at T1), W1 Map (not achieved)");
    },
    RUN_TIMEOUT_MS,
  );

  it(
    "antireverse gate on an earlier inconclusive Assessment exits 6, or 0 skipped with --on-no-score pass",
    async () => {
      const id = queued.inconclusive as string;
      expect(id).toBeDefined();

      const fail = await gate(id, ["--min-rrs", "10", "--json"]);
      expect(fail.code, fail.stderr).toBe(6);
      const failReport = JSON.parse(fail.stdout) as GateReport;
      expect(failReport.assessment).toEqual({ id, status: "inconclusive", tier: "T1", rrs: null });
      expect(failReport.gate).toMatchObject({ result: "no_score", rrs: null, threshold: 10, status: "inconclusive" });
      expect(fail.stderr).toContain("gate: RRS gate has no score:");

      const pass = await gate(id, ["--min-rrs", "10", "--on-no-score", "pass", "--json"]);
      expect(pass.code, pass.stderr).toBe(0);
      expect((JSON.parse(pass.stdout) as GateReport).gate).toMatchObject({
        result: "skipped",
        rrs: null,
        threshold: 10,
        status: "inconclusive",
      });
      expect(pass.stderr).toContain("gate: warning: RRS gate skipped (--on-no-score pass): no score:");
    },
    RUN_TIMEOUT_MS,
  );

  it(
    "a short --wait while the Assessment is held exits 6 (harden and gate)",
    async () => {
      mode = "scored";
      writeFileSync(holdFile, "held");
      try {
        const run = await hardenAssess(["--min-rrs", "10", "--wait", "2", "--json"]);
        expect(run.code, run.stderr).toBe(6);
        const report = hardenReport(run);
        const held = rrsGate(report);
        expect(held).toMatchObject({ result: "no_score", rrs: null, threshold: 10 });
        expect(["queued", "running"]).toContain(held.status);
        expect(held.reason).toContain("the wait of 2 s ended before the Assessment finished");
        expect(run.stderr).toContain("harden: RRS gate has no score: the wait of 2 s ended");

        const id = assessmentId(report);
        const viaGate = await gate(id, ["--min-rrs", "10", "--wait", "1", "--json"]);
        expect(viaGate.code, viaGate.stderr).toBe(6);
        const gateReport = JSON.parse(viaGate.stdout) as GateReport;
        expect(gateReport.gate).toMatchObject({ result: "no_score", rrs: null, threshold: 10 });
        expect(["queued", "running"]).toContain(gateReport.gate.status);
        expect(gateReport.gate.reason).toContain("the wait of 1 s ended before the Assessment finished");

        // Released, the same Assessment finishes and the gate passes.
        rmSync(holdFile, { force: true });
        expect((await waitFinished(id)).status).toBe("scored");
        const after = await gate(id, ["--min-rrs", "10", "--json"]);
        expect(after.code, after.stderr).toBe(0);
        expect((JSON.parse(after.stdout) as GateReport).gate).toMatchObject({ result: "passed", rrs: RRS });
      } finally {
        rmSync(holdFile, { force: true });
      }
    },
    RUN_TIMEOUT_MS,
  );

  it(
    "a held Assessment keeps the CLI polling for the whole --wait before it exits 6",
    async () => {
      // AC: waiting polls "until it finishes or --wait <seconds> runs out". The exit must not come before the wait has
      // run out: with --wait 2 not before 2 s, with --wait 7 not before 7 s.
      mode = "scored";
      writeFileSync(holdFile, "held");
      try {
        const short = await hardenAssess(["--min-rrs", "10", "--wait", "2", "--json"]);
        expect(short.code, short.stderr).toBe(6);
        const id = assessmentId(hardenReport(short));
        const longer = await gate(id, ["--min-rrs", "10", "--wait", "7", "--json"]);
        expect(longer.code, longer.stderr).toBe(6);
        expect({ harden_wait_2_ms: short.ms, gate_wait_7_ms: longer.ms }).toEqual({
          harden_wait_2_ms: expect.toSatisfy((ms: number) => ms >= 2000),
          gate_wait_7_ms: expect.toSatisfy((ms: number) => ms >= 7000),
        });
      } finally {
        rmSync(holdFile, { force: true });
      }
    },
    RUN_TIMEOUT_MS,
  );

  it("never prints the admin key on stdout or stderr", () => {
    expect(runs.length).toBeGreaterThanOrEqual(18);
    expect(adminKey.length).toBeGreaterThan(16);
    for (const run of runs) {
      expect(run.stdout).not.toContain(adminKey);
      expect(run.stderr).not.toContain(adminKey);
    }
  });
});
