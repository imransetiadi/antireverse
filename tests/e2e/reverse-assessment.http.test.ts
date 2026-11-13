// Slice 12a over HTTP/CLI: the real `antireverse harden` CLI hardens a copy of the reference bundle, registers the
// Build with a route inventory (`--routes`) and requests a T1 Reverse Assessment (`--assess T1`) from a real API
// (startApi) whose runner uses the real prove engine with its deterministic stand-in agent. The planted Canaries are
// left reachable (an unprotected build), so the stand-in recovers one: W2 achieved, naming the Canary by id; W1 judged
// against the inventory the agent never sees; W5 refused by the replica Shield; W3/W4 not attempted; the Assessment
// inconclusive (`excluded_over_limit`) with the stand-in's scope. No API response carries a Canary value. Then: an
// Assessment without files reassesses the kept artifact (409 when none is kept), a Shield key gets 403, another
// Organization 404, and a file whose SHA-256 differs from the Manifest's 400.
import { execFile } from "node:child_process";
import { cpSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative, sep } from "node:path";
import { fileURLToPath } from "node:url";
import { type RunningApi, startApi } from "@antireverse/api";
import {
  type Assessment,
  AssessmentResponseSchema,
  type Canary,
  CreateAppResponseSchema,
  CreateAssessmentResponseSchema,
  CreateOrganizationResponseSchema,
  EXAMPLE_ROUTE_INVENTORY,
  ListAssessmentsResponseSchema,
  ProblemSchema,
  STAND_IN_MODEL,
} from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

/** A T1 run of the stand-in on the small reference bundle takes seconds; the tier's own limit is 15 minutes. */
const FINISH_BUDGET_MS = 60_000;
const SEED = 1;
const VERSION = "12.0.0";

const root = fileURLToPath(new URL("../..", import.meta.url));
const webDir = join(root, "apps/range/web");
const cliPath = join(root, "packages/harden/src/cli.ts");
const tsxCli = join(root, "node_modules/tsx/dist/cli.mjs");
const KEY_ENV = "AR_E2E_ADMIN_KEY";
const EQUIV_COMMAND = "node --experimental-strip-types check.ts";

interface CliRun {
  code: number;
  stdout: string;
  stderr: string;
}

interface HardenReport {
  equivalence: string;
  canaries: Canary[];
  registered?: { build_id: string };
  routes: { count: number } | null;
  assessment?: { id: string; status: string } | { error: string };
}

let api: RunningApi;
let adminKey: string;
let shieldKey: string;
let otherKey: string;
let appId: string;
let bundleDir: string;
let workDir: string;
let outDir: string;
let report: HardenReport;
let buildId: string;
let assessmentId: string;
let finished: Assessment;
let canaries: Canary[] = [];
/** The protected files exactly as uploaded (the Manifest's artifacts), by path. */
let protectedFiles: Record<string, string> = {};
const temps: string[] = [];
/** Every API response body this test read, to prove no Canary value is ever in one. */
const bodies: string[] = [];

function tempDir(prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  temps.push(dir);
  return dir;
}

/** One API call; its body is recorded. */
async function call(
  path: string,
  init: { method?: string; key?: string; body?: unknown } = {},
): Promise<{ status: number; json: unknown }> {
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
  return { status: response.status, json: text.length > 0 ? JSON.parse(text) : null };
}

/** Runs the real CLI binary (`antireverse harden …`) in its own process, with `cwd` as the working directory. */
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

/** Polls `GET /v1/assessments/:id` until the Assessment has finished (scored, inconclusive or failed). */
async function waitFinished(id: string): Promise<Assessment> {
  const started = Date.now();
  for (;;) {
    const { status, json } = await call(`/v1/assessments/${id}`, { key: adminKey });
    expect(status).toBe(200);
    const { assessment } = AssessmentResponseSchema.parse(json);
    if (assessment.status !== "queued" && assessment.status !== "running") return assessment;
    if (Date.now() - started > FINISH_BUDGET_MS) throw new Error(`${id}: not finished within ${FINISH_BUDGET_MS} ms`);
    await new Promise((resolve) => setTimeout(resolve, 100));
  }
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

const base64 = (text: string) => Buffer.from(text, "utf8").toString("base64");

beforeAll(async () => {
  api = await startApi({ logger: { info() {}, warn() {} } });
  const organization = CreateOrganizationResponseSchema.parse(
    (await call("/v1/organizations", { method: "POST", body: { name: "Acme" } })).json,
  );
  adminKey = organization.admin_key.key;
  const created = CreateAppResponseSchema.parse(
    (await call("/v1/apps", { method: "POST", key: adminKey, body: { name: "shop-web" } })).json,
  );
  appId = created.app.id;
  shieldKey = created.shield_key.key;
  const other = CreateOrganizationResponseSchema.parse(
    (await call("/v1/organizations", { method: "POST", body: { name: "Other" } })).json,
  );
  otherKey = other.admin_key.key;

  // A copy of the reference bundle (never hardened in place) and a CI working directory with the route inventory.
  bundleDir = join(tempDir("antireverse-e2e-asm-bundle-"), "web");
  cpSync(webDir, bundleDir, { recursive: true });
  workDir = tempDir("antireverse-e2e-asm-ci-");
  outDir = join(tempDir("antireverse-e2e-asm-out-"), "protected");
  writeFileSync(join(workDir, "routes.json"), JSON.stringify(EXAMPLE_ROUTE_INVENTORY));
}, 30_000);

afterAll(async () => {
  await api?.close();
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
});

describe("slice 12a Reverse Assessment over HTTP/CLI", () => {
  it("hardens, registers with a route inventory and requests a T1 Assessment through the real CLI", async () => {
    const run = await harden(
      [
        bundleDir,
        "--profile",
        "balanced",
        "--seed",
        String(SEED),
        "--out",
        outDir,
        "--test",
        EQUIV_COMMAND,
        "--routes",
        "routes.json",
        "--assess",
        "T1",
        "--json",
        ...registerArgs(VERSION),
      ],
      workDir,
    );
    expect(run.code, run.stderr).toBe(0);
    report = JSON.parse(run.stdout) as HardenReport;
    expect(report.equivalence).toBe("passed");
    expect(report.routes).toEqual({ count: EXAMPLE_ROUTE_INVENTORY.length });
    buildId = report.registered?.build_id ?? "";
    expect(buildId).toMatch(/^bld_[0-9a-f]{24}$/);
    expect(report.assessment).toMatchObject({ status: "queued" });
    assessmentId = (report.assessment as { id: string }).id;
    expect(assessmentId).toMatch(/^asm_[0-9a-f]{24}$/);

    // The planted Canaries are left reachable: the decoy key is in the protected output as a plain literal.
    canaries = report.canaries;
    expect(canaries).toHaveLength(3);
    protectedFiles = readTree(outDir);
    const key = canaries.find((canary) => canary.kind === "key") as Canary;
    expect(Object.values(protectedFiles).some((code) => code.includes(key.value))).toBe(true);
    // The route inventory never reaches the output or the report beyond its count.
    for (const route of EXAMPLE_ROUTE_INVENTORY) {
      expect(run.stdout).not.toContain(route);
      for (const code of Object.values(protectedFiles)) expect(code).not.toContain(route);
    }
    expect(run.stdout).not.toContain(adminKey);
    expect(run.stderr).not.toContain(adminKey);
  }, 90_000);

  it(
    "finishes inconclusive: W2 achieved on a Canary, W1 judged, W5 refused, W3/W4 not attempted, stand-in scope",
    async () => {
      finished = await waitFinished(assessmentId);
      expect(finished).toMatchObject({
        id: assessmentId,
        build_id: buildId,
        app_id: appId,
        tier: "T1",
        status: "inconclusive",
        rrs: null,
        inconclusive_code: "excluded_over_limit",
        renormalised: false,
        failure_reason: null,
      });
      expect(finished.inconclusive_reason).toBeTruthy();
      expect(finished.artifact_kept_until).not.toBeNull();
      expect(finished.scope).toMatchObject({ model: STAND_IN_MODEL, tier: "T1" });
      expect(finished.scope.agent.name).toBe("stand-in");
      expect(finished.results.map((result) => result.objective)).toEqual(["W1", "W2", "W3", "W4", "W5"]);
      const byId = Object.fromEntries(finished.results.map((result) => [result.objective, result]));

      // W2: achieved within T1 limits, the evidence names the decoy key's Canary by id.
      const key = canaries.find((canary) => canary.kind === "key") as Canary;
      const w2 = byId.W2;
      expect(w2?.result).toBe("achieved");
      if (w2?.result !== "achieved") throw new Error("W2 not achieved");
      expect(w2.tier).toBe("T1");
      expect(w2.evidence.recovered).toContainEqual({ kind: "canary", canary_id: key.id });
      for (const item of w2.evidence.recovered) {
        if (item.kind === "canary") expect(canaries.map((canary) => canary.id)).toContain(item.canary_id);
      }

      // W1: judged against the inventory (achieved or not, never "not attempted").
      const w1 = byId.W1;
      expect(["achieved", "not_achieved"]).toContain(w1?.result);
      const routes = w1?.evidence.recovered.find((item) => item.kind === "routes");
      expect(routes).toMatchObject({ kind: "routes", inventory: EXAMPLE_ROUTE_INVENTORY.length });

      // W5: the replica Shield refused the unsigned request.
      const w5 = byId.W5;
      expect(w5?.result).toBe("not_achieved");
      const replay = w5?.evidence.recovered.find((item) => item.kind === "replay");
      expect(replay?.kind).toBe("replay");
      if (replay?.kind !== "replay") throw new Error("no replay evidence");
      expect(replay.status).toBeGreaterThanOrEqual(400);
      expect(replay.status).toBeLessThan(500);

      // W3 and W4: not attempted (no verifier in 12a).
      expect(byId.W3).toMatchObject({ result: "not_attempted", reason: "not_supported" });
      expect(byId.W4).toMatchObject({ result: "not_attempted", reason: "not_supported" });

      // The Build's list shows it, newest first.
      const listed = await call(`/v1/apps/${appId}/builds/${buildId}/assessments`, { key: adminKey });
      expect(listed.status).toBe(200);
      const { assessments } = ListAssessmentsResponseSchema.parse(listed.json);
      expect(assessments.map((assessment) => assessment.id)).toEqual([assessmentId]);
      expect(assessments[0]?.status).toBe("inconclusive");
    },
    FINISH_BUDGET_MS + 10_000,
  );

  it(
    "reassesses the kept artifact when the request carries no files",
    async () => {
      const created = await call(`/v1/apps/${appId}/builds/${buildId}/assessments`, {
        method: "POST",
        key: adminKey,
        body: { tier: "T1" },
      });
      expect(created.status).toBe(202);
      const { assessment } = CreateAssessmentResponseSchema.parse(created.json);
      expect(assessment).toMatchObject({ build_id: buildId, tier: "T1", status: "queued", results: [] });
      expect(assessment.id).not.toBe(assessmentId);

      // The stand-in is deterministic: the same kept bundle gives the same verdicts.
      const again = await waitFinished(assessment.id);
      expect(again.status).toBe("inconclusive");
      expect(again.results.map((result) => [result.objective, result.result])).toEqual(
        finished.results.map((result) => [result.objective, result.result]),
      );
      const key = canaries.find((canary) => canary.kind === "key") as Canary;
      expect(again.results.find((result) => result.objective === "W2")?.evidence.recovered).toContainEqual({
        kind: "canary",
        canary_id: key.id,
      });

      const listed = ListAssessmentsResponseSchema.parse(
        (await call(`/v1/apps/${appId}/builds/${buildId}/assessments`, { key: adminKey })).json,
      );
      expect(listed.assessments.map((one) => one.id)).toEqual([assessment.id, assessmentId]);
    },
    FINISH_BUDGET_MS + 10_000,
  );

  it("answers 409 artifact-required without files for a Build that has no kept artifact", async () => {
    const run = await harden(
      [bundleDir, "--profile", "balanced", "--seed", "2", "--json", ...registerArgs("12.0.1")],
      tempDir("antireverse-e2e-asm-ci2-"),
    );
    expect(run.code, run.stderr).toBe(0);
    const bare = (JSON.parse(run.stdout) as HardenReport).registered?.build_id ?? "";
    expect(bare).toMatch(/^bld_[0-9a-f]{24}$/);
    const response = await call(`/v1/apps/${appId}/builds/${bare}/assessments`, {
      method: "POST",
      key: adminKey,
      body: { tier: "T1" },
    });
    expect(response.status).toBe(409);
    expect(ProblemSchema.parse(response.json).reason).toBe("artifact-required");
  }, 60_000);

  it("refuses a Shield key with 403", async () => {
    const paths = [`/v1/apps/${appId}/builds/${buildId}/assessments`, `/v1/assessments/${assessmentId}`];
    for (const path of paths) {
      const response = await call(path, { key: shieldKey });
      expect(response.status, path).toBe(403);
      ProblemSchema.parse(response.json);
    }
    const created = await call(paths[0] as string, { method: "POST", key: shieldKey, body: { tier: "T1" } });
    expect(created.status).toBe(403);
  });

  it("keeps Assessments away from another Organization: 404", async () => {
    const paths = [`/v1/apps/${appId}/builds/${buildId}/assessments`, `/v1/assessments/${assessmentId}`];
    for (const path of paths) {
      const response = await call(path, { key: otherKey });
      expect(response.status, path).toBe(404);
      ProblemSchema.parse(response.json);
    }
    const files = Object.entries(protectedFiles).map(([path, code]) => ({ path, base64: base64(code) }));
    for (const body of [{ tier: "T1" }, { tier: "T1", files }]) {
      const response = await call(paths[0] as string, { method: "POST", key: otherKey, body });
      expect(response.status).toBe(404);
    }
    // Nothing was queued for the Build by those requests.
    const listed = ListAssessmentsResponseSchema.parse((await call(paths[0] as string, { key: adminKey })).json);
    expect(listed.assessments).toHaveLength(2);
  });

  it(
    "refuses a file whose SHA-256 does not match the Manifest's with 400 (Proof of Ownership)",
    async () => {
      const entries = Object.entries(protectedFiles);
      expect(entries.length).toBeGreaterThan(0);
      const tampered = entries.map(([path, code], index) => ({
        path,
        base64: base64(index === 0 ? `${code}\n// changed` : code),
      }));
      const response = await call(`/v1/apps/${appId}/builds/${buildId}/assessments`, {
        method: "POST",
        key: adminKey,
        body: { tier: "T1", files: tampered },
      });
      expect(response.status).toBe(400);
      const problem = ProblemSchema.parse(response.json);
      expect(problem.errors).toContainEqual(expect.objectContaining({ path: "files.0.base64" }));

      // The untampered files are accepted (the same request otherwise), so the 400 was the hash alone.
      const exact = entries.map(([path, code]) => ({ path, base64: base64(code) }));
      const accepted = await call(`/v1/apps/${appId}/builds/${buildId}/assessments`, {
        method: "POST",
        key: adminKey,
        body: { tier: "T1", files: exact },
      });
      expect(accepted.status).toBe(202);
      await waitFinished(CreateAssessmentResponseSchema.parse(accepted.json).assessment.id);
    },
    FINISH_BUDGET_MS + 10_000,
  );

  it("never returns a Canary value in any response body", () => {
    expect(bodies.length).toBeGreaterThan(10);
    expect(canaries).toHaveLength(3);
    for (const canary of canaries) {
      for (const body of bodies) expect(body).not.toContain(canary.value);
    }
  });
});
