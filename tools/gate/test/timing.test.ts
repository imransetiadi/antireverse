// D-147 to D-149 (slice 23b): a test whose time bound measures CPU work, a ratio of two timings, or the start of a
// process is not run beside four hundred other files — the full run made Guard's 25 ms budget read 25.6 ms twice and
// blocked a release gate with unchanged code. The files that hold such tests are listed once (vitest.timing.ts) and
// run whole, one at a time, after everything else. These tests keep every counter of tests on that one list, and
// one of them proves the order with a real run.
import { execFile } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import rootConfig from "../../../vitest.config.ts";
import { TIMING_FILES, TIMING_SUFFIX, timingFilesOf, timingProjectOf } from "../../../vitest.timing.ts";
import { MATRICES, PROJECT_DIRS, selectMatrixFiles } from "../src/matrix.ts";
import { REPO_ROOT } from "../src/paths.ts";

interface Project {
  test: {
    name: string;
    root: string;
    environment?: string;
    include?: string[];
    exclude?: string[];
    fileParallelism?: boolean;
    testTimeout?: number;
    sequence?: { groupOrder?: number };
  };
}
const projects = (rootConfig as unknown as { test: { projects: Project[] } }).test.projects.map((p) => p.test);
const project = (name: string) => projects.find((p) => p.name === name);
const timed = [...new Set(TIMING_FILES.map((entry) => entry.project))];

describe("the list of files that run late", () => {
  it("names real test files, each with a clock in it and a reason, once", () => {
    expect(TIMING_FILES.length).toBeGreaterThanOrEqual(13);
    expect(new Set(TIMING_FILES.map((entry) => entry.file)).size).toBe(TIMING_FILES.length);
    for (const entry of TIMING_FILES) {
      expect(existsSync(join(REPO_ROOT, entry.file)), entry.file).toBe(true);
      expect(readFileSync(join(REPO_ROOT, entry.file), "utf8"), entry.file).toMatch(
        /performance\.now\(\)|Date\.now\(\)/,
      );
      expect(entry.why.length, entry.file).toBeGreaterThan(40);
      expect(["cpu", "ratio", "start-up"]).toContain(entry.kind);
      expect(entry.file.startsWith(`${project(entry.project)?.root.replace(/^\.\//, "")}/test/`), entry.file).toBe(
        true,
      );
    }
    // The two that failed, and the rest of what the measurement found.
    for (const file of [
      "packages/guard/test/integrity.test.ts",
      "packages/harden/test/leaks.test.ts",
      "packages/shield-node/test/decide.test.ts",
      "packages/shield-node/test/shield.test.ts",
      "packages/shield-node/test/patches-differential.test.ts",
      "apps/api/test/campaign-review-redact.test.ts",
      "apps/api/test/campaign-review2-redact.test.ts",
      "packages/prove/test/sandbox.test.ts",
      "packages/prove/test/assess-worker.test.ts",
      "packages/prove/test/logic.test.ts",
      "packages/prove/test/tamper.test.ts",
      "packages/prove/test/stand-in.test.ts",
      "apps/api/test/integrity-review.test.ts",
    ]) {
      expect(
        TIMING_FILES.map((entry) => entry.file),
        file,
      ).toContain(file);
    }
  });
});

describe("the root configuration", () => {
  it("every ordinary project leaves its late files out, and a project of its own runs exactly those", () => {
    for (const name of timed) {
      const ordinary = project(name);
      const late = project(timingProjectOf(name));
      const files = timingFilesOf(name);
      expect(files.length, name).toBeGreaterThan(0);
      expect(ordinary?.exclude, name).toEqual(files);
      expect(late, name).toBeDefined();
      expect(late?.include, name).toEqual(files);
      expect(late?.root, name).toBe(ordinary?.root);
      expect(late?.environment, name).toBe(ordinary?.environment);
      expect(late?.testTimeout, name).toBe(ordinary?.testTimeout);
      expect(late?.exclude, name).toBeUndefined();
    }
    // A project without late files has no late twin and no exclusion.
    for (const p of projects) {
      if (p.name.endsWith(TIMING_SUFFIX)) expect(timed, p.name).toContain(p.name.slice(0, -TIMING_SUFFIX.length));
      else if (!timed.includes(p.name)) expect(p.exclude, p.name).toBeUndefined();
    }
  });

  it("the late projects run one file at a time, each in a group of its own after everything else", () => {
    const orders = timed.map((name) => project(timingProjectOf(name))?.sequence?.groupOrder);
    for (const order of orders) expect(order).toBeGreaterThanOrEqual(1);
    expect(new Set(orders).size).toBe(orders.length);
    for (const name of timed) expect(project(timingProjectOf(name))?.fileParallelism, name).toBe(false);
    for (const p of projects) {
      if (!p.name.endsWith(TIMING_SUFFIX)) {
        expect(p.sequence?.groupOrder ?? 0, p.name).toBe(0);
        expect(p.fileParallelism, p.name).toBeUndefined();
      }
    }
  });
});

describe("the gate's matrices", () => {
  it("know the late project of a file they select, so the file is run where it lives", () => {
    const safety = selectMatrixFiles(
      MATRICES.find((m) => m.id === "campaign-safety") as (typeof MATRICES)[number],
      REPO_ROOT,
    );
    const byFile = new Map(safety.map((entry) => [entry.file, entry.project]));
    expect(byFile.get("apps/api/test/campaign-review-redact.test.ts")).toBe("api-timing");
    expect(byFile.get("apps/api/test/campaign-review2-redact.test.ts")).toBe("api-timing");
    expect(byFile.get("apps/api/test/campaign-gate.test.ts")).toBe("api");
    // Whatever a matrix selects, its project is the one whose configuration includes the file.
    for (const matrix of MATRICES) {
      for (const entry of selectMatrixFiles(matrix, REPO_ROOT)) {
        const late = TIMING_FILES.some((t) => t.file === entry.file);
        expect(entry.project.endsWith(TIMING_SUFFIX), `${matrix.id} ${entry.file}`).toBe(late);
      }
    }
    for (const name of Object.keys(PROJECT_DIRS)) expect(project(name), name).toBeDefined();
  });
});

describe("a real run", () => {
  const dir = mkdtempSync(join(tmpdir(), "airverse-gate-timing-"));
  afterAll(() => rmSync(dir, { recursive: true, force: true }));

  it("runs the late files after every other file of the run, one at a time, and no file twice or not at all", async () => {
    const json = join(dir, "run.json");
    // Guard's ordinary files and three projects' late files: enough to see the groups, small enough to run beside
    // everything else. Only the order is judged here. Whether the late tests pass is theirs to say in the run proper:
    // this child runs while the rest of the suite is busy, which is exactly what they are kept away from.
    const names = ["guard", ...["guard", "harden", "prove"].map((name) => timingProjectOf(name))];
    const env: NodeJS.ProcessEnv = {};
    for (const [key, value] of Object.entries(process.env)) if (!/^(VITEST|NODE_OPTIONS$)/.test(key)) env[key] = value;
    await new Promise<void>((done) => {
      execFile(
        process.execPath,
        [
          join(REPO_ROOT, "node_modules/vitest/vitest.mjs"),
          "run",
          ...names.flatMap((n) => ["--project", n]),
          "--reporter=json",
          `--outputFile=${json}`,
        ],
        { cwd: REPO_ROOT, env, maxBuffer: 64 * 1024 * 1024 },
        () => done(),
      );
    });
    const report = JSON.parse(readFileSync(json, "utf8")) as {
      numFailedTests: number;
      numPendingTests: number;
      testResults: Array<{ name: string; startTime: number; endTime: number; assertionResults: unknown[] }>;
    };
    expect(report.numPendingTests).toBe(0);
    const rel = (name: string) => name.slice(REPO_ROOT.length + 1);
    const late = report.testResults.filter((file) => TIMING_FILES.some((t) => t.file === rel(file.name)));
    const early = report.testResults.filter((file) => !late.includes(file));
    expect(late.map((file) => rel(file.name)).sort()).toEqual(
      TIMING_FILES.filter((t) => ["guard", "harden", "prove"].includes(t.project))
        .map((t) => t.file)
        .sort(),
    );
    expect(early.length).toBeGreaterThanOrEqual(5);
    for (const file of early) expect(rel(file.name).startsWith("packages/guard/test/"), file.name).toBe(true);
    // Each file once.
    expect(new Set(report.testResults.map((file) => file.name)).size).toBe(report.testResults.length);
    for (const file of report.testResults) expect(file.assertionResults.length, file.name).toBeGreaterThan(0);
    // Nothing else is running when a late file starts, and the late files do not overlap.
    const lastEarlyEnd = Math.max(...early.map((file) => file.endTime));
    for (const file of late) expect(file.startTime, rel(file.name)).toBeGreaterThanOrEqual(lastEarlyEnd);
    const inOrder = [...late].sort((a, b) => a.startTime - b.startTime);
    for (let i = 1; i < inOrder.length; i++) {
      expect((inOrder[i] as (typeof inOrder)[number]).startTime).toBeGreaterThanOrEqual(
        (inOrder[i - 1] as (typeof inOrder)[number]).endTime,
      );
    }
  }, 240_000);
});
