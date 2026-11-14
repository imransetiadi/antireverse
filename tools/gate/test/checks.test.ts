// Slice 18e: each check turns its child process's exit code and output into pass / fail / not-checkable with evidence.
// The child process is faked: these tests read what a real run prints.
import { writeFileSync } from "node:fs";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { type CheckContext, createExecutors } from "../src/checks.ts";
import { MATRICES, selectMatrixFiles } from "../src/matrix.ts";
import { MIN_BENCH_SAMPLES } from "../src/parsers.ts";
import { REPO_ROOT } from "../src/paths.ts";
import type { RunOptions, RunResult } from "../src/run.ts";

function context(reply: (options: RunOptions) => Partial<RunResult>) {
  const calls: RunOptions[] = [];
  const ctx: CheckContext = {
    root: REPO_ROOT,
    async run(options) {
      calls.push(options);
      return { exitCode: 0, signal: null, timedOut: false, durationMs: 1234, output: "", ...reply(options) };
    },
  };
  return { ctx, calls };
}

const VITEST_OK = " Test Files  10 passed (10)\n      Tests  120 passed (120)\n";
const VITEST_FAIL = " Test Files  1 failed | 9 passed (10)\n      Tests  2 failed | 118 passed (120)\n";

describe("verify", () => {
  it("passes on exit 0 with a vitest summary, recording the counts and the command", async () => {
    const { ctx, calls } = context(() => ({ output: `biome ok\ntsc ok\n${VITEST_OK}` }));
    const out = await createExecutors(ctx).verify();
    expect(calls[0]).toMatchObject({ command: "npm", args: ["run", "verify"], cwd: REPO_ROOT });
    expect(calls[0]?.timeoutMs).toBeGreaterThanOrEqual(10 * 60_000);
    expect(out).toMatchObject({ state: "pass", command: "npm run verify", durationMs: 1234 });
    expect(out.measurements).toMatchObject({ tests_passed: 120, tests_failed: 0, files: 10 });
  });

  it("fails on a non-zero exit, on a timeout, and on exit 0 without a summary", async () => {
    expect((await createExecutors(context(() => ({ exitCode: 1, output: VITEST_FAIL })).ctx).verify()).state).toBe(
      "fail",
    );
    const timedOut = await createExecutors(context(() => ({ exitCode: null, timedOut: true })).ctx).verify();
    expect(timedOut).toMatchObject({ state: "fail", summary: expect.stringMatching(/timed out/) });
    expect((await createExecutors(context(() => ({ output: "lint only" })).ctx).verify()).state).toBe("fail");
  });

  it("keeps a trimmed excerpt of the output", async () => {
    const long = `${Array.from({ length: 500 }, (_, i) => `line ${i}`).join("\n")}\n${VITEST_OK}`;
    const out = await createExecutors(context(() => ({ output: long })).ctx).verify();
    expect(out.excerpt?.split("\n").length).toBeLessThanOrEqual(41);
    expect(out.excerpt).toContain("Tests  120 passed (120)");
  });
});

describe("e2e-browser", () => {
  it("runs the Playwright suite through its own config and passes when all passed", async () => {
    const { ctx, calls } = context(() => ({ output: "  25 passed (3.1m)\n" }));
    const out = await createExecutors(ctx)["e2e-browser"]();
    expect(calls[0]).toMatchObject({ command: "npm", args: ["run", "e2e"] });
    expect(out).toMatchObject({ state: "pass", measurements: { passed: 25, failed: 0 } });
  });

  it("fails on a failed or flaky test, or no summary", async () => {
    const run = async (output: string, exitCode = 1) =>
      (await createExecutors(context(() => ({ output, exitCode })).ctx)["e2e-browser"]()).state;
    expect(await run("  1 failed\n  24 passed (3m)\n")).toBe("fail");
    expect(await run("  1 flaky\n  24 passed (3m)\n", 0)).toBe("fail");
    expect(await run("Error: browser missing")).toBe("fail");
  });
});

describe("matrices", () => {
  it("runs the selected files whole, by project, and passes when all their tests pass", async () => {
    // The JSON reporter's file, as vitest writes it: every matching name of every selected file ran and passed.
    const { ctx, calls } = context((options) => {
      const arg = options.args.find((a) => a.startsWith("--outputFile.json="));
      const spec = MATRICES.find((m) => m.id === "matrix-tenant") as (typeof MATRICES)[number];
      const testResults = selectMatrixFiles(spec, REPO_ROOT).map((f) => ({
        name: join(REPO_ROOT, f.file),
        assertionResults: f.names.map((title) => ({ title, ancestorTitles: [], status: "passed" })),
      }));
      if (arg) writeFileSync(arg.slice("--outputFile.json=".length), JSON.stringify({ testResults }));
      return { output: VITEST_OK };
    });
    const out = await createExecutors(ctx)["matrix-tenant"]();
    const args = calls[0]?.args ?? [];
    expect(calls[0]?.command).toBe(process.execPath);
    expect(args.join(" ")).toMatch(/vitest\.mjs run/);
    expect(args).toContain("--project");
    expect(args).not.toContain("-t");
    expect(args.some((a) => a.startsWith("apps/api/test/"))).toBe(true);
    expect(out.state).toBe("pass");
    expect(out.measurements).toMatchObject({ tests_passed: 120 });
    expect(Number(out.measurements?.matching_test_names)).toBeGreaterThan(0);
  });

  it("fails when a test fails or nothing ran", async () => {
    expect(
      (await createExecutors(context(() => ({ exitCode: 1, output: VITEST_FAIL })).ctx)["matrix-authz"]()).state,
    ).toBe("fail");
    const none = " Test Files  0 passed (0)\n      Tests  0 passed (0)\n";
    expect((await createExecutors(context(() => ({ output: none })).ctx)["matrix-privacy"]()).state).toBe("fail");
  });
});

describe("bench-shield", () => {
  // As many scenarios as the real bench measures per budget (MIN_BENCH_SAMPLES).
  const lines = (n: number, p99: string) =>
    Array.from({ length: n }, (_, i) => `  GET /s${i}\n    p50 3.21 µs   p99 ${p99} µs   mean 3 µs   max 9 µs`).join(
      "\n",
    );
  const bench = (p99: string) =>
    `Built-in Policy (no Rules)\n${lines(MIN_BENCH_SAMPLES["PB-02"], p99)}\nAttested (budget PB-01: p99 <= 1500 µs)\n${lines(MIN_BENCH_SAMPLES["PB-01"], "70.00")}\n`;

  it("passes within PB-01 and PB-02, with the worst numbers", async () => {
    const { ctx, calls } = context(() => ({ output: bench("10.00") }));
    const out = await createExecutors(ctx)["bench-shield"]();
    expect(calls[0]).toMatchObject({ command: "npm", args: ["run", "bench"] });
    expect(out.state).toBe("pass");
    expect(out.measurements).toMatchObject({ "PB-02 p99 µs": 10, "PB-01 p99 µs": 70 });
  });

  it("fails on a breach and on a non-zero exit", async () => {
    expect((await createExecutors(context(() => ({ output: bench("600.00") })).ctx)["bench-shield"]()).state).toBe(
      "fail",
    );
    expect(
      (await createExecutors(context(() => ({ output: bench("10.00"), exitCode: 1 })).ctx)["bench-shield"]()).state,
    ).toBe("fail");
  });
});

describe("rrs-stand-in and load-smoke read their child's GATE-RESULT line", () => {
  it("rrs-stand-in: runs its child script and judges the gates", async () => {
    const result = {
      variants: [
        {
          profile: "balanced",
          threshold: 70,
          exitCode: 5,
          gate: { result: "failed", rrs: 40, threshold: 70, status: "scored", reason: null, weakest: [] },
        },
      ],
    };
    const { ctx, calls } = context(() => ({ output: `GATE-RESULT ${JSON.stringify(result)}\n` }));
    const out = await createExecutors(ctx)["rrs-stand-in"]();
    expect(calls[0]?.args.join(" ")).toMatch(/rrs-run\.ts/);
    expect(out).toMatchObject({ state: "fail", measurements: { "balanced RRS": 40 } });
  });

  it("load-smoke: judges the latencies its child measured", async () => {
    const series = { "control-read": [2], "control-write": [3], ingest: [4], attest: [5] };
    const { ctx, calls } = context(() => ({ output: `GATE-RESULT ${JSON.stringify({ series, errors: [] })}\n` }));
    const out = await createExecutors(ctx)["load-smoke"]();
    expect(calls[0]?.args.join(" ")).toMatch(/load-smoke\.ts/);
    expect(calls[0]?.timeoutMs).toBeLessThanOrEqual(120_000);
    expect(out.state).toBe("pass");
    expect(out.measurements).toMatchObject({ "PB-21 control-read p95 ms": 2, "SLO-01 attest p99 ms": 5 });
  });

  it("a child without a result line fails", async () => {
    expect((await createExecutors(context(() => ({ output: "crash", exitCode: 1 })).ctx)["load-smoke"]()).state).toBe(
      "fail",
    );
  });
});

describe("npm-audit", () => {
  it("fails on a high or critical vulnerability, passes on none", async () => {
    const audit = (high: number) =>
      JSON.stringify({ metadata: { vulnerabilities: { low: 1, moderate: 0, high, critical: 0, total: 1 + high } } });
    const { ctx, calls } = context(() => ({ output: audit(0), exitCode: 1 }));
    expect((await createExecutors(ctx)["npm-audit"]()).state).toBe("pass");
    expect(calls[0]).toMatchObject({ command: "npm", args: ["audit", "--json"] });
    expect((await createExecutors(context(() => ({ output: audit(2), exitCode: 1 })).ctx)["npm-audit"]()).state).toBe(
      "fail",
    );
    expect((await createExecutors(context(() => ({ output: "offline" })).ctx)["npm-audit"]()).state).toBe("fail");
  });
});
