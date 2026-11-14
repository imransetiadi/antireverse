// Slice 18e: parsing each check's output, and the budgets read from PERFORMANCE.md §2.
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { budgetTargets, performanceBudgets } from "../src/docs.ts";
import {
  judgeBench,
  judgeRrs,
  parseBench,
  parseNpmAudit,
  parsePlaywrightSummary,
  parseResultLine,
  parseVitestSummary,
  stripAnsi,
} from "../src/parsers.ts";
import { REPO_ROOT } from "../src/paths.ts";

const PERFORMANCE = readFileSync(`${REPO_ROOT}/PERFORMANCE.md`, "utf8");

describe("PERFORMANCE §2 budgets", () => {
  it("reads PB-01, PB-02 and PB-21 with their targets in milliseconds", () => {
    const budgets = performanceBudgets(PERFORMANCE);
    expect(budgets.get("PB-01")?.targets).toEqual([
      { variant: "all", percentile: 50, ms: 0.5 },
      { variant: "all", percentile: 99, ms: 1.5 },
    ]);
    expect(budgets.get("PB-02")?.targets).toEqual([
      { variant: "all", percentile: 50, ms: 0.1 },
      { variant: "all", percentile: 99, ms: 0.5 },
    ]);
    expect(budgets.get("PB-21")?.targets).toEqual([
      { variant: "read", percentile: 95, ms: 200 },
      { variant: "write", percentile: 95, ms: 500 },
    ]);
    expect(budgets.size).toBe(22);
  });

  it("parses seconds and refuses a target it cannot read", () => {
    expect(budgetTargets("p95 ≤ 5 s · p99 ≤ 30 s")).toEqual([
      { variant: "all", percentile: 95, ms: 5_000 },
      { variant: "all", percentile: 99, ms: 30_000 },
    ]);
    expect(budgetTargets("≤ 40 MB resident memory")).toEqual([]);
  });
});

describe("vitest summary", () => {
  it("reads files and tests, with ANSI colours", () => {
    const text =
      "\u001b[2m Test Files \u001b[22m \u001b[1m\u001b[32m3 passed\u001b[39m\u001b[22m | 35 skipped (38)\n      Tests  4 passed | 2045 skipped (2049)\n   Duration  1.16s";
    expect(parseVitestSummary(text)).toEqual({
      files: { passed: 3, failed: 0, skipped: 35, total: 38 },
      tests: { passed: 4, failed: 0, skipped: 2045, todo: 0, total: 2049 },
    });
  });

  it("reads failures, and the last summary of a run that prints several", () => {
    const text = [
      " Test Files  1 passed (1)",
      "      Tests  1 passed (1)",
      " Test Files  6 failed | 33 passed | 48 skipped (87)",
      "      Tests  7 failed | 61 passed | 1502 skipped | 2 todo (1572)",
    ].join("\n");
    expect(parseVitestSummary(text)).toEqual({
      files: { passed: 33, failed: 6, skipped: 48, total: 87 },
      tests: { passed: 61, failed: 7, skipped: 1502, todo: 2, total: 1572 },
    });
  });

  it("is null without a summary", () => {
    expect(parseVitestSummary("Error: no test files found")).toBeNull();
  });

  it("strips ANSI sequences", () => {
    expect(stripAnsi("\u001b[31mred\u001b[39m")).toBe("red");
  });
});

describe("Playwright summary", () => {
  it("reads passed, failed, flaky, skipped and did-not-run counts", () => {
    const text = [
      "  ✓  17 [chromium] › journey.e2e.ts:10:1 › x (3.2s)",
      "",
      "  1 failed",
      "    [chromium] › audit.e2e.ts:5:1 › audit",
      "  2 flaky",
      "  1 skipped",
      "  3 did not run",
      "  30 passed (2.4m)",
    ].join("\n");
    expect(parsePlaywrightSummary(text)).toEqual({
      passed: 30,
      failed: 1,
      flaky: 2,
      skipped: 1,
      didNotRun: 3,
      interrupted: 0,
      duration: "2.4m",
    });
  });

  it("is null without a summary", () => {
    expect(parsePlaywrightSummary("Error: browserType.launch: Executable doesn't exist")).toBeNull();
  });
});

const BENCH = `Shield overhead per request: 200,000 direct middleware calls per scenario
node v22.12.0, budget PB-02: p99 <= 500 µs

Built-in Policy (no Rules)
  GET /api/products/:id (route on the application)
    p50 3.21 µs   p99 10.33 µs   mean 3.65 µs   max 2853.38 µs
  Events: 735,001 handed to the transport, 144,999 dropped by the full buffer, 0 internal errors

As the previous run, plus 3 attestation keys; every request carries an ar-attestation header (budget PB-01: p99 <= 1500 µs)
  GET /api/products/:id (route on the application), valid token, cached (warm)
    p50 5.71 µs   p99 10.54 µs   mean 6.42 µs   max 2976.42 µs

  Signed requests (40,000 calls each, budget PB-01)
  GET /api/products/:id, signed, replayed (same headers every time)
    p50 102.04 µs   p99 208.50 µs   mean 111.57 µs   max 41184.79 µs

The first catalog's 9 patches and 50 Rules; a benign 108.3 KB JSON body (2,000 calls; budget PB-01: p99 <= 1500 µs)
  p50 496.13 µs   p99 1464.04 µs   mean 573.05 µs   max 26420.00 µs

PASS: worst p99 16.63 µs is within the budget of 500 µs.
`;

/** This excerpt has a sample or three per budget, not the real bench's count. */
const FEW = { "PB-01": 1, "PB-02": 1 };

describe("Shield bench", () => {
  it("attributes every measurement to its scenario and its budget", () => {
    const samples = parseBench(BENCH);
    expect(samples).toEqual([
      {
        budget: "PB-02",
        section: "Built-in Policy (no Rules)",
        scenario: "GET /api/products/:id (route on the application)",
        p50Us: 3.21,
        p99Us: 10.33,
      },
      {
        budget: "PB-01",
        section:
          "As the previous run, plus 3 attestation keys; every request carries an ar-attestation header (budget PB-01: p99 <= 1500 µs)",
        scenario: "GET /api/products/:id (route on the application), valid token, cached (warm)",
        p50Us: 5.71,
        p99Us: 10.54,
      },
      {
        budget: "PB-01",
        section: "Signed requests (40,000 calls each, budget PB-01)",
        scenario: "GET /api/products/:id, signed, replayed (same headers every time)",
        p50Us: 102.04,
        p99Us: 208.5,
      },
      {
        budget: "PB-01",
        section:
          "The first catalog's 9 patches and 50 Rules; a benign 108.3 KB JSON body (2,000 calls; budget PB-01: p99 <= 1500 µs)",
        scenario:
          "The first catalog's 9 patches and 50 Rules; a benign 108.3 KB JSON body (2,000 calls; budget PB-01: p99 <= 1500 µs)",
        p50Us: 496.13,
        p99Us: 1464.04,
      },
    ]);
  });

  it("judges p50 and p99 against PB-01 and PB-02, naming each breach", () => {
    const budgets = performanceBudgets(PERFORMANCE);
    const ok = judgeBench(parseBench(BENCH), budgets, FEW);
    expect(ok.breaches).toEqual([]);
    expect(ok.worst).toEqual({
      "PB-01": { p50Us: 496.13, p99Us: 1464.04 },
      "PB-02": { p50Us: 3.21, p99Us: 10.33 },
    });
    const slow = BENCH.replace("p50 3.21 µs", "p50 100.01 µs").replace("p99 1464.04 µs", "p99 1500.50 µs");
    const out = judgeBench(parseBench(slow), budgets, FEW);
    expect(out.breaches).toEqual([
      "PB-02 p50 100.01 µs > 100 µs: Built-in Policy (no Rules) / GET /api/products/:id (route on the application)",
      expect.stringMatching(/^PB-01 p99 1500\.5 µs > 1500 µs: The first catalog/),
    ]);
  });

  it("refuses an output without measurements of both budgets", () => {
    const budgets = performanceBudgets(PERFORMANCE);
    expect(judgeBench([], budgets, FEW).breaches).toEqual(["no PB-01 measurement", "no PB-02 measurement"]);
  });
});

describe("child result lines", () => {
  it("reads the last GATE-RESULT line as JSON", () => {
    const text = 'noise\nGATE-RESULT {"a":1}\nmore\nGATE-RESULT {"a":2}\n';
    expect(parseResultLine(text)).toEqual({ a: 2 });
    expect(parseResultLine("nothing")).toBeNull();
    expect(parseResultLine("GATE-RESULT {broken")).toBeNull();
  });
});

describe("RRS gate", () => {
  const gate = (result: string, rrs: number | null, threshold: number) => ({
    result,
    rrs,
    threshold,
    status: rrs === null ? "inconclusive" : "scored",
    reason: rrs === null ? "excluded_over_limit" : null,
    weakest: [],
  });

  it("passes when every profile's gate passed at its TC-PRV-006 threshold", () => {
    const out = judgeRrs({
      variants: [
        { profile: "balanced", threshold: 70, exitCode: 0, gate: gate("passed", 72, 70) },
        { profile: "maximum", threshold: 85, exitCode: 0, gate: gate("passed", 90, 85) },
      ],
    });
    expect(out).toEqual({ state: "pass", lines: ["balanced: RRS 72 ≥ 70 (passed)", "maximum: RRS 90 ≥ 85 (passed)"] });
  });

  it("fails when a gate failed (exit 5)", () => {
    const out = judgeRrs({
      variants: [
        { profile: "balanced", threshold: 70, exitCode: 5, gate: gate("failed", 41, 70) },
        { profile: "maximum", threshold: 85, exitCode: 0, gate: gate("passed", 90, 85) },
      ],
    });
    expect(out.state).toBe("fail");
    expect(out.lines[0]).toBe("balanced: RRS 41 < 70 (failed)");
  });

  it("is not checkable when the stand-in gives no score (exit 6), unless another profile failed", () => {
    const noScore = { profile: "maximum", threshold: 85, exitCode: 6, gate: gate("no_score", null, 85) };
    expect(
      judgeRrs({
        variants: [{ profile: "balanced", threshold: 70, exitCode: 0, gate: gate("passed", 72, 70) }, noScore],
      }).state,
    ).toBe("not-checkable");
    expect(
      judgeRrs({
        variants: [{ profile: "balanced", threshold: 70, exitCode: 5, gate: gate("failed", 1, 70) }, noScore],
      }).state,
    ).toBe("fail");
  });

  it("fails on an error, a missing gate report or an exit code that does not match the gate", () => {
    expect(judgeRrs({ error: "API did not start" }).state).toBe("fail");
    expect(judgeRrs({ variants: [] }).state).toBe("fail");
    expect(judgeRrs({ variants: [{ profile: "balanced", threshold: 70, exitCode: 1, gate: null }] }).state).toBe(
      "fail",
    );
    expect(
      judgeRrs({ variants: [{ profile: "balanced", threshold: 70, exitCode: 0, gate: gate("failed", 1, 70) }] }).state,
    ).toBe("fail");
  });
});

describe("npm audit", () => {
  it("counts high and critical vulnerabilities", () => {
    const json = JSON.stringify({
      metadata: { vulnerabilities: { info: 0, low: 2, moderate: 1, high: 1, critical: 0, total: 4 } },
    });
    expect(parseNpmAudit(json)).toEqual({ low: 2, moderate: 1, high: 1, critical: 0, total: 4 });
    expect(parseNpmAudit("not json")).toBeNull();
    expect(parseNpmAudit("{}")).toBeNull();
  });
});
