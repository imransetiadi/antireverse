// Slice 18e: the load smoke's client-side percentiles and its judgement against PB-21, SLO-02 and SLO-01. The targets
// come from PERFORMANCE §2 (PB-21) and the protocol's SLO catalog (SLO-01, SLO-02), never typed here.
import { readFileSync } from "node:fs";
import { SLO_CATALOG } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { performanceBudgets, sloTargets } from "../src/docs.ts";
import { judgeLoad, LOAD_PLAN, loadTargets, percentile } from "../src/load.ts";
import { REPO_ROOT } from "../src/paths.ts";

const PERFORMANCE = readFileSync(`${REPO_ROOT}/PERFORMANCE.md`, "utf8");
const budgets = performanceBudgets(PERFORMANCE);
const slos = sloTargets(PERFORMANCE);

describe("percentile (nearest rank)", () => {
  it("picks the nearest-rank value", () => {
    const values = Array.from({ length: 100 }, (_, i) => i + 1);
    expect(percentile(values, 50)).toBe(50);
    expect(percentile(values, 95)).toBe(95);
    expect(percentile(values, 99)).toBe(99);
    expect(percentile([5, 1, 3], 50)).toBe(3);
    expect(percentile([7], 99)).toBe(7);
  });

  it("refuses an empty series", () => {
    expect(() => percentile([], 95)).toThrow(/empty/);
  });
});

describe("load targets", () => {
  it("takes PB-21 from PERFORMANCE §2 and SLO-01/SLO-02 from the protocol catalog", () => {
    const slo01 = SLO_CATALOG.find((s) => s.id === "SLO-01");
    const slo02 = SLO_CATALOG.find((s) => s.id === "SLO-02");
    expect(loadTargets(budgets, slos)).toEqual([
      { id: "PB-21", series: "control-read", percentile: 95, ms: 200 },
      { id: "PB-21", series: "control-write", percentile: 95, ms: 500 },
      ...(slo02?.latency_targets ?? []).map((t) => ({
        id: "SLO-02",
        series: "ingest",
        percentile: t.percentile,
        ms: t.ms,
      })),
      ...(slo01?.latency_targets ?? []).map((t) => ({
        id: "SLO-01",
        series: "attest",
        percentile: t.percentile,
        ms: t.ms,
      })),
    ]);
  });

  it("keeps the plan small: well under a minute, inside the attestation prefix limit", () => {
    expect(LOAD_PLAN.attestPairs * 2).toBeLessThanOrEqual(60);
    expect(LOAD_PLAN.controlReads + LOAD_PLAN.controlWrites + LOAD_PLAN.ingestBatches).toBeLessThan(1_000);
  });
});

describe("judgeLoad", () => {
  const series = (ms: number, n = 20) => Array.from({ length: n }, () => ms);
  const good = {
    "control-read": series(3),
    "control-write": series(8),
    ingest: series(4),
    attest: series(6),
  };

  it("passes when every target is met, with the measured numbers", () => {
    const out = judgeLoad({ series: good, errors: [] }, loadTargets(budgets, slos));
    expect(out.state).toBe("pass");
    expect(out.measurements).toContainEqual({
      id: "PB-21",
      series: "control-read",
      percentile: 95,
      ms: 3,
      target: 200,
    });
  });

  it("fails on a breach, naming it", () => {
    const out = judgeLoad({ series: { ...good, ingest: series(151) }, errors: [] }, loadTargets(budgets, slos));
    expect(out.state).toBe("fail");
    expect(out.breaches).toEqual(["SLO-02 ingest p99 151 ms > 150 ms"]);
  });

  it("fails on request errors or a missing series", () => {
    expect(judgeLoad({ series: good, errors: ["POST /v1/events: 500"] }, loadTargets(budgets, slos)).state).toBe(
      "fail",
    );
    const { attest: _attest, ...noAttest } = good;
    const out = judgeLoad({ series: noAttest, errors: [] }, loadTargets(budgets, slos));
    expect(out.state).toBe("fail");
    expect(out.breaches).toContain("no samples for attest");
  });
});
