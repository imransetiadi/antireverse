import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  atThreshold,
  PROBE_BOUNDS,
  PROBE_PATH_PREFIX,
  PROBES_VARIABLE,
  ProbeStatusSchema,
  SLO_BURN_RULES,
  SLO_CATALOG,
  SLO_IDS,
  SLO_LATENCY_BOUNDS_MS,
  SLO_RETENTION_DAYS,
  SLO_THRESHOLD_TOLERANCE,
  SLO_WINDOWS,
  type SloReport,
  SloReportSchema,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";

// Slice 18d: the SLO catalog (PERFORMANCE §3), its runbooks (OPERATION §9), the burn rules (OPERATION §7) and the
// shape of `GET /v1/ops/slo`.

const root = (name: string) => readFileSync(fileURLToPath(new URL(`../../../${name}`, import.meta.url)), "utf8");

/** The rows of the first Markdown table under the heading that starts with `heading`. */
function tableUnder(markdown: string, heading: string): string[][] {
  const lines = markdown.split("\n");
  const start = lines.findIndex((line) => line.startsWith(heading));
  expect(start, heading).toBeGreaterThanOrEqual(0);
  const rows: string[][] = [];
  for (const line of lines.slice(start + 1)) {
    if (line.startsWith("## ")) break;
    if (!line.startsWith("|")) {
      if (rows.length > 0) break;
      continue;
    }
    if (/^\|\s*-/.test(line) || /^\|---/.test(line)) continue;
    rows.push(
      line
        .split("|")
        .slice(1, -1)
        .map((cell) => cell.trim()),
    );
  }
  return rows.slice(1);
}

describe("SLO catalog", () => {
  it("lists SLO-01 to SLO-10 in order, with the objectives of PERFORMANCE §3 as fractions", () => {
    expect([...SLO_IDS]).toEqual([
      "SLO-01",
      "SLO-02",
      "SLO-03",
      "SLO-04",
      "SLO-05",
      "SLO-06",
      "SLO-07",
      "SLO-08",
      "SLO-09",
      "SLO-10",
    ]);
    expect(SLO_CATALOG.map((slo) => slo.id)).toEqual([...SLO_IDS]);
    const table = tableUnder(root("PERFORMANCE.md"), "## 3. Service level objectives");
    expect(table.map((row) => row[0])).toEqual([...SLO_IDS]);
    for (const row of table) {
      const slo = SLO_CATALOG.find((entry) => entry.id === row[0]);
      // "99.99 %", "99 % of events", "95 % in 30 s, 99 % in 60 s": the first percentage is the objective.
      const percent = Number(/([0-9.]+) %/.exec(row[3] ?? "")?.[1]);
      expect(slo?.objective, row[0]).toBeCloseTo(percent / 100, 10);
      expect(slo?.name, row[0]).toBe(row[1]);
    }
  });

  it("measures every SLO but SLO-06 and SLO-08, which say why", () => {
    for (const slo of SLO_CATALOG) {
      if (slo.id === "SLO-06" || slo.id === "SLO-08") {
        expect(slo.measured, slo.id).toBe(false);
        expect(slo.not_measured_reason?.length ?? 0, slo.id).toBeGreaterThan(10);
      } else {
        expect(slo.measured, slo.id).toBe(true);
        expect(slo.not_measured_reason, slo.id).toBeNull();
      }
    }
  });

  it("marks SLO-06 as fed by the synthetic probe only, with PB-15's bounds, and SLO-08 as needing a browser (slice 18g)", () => {
    const of = (id: string) => SLO_CATALOG.find((slo) => slo.id === id);
    expect(SLO_CATALOG.filter((slo) => slo.probe).map((slo) => slo.id)).toEqual(["SLO-06"]);
    expect(of("SLO-06")?.good_within_ms).toBe(30_000);
    expect(of("SLO-06")?.latency_targets).toEqual([
      { variant: "all", percentile: 95, ms: 30_000 },
      { variant: "all", percentile: 99, ms: 60_000 },
    ]);
    // Off by default: the reason names the switch. The indicator says what the number is not.
    expect(of("SLO-06")?.not_measured_reason).toContain(`${PROBES_VARIABLE}=1`);
    expect(of("SLO-06")?.indicator).toMatch(/one Shield/i);
    expect(of("SLO-04")?.indicator).toMatch(/probe/i);
    // Review D-116 and D-117: the probe's own traffic feeds no other SLI, and a prober that cannot run counts as failing.
    for (const id of ["SLO-02", "SLO-03", "SLO-04", "SLO-05", "SLO-07"]) {
      expect(of(id)?.indicator, id).toMatch(/synthetic probes' own (requests|Events) (are|is) not counted/);
    }
    expect(of("SLO-06")?.indicator).toMatch(/cannot be set up/);
    expect(ProbeStatusSchema.shape.setup_failures).toBeDefined();
    expect(of("SLO-08")?.not_measured_reason).toMatch(/Core Web Vitals/);
    expect(of("SLO-08")?.probe).toBe(false);
    expect(PROBES_VARIABLE).toBe("AR_PROBES");
    expect(PROBE_PATH_PREFIX).toBe("/airverse-probe/");
    expect(PROBE_BOUNDS).toEqual({
      enforceGoodMs: 30_000,
      enforceTimeoutMs: 60_000,
      freshGoodMs: 5_000,
      freshTimeoutMs: 30_000,
    });
    expect(PROBE_BOUNDS.enforceGoodMs).toBe(of("SLO-06")?.good_within_ms);
    expect(PROBE_BOUNDS.freshGoodMs).toBe(of("SLO-04")?.good_within_ms);
  });

  it("states the good thresholds of the ticket and the latency targets of PERFORMANCE §2", () => {
    const of = (id: string) => SLO_CATALOG.find((slo) => slo.id === id);
    expect([of("SLO-01")?.good_within_ms, of("SLO-01")?.write_good_within_ms]).toEqual([120, null]);
    expect(of("SLO-02")?.good_within_ms).toBe(150);
    expect(of("SLO-03")?.good_within_ms).toBeNull();
    expect(of("SLO-04")?.good_within_ms).toBe(5_000);
    expect(of("SLO-05")?.good_within_ms).toBe(10_000);
    expect([of("SLO-07")?.good_within_ms, of("SLO-07")?.write_good_within_ms]).toEqual([200, 500]);
    expect(of("SLO-09")?.good_within_ms).toBe(60_000);
    expect(of("SLO-10")?.good_within_ms).toBe(1_800_000);
    expect(of("SLO-01")?.latency_targets).toEqual([
      { variant: "all", percentile: 95, ms: 50 },
      { variant: "all", percentile: 99, ms: 120 },
    ]);
    expect(of("SLO-07")?.latency_targets).toEqual([
      { variant: "read", percentile: 95, ms: 200 },
      { variant: "write", percentile: 95, ms: 500 },
    ]);
    expect(of("SLO-03")?.latency_targets).toEqual([]);
    // Every latency target and good threshold is a bucket bound, so that a percentile can be judged exactly.
    for (const slo of SLO_CATALOG) {
      for (const ms of [slo.good_within_ms, slo.write_good_within_ms, ...slo.latency_targets.map((t) => t.ms)]) {
        if (ms !== null) expect(SLO_LATENCY_BOUNDS_MS, `${slo.id} ${ms}`).toContain(ms);
      }
    }
    expect([...SLO_LATENCY_BOUNDS_MS]).toEqual([...SLO_LATENCY_BOUNDS_MS].sort((a, b) => a - b));
  });

  it("names a runbook of OPERATION §9 for every SLO (an alert without a runbook is a defect)", () => {
    const runbooks = tableUnder(root("OPERATION.md"), "## 9. Runbooks").map((row) => row[0]);
    expect(runbooks.length).toBeGreaterThanOrEqual(16);
    for (const slo of SLO_CATALOG) expect(runbooks, slo.id).toContain(slo.runbook);
    expect(Object.fromEntries(SLO_CATALOG.map((slo) => [slo.id, slo.runbook]))).toEqual({
      "SLO-01": "RB-03",
      "SLO-02": "RB-02",
      "SLO-03": "RB-04",
      "SLO-04": "RB-02",
      "SLO-05": "RB-02",
      "SLO-06": "RB-04",
      "SLO-07": "RB-07",
      "SLO-08": "RB-07",
      "SLO-09": "RB-02",
      "SLO-10": "RB-11",
    });
  });

  it("fails the runbook check for a runbook that OPERATION §9 does not have", () => {
    const runbooks = tableUnder(root("OPERATION.md"), "## 9. Runbooks").map((row) => row[0]);
    expect(runbooks).not.toContain("RB-99");
  });
});

describe("burn rules and windows", () => {
  it("pages at 14.4x over 1 h confirmed over 5 m and at 6x over 6 h confirmed over 30 m; tickets at 1x over 3 d", () => {
    expect(SLO_BURN_RULES).toEqual([
      { id: "fast", severity: "page", threshold: 14.4, long_window: "1h", short_window: "5m" },
      { id: "slow", severity: "page", threshold: 6, long_window: "6h", short_window: "30m" },
      { id: "ticket", severity: "ticket", threshold: 1, long_window: "3d", short_window: null },
    ]);
    expect(SLO_WINDOWS).toEqual({
      "5m": 300_000,
      "30m": 1_800_000,
      "1h": 3_600_000,
      "6h": 21_600_000,
      "3d": 259_200_000,
      "30d": 2_592_000_000,
    });
    expect(SLO_RETENTION_DAYS).toBe(35);
    expect(Object.isFrozen(SLO_CATALOG)).toBe(true);
    expect(Object.isFrozen(SLO_BURN_RULES[0])).toBe(true);
  });
});

describe("GET /v1/ops/slo", () => {
  const report: SloReport = {
    generated_at: "2026-11-14T10:00:00.000Z",
    window_days: 30,
    scope: "instance",
    probes: null,
    slos: [
      {
        id: "SLO-01",
        name: "Attestation",
        indicator: "x",
        objective: 0.9999,
        measured: true,
        not_measured_reason: null,
        runbook: "RB-03",
        good: 9,
        total: 10,
        attainment: 0.9,
        budget_remaining: -999,
        burn: { "5m": 1000, "30m": 1000, "1h": 1000, "6h": 1000, "3d": 1000 },
        latency: [{ variant: "all", percentile: 95, target_ms: 50, observed_ms: 25, met: true }],
        alerts: [{ rule: "fast", severity: "page", state: "firing", since: "2026-11-14T09:59:00.000Z" }],
      },
    ],
  };

  it("carries the probe status, or null when probes are off (slice 18g)", () => {
    expect(SloReportSchema.safeParse({ ...report, probes: undefined }).success).toBe(false);
    const probes = {
      interval_s: 60,
      runs: 3,
      failures: 1,
      consecutive_failures: 0,
      setup_failures: 0,
      last_run_at: "2026-11-14T09:59:00.000Z",
      enforcement: { outcome: "good", ms: 4200.5 },
      freshness: { outcome: "skipped", ms: null },
    };
    expect(SloReportSchema.parse({ ...report, probes })).toEqual({ ...report, probes });
    expect(ProbeStatusSchema.safeParse({ ...probes, organization_id: "x" }).success).toBe(false);
    expect(ProbeStatusSchema.safeParse({ ...probes, enforcement: { outcome: "fine", ms: 1 } }).success).toBe(false);
    const idle = { ...probes, runs: 0, failures: 0, last_run_at: null, enforcement: null, freshness: null };
    expect(ProbeStatusSchema.safeParse(idle).success).toBe(true);
  });

  it("parses a report and refuses members it does not define", () => {
    expect(SloReportSchema.parse(report)).toEqual(report);
    expect(SloReportSchema.safeParse({ ...report, organization_id: "x" }).success).toBe(false);
    const slo = report.slos[0];
    expect(SloReportSchema.safeParse({ ...report, slos: [{ ...slo, app_id: "x" }] }).success).toBe(false);
  });

  it("allows an unmeasured SLO with nulls", () => {
    const unmeasured = {
      ...report.slos[0],
      id: "SLO-06",
      measured: false,
      not_measured_reason: "needs a probe",
      good: 0,
      total: 0,
      attainment: null,
      budget_remaining: null,
      burn: { "5m": null, "30m": null, "1h": null, "6h": null, "3d": null },
      latency: [],
      alerts: [],
    };
    expect(SloReportSchema.safeParse({ ...report, slos: [unmeasured] }).success).toBe(true);
  });
});

describe("the burn threshold comparison", () => {
  it("holds at or over the threshold, within a relative tolerance of 1e-9, and never without a value", () => {
    expect(SLO_THRESHOLD_TOLERANCE).toBe(1e-9);
    // SLO-07 with 9 bad of 625: 14.399999999999986, a rounding error below 14.4.
    expect(atThreshold(9 / 625 / (1 - 0.999), 14.4)).toBe(true);
    expect(atThreshold(14.4, 14.4)).toBe(true);
    expect(atThreshold(20, 14.4)).toBe(true);
    expect(atThreshold(14.36, 14.4)).toBe(false);
    expect(atThreshold(14.4 * (1 - 2e-9), 14.4)).toBe(false);
    expect(atThreshold(null, 1)).toBe(false);
  });
});
