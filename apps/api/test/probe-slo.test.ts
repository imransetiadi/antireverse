import type { ProbeStatus } from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { type OwnedDb, openDb } from "../src/db/db.ts";
import { createSloService } from "../src/slo/service.ts";
import { captureLogger } from "./helpers.ts";

// Slice 18g: SLO-06 in the SLO job. Fed by the synthetic probes alone, it is measured, alerted on and shown in the
// metrics only while a prober is attached; its burn alerts are the existing rules and name RB-04.

const START = Date.parse("2026-11-20T08:00:00.000Z");
const STATUS: ProbeStatus = {
  interval_s: 60,
  runs: 4,
  failures: 4,
  consecutive_failures: 4,
  setup_failures: 0,
  last_run_at: "2026-11-20T08:03:30.000Z",
  enforcement: { outcome: "timeout", ms: 60_000 },
  freshness: { outcome: "skipped", ms: null },
};

let db: OwnedDb;
beforeAll(async () => {
  db = await openDb();
});
afterAll(async () => {
  await db.close();
});

describe("SLO-06 and the prober", () => {
  it("ignores SLO-06 without a prober, and with one fires the fast burn alert after failed probes, naming RB-04", async () => {
    let clock = START;
    const logger = captureLogger();
    const slo = createSloService({ db, now: () => new Date(clock), logger });
    // Four failed probe cycles, one a minute: every sample bad, given up at 60 s.
    for (let i = 0; i < 4; i++) {
      slo.recorder.record("SLO-06", false, 60_001);
      clock += 60_000;
    }

    expect((await slo.runOnce()).filter((t) => t.slo === "SLO-06")).toEqual([]);
    const off = (await slo.report()).slos.find((s) => s.id === "SLO-06");
    expect(off).toMatchObject({ measured: false, total: 0, attainment: null, latency: [], alerts: [] });
    expect((await slo.report()).probes).toBeNull();
    expect(await slo.metrics()).not.toContain('slo="SLO-06"');

    slo.attachProbes(() => STATUS);
    clock += 60_000;
    const transitions = (await slo.runOnce()).filter((t) => t.slo === "SLO-06");
    expect(transitions.map((t) => [t.rule.id, t.state])).toEqual([
      ["fast", "firing"],
      ["slow", "firing"],
      ["ticket", "firing"],
    ]);
    expect(logger.lines.filter((line) => line.includes("slo=SLO-06") && line.includes("rule=fast"))).toEqual([
      "slo alert firing slo=SLO-06 rule=fast severity=page runbook=RB-04 burn_long=20 burn_short=20",
    ]);

    clock += 20_000; // past the read cache
    const r = await slo.report();
    expect(r.probes).toEqual(STATUS);
    const on = r.slos.find((s) => s.id === "SLO-06");
    expect(on).toMatchObject({ measured: true, not_measured_reason: null, good: 0, total: 4, attainment: 0 });
    // All four samples lie past the 60 s bound (as the runner records a probe it gave up): both targets are missed.
    expect(on?.latency).toEqual([
      { variant: "all", percentile: 95, target_ms: 30_000, observed_ms: 300_000, met: false },
      { variant: "all", percentile: 99, target_ms: 60_000, observed_ms: 300_000, met: false },
    ]);
    expect(on?.alerts.find((alert) => alert.rule === "fast")).toMatchObject({ severity: "page", state: "firing" });
    const metrics = await slo.metrics();
    expect(metrics).toContain('airverse_slo_total{slo="SLO-06"} 4\n');
    expect(metrics).toContain('airverse_slo_alert_firing{slo="SLO-06",rule="fast",severity="page"} 1\n');
  });
});
