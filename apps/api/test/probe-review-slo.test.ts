import type { ProbeStatus } from "@antireverse/protocol";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { type OwnedDb, openDb } from "../src/db/db.ts";
import { createSloService } from "../src/slo/service.ts";
import { readSloAlerts } from "../src/slo/store.ts";
import { captureLogger } from "./helpers.ts";

// Slice 18g, independent review F3: an SLO-06 alert must not stay firing with nothing behind it. Without a prober its
// firing rules are resolved (the normal transition, logged and stored); with one, a rule whose long window holds no
// sample at all is resolved. Traffic-fed SLOs keep D-094: an empty window is no evidence, and they stay firing.

const NOW = Date.parse("2026-11-20T08:00:00.000Z");
const STATUS: ProbeStatus = {
  interval_s: 60,
  runs: 0,
  failures: 0,
  consecutive_failures: 0,
  setup_failures: 0,
  last_run_at: null,
  enforcement: null,
  freshness: null,
};

let db: OwnedDb;
beforeAll(async () => {
  db = await openDb();
});
afterAll(async () => {
  await db.close();
});
beforeEach(async () => {
  await db.owner(async (q) => {
    await q.query("DELETE FROM slo_minutes");
    await q.query("DELETE FROM slo_alerts");
    // What a process left behind that stopped while SLO-06 and SLO-01 were burning.
    await q.query(
      `INSERT INTO slo_alerts (slo, rule, since) VALUES
         ('SLO-06', 'fast', '2026-11-19T10:00:00Z'), ('SLO-06', 'ticket', '2026-11-19T10:00:00Z'),
         ('SLO-01', 'fast', '2026-11-19T10:00:00Z')`,
    );
  });
});

const stored = async () => (await db.owner((q) => readSloAlerts(q))).map((row) => `${row.slo}/${row.rule}`);

describe("F3: stale SLO-06 alerts", () => {
  it("resolves the firing rules of SLO-06 at the first evaluation of an instance without a prober", async () => {
    const logger = captureLogger();
    const slo = createSloService({ db, now: () => new Date(NOW), logger });
    const transitions = await slo.runOnce();
    expect(transitions.map((t) => [t.slo, t.rule.id, t.state, t.since.toISOString()])).toEqual([
      ["SLO-06", "fast", "resolved", "2026-11-19T10:00:00.000Z"],
      ["SLO-06", "ticket", "resolved", "2026-11-19T10:00:00.000Z"],
    ]);
    expect(await stored()).toEqual(["SLO-01/fast"]);
    expect(logger.lines.filter((line) => line.startsWith("slo alert resolved slo=SLO-06"))).toHaveLength(2);
    // Once.
    expect(await slo.runOnce()).toEqual([]);
  });

  it("with a prober, resolves a rule whose long window holds no sample, and keeps a traffic-fed SLO firing (D-094)", async () => {
    const slo = createSloService({ db, now: () => new Date(NOW), logger: captureLogger() });
    slo.attachProbes(() => STATUS);
    const transitions = await slo.runOnce();
    expect(transitions.map((t) => [t.slo, t.rule.id, t.state])).toEqual([
      ["SLO-06", "fast", "resolved"],
      ["SLO-06", "ticket", "resolved"],
    ]);
    expect(await stored()).toEqual(["SLO-01/fast"]);
    const report = await slo.report();
    expect(report.slos.find((s) => s.id === "SLO-06")?.alerts.map((a) => a.state)).toEqual(["ok", "ok", "ok"]);
    expect(report.slos.find((s) => s.id === "SLO-01")?.alerts.find((a) => a.rule === "fast")?.state).toBe("firing");
    expect(await slo.metrics()).toContain('airverse_slo_alert_firing{slo="SLO-06",rule="fast",severity="page"} 0\n');
  });

  it("with a prober and bad samples in the window, keeps the rule firing", async () => {
    const slo = createSloService({ db, now: () => new Date(NOW), logger: captureLogger() });
    slo.attachProbes(() => STATUS);
    for (let i = 0; i < 4; i++) slo.recorder.record("SLO-06", false, 60_001);
    expect((await slo.runOnce()).filter((t) => t.state === "resolved")).toEqual([]);
    expect(await stored()).toContain("SLO-06/fast");
  });
});
