// The load smoke's plan, targets and judgement (slice 18e). The child (load-smoke.ts) measures round trips; here they
// become client-side percentiles held to PB-21 (PERFORMANCE §2) and SLO-01 / SLO-02 (the protocol's SLO catalog).
// Client-side round trips include the loopback hop, so they are stricter than the server time the SLOs name.
import { SLO_CATALOG } from "@antireverse/protocol";
import { type Budget, requireTargets } from "./docs.ts";
import type { State } from "./verdict.ts";

export type Series = "control-read" | "control-write" | "ingest" | "attest";
export const SERIES: readonly Series[] = ["control-read", "control-write", "ingest", "attest"];

/**
 * A fixed amount of work, well under a minute. Attestation is limited to 60 requests per minute per caller prefix
 * (both endpoints together), so 25 challenge-and-attest pairs stay inside it.
 */
export const LOAD_PLAN = {
  controlReads: 200,
  controlWrites: 40,
  ingestBatches: 100,
  eventsPerBatch: 10,
  attestPairs: 25,
  concurrency: 4,
} as const;

export interface LoadTarget {
  id: string;
  series: Series;
  percentile: number;
  ms: number;
}

/** Nearest-rank percentile. */
export function percentile(values: readonly number[], p: number): number {
  if (values.length === 0) throw new Error("percentile of an empty series");
  const sorted = [...values].sort((a, b) => a - b);
  const rank = Math.max(1, Math.ceil((p / 100) * sorted.length));
  return sorted[rank - 1] as number;
}

/**
 * PB-21 from PERFORMANCE §2 and SLO-01 / SLO-02 from PERFORMANCE §3, cross-checked with the protocol's SLO catalog:
 * a target that cannot be read, or a document and a catalog that disagree, is an error, never a smaller check.
 */
export function loadTargets(
  budgets: ReadonlyMap<string, Budget>,
  slos: ReadonlyMap<string, ReadonlyArray<{ percentile: number; ms: number }>>,
): LoadTarget[] {
  const out: LoadTarget[] = [];
  for (const t of requireTargets(budgets, "PB-21")) {
    out.push({
      id: "PB-21",
      series: t.variant === "read" ? "control-read" : "control-write",
      percentile: t.percentile,
      ms: t.ms,
    });
  }
  const show = (ts: ReadonlyArray<{ percentile: number; ms: number }>) =>
    ts.map((t) => `p${t.percentile} ≤ ${t.ms} ms`).join(", ") || "nothing";
  for (const [id, series] of [
    ["SLO-02", "ingest"],
    ["SLO-01", "attest"],
  ] as const) {
    const fromDoc = slos.get(id) ?? [];
    const fromCatalog = (SLO_CATALOG.find((s) => s.id === id)?.latency_targets ?? []).map((t) => ({
      percentile: t.percentile,
      ms: t.ms,
    }));
    if (fromDoc.length === 0 || show(fromDoc) !== show(fromCatalog)) {
      throw new Error(`${id}: PERFORMANCE §3 says ${show(fromDoc)}, the protocol catalog ${show(fromCatalog)}`);
    }
    for (const t of fromDoc) out.push({ id, series, percentile: t.percentile, ms: t.ms });
  }
  return out;
}

export interface LoadRun {
  series: Partial<Record<Series, number[]>>;
  errors: string[];
}

export interface LoadMeasurement extends LoadTarget {
  target: number;
}

export function judgeLoad(
  run: LoadRun,
  targets: readonly LoadTarget[],
): { state: State; breaches: string[]; measurements: Array<Omit<LoadMeasurement, "ms"> & { ms: number }> } {
  const breaches: string[] = [...run.errors.map((e) => `request error: ${e}`)];
  const measurements: Array<Omit<LoadMeasurement, "ms"> & { ms: number }> = [];
  if (targets.length === 0) breaches.push("no targets");
  for (const series of SERIES) {
    if ((run.series[series] ?? []).length === 0) breaches.push(`no samples for ${series}`);
  }
  for (const t of targets) {
    const values = run.series[t.series] ?? [];
    if (values.length === 0) continue;
    const ms = Math.round(percentile(values, t.percentile) * 100) / 100;
    measurements.push({ id: t.id, series: t.series, percentile: t.percentile, ms, target: t.ms });
    if (ms > t.ms) breaches.push(`${t.id} ${t.series} p${t.percentile} ${ms} ms > ${t.ms} ms`);
  }
  return { state: breaches.length === 0 ? "pass" : "fail", breaches, measurements };
}
