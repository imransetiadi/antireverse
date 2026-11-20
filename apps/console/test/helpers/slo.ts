import { SLO_CATALOG, type SloId, type SloReport, type SloStatus } from "@antireverse/protocol";

/** Slice 18d: an SLO report as `GET /v1/ops/slo` answers it, shared by the operator dashboard tests. */

export const GENERATED_AT = "2026-11-14T09:30:00.000Z";
export const OPS_TOKEN = "operator-token-for-the-console-tests-0123456789";

/** One SLO as the API reports it: healthy traffic when measured, zeros and nulls when not. */
export function sloStatus(id: SloId, overrides: Partial<SloStatus> = {}): SloStatus {
  const def = SLO_CATALOG.find((entry) => entry.id === id);
  if (def === undefined) throw new Error(`unknown SLO ${id}`);
  const base: SloStatus = {
    id: def.id,
    name: def.name,
    indicator: def.indicator,
    objective: def.objective,
    measured: def.measured,
    not_measured_reason: def.not_measured_reason,
    runbook: def.runbook,
    good: 0,
    total: 0,
    attainment: null,
    budget_remaining: null,
    burn: { "5m": null, "30m": null, "1h": null, "6h": null, "3d": null },
    latency: [],
    alerts: [],
  };
  if (def.measured) {
    Object.assign(base, {
      good: 99_995,
      total: 100_000,
      attainment: 0.99995,
      budget_remaining: 1 - 0.00005 / (1 - def.objective),
      burn: { "5m": 0, "30m": 0.5, "1h": 0.25, "6h": 0.2, "3d": 0.1 },
      latency: def.latency_targets.map((target) => ({
        variant: target.variant,
        percentile: target.percentile,
        target_ms: target.ms,
        observed_ms: target.ms,
        met: true,
      })),
      alerts: (["fast", "slow", "ticket"] as const).map((rule) => ({
        rule,
        severity: rule === "ticket" ? "ticket" : "page",
        state: "ok",
        since: null,
      })),
    } satisfies Partial<SloStatus>);
  }
  return { ...base, ...overrides };
}

/** All ten SLOs in catalog order, each replaced by `overrides[id]` where given. */
export function sloReport(overrides: Partial<Record<SloId, Partial<SloStatus>>> = {}): SloReport {
  return {
    generated_at: GENERATED_AT,
    window_days: 30,
    scope: "instance",
    // Slice 18g: the synthetic probes are off unless a test says otherwise.
    probes: null,
    slos: SLO_CATALOG.map((def) => sloStatus(def.id, overrides[def.id] ?? {})),
  };
}
