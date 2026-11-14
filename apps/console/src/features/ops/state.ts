import { atThreshold, SLO_BURN_RULES, type SloBurnWindow, type SloStatus } from "@antireverse/protocol";

// Slice 18d: what the dashboard derives from the report — each SLO's state and each burn window's threshold.

export type SloState = "firing" | "objective-missed" | "ok" | "no-traffic" | "not-measured";

/**
 * How far below zero the budget left may be and still count as not overspent: an attainment exactly at the objective
 * leaves −1e−13 or so by binary rounding.
 */
export const BUDGET_TOLERANCE = 1e-9;

/** True when the error budget is spent beyond the rounding tolerance — attainment below the objective. */
export function isOverspent(remaining: number | null): boolean {
  return remaining !== null && remaining <= -BUDGET_TOLERANCE;
}

/**
 * Not measured; else firing when any alert rule fires; else objective missed when the 30-day budget is overspent;
 * else no traffic without events; else ok.
 */
export function sloState(slo: SloStatus): SloState {
  if (!slo.measured) return "not-measured";
  if (slo.alerts.some((alert) => alert.state === "firing")) return "firing";
  if (isOverspent(slo.budget_remaining)) return "objective-missed";
  return slo.total === 0 ? "no-traffic" : "ok";
}

/** True when a window burns at or over its rule's threshold, by the API's own comparison. */
export function burnsOver(rate: number | null, window: SloBurnWindow): boolean {
  return atThreshold(rate, windowThreshold(window).threshold);
}

export interface WindowThreshold {
  threshold: number;
  severity: "page" | "ticket";
}

/**
 * The threshold each burn window is judged against: the rule whose long or confirming window it is (OPERATION §7) —
 * 5 m and 1 h at 14.4×, 30 m and 6 h at 6×, 3 d at 1×.
 */
export function windowThreshold(window: SloBurnWindow): WindowThreshold {
  const rule = SLO_BURN_RULES.find((entry) => entry.long_window === window || entry.short_window === window);
  if (rule === undefined) throw new Error(`no burn rule uses the window ${window}`);
  return { threshold: rule.threshold, severity: rule.severity };
}
