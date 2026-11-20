import {
  atThreshold,
  SLO_ALERT_MIN_EVENTS,
  SLO_BURN_RULES,
  SLO_BURN_WINDOWS,
  SLO_LATENCY_BOUNDS_MS,
  SLO_WINDOWS,
  type SloAlert,
  type SloBurnRule,
  type SloBurnWindow,
  type SloDefinition,
  type SloId,
  type SloLatency,
  type SloStatus,
  type SloVariant,
} from "@antireverse/protocol";

// Slice 18d: pure functions from per-minute SLI buckets to what PERFORMANCE §3 and OPERATION §7 ask: the 30-day
// attainment, the error budget left, the burn rate per window and the latency percentiles; and the alert state
// machine of the burn rules. No clock, no I/O: every instant is an argument.

const MINUTE = 60_000;

/** One minute of one SLI series: no tenant identifier. `histogram` has one count per bound plus the overflow bucket. */
export interface SloBucket {
  /** The minute's start, ms since the epoch (UTC, a multiple of 60,000). */
  minute: number;
  slo: SloId;
  variant: SloVariant;
  good: number;
  total: number;
  histogram: number[];
}

export interface WindowSums {
  good: number;
  total: number;
}

export type WindowName = keyof typeof SLO_WINDOWS;

export interface SloAggregate {
  windows: Record<WindowName, WindowSums>;
  /** Over 30 days, per variant. */
  histograms: Partial<Record<SloVariant, number[]>>;
}

export const HISTOGRAM_SIZE = SLO_LATENCY_BOUNDS_MS.length + 1;

/** The minute an instant falls in. */
export const minuteOf = (ms: number): number => Math.floor(ms / MINUTE) * MINUTE;

/** The bucket index of a latency: the first bound at or above it, else the overflow bucket. */
export function bucketIndex(ms: number): number {
  for (let i = 0; i < SLO_LATENCY_BOUNDS_MS.length; i++) {
    if (ms <= (SLO_LATENCY_BOUNDS_MS[i] as number)) return i;
  }
  return SLO_LATENCY_BOUNDS_MS.length;
}

const WINDOW_NAMES = Object.keys(SLO_WINDOWS) as WindowName[];

/**
 * The earliest minute of each window at `now`: a window of w ms holds the last w / 60,000 minutes, the current
 * (partial) minute included. Minutes after the current one (clock skew) count in none.
 */
export function windowStarts(now: number): Record<WindowName, number> {
  const current = minuteOf(now);
  return Object.fromEntries(WINDOW_NAMES.map((name) => [name, current - SLO_WINDOWS[name] + MINUTE])) as Record<
    WindowName,
    number
  >;
}

const emptyWindows = (): Record<WindowName, WindowSums> =>
  Object.fromEntries(WINDOW_NAMES.map((name) => [name, { good: 0, total: 0 }])) as Record<WindowName, WindowSums>;

/** Sums buckets per SLO into every window, and their histograms per variant over 30 days. */
export function aggregate(buckets: Iterable<SloBucket>, now: number): Map<SloId, SloAggregate> {
  const starts = windowStarts(now);
  const current = minuteOf(now);
  const out = new Map<SloId, SloAggregate>();
  for (const b of buckets) {
    if (b.minute > current || b.minute < starts["30d"]) continue;
    let agg = out.get(b.slo);
    if (agg === undefined) {
      agg = { windows: emptyWindows(), histograms: {} };
      out.set(b.slo, agg);
    }
    for (const name of WINDOW_NAMES) {
      if (b.minute >= starts[name]) {
        agg.windows[name].good += b.good;
        agg.windows[name].total += b.total;
      }
    }
    const histogram = agg.histograms[b.variant] ?? new Array<number>(HISTOGRAM_SIZE).fill(0);
    for (let i = 0; i < HISTOGRAM_SIZE; i++) histogram[i] = (histogram[i] ?? 0) + (b.histogram[i] ?? 0);
    agg.histograms[b.variant] = histogram;
  }
  return out;
}

/** Error rate over the budget rate (1 − objective); null without events. */
export function burnRate(sums: WindowSums, objective: number): number | null {
  if (sums.total === 0) return null;
  return (sums.total - sums.good) / sums.total / (1 - objective);
}

/**
 * The upper bound of the bucket holding the p-th percentile (nearest rank); null without events, or when it lies in
 * the overflow bucket.
 */
export function percentileOf(histogram: readonly number[], percentile: number): number | null {
  const n = histogram.reduce((sum, count) => sum + count, 0);
  if (n === 0) return null;
  const rank = Math.ceil((percentile / 100) * n);
  let seen = 0;
  for (let i = 0; i < histogram.length; i++) {
    seen += histogram[i] ?? 0;
    if (seen >= rank) return i < SLO_LATENCY_BOUNDS_MS.length ? (SLO_LATENCY_BOUNDS_MS[i] as number) : null;
  }
  return null;
}

/** An SLO's status, alerts aside. */
export function evaluateSlo(def: SloDefinition, agg: SloAggregate | undefined): Omit<SloStatus, "alerts"> {
  const windows = agg?.windows ?? emptyWindows();
  const month = windows["30d"];
  const burn30 = burnRate(month, def.objective);
  const burn = Object.fromEntries(SLO_BURN_WINDOWS.map((w) => [w, burnRate(windows[w], def.objective)])) as Record<
    SloBurnWindow,
    number | null
  >;
  const latency: SloLatency[] = def.measured
    ? def.latency_targets.map((target) => {
        const histogram = agg?.histograms[target.variant];
        const observed = histogram === undefined ? null : percentileOf(histogram, target.percentile);
        const any = histogram?.some((n) => n > 0) === true;
        return {
          variant: target.variant,
          percentile: target.percentile,
          target_ms: target.ms,
          observed_ms: observed,
          met: any ? observed !== null && observed <= target.ms : null,
        };
      })
    : [];
  return {
    id: def.id,
    name: def.name,
    indicator: def.indicator,
    objective: def.objective,
    measured: def.measured,
    not_measured_reason: def.not_measured_reason,
    runbook: def.runbook,
    good: month.good,
    total: month.total,
    attainment: month.total === 0 ? null : month.good / month.total,
    budget_remaining: burn30 === null ? null : 1 - burn30,
    burn,
    latency,
  };
}

/** What the alert rules read of an SLO: the burn rate and the number of events of every burn window. */
export interface SloSignal {
  burn: Record<SloBurnWindow, number | null>;
  totals: Record<SloBurnWindow, number>;
}

/** The burn rates and event counts of an SLO's windows. */
export function signalOf(def: SloDefinition, agg: SloAggregate | undefined): SloSignal {
  const burn = {} as Record<SloBurnWindow, number | null>;
  const totals = {} as Record<SloBurnWindow, number>;
  for (const w of SLO_BURN_WINDOWS) {
    const sums = agg?.windows[w] ?? { good: 0, total: 0 };
    burn[w] = burnRate(sums, def.objective);
    totals[w] = sums.total;
  }
  return { burn, totals };
}

/** True when the rule's long window, and its confirmation window if any, burn at or above its threshold. */
export function ruleHolds(rule: SloBurnRule, burn: Record<SloBurnWindow, number | null>): boolean {
  return (
    atThreshold(burn[rule.long_window], rule.threshold) &&
    (rule.short_window === null || atThreshold(burn[rule.short_window], rule.threshold))
  );
}

/** A rule may fire: it holds and its long window has at least `SLO_ALERT_MIN_EVENTS` events. */
function mayFire(rule: SloBurnRule, signal: SloSignal): boolean {
  return ruleHolds(rule, signal.burn) && signal.totals[rule.long_window] >= SLO_ALERT_MIN_EVENTS;
}

/**
 * A firing rule ends only on evidence: its long window has events burning below the threshold, or its confirmation
 * window has events burning below it. Empty windows keep it firing.
 */
function hasEnded(rule: SloBurnRule, signal: SloSignal): boolean {
  const below = (w: SloBurnWindow) => signal.totals[w] > 0 && !atThreshold(signal.burn[w], rule.threshold);
  return below(rule.long_window) || (rule.short_window !== null && below(rule.short_window));
}

export interface AlertTransition {
  slo: SloId;
  rule: SloBurnRule;
  state: "firing" | "resolved";
  at: Date;
  /** When the episode started firing: with the SLO and the rule, the episode's identity. */
  since: Date;
  burn: Record<SloBurnWindow, number | null>;
}

/** A rule firing since `since` (persisted across restarts, review M2). */
export interface FiringState {
  slo: SloId;
  rule: SloBurnRule["id"];
  since: Date;
}

/** The stable id of an episode: `<slo>/<rule>/<since ISO>`. */
export const episodeId = (slo: SloId, rule: SloBurnRule["id"], since: Date): string =>
  `${slo}/${rule}/${since.toISOString()}`;

export interface AlertMachine {
  /** Steps every rule of the SLO; returns the rules that fired or resolved now. */
  update(slo: SloId, signal: SloSignal, at: Date): AlertTransition[];
  /**
   * Ends the firing episodes of the SLO whose rule `ends` names, whatever the burn says: a `resolved` transition each.
   * For an SLO only the synthetic probes feed (slice 18g, review F3), whose alert has nothing behind it once the
   * probes are off or its window holds no sample.
   */
  end(slo: SloId, signal: SloSignal, at: Date, ends: (rule: SloBurnRule) => boolean): AlertTransition[];
  /** The state of every rule of the SLO, in rule order. */
  states(slo: SloId): SloAlert[];
  /** Every rule firing now. */
  firing(): FiringState[];
}

/**
 * Per SLO per rule: ok → firing when the rule may fire (once per episode), firing → ok (resolved) when it has ended.
 * `initial`: the rules firing when the process last stopped.
 */
export function createAlertMachine(initial: readonly FiringState[] = []): AlertMachine {
  const key = (slo: SloId, rule: SloBurnRule["id"]) => `${slo}|${rule}`;
  const firingSince = new Map<string, FiringState>(initial.map((state) => [key(state.slo, state.rule), state]));
  return {
    update(slo, signal, at) {
      const transitions: AlertTransition[] = [];
      for (const rule of SLO_BURN_RULES) {
        const current = firingSince.get(key(slo, rule.id));
        if (current === undefined && mayFire(rule, signal)) {
          firingSince.set(key(slo, rule.id), { slo, rule: rule.id, since: at });
          transitions.push({ slo, rule, state: "firing", at, since: at, burn: signal.burn });
        } else if (current !== undefined && hasEnded(rule, signal)) {
          firingSince.delete(key(slo, rule.id));
          transitions.push({ slo, rule, state: "resolved", at, since: current.since, burn: signal.burn });
        }
      }
      return transitions;
    },
    end(slo, signal, at, ends) {
      const transitions: AlertTransition[] = [];
      for (const rule of SLO_BURN_RULES) {
        const current = firingSince.get(key(slo, rule.id));
        if (current === undefined || !ends(rule)) continue;
        firingSince.delete(key(slo, rule.id));
        transitions.push({ slo, rule, state: "resolved", at, since: current.since, burn: signal.burn });
      }
      return transitions;
    },
    states(slo) {
      return SLO_BURN_RULES.map((rule) => {
        const since = firingSince.get(key(slo, rule.id))?.since;
        return {
          rule: rule.id,
          severity: rule.severity,
          state: since === undefined ? "ok" : "firing",
          since: since === undefined ? null : since.toISOString(),
        };
      });
    },
    firing: () => [...firingSince.values()],
  };
}
