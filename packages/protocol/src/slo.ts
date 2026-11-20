// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { deepFreeze } from "./shared.ts";

// Service level objectives (slice 18d, PERFORMANCE §3, OPERATION §7 and §9). The API measures the SLIs in process and
// per instance, in per-minute buckets of good and total counts with a fixed latency histogram; nothing in them names
// a tenant. An operator reads them at `GET /v1/ops/slo` (this schema) and `GET /metrics` (Prometheus text), with the
// operator token `AR_OPS_TOKEN` only.
//
// Slice 18g: with `AR_PROBES=1` the API runs the synthetic probes of OPERATION §7 once a minute, inside its own process
// and against one Shield of its own: a marked block Rule, timed to its enforcement (SLO-06, PB-15), and that blocked
// request's Event, timed to readable through the Events route (SLO-04, PB-13). SLO-06 is fed by the probe alone, so
// the report shows it as measured only while probes run. SLO-08 needs a browser and stays not measured.

/** The environment variable that turns the synthetic probes on: exactly `1`. Off by default. */
export const PROBES_VARIABLE = "AR_PROBES";

/** The marked block of a probe cycle is a Rule on this prefix and a fresh nonce; its Event carries the same route. */
export const PROBE_PATH_PREFIX = "/airverse-probe/";

/**
 * The probes' bounds, in ms. Enforcement (PB-15): good within 30 s, given up at 60 s. Freshness (PB-13): good within
 * 5 s, given up at 30 s. A probe that is given up is a bad sample.
 *
 * What the probe itself sends to the API is no tenant's traffic: its requests and Events feed none of the other SLIs
 * (SLO-02, -03, -05, -07 and the in-process count of SLO-04), only its two measurements are recorded (D-116).
 */
export const PROBE_BOUNDS = deepFreeze({
  enforceGoodMs: 30_000,
  enforceTimeoutMs: 60_000,
  freshGoodMs: 5_000,
  freshTimeoutMs: 30_000,
} as const);

export const SLO_IDS = deepFreeze([
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
] as const);
export type SloId = (typeof SLO_IDS)[number];

/** A latency series of an SLO: `all`, or SLO-07's reads (GET, HEAD) and writes (every other method). */
export const SLO_VARIANTS = deepFreeze(["all", "read", "write"] as const);
export type SloVariant = (typeof SLO_VARIANTS)[number];

/**
 * Upper bounds (inclusive, in ms) of the latency histogram's buckets; one more bucket holds everything above the last.
 * Every good threshold and latency target of the catalog is one of them, so a percentile is judged exactly.
 */
export const SLO_LATENCY_BOUNDS_MS = deepFreeze([
  5, 10, 25, 50, 75, 100, 120, 150, 200, 300, 500, 750, 1_000, 2_500, 5_000, 10_000, 30_000, 60_000, 300_000, 900_000,
  1_800_000, 3_600_000,
] as const);

/** Per-minute buckets are kept this long (the 30-day window plus margin), then swept. */
export const SLO_RETENTION_DAYS = 35;

/** The windows of attainment (30 d) and of the burn rates, in ms. */
export const SLO_WINDOWS = deepFreeze({
  "5m": 300_000,
  "30m": 1_800_000,
  "1h": 3_600_000,
  "6h": 21_600_000,
  "3d": 259_200_000,
  "30d": 2_592_000_000,
} as const);
export const SLO_BURN_WINDOWS = deepFreeze(["5m", "30m", "1h", "6h", "3d"] as const);
export type SloBurnWindow = (typeof SLO_BURN_WINDOWS)[number];

export interface SloLatencyTarget {
  variant: SloVariant;
  percentile: 95 | 99;
  ms: number;
}

export interface SloDefinition {
  id: SloId;
  /** As in PERFORMANCE §3. */
  name: string;
  /** What is counted, as measured in process. */
  indicator: string;
  /** The 30-day objective as a fraction (99.99 % is 0.9999). */
  objective: number;
  /**
   * False when this product does not measure it as it stands; `not_measured_reason` says why. An SLO with `probe`
   * is measured while the synthetic probes run: the report says so then.
   */
  measured: boolean;
  not_measured_reason: string | null;
  /** True when only the synthetic probes feed it (slice 18g): measured while they run, not otherwise. */
  probe: boolean;
  /** The OPERATION §9 runbook every alert of this SLO names. */
  runbook: string;
  /** An event is good only within this many ms (SLO-07: reads). Null: no latency condition. */
  good_within_ms: number | null;
  /** SLO-07 only: the bound of writes. */
  write_good_within_ms: number | null;
  /** The percentiles shown against a target (PERFORMANCE §2 and §3). */
  latency_targets: readonly SloLatencyTarget[];
}

const all = (percentile: 95 | 99, ms: number): SloLatencyTarget => ({ variant: "all", percentile, ms });

/**
 * The catalog. Runbooks (OPERATION §9): attestation → RB-03; ingest, freshness and detection latency → RB-02 (pipeline
 * lag); policy distribution and enforcement propagation → RB-04 (bundle); Control API and Console → RB-07 (store
 * pressure, slow queries); alert delivery → RB-02 (there is no alerting runbook; the alert queue is a pipeline stage);
 * Prove → RB-11 (model provider, queue).
 */
export const SLO_CATALOG: readonly SloDefinition[] = deepFreeze([
  {
    id: "SLO-01",
    name: "Attestation",
    indicator:
      "POST /v1/attest and /v1/attest/challenge: good when not 5xx and server time at most 120 ms; client 4xx not counted.",
    objective: 0.9999,
    measured: true,
    not_measured_reason: null,
    probe: false,
    runbook: "RB-03",
    good_within_ms: 120,
    write_good_within_ms: null,
    latency_targets: [all(95, 50), all(99, 120)],
  },
  {
    id: "SLO-02",
    name: "Ingest",
    indicator:
      "POST /v1/events: good when acknowledged (not 5xx) within 150 ms; client 4xx not counted. The synthetic probes' own requests are not counted.",
    objective: 0.9995,
    measured: true,
    not_measured_reason: null,
    probe: false,
    runbook: "RB-02",
    good_within_ms: 150,
    write_good_within_ms: null,
    latency_targets: [all(99, 150)],
  },
  {
    id: "SLO-03",
    name: "Policy distribution",
    indicator:
      "GET /v1/policy-bundle and /v1/signing-key: good when served (not 5xx); client 4xx not counted. The synthetic probes' own requests are not counted.",
    objective: 0.9999,
    measured: true,
    not_measured_reason: null,
    probe: false,
    runbook: "RB-04",
    good_within_ms: null,
    write_good_within_ms: null,
    latency_targets: [],
  },
  {
    id: "SLO-04",
    name: "Event freshness",
    indicator:
      "Each Event stored at ingest: good when published on the live bus within 5 s of being received (PB-13). With the synthetic probes on, also one sample a minute: the probe's marked Event, good when readable through the Events route within 5 s of its request. In the count from receipt to live bus the synthetic probes' own Events are not counted.",
    objective: 0.99,
    measured: true,
    not_measured_reason: null,
    probe: false,
    runbook: "RB-02",
    good_within_ms: 5_000,
    write_good_within_ms: null,
    latency_targets: [all(95, 5_000), all(99, 30_000)],
  },
  {
    id: "SLO-05",
    name: "Detection latency",
    indicator:
      "Each Detection: good when recorded within 10 s of its triggering Event being received (PB-14). The synthetic probes' own Events are not counted: nothing is detected on them.",
    objective: 0.95,
    measured: true,
    not_measured_reason: null,
    probe: false,
    runbook: "RB-02",
    good_within_ms: 10_000,
    write_good_within_ms: null,
    latency_targets: [all(95, 10_000)],
  },
  {
    id: "SLO-06",
    name: "Enforcement propagation",
    indicator:
      "Synthetic probe, once a minute: a marked block Rule published through the Control API, good when the probe's Shield refuses the marked request within 30 s (PB-15); a probe that fails or is given up at 60 s is bad, and so is each cycle of a prober that cannot be set up, from its fourth failed cycle in a row. Measured inside this API instance against one Shield of its own: not per region, and not on every Shield.",
    objective: 0.95,
    measured: false,
    not_measured_reason:
      "Measured by the synthetic probes only, and they are off on this instance. Start the API with AR_PROBES=1 to measure it.",
    probe: true,
    runbook: "RB-04",
    good_within_ms: 30_000,
    write_good_within_ms: null,
    latency_targets: [all(95, 30_000), all(99, 60_000)],
  },
  {
    id: "SLO-07",
    name: "Control API",
    indicator:
      "Other /v1 routes of the admin key: good when not 5xx, reads within 200 ms and writes within 500 ms; client 4xx not counted. The synthetic probes' own requests are not counted.",
    objective: 0.999,
    measured: true,
    not_measured_reason: null,
    probe: false,
    runbook: "RB-07",
    good_within_ms: 200,
    write_good_within_ms: 500,
    latency_targets: [
      { variant: "read", percentile: 95, ms: 200 },
      { variant: "write", percentile: 95, ms: 500 },
    ],
  },
  {
    id: "SLO-08",
    name: "Console",
    indicator: "Console page loads meeting PB-19.",
    objective: 0.999,
    measured: false,
    not_measured_reason:
      "Needs Core Web Vitals (LCP, INP, CLS) measured in a browser; the API and its synthetic probes do not see page loads.",
    probe: false,
    runbook: "RB-07",
    good_within_ms: null,
    write_good_within_ms: null,
    latency_targets: [],
  },
  {
    id: "SLO-09",
    name: "Alert delivery",
    indicator:
      "Each Incident alert per channel: good when delivered within 60 s of the Incident's creation (PB-18); a failed delivery is bad.",
    objective: 0.99,
    measured: true,
    not_measured_reason: null,
    probe: false,
    runbook: "RB-02",
    good_within_ms: 60_000,
    write_good_within_ms: null,
    latency_targets: [all(95, 60_000)],
  },
  {
    id: "SLO-10",
    name: "Prove",
    indicator:
      "Each T1 Assessment: good when it ends with a result (scored or inconclusive) within 30 min of creation (PB-22).",
    objective: 0.95,
    measured: true,
    not_measured_reason: null,
    probe: false,
    runbook: "RB-11",
    good_within_ms: 1_800_000,
    write_good_within_ms: null,
    latency_targets: [all(95, 1_800_000)],
  },
] satisfies SloDefinition[]);

export interface SloBurnRule {
  id: "fast" | "slow" | "ticket";
  severity: "page" | "ticket";
  /** Burn rate (error rate over the error budget rate) at or above which the rule holds. */
  threshold: number;
  long_window: SloBurnWindow;
  /** Confirmation: the rule holds only when this window burns at the threshold too. */
  short_window: SloBurnWindow | null;
}

/**
 * Events a burn rule's long window must hold before the rule may fire (slice 18d review M1; Jev min3, 0.94): one bad
 * event of one (a single failed Prove run) never pages. A rule that fires stays firing until there is evidence that it
 * no longer holds: events in its confirmation window burning below the threshold, or its long window doing so. An
 * empty window is no evidence and keeps the state.
 */
export const SLO_ALERT_MIN_EVENTS = 3;

/** OPERATION §7: page at 14.4× over 1 h (confirmed over 5 m) and 6× over 6 h (30 m); ticket at 1× over 3 d. */
export const SLO_BURN_RULES: readonly SloBurnRule[] = deepFreeze([
  { id: "fast", severity: "page", threshold: 14.4, long_window: "1h", short_window: "5m" },
  { id: "slow", severity: "page", threshold: 6, long_window: "6h", short_window: "30m" },
  { id: "ticket", severity: "ticket", threshold: 1, long_window: "3d", short_window: null },
] satisfies SloBurnRule[]);

/** Relative tolerance of a burn threshold comparison: a burn of exactly 14.4 must not miss it by a rounding error. */
export const SLO_THRESHOLD_TOLERANCE = 1e-9;

/** True when a burn rate is at or over `threshold` (within the tolerance); false without a rate. */
export function atThreshold(value: number | null, threshold: number): boolean {
  return value !== null && value >= threshold * (1 - SLO_THRESHOLD_TOLERANCE);
}

const count = () => z.int().min(0);
const rate = () => z.number().min(0).nullable();

export const SloLatencySchema = z.strictObject({
  variant: z.enum(SLO_VARIANTS),
  percentile: z.union([z.literal(95), z.literal(99)]),
  target_ms: z.number().positive(),
  /** The upper bound of the histogram bucket holding the percentile; null without events or above the last bound. */
  observed_ms: z.number().positive().nullable(),
  /** Null without events. */
  met: z.boolean().nullable(),
});
export type SloLatency = z.infer<typeof SloLatencySchema>;

export const SloAlertSchema = z.strictObject({
  rule: z.enum(["fast", "slow", "ticket"]),
  severity: z.enum(["page", "ticket"]),
  state: z.enum(["firing", "ok"]),
  /** When the current episode started firing; null while ok. */
  since: z.iso.datetime().nullable(),
});
export type SloAlert = z.infer<typeof SloAlertSchema>;

/**
 * One SLO over the rolling 30 days. `attainment`: good / total (null without events). `budget_remaining`: 1 less the
 * fraction of the error budget spent, negative once overspent (null without events). `burn`: error rate over the
 * budget rate (1 − objective) per window (null without events in it). An unmeasured SLO has zeros, nulls and no
 * latency or alerts.
 */
export const SloStatusSchema = z.strictObject({
  id: z.enum(SLO_IDS),
  name: z.string().min(1),
  indicator: z.string().min(1),
  objective: z.number().gt(0).lt(1),
  measured: z.boolean(),
  not_measured_reason: z.string().nullable(),
  runbook: z.string().regex(/^RB-[0-9]{2}$/),
  good: count(),
  total: count(),
  attainment: z.number().min(0).max(1).nullable(),
  budget_remaining: z.number().max(1).nullable(),
  burn: z.strictObject({ "5m": rate(), "30m": rate(), "1h": rate(), "6h": rate(), "3d": rate() }),
  latency: z.array(SloLatencySchema),
  alerts: z.array(SloAlertSchema),
});
export type SloStatus = z.infer<typeof SloStatusSchema>;

/**
 * One leg of a probe cycle. `good`: within its bound. `late`: seen, but after the bound. `timeout`: given up.
 * `failed`: could not be run (the publish was refused, the probe could not be set up). `skipped`: not exercised, as
 * the block leg before it did not succeed; a skipped leg is not an SLI sample. `ms`: the latency, null when there is
 * none (failed before timing began, or skipped).
 */
export const ProbeLegSchema = z.strictObject({
  outcome: z.enum(["good", "late", "timeout", "failed", "skipped"]),
  ms: z.number().min(0).nullable(),
});
export type ProbeLeg = z.infer<typeof ProbeLegSchema>;

/**
 * The synthetic probes of the API instance that answered (slice 18g). The counts are since this process started;
 * the SLO buckets they feed persist. A run failed when its enforcement leg or its freshness leg was not `good`
 * (a skipped freshness leg follows a failed enforcement leg). Nothing here names the probe's Organization.
 */
export const ProbeStatusSchema = z.strictObject({
  interval_s: z.number().positive(),
  runs: count(),
  failures: count(),
  consecutive_failures: count(),
  /**
   * Cycles in a row in which the probe could not be set up at all (its Organization, its Shield or its loopback
   * server). Up to three record no sample; each further one is a bad SLO-06 sample (D-117). 0 once it is set up.
   */
  setup_failures: count(),
  /** When the last cycle ended; null before the first. */
  last_run_at: z.iso.datetime().nullable(),
  /** The last cycle's legs; null before the first. */
  enforcement: ProbeLegSchema.nullable(),
  freshness: ProbeLegSchema.nullable(),
});
export type ProbeStatus = z.infer<typeof ProbeStatusSchema>;

/**
 * `GET /v1/ops/slo`. `scope: "instance"`: the figures of the API instance that answered. `probes`: null when the
 * synthetic probes are off on that instance.
 */
export const SloReportSchema = z.strictObject({
  generated_at: z.iso.datetime(),
  window_days: z.literal(30),
  scope: z.literal("instance"),
  probes: ProbeStatusSchema.nullable(),
  slos: z.array(SloStatusSchema),
});
export type SloReport = z.infer<typeof SloReportSchema>;
