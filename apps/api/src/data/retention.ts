import { USAGE_DEVICE_DAILY_CAP, usageMonthOf } from "@antireverse/protocol";
import type { OwnedDb } from "../db/db.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import { sweepCampaigns } from "../stores/campaigns.ts";
import {
  expireArtifactsByOrganization,
  recordRetentionRun,
  type SweepCounts,
  sweepRetention,
} from "../stores/retention.ts";
import { rollupUsage } from "../stores/usage.ts";
import type { UsageSalts } from "../usage/salts.ts";

// The daily retention job (slice 18c): makes the SECURITY §8 periods true for the data Airverse holds. Each run takes
// one instant `at` and calls the owner-only `retention_sweep` (migration 0035) — one owner transaction per call, each
// step bounded by `batch` rows shared fairly over a rotating window of Organizations — until a series of calls in
// which no Organization used its whole share has covered every Organization, or `maxCallsPerRun` calls were made; a
// run cut short continues at the next run and is logged as a warning. Then it expires the protected artifacts past
// their keep date (counted per Organization), rolls up usage (slice 17a: closes the months that ended, deleting their
// device references, and removes usage older than 13 months; called until done within a budget of its own, then the
// closed months' salts are forgotten),
// and records one run row per Organization it swept (every Organization whose deletion is not pending, with its counts,
// none included, so that each sees when the job last ran), keeping the 30 most recent. Runs in process on a timer:
// first `firstRunMs` after the start, then every `everyMs`. It holds nothing per Organization in memory. Log lines
// carry counts and error kinds only, never an identifier.

/** How a tenant table is treated by retention: swept by a rule, or kept for a reason. */
export type RetentionClass = { rule: string } | { reason: string };

/**
 * Every table of `public` with an `organization_id` column, as swept (its rule) or kept (why). A test compares it
 * with the catalog: a table added later fails it until it is classified here.
 */
export const RETENTION_CLASSES: Readonly<Record<string, RetentionClass>> = Object.freeze({
  events: {
    rule: "received before the Organization's Event retention; Events carrying a Guard report after at most 30 days",
  },
  containments: { rule: "ended (lifted, else expired) longer ago than the Organization's Event retention" },
  incidents: {
    rule: "last activity older than 395 days, with their Detections and alert deliveries first; kept while any containment still names them",
  },
  detections: { rule: "with their Incident (395 days after its last activity)" },
  alert_deliveries: { rule: "older than 395 days, or with their Incident" },
  assessments: { rule: "finished (scored, inconclusive or failed) more than 395 days ago" },
  artifacts: { rule: "30 days after the last Assessment that used them (the artifact expiry of 0026/0028)" },
  artifact_files: { rule: "with their artifact (cascade)" },
  campaigns: { rule: "ended (completed, stopped, refused, failed or interrupted) more than 395 days ago (slice 15a)" },
  campaign_requests: { rule: "with their Campaign (cascade): 395 days after it ended" },
  campaign_findings: { rule: "with their Campaign (cascade): 395 days after it ended" },
  retention_runs: { rule: "the 30 most recent runs per Organization are kept" },
  usage_daily: { rule: "13 months of usage history: days before the 13th month before the current one" },
  usage_device_days: { rule: "with its month's rollup, once the month is closed (slice 17a)" },
  usage_devices: {
    rule: "the device references of a month, once the month is closed and its distinct count rolled up (slice 17a)",
  },
  usage_monthly_devices: { rule: "13 months of usage history: months before the 13th month before the current one" },
  setup_milestones: {
    reason:
      "one row per App Environment: when its Shield and Guard set-up steps were first done, kept once the Events are gone",
  },
  organization_deletions: { reason: "the owner's deletion requests and tombstones: they outlive the Organization" },
  api_keys: { reason: "configuration: the Organization's keys, revoked ones as the audit's actors" },
  apps: { reason: "configuration: the Organization's Apps" },
  builds: { reason: "a Build has no end of life yet; old Builds still serve clone beacons and Canary lookups" },
  build_beacons: { reason: "with its Build (Builds are not pruned)" },
  build_routes: { reason: "with its Build (Builds are not pruned)" },
  build_logic: { reason: "with its Build (Builds are not pruned)" },
  canaries: { reason: "with its Build: Canary lookups must find old Builds' values" },
  inventories: { reason: "the current component inventory; replaced in place, expired instances deleted on write" },
  findings: { reason: "the current exposure; closed runtime Findings are deleted 30 days after they close (slice 19)" },
  policy_versions: { reason: "configuration: the Policy history that rollback and the audit refer to" },
  patch_modes: { reason: "configuration: one mode per virtual patch and Environment" },
  allowlist_entries: { reason: "configuration: removed by the Organization" },
  alert_channels: { reason: "configuration: removed by the Organization" },
  alert_recipients: { reason: "configuration: removed with their channel" },
  targets: { reason: "configuration: removed by the Organization" },
  verify_limits: { reason: "one counter per host, reset by the next attempt after its window" },
  rules_of_engagement: { reason: "signed authorisations: kept as the evidence of what testing was allowed" },
  audit_entries: {
    reason: "the audit log, kept for the Organization's lifetime (pruning would need a verify checkpoint)",
  },
  audit_heads: { reason: "the head of the audit chain" },
});

export const RETENTION_DEFAULTS = Object.freeze({
  /** Between runs: daily. */
  everyMs: 86_400_000,
  /** The first run after the start (after the purge's, so that a due purge goes first). */
  firstRunMs: 120_000,
  /** Rows per table per call: one call holds its locks briefly. */
  batch: 1000,
  /** Calls per run; the rest waits for the next run. */
  maxCallsPerRun: 200,
  /** Device references (and old usage rows) per usage rollup call. */
  usageBatch: 5_000,
  /**
   * Usage rollup calls per run, its own budget (review M2): enough for one App's month at the daily cap (31 days of
   * `USAGE_DEVICE_DAILY_CAP` new references) in one run.
   */
  usageMaxCallsPerRun: Math.ceil((USAGE_DEVICE_DAILY_CAP * 31) / 5_000),
});

export interface RetentionResult {
  /** Sweep calls made. */
  calls: number;
  /** True when every Organization was swept to the end; false when the run stopped at its cap or on an error. */
  complete: boolean;
  /** Rows removed per table, over every Organization (tables with none left out), `artifacts` included. */
  rows: Record<string, number>;
  /** Errors of ours (database); what was removed before stays removed, and the next run continues. */
  failed: number;
}

export interface RetentionOptions {
  /** The owner's database: the sweep function is the owner's only. */
  db: OwnedDb;
  now?: (() => Date) | undefined;
  logger?: Logger | undefined;
  everyMs?: number;
  firstRunMs?: number;
  batch?: number;
  maxCallsPerRun?: number;
  /** The month salts of the Guard device references: the closed months' are forgotten after the rollup. */
  usageSalts?: UsageSalts | undefined;
  usageBatch?: number;
  usageMaxCallsPerRun?: number;
  /** Default: `setTimeout`, unref'd so that the timer never keeps the process alive. */
  setTimer?: (fn: () => void, ms: number) => unknown;
  clearTimer?: (handle: unknown) => void;
}

export interface RetentionJob {
  /** Schedules the runs; returns `stop`, which cancels the next run (a run in progress finishes; see `flush`). */
  start(): () => void;
  /** One run now. Never rejects. */
  runOnce(): Promise<RetentionResult>;
  /** Resolves when the run in progress, if any, has finished. */
  flush(): Promise<void>;
}

const defaultSetTimer = (fn: () => void, ms: number): unknown => {
  const timer = setTimeout(fn, ms);
  timer.unref?.();
  return timer;
};
const defaultClearTimer = (handle: unknown): void => clearTimeout(handle as ReturnType<typeof setTimeout>);

function addCounts(into: SweepCounts, from: SweepCounts): void {
  for (const [organizationId, tables] of Object.entries(from)) {
    const target = into[organizationId] ?? {};
    for (const [table, n] of Object.entries(tables)) target[table] = (target[table] ?? 0) + n;
    into[organizationId] = target;
  }
}

function totals(counts: SweepCounts): Record<string, number> {
  const sum: Record<string, number> = {};
  for (const tables of Object.values(counts)) {
    for (const [table, n] of Object.entries(tables)) if (n > 0) sum[table] = (sum[table] ?? 0) + n;
  }
  return sum;
}

export function createRetentionJob(options: RetentionOptions): RetentionJob {
  const { db } = options;
  const now = options.now ?? (() => new Date());
  const logger = redacting(options.logger ?? consoleLogger);
  const everyMs = options.everyMs ?? RETENTION_DEFAULTS.everyMs;
  const firstRunMs = options.firstRunMs ?? RETENTION_DEFAULTS.firstRunMs;
  const batch = Math.max(1, Math.floor(options.batch ?? RETENTION_DEFAULTS.batch));
  const maxCallsPerRun = Math.max(1, Math.floor(options.maxCallsPerRun ?? RETENTION_DEFAULTS.maxCallsPerRun));
  const usageBatch = Math.max(1, Math.floor(options.usageBatch ?? RETENTION_DEFAULTS.usageBatch));
  const usageMaxCallsPerRun = Math.max(
    1,
    Math.floor(options.usageMaxCallsPerRun ?? RETENTION_DEFAULTS.usageMaxCallsPerRun),
  );
  const setTimer = options.setTimer ?? defaultSetTimer;
  const clearTimer = options.clearTimer ?? defaultClearTimer;

  let running: Promise<RetentionResult> | undefined;

  const errorName = (error: unknown) => (error as Error)?.name ?? "Error";

  async function run(): Promise<RetentionResult> {
    const at = now();
    const counts: SweepCounts = {};
    const result: RetentionResult = { calls: 0, complete: false, rows: {}, failed: 0 };
    // Organizations covered by consecutive calls in which no Organization used its whole share.
    let clean = 0;
    let done = false;
    try {
      while (!done && result.calls < maxCallsPerRun) {
        const swept = await db.owner((q) => sweepRetention(q, at, batch));
        result.calls++;
        addCounts(counts, swept.rows);
        clean = swept.saturated ? 0 : clean + swept.window;
        done = clean >= swept.organizations;
      }
      result.complete = done;
    } catch (error) {
      result.failed++;
      logger.warn(`retention sweep error ${errorName(error)}`);
    }
    try {
      const artifacts = await db.owner((q) => expireArtifactsByOrganization(q, at));
      addCounts(
        counts,
        Object.fromEntries(Object.entries(artifacts).map(([organizationId, n]) => [organizationId, { artifacts: n }])),
      );
    } catch (error) {
      result.failed++;
      logger.warn(`retention artifact expiry error ${errorName(error)}`);
    }
    try {
      // Pentest Campaigns (slice 15a): 395 days after they ended, with their request log and Findings.
      const campaigns = await db.owner((q) => sweepCampaigns(q, at, batch));
      addCounts(
        counts,
        Object.fromEntries(Object.entries(campaigns).map(([organizationId, n]) => [organizationId, { campaigns: n }])),
      );
    } catch (error) {
      result.failed++;
      logger.warn(`retention campaign sweep error ${errorName(error)}`);
    }
    try {
      // Usage (slice 17a): the monthly rollup and the 13-month sweep, until a call leaves nothing, within its own
      // budget. Its first call writes the closed months' counts, so their salts can go after it (review M3).
      let more = true;
      for (let call = 0; more && call < usageMaxCallsPerRun; call++) {
        const rolled = await db.owner((q) => rollupUsage(q, at, usageBatch));
        addCounts(counts, rolled.rows);
        more = rolled.saturated;
      }
      if (more) result.complete = false;
      options.usageSalts?.forgetBefore(usageMonthOf(new Date(at.getTime() - 3_600_000)));
    } catch (error) {
      result.failed++;
      logger.warn(`retention usage rollup error ${errorName(error)}`);
    }
    try {
      await db.owner((q) => recordRetentionRun(q, at, counts, result.complete));
    } catch (error) {
      result.failed++;
      logger.warn(`retention record error ${errorName(error)}`);
    }
    result.rows = totals(counts);
    const removed = Object.entries(result.rows)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))
      .map(([table, n]) => `${table}=${n}`)
      .join(" ");
    const line = `calls=${result.calls} complete=${result.complete} failed=${result.failed}${removed === "" ? "" : ` ${removed}`}`;
    if (result.complete) logger.info(`retention run ${line}`);
    // Cut short (call cap or error): the rest waits for the next run. Operators should see a backlog that persists.
    else logger.warn(`retention run incomplete ${line}`);
    return result;
  }

  function runOnce(): Promise<RetentionResult> {
    // One run at a time.
    running ??= run().finally(() => {
      running = undefined;
    });
    return running;
  }

  return {
    start() {
      let stopped = false;
      let handle: unknown;
      const schedule = (ms: number) => {
        if (stopped) return;
        handle = setTimer(() => {
          if (stopped) return;
          void runOnce().finally(() => schedule(everyMs));
        }, ms);
      };
      schedule(firstRunMs);
      return () => {
        stopped = true;
        clearTimer(handle);
      };
    },
    runOnce,
    async flush() {
      while (running !== undefined) await running.catch(() => {});
    },
  };
}
