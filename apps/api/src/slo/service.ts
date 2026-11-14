import { SLO_BURN_WINDOWS, SLO_CATALOG, type SloId, type SloReport } from "@antireverse/protocol";
import { signWebhookBody } from "@antireverse/protocol/server";
import type { OwnedDb } from "../db/db.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import { type AlertFetch, pinnedFetch } from "../notify/notifier.ts";
import { checkDestination, defaultResolve, type Resolve, resolveWithin } from "../notify/ssrf.ts";
import {
  type AlertMachine,
  type AlertTransition,
  createAlertMachine,
  episodeId,
  evaluateSlo,
  type SloAggregate,
  signalOf,
} from "./evaluate.ts";
import { createSloRecorder, type SloRecorder } from "./recorder.ts";
import type { OpsWebhook } from "./settings.ts";
import { readSloAggregates, readSloAlerts, saveSloAlertTransitions, sweepSloMinutes } from "./store.ts";

// Slice 18d: the SLO job. Every minute (and on `runOnce`): flush the recorder, read the window sums afresh, sweep
// minutes past the 35 days, step the alert state machine of every measured SLO and rule, and write the rules firing to
// `slo_alerts` (review M2: loaded on the first use after a start, so a restart neither fires a still-holding burn again
// nor forgets to resolve an ended one). For each alert that fired or resolved: one log line (SLO, rule, runbook and
// burn rates: no tenant data exists here) and, if set, a POST to the operator webhook through the alert sender's pinned
// transport, signed like alert-channel webhooks, up to 3 attempts, naming the episode (`<slo>/<rule>/<since>`).
// Reads (`GET /v1/ops/slo`, `GET /metrics`) use an aggregate at most `readCacheMs` old (a scrape does not re-aggregate
// 30 days each time); a fresh one flushes the recorder first. On close (`flush`): the recorder first, then webhook posts
// in flight get at most `closeWaitMs` before they are aborted.

export const SLO_JOB_DEFAULTS = Object.freeze({
  /** Between evaluations: every minute. */
  everyMs: 60_000,
  /** One webhook attempt: lookup, connection and response. */
  timeoutMs: 5_000,
  attempts: 3,
  /** The wait after a failed attempt; doubles after each further one. */
  backoffMs: 1_000,
  /** How old the aggregate served to reads may be. */
  readCacheMs: 15_000,
  /** How long `flush` waits for webhook posts in flight before aborting them. */
  closeWaitMs: 1_500,
});

export interface SloServiceOptions {
  /** The owner's database: `slo_minutes` and `slo_alerts` are owner-only. */
  db: OwnedDb;
  now?: (() => Date) | undefined;
  logger?: Logger | undefined;
  /** Default: a recorder on `db` and `now`. */
  recorder?: SloRecorder | undefined;
  webhook?: OpsWebhook | null | undefined;
  /** Default: `pinnedFetch`, the transport of alert channels. */
  fetch?: AlertFetch | undefined;
  resolve?: Resolve | undefined;
  sleep?: ((ms: number) => Promise<void>) | undefined;
  everyMs?: number | undefined;
  /** Default: `setTimeout`, unref'd. */
  setTimer?: ((fn: () => void, ms: number) => unknown) | undefined;
  clearTimer?: ((handle: unknown) => void) | undefined;
}

export interface SloService {
  recorder: SloRecorder;
  /** Schedules the evaluations; returns `stop`. */
  start(): () => void;
  /** One evaluation now: the alerts that fired or resolved. Never rejects. */
  runOnce(): Promise<AlertTransition[]>;
  /** `GET /v1/ops/slo`. */
  report(): Promise<SloReport>;
  /** `GET /metrics`: Prometheus text format 0.0.4. */
  metrics(): Promise<string>;
  /**
   * Waits for the evaluation in progress, flushes the recorder (on close: the last minute), then gives webhook posts in
   * flight at most `closeWaitMs` and aborts the rest.
   */
  flush(): Promise<void>;
}

const defaultSetTimer = (fn: () => void, ms: number): unknown => {
  const timer = setTimeout(fn, ms);
  timer.unref?.();
  return timer;
};
const defaultClearTimer = (handle: unknown): void => clearTimeout(handle as ReturnType<typeof setTimeout>);
const defaultSleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms).unref?.());

const USER_AGENT = "Airverse-Ops/1";

/** A burn rate for a log line: two decimals, no trailing zeros; `none` without events. */
const rateText = (rate: number | null): string => (rate === null ? "none" : String(Number(rate.toFixed(2))));

/** A number in Prometheus text: NaN for none. */
const sample = (value: number | null): string => (value === null ? "NaN" : String(value));

export function createSloService(options: SloServiceOptions): SloService {
  const { db } = options;
  const now = options.now ?? (() => new Date());
  const logger = redacting(options.logger ?? consoleLogger);
  const recorder = options.recorder ?? createSloRecorder({ db, now });
  const webhook = options.webhook ?? null;
  const fetch = options.fetch ?? pinnedFetch;
  const resolve = options.resolve ?? defaultResolve;
  const sleep = options.sleep ?? defaultSleep;
  const everyMs = options.everyMs ?? SLO_JOB_DEFAULTS.everyMs;
  const setTimer = options.setTimer ?? defaultSetTimer;
  const clearTimer = options.clearTimer ?? defaultClearTimer;
  const sending = new Set<Promise<void>>();
  /** Aborts webhook posts (and their waits) on close. */
  const stop = new AbortController();
  let running: Promise<AlertTransition[]> | undefined;
  let machine: Promise<AlertMachine> | undefined;
  let cached: { at: Date; aggregates: Map<SloId, SloAggregate> } | undefined;

  const errorName = (error: unknown) => (error as Error)?.name ?? "Error";

  /** The alert machine, with the rules that were firing when the process last stopped. */
  function alerts(): Promise<AlertMachine> {
    machine ??= db
      .owner((q) => readSloAlerts(q))
      .then(
        (firing) => createAlertMachine(firing),
        (error: unknown) => {
          machine = undefined;
          throw error;
        },
      );
    return machine;
  }

  async function flushQuietly(): Promise<void> {
    try {
      await recorder.flush();
    } catch (error) {
      logger.warn(`slo flush error ${errorName(error)}`);
    }
  }

  /** The aggregates at `at`: afresh (after a flush), or for reads the cached ones if at most `readCacheMs` old. */
  async function aggregates(at: Date, fresh: boolean): Promise<{ at: Date; aggregates: Map<SloId, SloAggregate> }> {
    const age = cached === undefined ? Number.POSITIVE_INFINITY : at.getTime() - cached.at.getTime();
    if (!fresh && cached !== undefined && age >= 0 && age <= SLO_JOB_DEFAULTS.readCacheMs) return cached;
    await flushQuietly();
    cached = { at, aggregates: await db.owner((q) => readSloAggregates(q, at.getTime())) };
    return cached;
  }

  const sleepOrStop = (ms: number) =>
    stop.signal.aborted
      ? Promise.resolve()
      : Promise.race([sleep(ms), new Promise<void>((done) => stop.signal.addEventListener("abort", () => done()))]);

  /** One POST, up to the attempts; logs the outcome by status only. */
  async function post(transition: AlertTransition, hook: OpsWebhook): Promise<void> {
    const def = SLO_CATALOG.find((entry) => entry.id === transition.slo);
    const body = JSON.stringify({
      type: "slo.alert",
      state: transition.state,
      episode: episodeId(transition.slo, transition.rule.id, transition.since),
      slo: transition.slo,
      name: def?.name ?? transition.slo,
      rule: transition.rule.id,
      severity: transition.rule.severity,
      threshold: transition.rule.threshold,
      long_window: transition.rule.long_window,
      short_window: transition.rule.short_window,
      burn: transition.burn,
      runbook: def?.runbook ?? null,
      since: transition.since.toISOString(),
      at: transition.at.toISOString(),
    });
    let status: number | null = null;
    let attempt = 0;
    while (attempt < SLO_JOB_DEFAULTS.attempts && !stop.signal.aborted) {
      attempt++;
      const signal = AbortSignal.any([AbortSignal.timeout(SLO_JOB_DEFAULTS.timeoutMs), stop.signal]);
      status = null;
      try {
        const check = await checkDestination(hook.url, { resolve: resolveWithin(resolve, signal), allowPrivate: true });
        if (check.ok) {
          const headers: Record<string, string> = { "content-type": "application/json", "user-agent": USER_AGENT };
          if (hook.secret !== null) {
            const t = Math.floor(now().getTime() / 1_000);
            headers["ar-signature"] = `t=${t},v1=${signWebhookBody(hook.secret, t, body)}`;
          }
          const response = await fetch(hook.url, { method: "POST", headers, body, redirect: "manual", signal }, check);
          await response.body?.cancel().catch(() => {});
          status = response.status;
        }
      } catch {
        status = null;
      }
      if (status !== null && status >= 200 && status < 300) {
        logger.info(
          `slo webhook slo=${transition.slo} rule=${transition.rule.id} state=${transition.state} attempt=${attempt} outcome=delivered status=${status}`,
        );
        return;
      }
      if (attempt < SLO_JOB_DEFAULTS.attempts) await sleepOrStop(SLO_JOB_DEFAULTS.backoffMs * 2 ** (attempt - 1));
    }
    logger.warn(
      `slo webhook slo=${transition.slo} rule=${transition.rule.id} state=${transition.state} attempt=${attempt} outcome=${stop.signal.aborted ? "aborted" : "failed"} status=${status ?? "none"}`,
    );
  }

  async function run(): Promise<AlertTransition[]> {
    const at = now();
    const transitions: AlertTransition[] = [];
    try {
      const machineNow = await alerts();
      const { aggregates: current } = await aggregates(at, true);
      await db.owner((q) => sweepSloMinutes(q, at));
      for (const def of SLO_CATALOG) {
        if (!def.measured) continue;
        transitions.push(...machineNow.update(def.id, signalOf(def, current.get(def.id)), at));
      }
      if (transitions.length > 0) await db.owner((q) => saveSloAlertTransitions(q, transitions));
    } catch (error) {
      logger.warn(`slo evaluation error ${errorName(error)}`);
      return transitions;
    }
    for (const t of transitions) {
      const def = SLO_CATALOG.find((entry) => entry.id === t.slo);
      const line = `slo alert ${t.state} slo=${t.slo} rule=${t.rule.id} severity=${t.rule.severity} runbook=${def?.runbook} burn_long=${rateText(t.burn[t.rule.long_window])}${t.rule.short_window === null ? "" : ` burn_short=${rateText(t.burn[t.rule.short_window])}`}`;
      if (t.state === "firing") logger.warn(line);
      else logger.info(line);
      if (webhook !== null && !stop.signal.aborted) {
        const sent = post(t, webhook).catch((error: unknown) => logger.warn(`slo webhook error ${errorName(error)}`));
        sending.add(sent);
        void sent.finally(() => sending.delete(sent));
      }
    }
    return transitions;
  }

  function runOnce(): Promise<AlertTransition[]> {
    running ??= run().finally(() => {
      running = undefined;
    });
    return running;
  }

  async function report(): Promise<SloReport> {
    const machineNow = await alerts();
    const { at, aggregates: current } = await aggregates(now(), false);
    return {
      generated_at: at.toISOString(),
      window_days: 30,
      scope: "instance",
      slos: SLO_CATALOG.map((def) => ({
        ...evaluateSlo(def, def.measured ? current.get(def.id) : undefined),
        alerts: def.measured ? machineNow.states(def.id) : [],
      })),
    };
  }

  async function metrics(): Promise<string> {
    const r = await report();
    const measured = r.slos.filter((s) => s.measured);
    const lines: string[] = [];
    const gauge = (name: string, help: string, rows: [string, number | null][]) => {
      lines.push(`# HELP ${name} ${help}`, `# TYPE ${name} gauge`);
      for (const [labels, value] of rows) lines.push(`${name}{${labels}} ${sample(value)}`);
    };
    const bySlo = (pick: (s: (typeof measured)[number]) => number | null): [string, number | null][] =>
      measured.map((s) => [`slo="${s.id}"`, pick(s)]);
    gauge(
      "airverse_slo_objective",
      "The 30-day objective, as a fraction.",
      bySlo((s) => s.objective),
    );
    gauge(
      "airverse_slo_good",
      "Good events over the rolling 30 days (this instance).",
      bySlo((s) => s.good),
    );
    gauge(
      "airverse_slo_total",
      "Counted events over the rolling 30 days (this instance).",
      bySlo((s) => s.total),
    );
    gauge(
      "airverse_slo_attainment",
      "Good over total, rolling 30 days; NaN without events.",
      bySlo((s) => s.attainment),
    );
    gauge(
      "airverse_slo_error_budget_remaining",
      "1 less the fraction of the 30-day error budget spent; negative when overspent.",
      bySlo((s) => s.budget_remaining),
    );
    gauge(
      "airverse_slo_burn_rate",
      "Error rate over the budget rate (1 - objective) per window; NaN without events.",
      measured.flatMap((s) =>
        SLO_BURN_WINDOWS.map((w): [string, number | null] => [`slo="${s.id}",window="${w}"`, s.burn[w]]),
      ),
    );
    gauge(
      "airverse_slo_alert_firing",
      "1 while the burn rule fires.",
      measured.flatMap((s) =>
        s.alerts.map((a): [string, number] => [
          `slo="${s.id}",rule="${a.rule}",severity="${a.severity}"`,
          a.state === "firing" ? 1 : 0,
        ]),
      ),
    );
    return `${lines.join("\n")}\n`;
  }

  return {
    recorder,
    start() {
      let stopped = false;
      let handle: unknown;
      const schedule = () => {
        if (stopped) return;
        handle = setTimer(() => {
          if (stopped) return;
          void runOnce().finally(schedule);
        }, everyMs);
      };
      schedule();
      return () => {
        stopped = true;
        clearTimer(handle);
      };
    },
    runOnce,
    report,
    metrics,
    async flush() {
      while (running !== undefined) await running.catch(() => {});
      await flushQuietly();
      if (sending.size === 0) return;
      let timer: ReturnType<typeof setTimeout> | undefined;
      const bound = new Promise<void>((done) => {
        timer = setTimeout(done, SLO_JOB_DEFAULTS.closeWaitMs);
      });
      await Promise.race([Promise.allSettled([...sending]), bound]);
      clearTimeout(timer);
      if (sending.size > 0) {
        stop.abort();
        await Promise.allSettled([...sending]);
      }
    },
  };
}
