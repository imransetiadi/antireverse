import {
  SLO_BURN_RULES,
  SLO_BURN_WINDOWS,
  type SloAlert,
  type SloBurnWindow,
  type SloLatency,
  type SloStatus,
} from "@antireverse/protocol";
import { Icon, type IconName } from "@/components/icons.tsx";
import { formatCount, formatDateTime } from "@/lib/format.ts";
import { type MessageKey, t } from "@/lib/t.ts";
import { formatBurn, formatDuration, formatObjective, formatPercent } from "./format.ts";
import { burnsOver, isOverspent, type SloState, sloState, windowThreshold } from "./state.ts";

const STATUS: Record<SloState, { key: MessageKey; icon: IconName; className: string }> = {
  firing: {
    key: "ops.status.firing",
    icon: "warning-octagon",
    className: "border-sev-critical-text text-sev-critical-text",
  },
  "objective-missed": {
    key: "ops.status.missed",
    icon: "warning-circle",
    className: "border-sev-medium text-sev-medium",
  },
  ok: { key: "ops.status.ok", icon: "check-circle", className: "border-primary text-primary" },
  "no-traffic": {
    key: "ops.status.noTraffic",
    icon: "hourglass-medium",
    className: "border-border-strong text-fg-muted",
  },
  "not-measured": {
    key: "ops.status.notMeasured",
    icon: "circle-dashed",
    className: "border-border-strong text-fg-muted",
  },
};

const WINDOW_LABEL: Record<SloBurnWindow, MessageKey> = {
  "5m": "ops.window.5m",
  "30m": "ops.window.30m",
  "1h": "ops.window.1h",
  "6h": "ops.window.6h",
  "3d": "ops.window.3d",
};

const HEAD = "h-10 px-2 sm:px-3 text-start caption-1 text-fg-muted whitespace-nowrap";
const HEAD_NUMBER = "h-10 px-2 sm:px-3 text-end caption-1 text-fg-muted whitespace-nowrap";
const CELL = "h-10 px-2 py-2 sm:px-3 align-middle";
const NUMBER = `${CELL} text-end code-2 whitespace-nowrap`;
const SUBTITLE = "heading-6 text-fg";

/** The state word of an SLO: an icon, a word and a border — never colour alone (UIUX.md §4.2). */
function StatusTag({ state }: { state: SloState }) {
  const { key, icon, className } = STATUS[state];
  return (
    <span className={`inline-flex items-center gap-1 rounded-control border px-2 py-0.5 caption-1 ${className}`}>
      <Icon name={icon} className="size-4" />
      <span data-testid="slo-status">{t(key)}</span>
    </span>
  );
}

/**
 * The error budget left as a meter (dataviz: one value against its whole, the accent while some is left; overspent
 * fills the track in the critical colour). The words beside it carry the value; the meter is decorative.
 */
function BudgetMeter({ remaining }: { remaining: number }) {
  const share = Math.min(Math.max(remaining, 0), 1) * 100;
  const overspent = isOverspent(remaining);
  return (
    <div aria-hidden="true" className="h-2 w-full overflow-hidden rounded-full bg-muted">
      <div
        data-testid="slo-budget-bar"
        className={`h-full rounded-full ${overspent ? "bg-sev-critical-text" : "bg-primary"}`}
        style={{ width: `${overspent ? 100 : share}%` }}
      />
    </div>
  );
}

function Budget({ slo }: { slo: SloStatus }) {
  const remaining = slo.budget_remaining;
  if (remaining === null) {
    return (
      <dd data-testid="slo-budget" data-overspent="false" className="body-4 text-fg-muted">
        {t("ops.budget.none")}
      </dd>
    );
  }
  const overspent = isOverspent(remaining);
  return (
    <dd data-testid="slo-budget" data-overspent={String(overspent)} className="flex flex-col gap-1">
      <span className={`title-4 tabular-nums ${overspent ? "text-sev-critical-text" : "text-fg"}`}>
        {overspent
          ? t("ops.budget.overspent", { pct: formatPercent(-remaining, 1) })
          : t("ops.budget.left", { pct: formatPercent(Math.max(remaining, 0), 1) })}
      </span>
      <BudgetMeter remaining={remaining} />
    </dd>
  );
}

/**
 * Burn rates per window, each against the threshold of the rule that uses the window. A grid of five that wraps on a
 * narrow screen; a rate at or over its threshold carries an icon and words as well as the critical colour.
 */
function BurnRates({ slo }: { slo: SloStatus }) {
  return (
    <section aria-label={t("ops.burn.title")} className="flex flex-col gap-2">
      <h3 className={SUBTITLE}>{t("ops.burn.title")}</h3>
      <p className="body-5 text-fg-muted">{t("ops.burn.lead")}</p>
      <dl data-testid="slo-burn" className="grid grid-cols-2 gap-2 sm:grid-cols-3 lg:grid-cols-5">
        {SLO_BURN_WINDOWS.map((window) => {
          const rate = slo.burn[window];
          const { threshold, severity } = windowThreshold(window);
          const over = burnsOver(rate, window);
          return (
            <div
              key={window}
              className={`flex flex-col gap-1 rounded-control border px-3 py-2 ${over ? "border-sev-critical-text" : "border-border"}`}
            >
              <dt className="flex flex-col">
                <span className="body-5 text-fg">{t(WINDOW_LABEL[window])}</span>
                <span className="body-5 text-fg-subtle">
                  {t(severity === "page" ? "ops.burn.threshold" : "ops.burn.threshold.ticket", { threshold })}
                </span>
              </dt>
              <dd
                data-testid={`slo-burn-${window}`}
                data-over={String(over)}
                className={`flex flex-col ${over ? "text-sev-critical-text" : rate === null ? "text-fg-muted" : "text-fg"}`}
              >
                {rate === null ? (
                  <span className="body-5">{t("ops.burn.none")}</span>
                ) : (
                  <>
                    <span className="code-1 whitespace-nowrap">{formatBurn(rate)}</span>
                    {over ? (
                      <span className="inline-flex items-center gap-1 body-5">
                        <Icon name="warning-octagon" className="size-3" />
                        {t("ops.burn.over", { threshold })}
                      </span>
                    ) : null}
                  </>
                )}
              </dd>
            </div>
          );
        })}
      </dl>
    </section>
  );
}

function percentileLabel(row: SloLatency): string {
  const variant = t(`ops.latency.variant.${row.variant}`);
  return variant === "" ? `p${row.percentile}` : `p${row.percentile} ${variant}`;
}

function observedOf(row: SloLatency, total: number): string {
  if (row.observed_ms !== null) return formatDuration(row.observed_ms);
  // Null with events: above the histogram's last bound, which the API judged missed.
  return row.met === false && total > 0 ? t("ops.latency.above", { ms: formatDuration(row.target_ms) }) : "—";
}

function LatencyTable({ slo }: { slo: SloStatus }) {
  return (
    <section aria-label={t("ops.latency.title")} className="flex flex-col gap-2">
      <h3 className={SUBTITLE}>{t("ops.latency.title")}</h3>
      <section
        aria-label={t("ops.latency.caption", { name: slo.name })}
        // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
        tabIndex={0}
        className="overflow-x-auto"
      >
        <table data-testid="slo-latency" className="w-full border-collapse text-start body-5">
          <caption className="sr-only">{t("ops.latency.caption", { name: slo.name })}</caption>
          <thead>
            <tr className="border-border border-b">
              <th scope="col" className={HEAD}>
                {t("ops.latency.col.percentile")}
              </th>
              <th scope="col" className={HEAD_NUMBER}>
                {t("ops.latency.col.target")}
              </th>
              <th scope="col" className={HEAD_NUMBER}>
                {t("ops.latency.col.observed")}
              </th>
              <th scope="col" className={HEAD}>
                {t("ops.latency.col.result")}
              </th>
            </tr>
          </thead>
          <tbody>
            {slo.latency.map((row) => (
              <tr
                key={`${row.variant}-${row.percentile}`}
                data-testid="slo-latency-row"
                data-met={row.met === null ? "none" : String(row.met)}
                className="border-border border-b"
              >
                <th scope="row" className={`${CELL} text-start code-2 whitespace-nowrap text-fg`}>
                  {percentileLabel(row)}
                </th>
                <td className={`${NUMBER} text-fg`}>{formatDuration(row.target_ms)}</td>
                <td className={`${NUMBER} ${row.met === false ? "text-sev-critical-text" : "text-fg"}`}>
                  {observedOf(row, slo.total)}
                </td>
                <td className={CELL}>
                  {row.met === null ? (
                    <span className="text-fg-muted">{t("ops.latency.none")}</span>
                  ) : row.met ? (
                    <span className="inline-flex items-center gap-1 text-fg">
                      <Icon name="check-circle" className="size-4 text-primary" />
                      {t("ops.latency.met")}
                    </span>
                  ) : (
                    <span className="inline-flex items-center gap-1 text-sev-critical-text">
                      <Icon name="warning-octagon" className="size-4" />
                      {t("ops.latency.missed")}
                    </span>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </section>
  );
}

function ruleText(alert: SloAlert): string {
  const rule = SLO_BURN_RULES.find((entry) => entry.id === alert.rule);
  if (rule === undefined) return alert.rule;
  return t(`ops.alert.${rule.id}`, {
    threshold: rule.threshold,
    long: t(WINDOW_LABEL[rule.long_window]),
    short: rule.short_window === null ? "" : t(WINDOW_LABEL[rule.short_window]),
  });
}

function Alerts({ slo }: { slo: SloStatus }) {
  return (
    <section aria-label={t("ops.alerts.title")} className="flex flex-col gap-2">
      <h3 className={SUBTITLE}>{t("ops.alerts.title")}</h3>
      <ul className="flex flex-col gap-1">
        {slo.alerts.map((alert) => {
          const firing = alert.state === "firing";
          return (
            <li
              key={alert.rule}
              data-testid="slo-alert"
              data-rule={alert.rule}
              data-state={alert.state}
              className="flex flex-wrap items-center gap-x-3 gap-y-1 body-5"
            >
              <span className="caption-1 rounded-control border border-border-strong px-2 py-0.5 text-fg">
                {t(alert.severity === "page" ? "ops.alert.severity.page" : "ops.alert.severity.ticket")}
              </span>
              <span className="text-fg">{ruleText(alert)}</span>
              {firing ? (
                <span className="inline-flex items-center gap-1 title-5 text-sev-critical-text">
                  <Icon name="warning-octagon" className="size-4" />
                  {alert.since === null ? (
                    t("ops.alert.firingNow")
                  ) : (
                    <time dateTime={alert.since}>
                      {t("ops.alert.firing", { time: formatDateTime(alert.since).text })}
                    </time>
                  )}
                </span>
              ) : (
                <span className="text-fg-muted">{t("ops.alert.ok")}</span>
              )}
            </li>
          );
        })}
      </ul>
    </section>
  );
}

/** One SLO over the rolling 30 days (slice 18d): what it measures, how it did, its budget, burn, latency and alerts. */
export function SloPanel({ slo }: { slo: SloStatus }) {
  const state = sloState(slo);
  const titleId = `slo-${slo.id}-title`;
  return (
    <section
      aria-labelledby={titleId}
      data-testid="slo-panel"
      data-slo-id={slo.id}
      data-state={state}
      className={`flex flex-col gap-4 rounded-card border bg-surface p-4 ${state === "firing" ? "border-sev-critical-text" : "border-border"}`}
    >
      <div className="flex flex-wrap items-start justify-between gap-2">
        <h2 id={titleId} className="flex flex-wrap items-baseline gap-2 heading-4">
          <span>{slo.name}</span>
          <span className="code-2 text-fg-muted">{slo.id}</span>
        </h2>
        <StatusTag state={state} />
      </div>
      <p data-testid="slo-indicator" className="max-w-3xl body-5 text-fg-muted">
        {slo.indicator}
      </p>
      {slo.measured ? null : (
        <p data-testid="slo-not-measured" className="max-w-3xl body-4 text-fg">
          {t("ops.notMeasured", { reason: slo.not_measured_reason ?? "" })}
        </p>
      )}
      <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-4">
        <div className="flex flex-col gap-1">
          <dt className="body-5 text-fg-muted">{t("ops.objective")}</dt>
          <dd data-testid="slo-objective" className="title-4 text-fg tabular-nums">
            {formatObjective(slo.objective)}
          </dd>
        </div>
        {slo.measured ? (
          <>
            <div className="flex flex-col gap-1">
              <dt className="body-5 text-fg-muted">{t("ops.attainment")}</dt>
              <dd
                data-testid="slo-attainment"
                className={`title-4 tabular-nums ${
                  isOverspent(slo.budget_remaining) ? "text-sev-critical-text" : "text-fg"
                }`}
              >
                {slo.attainment === null ? t("ops.noTraffic") : formatPercent(slo.attainment, 3)}
              </dd>
              <dd data-testid="slo-counts" className="body-5 text-fg-muted tabular-nums">
                {t("ops.counts", { good: formatCount(slo.good), total: formatCount(slo.total) })}
              </dd>
            </div>
            <div className="flex flex-col gap-1">
              <dt className="body-5 text-fg-muted">{t("ops.budget")}</dt>
              <Budget slo={slo} />
            </div>
          </>
        ) : null}
        <div className="flex flex-col gap-1">
          <dt className="body-5 text-fg-muted">{t("ops.runbook")}</dt>
          <dd data-testid="slo-runbook" className="code-2 text-fg">
            {slo.runbook}
          </dd>
        </div>
      </dl>
      {slo.measured ? <BurnRates slo={slo} /> : null}
      {slo.latency.length > 0 ? <LatencyTable slo={slo} /> : null}
      {slo.alerts.length > 0 ? <Alerts slo={slo} /> : null}
    </section>
  );
}
