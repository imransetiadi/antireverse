import type { UsageDay } from "@antireverse/protocol";
import { formatCount } from "@/lib/format.ts";
import { t } from "@/lib/t.ts";
import { monthName } from "./query.ts";

interface DailyRequestsChartProps {
  /** Every day of the month, in order (the API sends zeros too). */
  daily: readonly UsageDay[];
  month: string;
  /** False while the month is in progress: the summary says "so far". */
  closed: boolean;
}

/** The days labelled under the bars: one a week. */
const LABELLED_DAYS = new Set([1, 8, 15, 22, 29]);
/** The share of a day's slot a bar takes; the rest is air between bars. */
const BAR_SHARE = 0.6;
/** The least height of a day with requests, in percent of the plot: a tiny count stays visible. */
const MIN_SHARE = 2;

/**
 * Daily protected requests of a month as columns (dataviz: magnitude over time, one series in the accent, no legend —
 * the heading names it). Drawn in percentages, so it fills its width without stretching the 4 px rounded data-ends: a
 * bar runs from its value to below the plot, which clips it, so it is square at the baseline. Each day carries its
 * value as a native tooltip; the image has a summary as its name, and a table of every day is its text equivalent.
 * No client JavaScript.
 */
export function DailyRequestsChart({ daily, month, closed }: DailyRequestsChartProps) {
  const name = monthName(month);
  const total = daily.reduce((sum, day) => sum + day.requests, 0);
  const busiest = daily.reduce<UsageDay | undefined>(
    (top, day) => (top === undefined || day.requests > top.requests ? day : top),
    undefined,
  );
  const max = busiest?.requests ?? 0;
  const summary = t(closed ? "usage.daily.summary" : "usage.daily.summary.open", {
    month: name,
    total: formatCount(total),
    day: busiest?.day ?? "",
    count: formatCount(max),
  });
  const slot = 100 / Math.max(daily.length, 1);
  const inset = (slot * (1 - BAR_SHARE)) / 2;

  return (
    <div className="flex flex-col gap-3">
      <figure
        data-testid="usage-chart"
        className="flex flex-col gap-1 rounded-card border border-border bg-surface p-3"
      >
        <p className="body-5 text-fg-muted">
          {t("usage.daily.scale")}{" "}
          <span data-testid="usage-chart-max" className="title-5 text-fg">
            {formatCount(max)}
          </span>
        </p>
        <svg role="img" aria-label={summary} width="100%" height="160" className="overflow-visible">
          {/* Recessive grid: the top of the scale and the baseline. */}
          <line x1="0" x2="100%" y1="0" y2="0" className="stroke-border" strokeWidth="1" />
          {/* The plot: it clips each bar below the baseline, so a bar is rounded at its value only. */}
          <svg x="0" y="0" width="100%" height="100%" aria-hidden="true">
            {daily.map((day, i) => {
              // A day with any request keeps a visible stub (2 % of the height); a day without none.
              const share = day.requests === 0 ? 0 : Math.max((day.requests / max) * 100, MIN_SHARE);
              const label = t("usage.daily.bar", { day: day.day, count: formatCount(day.requests) });
              return (
                <g key={day.day} data-testid="usage-day" className="group">
                  <title>{label}</title>
                  {/* The hit target: the whole slot, taller and wider than the bar. */}
                  <rect x={`${i * slot}%`} y="0" width={`${slot}%`} height="100%" fill="transparent" />
                  <rect
                    data-testid="usage-bar"
                    data-empty={day.requests === 0 ? "true" : undefined}
                    x={`${i * slot + inset}%`}
                    y={`${100 - share}%`}
                    width={`${slot - 2 * inset}%`}
                    height={day.requests === 0 ? "0" : "100%"}
                    rx="4"
                    className="fill-primary group-hover:fill-fg"
                  />
                </g>
              );
            })}
          </svg>
          <line x1="0" x2="100%" y1="100%" y2="100%" className="stroke-border-strong" strokeWidth="1" />
        </svg>
        <div
          aria-hidden="true"
          className="grid body-5 text-fg-muted"
          style={{ gridTemplateColumns: `repeat(${Math.max(daily.length, 1)}, minmax(0, 1fr))` }}
        >
          {daily.map((day) => {
            const date = Number(day.day.slice(8, 10));
            return LABELLED_DAYS.has(date) ? (
              <span key={day.day} data-testid="usage-chart-day" className="text-center">
                {date}
              </span>
            ) : (
              <span key={day.day} />
            );
          })}
        </div>
      </figure>
      <details className="max-w-md">
        <summary className="cursor-pointer body-4 text-link underline">{t("usage.daily.table")}</summary>
        <table data-testid="usage-daily-table" className="mt-2 w-full border-collapse text-start body-5">
          <caption className="sr-only">{t("usage.daily.caption", { month: name })}</caption>
          <thead>
            <tr className="border-border border-b">
              <th scope="col" className="h-10 px-3 text-start caption-1 text-fg-muted">
                {t("usage.daily.col.day")}
              </th>
              <th scope="col" className="h-10 px-3 text-end caption-1 text-fg-muted">
                {t("usage.daily.col.requests")}
              </th>
            </tr>
          </thead>
          <tbody>
            {daily.map((day) => (
              <tr key={day.day} data-testid="usage-daily-row" className="border-border border-b">
                <th scope="row" className="h-10 px-3 py-2 text-start code-2 text-fg">
                  {day.day}
                </th>
                <td className="h-10 px-3 py-2 text-end code-2 text-fg">{formatCount(day.requests)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </details>
    </div>
  );
}
