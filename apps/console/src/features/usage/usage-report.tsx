import { USAGE_DEVICE_DAILY_CAP, type UsageCounts, type UsageResponse } from "@antireverse/protocol";
import Link from "next/link";
import { EmptyState } from "@/components/empty-state.tsx";
import { formatCount } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { DailyRequestsChart } from "./daily-requests-chart.tsx";
import { formatMinutes, monthName } from "./query.ts";

const SECTION = "flex flex-col gap-3";
const SECTION_TITLE = "heading-4";
const HEAD = "h-10 px-3 text-start caption-1 text-fg-muted whitespace-nowrap";
const HEAD_NUMBER = "h-10 px-3 text-end caption-1 text-fg-muted whitespace-nowrap";
const CELL = "h-10 px-3 py-2 align-middle";
const NUMBER = `${CELL} text-end code-2 text-fg`;

/** Guard devices, said as a lower bound when recording stopped at the daily cap (`guard_devices_capped`). */
function devicesOf(counts: Pick<UsageCounts, "guard_devices" | "guard_devices_capped">): string {
  const count = formatCount(counts.guard_devices);
  return counts.guard_devices_capped ? t("usage.devices.atLeast", { count }) : count;
}

/** One stat tile: what is counted, the count, and what the count leaves out. */
function Total({ label, value, note, warning }: { label: string; value: string; note: string; warning?: string }) {
  return (
    <div data-testid="usage-total" className="flex flex-col gap-1 rounded-card border border-border bg-surface p-3">
      <dt className="body-4 text-fg-muted">{label}</dt>
      <dd data-testid="usage-total-value" className="heading-3 text-fg tabular-nums">
        {value}
      </dd>
      <dd className="body-5 text-fg-muted">{note}</dd>
      {warning === undefined ? null : (
        <dd data-testid="usage-devices-capped" className="body-5 text-sev-medium">
          {warning}
        </dd>
      )}
    </div>
  );
}

/** A month of usage (slice 17a): its status, the totals, the Organization's current facts, per App, and per day. */
export function UsageReport({ usage }: { usage: UsageResponse }) {
  const name = monthName(usage.month);
  const { totals } = usage;
  return (
    <>
      <p data-testid="usage-status" className="body-4 text-fg">
        {t(usage.closed ? "usage.status.closed" : "usage.status.open", { month: name })}
      </p>

      <section aria-labelledby="usage-totals-title" className={SECTION}>
        <h2 id="usage-totals-title" className={SECTION_TITLE}>
          {t("usage.totals.title")}
        </h2>
        <dl data-testid="usage-totals" className="grid grid-cols-1 gap-3 md:grid-cols-3">
          <Total label={t("usage.requests")} value={formatCount(totals.requests)} note={t("usage.requests.note")} />
          <Total
            label={t("usage.devices")}
            value={devicesOf(totals)}
            note={t("usage.devices.note", { cap: formatCount(USAGE_DEVICE_DAILY_CAP) })}
            warning={
              totals.guard_devices_capped
                ? t("usage.devices.capped", { cap: formatCount(USAGE_DEVICE_DAILY_CAP) })
                : undefined
            }
          />
          <Total
            label={t("usage.sandbox")}
            value={formatMinutes(totals.sandbox_minutes)}
            note={t("usage.sandbox.note")}
          />
        </dl>
      </section>

      <section aria-labelledby="usage-daily-title" className={SECTION}>
        <h2 id="usage-daily-title" className={SECTION_TITLE}>
          {t("usage.daily.title")}
        </h2>
        {totals.requests === 0 ? (
          <p data-testid="usage-daily-empty" className="body-4 text-fg-muted">
            {t("usage.daily.empty", { month: name })}
          </p>
        ) : (
          <DailyRequestsChart daily={usage.daily} month={usage.month} closed={usage.closed} />
        )}
      </section>

      <section aria-labelledby="usage-apps-title" className={SECTION}>
        <h2 id="usage-apps-title" className={SECTION_TITLE}>
          {t("usage.perApp.title")}
        </h2>
        {usage.apps.length === 0 ? (
          <div data-testid="usage-apps-empty">
            <EmptyState>{t("usage.apps.empty")}</EmptyState>
          </div>
        ) : (
          <section
            aria-label={t("usage.perApp.caption", { month: name })}
            // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
            tabIndex={0}
            className="overflow-x-auto"
          >
            <table data-testid="usage-apps" className="w-full border-collapse text-start body-5">
              <caption className="sr-only">{t("usage.perApp.caption", { month: name })}</caption>
              <thead>
                <tr className="border-border border-b">
                  <th scope="col" className={HEAD}>
                    {t("usage.col.app")}
                  </th>
                  <th scope="col" className={HEAD_NUMBER}>
                    {t("usage.col.requests")}
                  </th>
                  <th scope="col" className={HEAD_NUMBER}>
                    {t("usage.col.devices")}
                  </th>
                  <th scope="col" className={HEAD_NUMBER}>
                    {t("usage.col.sandbox")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {usage.apps.map((app) => (
                  <tr
                    key={app.app_id}
                    data-testid="usage-app-row"
                    data-app-id={app.app_id}
                    className="border-border border-b"
                  >
                    <th scope="row" className={`${CELL} text-start title-5 text-fg`}>
                      {app.name}
                    </th>
                    <td className={NUMBER}>{formatCount(app.requests)}</td>
                    <td className={NUMBER}>{devicesOf(app)}</td>
                    <td className={NUMBER}>{formatMinutes(app.sandbox_minutes)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        )}
      </section>

      <section aria-labelledby="usage-organization-title" className={SECTION}>
        <h2 id="usage-organization-title" className={SECTION_TITLE}>
          {t("usage.organization.title")}
        </h2>
        <p className="body-5 text-fg-muted">{t("usage.current")}</p>
        <dl data-testid="usage-organization" className="grid max-w-3xl grid-cols-1 gap-x-6 gap-y-2 sm:grid-cols-3">
          <div className="flex flex-col gap-1">
            <dt className="body-4 text-fg-muted">{t("usage.apps")}</dt>
            <dd data-testid="usage-apps-count" className="title-3 text-fg">
              {formatCount(usage.apps_count)}
            </dd>
          </div>
          <div className="flex flex-col gap-1">
            <dt className="body-4 text-fg-muted">{t("usage.retention")}</dt>
            <dd data-testid="usage-retention" className="flex flex-col gap-1">
              <span className="title-3 text-fg">
                {t("usage.retention.value", { days: usage.event_retention_days })}
              </span>
              <Link href={ROUTES.dataControls()} className="body-5">
                {t("usage.retention.link")}
              </Link>
            </dd>
          </div>
          <div className="flex flex-col gap-1">
            <dt className="body-4 text-fg-muted">{t("usage.seats")}</dt>
            <dd data-testid="usage-seats" className="body-4 text-fg">
              {t("usage.seats.value")}
            </dd>
          </div>
        </dl>
      </section>
    </>
  );
}
