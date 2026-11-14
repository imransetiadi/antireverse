import type { SloReport } from "@antireverse/protocol";
import { formatDateTime } from "@/lib/format.ts";
import { t } from "@/lib/t.ts";
import { sloState } from "./state.ts";

function Count({ label, value, testId, alert }: { label: string; value: number; testId: string; alert?: boolean }) {
  return (
    <div className="flex flex-col gap-1 rounded-card border border-border bg-surface p-3">
      <dt className="body-4 text-fg-muted">{label}</dt>
      <dd
        data-testid={testId}
        className={`heading-3 tabular-nums ${alert === true && value > 0 ? "text-sev-critical-text" : "text-fg"}`}
      >
        {value}
      </dd>
    </div>
  );
}

/** How many SLOs fire, miss their objective without firing, are OK (no traffic included) or are not measured; the scope, the window and when generated. */
export function OpsSummary({ report }: { report: SloReport }) {
  const states = report.slos.map(sloState);
  const firing = states.filter((state) => state === "firing").length;
  const missed = states.filter((state) => state === "objective-missed").length;
  const notMeasured = states.filter((state) => state === "not-measured").length;
  const ok = states.length - firing - missed - notMeasured;
  const generated = formatDateTime(report.generated_at);
  return (
    <section aria-labelledby="ops-summary-title" data-testid="ops-summary" className="flex flex-col gap-3">
      <h2 id="ops-summary-title" className="sr-only">
        {t("ops.summary.title")}
      </h2>
      <dl className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <Count label={t("ops.summary.firing")} value={firing} testId="ops-count-firing" alert />
        <Count label={t("ops.summary.missed")} value={missed} testId="ops-count-missed" alert />
        <Count label={t("ops.summary.ok")} value={ok} testId="ops-count-ok" />
        <Count label={t("ops.summary.notMeasured")} value={notMeasured} testId="ops-count-not-measured" />
      </dl>
      <div className="flex flex-col gap-1 body-5 text-fg-muted">
        <p data-testid="ops-scope">{t("ops.summary.scope")}</p>
        <p>{t("ops.summary.window", { days: report.window_days })}</p>
        <p data-testid="ops-generated">
          {t("ops.summary.generated")} <time dateTime={generated.iso}>{generated.text} UTC</time>
        </p>
      </div>
    </section>
  );
}
