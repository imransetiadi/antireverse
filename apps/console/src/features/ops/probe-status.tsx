import { PROBE_BOUNDS, type ProbeLeg, type ProbeStatus } from "@antireverse/protocol";
import { Icon, type IconName } from "@/components/icons.tsx";
import { formatDateTime } from "@/lib/format.ts";
import { type MessageKey, t } from "@/lib/t.ts";
import { formatDuration } from "./format.ts";

// Slice 18g: the synthetic probes of the API instance that answered, above the SLO panels. Off, it says so and names
// the switch; on, it shows the last cycle's two legs, when it ended and how many cycles failed since the instance
// started. The lead says what the number is: measured inside this API instance against one Shield of its own. The
// 30-day figures are in the panels of SLO-06 and SLO-04.

type Outcome = ProbeLeg["outcome"];

const OUTCOME: Record<Outcome, { icon: IconName; className: string }> = {
  good: { icon: "check-circle", className: "text-fg" },
  late: { icon: "warning-octagon", className: "text-sev-critical-text" },
  timeout: { icon: "warning-octagon", className: "text-sev-critical-text" },
  failed: { icon: "warning-octagon", className: "text-sev-critical-text" },
  skipped: { icon: "circle-dashed", className: "text-fg-muted" },
};

/** What a leg's outcome says, in words. */
function outcomeText(leg: ProbeLeg, timeoutMs: number): string {
  switch (leg.outcome) {
    case "good":
      return t("ops.probes.leg.good");
    case "late":
      return t("ops.probes.leg.late");
    case "timeout":
      return t("ops.probes.leg.timeout", { time: formatDuration(timeoutMs) });
    case "failed":
      return t("ops.probes.leg.failed");
    case "skipped":
      return t("ops.probes.leg.skipped");
  }
}

/** One leg of the last cycle: an icon and words for the outcome (never colour alone), the latency and its bound. */
function Leg({
  name,
  label,
  leg,
  goodMs,
  timeoutMs,
}: {
  name: "enforcement" | "freshness";
  label: MessageKey;
  leg: ProbeLeg | null;
  goodMs: number;
  timeoutMs: number;
}) {
  const style = leg === null ? null : OUTCOME[leg.outcome];
  const timed = leg !== null && leg.ms !== null && (leg.outcome === "good" || leg.outcome === "late");
  return (
    <div className="flex flex-col gap-1">
      <dt className="body-5 text-fg-muted">{t(label)}</dt>
      <dd
        data-testid={`ops-probe-${name}`}
        data-outcome={leg === null ? "none" : leg.outcome}
        className="flex flex-col gap-1"
      >
        {leg === null || style === null ? (
          <span className="body-4 text-fg-muted">{t("ops.probes.never")}</span>
        ) : (
          <>
            <span className={`inline-flex items-center gap-1 title-5 ${style.className}`}>
              <Icon name={style.icon} className={`size-4 ${leg.outcome === "good" ? "text-primary" : ""}`} />
              {outcomeText(leg, timeoutMs)}
            </span>
            {timed ? (
              <span className="code-2 text-fg tabular-nums">
                {formatDuration(leg.ms ?? 0)}{" "}
                <span className="body-5 text-fg-muted">
                  {t("ops.probes.leg.bound", { bound: formatDuration(goodMs) })}
                </span>
              </span>
            ) : null}
          </>
        )}
      </dd>
    </div>
  );
}

function stateOf(probes: ProbeStatus | null): "off" | "idle" | "ok" | "failing" {
  if (probes === null) return "off";
  if (probes.last_run_at === null) return "idle";
  return probes.consecutive_failures > 0 ? "failing" : "ok";
}

export function ProbeStatusSection({ probes }: { probes: ProbeStatus | null }) {
  const state = stateOf(probes);
  const last = probes?.last_run_at == null ? null : formatDateTime(probes.last_run_at);
  return (
    <section
      aria-labelledby="ops-probes-title"
      data-testid="ops-probes"
      data-state={state}
      className={`flex flex-col gap-4 rounded-card border bg-surface p-4 ${state === "failing" ? "border-sev-critical-text" : "border-border"}`}
    >
      <h2 id="ops-probes-title" className="heading-4">
        {t("ops.probes.title")}
      </h2>
      <p data-testid="ops-probes-scope" className="max-w-3xl body-5 text-fg-muted">
        {t("ops.probes.lead")}
      </p>
      {probes === null ? (
        <p role="status" data-testid="ops-probes-off" className="max-w-3xl body-4 text-fg">
          {t("ops.probes.off")}
        </p>
      ) : (
        <>
          {probes.setup_failures > 0 ? (
            <p
              role="alert"
              data-testid="ops-probes-setup"
              className="max-w-3xl rounded-card border border-sev-critical-text p-3 body-4 text-fg"
            >
              {t("ops.probes.setup", { count: probes.setup_failures })}
            </p>
          ) : null}
          <dl className="grid grid-cols-1 gap-x-6 gap-y-3 sm:grid-cols-2 lg:grid-cols-4">
            <Leg
              name="enforcement"
              label="ops.probes.enforcement"
              leg={probes.enforcement}
              goodMs={PROBE_BOUNDS.enforceGoodMs}
              timeoutMs={PROBE_BOUNDS.enforceTimeoutMs}
            />
            <Leg
              name="freshness"
              label="ops.probes.freshness"
              leg={probes.freshness}
              goodMs={PROBE_BOUNDS.freshGoodMs}
              timeoutMs={PROBE_BOUNDS.freshTimeoutMs}
            />
            <div className="flex flex-col gap-1">
              <dt className="body-5 text-fg-muted">{t("ops.probes.runs")}</dt>
              <dd data-testid="ops-probes-runs" className="title-4 text-fg tabular-nums">
                {t("ops.probes.runs.value", { runs: probes.runs, failures: probes.failures })}
              </dd>
            </div>
            <div className="flex flex-col gap-1">
              <dt className="body-5 text-fg-muted">{t("ops.probes.consecutive")}</dt>
              <dd
                data-testid="ops-probes-consecutive"
                className={`title-4 tabular-nums ${probes.consecutive_failures > 0 ? "text-sev-critical-text" : "text-fg"}`}
              >
                {probes.consecutive_failures}
              </dd>
            </div>
          </dl>
          <div className="flex flex-col gap-1 body-5 text-fg-muted">
            <p data-testid="ops-probes-last">
              {last === null ? (
                t("ops.probes.never")
              ) : (
                <>
                  {t("ops.probes.lastRun")} <time dateTime={last.iso}>{last.text} UTC</time>
                </>
              )}
            </p>
            <p data-testid="ops-probes-interval">{t("ops.probes.interval", { seconds: probes.interval_s })}</p>
          </div>
        </>
      )}
    </section>
  );
}
