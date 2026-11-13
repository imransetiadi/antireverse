import {
  type Assessment,
  type AssessmentCost,
  type AssessmentStatus,
  type NotAttemptedReason,
  OBJECTIVES,
  type ObjectiveResult,
  type RecoveredItem,
  STAND_IN_MODEL,
} from "@antireverse/protocol";
import { EmptyState } from "@/components/empty-state.tsx";
import { Icon, type IconName } from "@/components/icons.tsx";
import { formatCount, formatDateTime } from "@/lib/format.ts";
import { type MessageKey, t } from "@/lib/t.ts";
import { AssessAgainForm } from "./assess-again-form.tsx";
import { formatDuration } from "./format.ts";

const HEAD = "h-10 px-3 text-start caption-1 text-fg-muted";
const CELL = "h-10 px-3 py-2 align-top";

const REASON_LABEL: Record<NotAttemptedReason, MessageKey> = {
  not_supported: "assessment.reason.not_supported",
  refused: "assessment.reason.refused",
  tool_failure: "assessment.reason.tool_failure",
  sandbox_error: "assessment.reason.sandbox_error",
  budget_exhausted_before_attempt: "assessment.reason.budget_exhausted_before_attempt",
  no_inventory: "assessment.reason.no_inventory",
  not_designated: "assessment.reason.not_designated",
  no_runnable_file: "assessment.reason.no_runnable_file",
};

/** W3 not attempted for want of a designated function: how to designate one, with the flag set as code. */
function LogicHint() {
  const MARK = "\u0001";
  const [before, after] = t("assessment.hint.logic", { flag: MARK }).split(MARK);
  return (
    <p data-testid="objective-hint" className="text-fg-muted">
      {before}
      <code className="code-3">--logic</code>
      {after}
    </p>
  );
}

const STATUS_LABEL: Record<AssessmentStatus, MessageKey> = {
  queued: "assessment.status.queued",
  running: "assessment.status.running",
  scored: "assessment.status.scored",
  inconclusive: "assessment.status.inconclusive",
  failed: "assessment.status.failed",
};

function formatCost(cost: AssessmentCost): string {
  const calls =
    cost.calls === 1 ? t("assessment.calls.one") : t("assessment.calls", { count: formatCount(cost.calls) });
  return t("assessment.cost", { calls, time: formatDuration(cost.seconds) });
}

function recoveredText(item: RecoveredItem): string {
  switch (item.kind) {
    case "canary":
      return t("assessment.recovered.canary", { id: item.canary_id });
    case "leak":
      return t("assessment.recovered.leak", { rule: item.rule, fingerprint: item.fingerprint.slice(0, 12) });
    case "routes":
      return t("assessment.recovered.routes", { matched: item.matched, inventory: item.inventory });
    case "replay":
      return t("assessment.recovered.replay", { status: item.status });
  }
}

// D-053: a glyph, a word and a colour per result — never the colour alone. Achieved means the attacker got the
// Objective, so it takes the warning colour and a tint; not achieved is the good outcome and takes the accent;
// not attempted stays a hollow chip in the muted text colour, since it says nothing about resistance.
const RESULT_TONE: Record<ObjectiveResult["result"], string> = {
  achieved: "bg-current/16 text-sev-high",
  not_achieved: "bg-current/16 text-primary",
  not_attempted: "bg-transparent text-fg-muted",
};
const RESULT_ICON: Record<ObjectiveResult["result"], IconName> = {
  achieved: "warning-circle",
  not_achieved: "check-circle",
  not_attempted: "circle-dashed",
};

function ResultChip({ result }: { result: ObjectiveResult }) {
  let label: string;
  let help: string;
  if (result.result === "achieved") {
    label = t("assessment.result.achieved", { tier: result.tier });
    help = t("assessment.result.achieved.help", { tier: result.tier });
  } else if (result.result === "not_achieved") {
    label = t("assessment.result.notAchieved");
    help = t("assessment.result.notAchieved.help");
  } else {
    label = t("assessment.result.notAttempted", { reason: t(REASON_LABEL[result.reason]) });
    help = t("assessment.result.notAttempted.help");
  }
  return (
    <span
      data-testid="objective-result"
      data-result={result.result}
      title={help}
      className={`inline-flex h-6 items-center gap-1 rounded-control border border-current border-solid px-2 caption-1 whitespace-nowrap ${RESULT_TONE[result.result]}`}
    >
      <Icon name={RESULT_ICON[result.result]} />
      {label}
    </span>
  );
}

/**
 * The RRS as a bullet chart on the fixed scale 0 to 100 (UIUX §8, §9): the value in Geist Mono, a bar filled to
 * it, the scale's ends labelled, and a one sentence summary. No threshold marker until a threshold exists (slice
 * 13). The bar is decorative: the figure and the summary carry the value.
 */
function RrsMeter({ rrs, tier }: { rrs: number; tier: string }) {
  const fill = Math.max(0, Math.min(100, rrs));
  return (
    <div data-testid="rrs-meter" className="flex flex-col gap-2">
      <div className="flex items-baseline gap-3">
        <span className="caption-1 text-fg-muted">{t("assessment.rrs")}</span>
        <span data-testid="rrs-value" className="code-1 text-fg">
          {rrs}
        </span>
      </div>
      <div className="relative h-2 rounded-full bg-muted" aria-hidden="true">
        <div
          data-testid="rrs-fill"
          className="absolute inset-y-0 start-0 rounded-full bg-primary"
          style={{ width: `${fill}%` }}
        />
      </div>
      <div data-testid="rrs-scale" className="flex justify-between code-3 text-fg-subtle" aria-hidden="true">
        <span>{t("assessment.rrs.scale.min")}</span>
        <span>{t("assessment.rrs.scale.max")}</span>
      </div>
      <p data-testid="rrs-summary" className="sr-only">
        {t("assessment.rrs.summary", { rrs, tier })}
      </p>
    </div>
  );
}

function ObjectiveRows({ results }: { results: readonly ObjectiveResult[] }) {
  const rows = OBJECTIVES.flatMap((objective) => {
    const result = results.find((one) => one.objective === objective.id);
    return result ? [{ objective, result }] : [];
  });
  return (
    <div className="overflow-x-auto">
      <table className="w-full border-collapse text-start body-5">
        <caption className="sr-only">{t("assessment.objectives.caption")}</caption>
        <thead>
          <tr className="border-border border-b">
            <th scope="col" className={HEAD}>
              {t("assessment.col.objective")}
            </th>
            <th scope="col" className={HEAD}>
              {t("assessment.col.result")}
            </th>
            <th scope="col" className={HEAD}>
              {t("assessment.col.cost")}
            </th>
            <th scope="col" className={HEAD}>
              {t("assessment.col.evidence")}
            </th>
          </tr>
        </thead>
        <tbody>
          {rows.map(({ objective, result }) => (
            <tr
              key={objective.id}
              data-testid="objective-row"
              data-objective={objective.id}
              className="border-border border-b"
            >
              <th scope="row" className={`${CELL} whitespace-nowrap text-start body-5`}>
                <span className="flex flex-col">
                  <span data-testid="objective-name">{objective.name}</span>
                  <span data-testid="objective-weight" className="code-3 text-fg-subtle">
                    {t("assessment.weight", { id: objective.id, weight: Math.round(objective.weight * 100) })}
                  </span>
                </span>
              </th>
              <td className={CELL}>
                <ResultChip result={result} />
              </td>
              <td className={`${CELL} whitespace-nowrap`}>
                <span data-testid="objective-cost" className="code-3">
                  {result.result === "not_attempted" ? t("assessment.cost.none") : formatCost(result.cost)}
                </span>
              </td>
              <td className={`${CELL} min-w-64`}>
                <div className="flex flex-col gap-2">
                  <p data-testid="objective-summary">{result.evidence.summary}</p>
                  {result.evidence.recovered.length > 0 ? (
                    <ul aria-label={t("assessment.recovered")} className="flex list-none flex-wrap gap-2 ps-0">
                      {result.evidence.recovered.map((item, index) => (
                        <li
                          // Recovered items have no id of their own; their order is the verifier's.
                          // biome-ignore lint/suspicious/noArrayIndexKey: a static list, never reordered
                          key={index}
                          data-testid="recovered-item"
                          data-kind={item.kind}
                          className="break-all code-3 text-fg-muted"
                        >
                          {recoveredText(item)}
                        </li>
                      ))}
                    </ul>
                  ) : null}
                  {result.result === "not_attempted" && result.reason === "not_designated" ? <LogicHint /> : null}
                  {result.result === "achieved" ? (
                    <p data-testid="objective-fix" className="text-fg-muted">
                      {t("assessment.fix", { fix: objective.fix })}
                    </p>
                  ) : null}
                </div>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

/** The scope statement: who produced the result and with what. Shown with every finished result. */
function ScopeLine({ assessment }: { assessment: Assessment }) {
  const { scope } = assessment;
  return (
    <p data-testid="assessment-scope" className="code-3 text-fg-subtle">
      {t("assessment.scope", {
        agent: scope.agent.name,
        version: scope.agent.version,
        model: scope.model,
        toolbelt: scope.toolbelt,
        tier: scope.tier,
      })}
    </p>
  );
}

function StandInNote() {
  return (
    <p data-testid="assessment-stand-in" className="flex items-start gap-2 text-fg-muted">
      <Icon name="info" className="mt-0.5 size-4 shrink-0" />
      <span>{t("assessment.standIn")}</span>
    </p>
  );
}

/** The latest Assessment: its score or why there is none, its progress, or its failure; then its Objective rows. */
function LatestAssessment({ assessment }: { assessment: Assessment }) {
  const { status } = assessment;
  const finished = status === "scored" || status === "inconclusive" || status === "failed";
  return (
    <div data-testid="assessment-latest" data-status={status} className="flex flex-col gap-3">
      {status === "scored" && assessment.rrs !== null ? <RrsMeter rrs={assessment.rrs} tier={assessment.tier} /> : null}
      {status === "inconclusive" ? (
        <p data-testid="assessment-inconclusive" className="flex items-start gap-2">
          <Icon name="seal-question" className="mt-0.5 size-4 shrink-0 text-fg-muted" />
          <span>{t("assessment.inconclusive", { reason: assessment.inconclusive_reason ?? "" })}</span>
        </p>
      ) : null}
      {status === "queued" || status === "running" ? (
        <p data-testid="assessment-progress" data-status={status} className="flex items-center gap-2 text-fg-muted">
          <Icon name="hourglass-medium" className="size-4 shrink-0" />
          <span>
            {status === "queued"
              ? t("assessment.progress.queued", { time: formatDateTime(assessment.created_at).text })
              : t("assessment.progress.running", {
                  time: formatDateTime(assessment.started_at ?? assessment.created_at).text,
                })}
          </span>
        </p>
      ) : null}
      {status === "failed" ? (
        <p data-testid="assessment-failed" className="flex items-start gap-2 text-sev-high">
          <Icon name="warning-circle" className="mt-0.5 size-4 shrink-0" />
          <span>{t("assessment.failed", { reason: assessment.failure_reason ?? "" })}</span>
        </p>
      ) : null}
      {finished ? <ScopeLine assessment={assessment} /> : null}
      {status === "scored" && assessment.renormalised ? (
        <p data-testid="assessment-renormalised" className="text-fg-muted">
          {t("assessment.renormalised")}
        </p>
      ) : null}
      {finished && assessment.scope.model === STAND_IN_MODEL ? <StandInNote /> : null}
      {status === "failed" && assessment.results.length > 0 ? (
        <h3 data-testid="assessment-partial" className="heading-5">
          {t("assessment.partial")}
        </h3>
      ) : null}
      {assessment.results.length > 0 ? <ObjectiveRows results={assessment.results} /> : null}
    </div>
  );
}

function History({ assessments }: { assessments: readonly Assessment[] }) {
  return (
    <div className="flex flex-col gap-2">
      <h3 className="heading-5">{t("assessment.history")}</h3>
      <div className="overflow-x-auto">
        <table className="w-full border-collapse text-start body-5">
          <caption className="sr-only">{t("assessment.history.caption")}</caption>
          <thead>
            <tr className="border-border border-b">
              <th scope="col" className={HEAD}>
                {t("assessment.col.created")}
              </th>
              <th scope="col" className={HEAD}>
                {t("assessment.col.tier")}
              </th>
              <th scope="col" className={HEAD}>
                {t("assessment.col.status")}
              </th>
              <th scope="col" className={`${HEAD} text-end`}>
                {t("assessment.col.score")}
              </th>
            </tr>
          </thead>
          <tbody>
            {assessments.map((assessment) => {
              const created = formatDateTime(assessment.created_at);
              let score = t("assessment.score.none");
              if (assessment.status === "scored" && assessment.rrs !== null) score = String(assessment.rrs);
              if (assessment.status === "inconclusive") score = t("assessment.status.inconclusive");
              return (
                <tr
                  key={assessment.id}
                  data-testid="history-row"
                  data-assessment-id={assessment.id}
                  data-status={assessment.status}
                  className="border-border border-b"
                >
                  <th scope="row" className={`${CELL} whitespace-nowrap text-start code-3`}>
                    <time data-testid="history-created" dateTime={created.iso} title={created.iso}>
                      {created.text}
                    </time>
                  </th>
                  <td className={`${CELL} code-3`} data-testid="history-tier">
                    {assessment.tier}
                  </td>
                  <td className={CELL} data-testid="history-status">
                    {t(STATUS_LABEL[assessment.status])}
                  </td>
                  <td
                    className={`${CELL} text-end ${assessment.status === "scored" ? "code-3" : "text-fg-muted"}`}
                    data-testid="history-score"
                  >
                    {score}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>
    </div>
  );
}

/**
 * The Build page's "Reverse resistance" section (slice 12a, UIUX SCR-07): the latest Assessment — the RRS meter
 * with the scope line beneath, or "Inconclusive: <reason>" and never a number, its progress while queued or
 * running, or its failure with the results it reached — then its Objective rows, "Assess again" while the latest
 * Assessment is finished and its bundle still kept, and the history. `assessments`
 * is the API's list, newest first; null when it could not be read.
 */
export function ReverseResistance({
  assessments,
  now = Date.now(),
}: {
  assessments: readonly Assessment[] | null;
  /** The time the page is rendered at (ms): "Assess again" is offered while the latest artifact is kept beyond it. */
  now?: number;
}) {
  const latest = assessments?.[0];
  const keptUntil = latest?.artifact_kept_until ?? null;
  // Not while the latest is queued or running: one run at a time, and its result comes first.
  const active = latest?.status === "queued" || latest?.status === "running";
  const kept = !active && keptUntil !== null && Date.parse(keptUntil) > now;
  return (
    <section aria-labelledby="build-assessment-title" className="flex flex-col gap-3" data-testid="build-assessment">
      <h2 id="build-assessment-title" className="heading-4">
        {t("assessment.title")}
      </h2>
      {assessments === null ? (
        <p data-testid="assessment-unavailable" className="text-fg-muted">
          {t("assessment.unavailable")}
        </p>
      ) : latest === undefined ? (
        <div data-testid="assessment-empty">
          <EmptyState icon="shield-check">{t("assessment.empty")}</EmptyState>
        </div>
      ) : (
        <>
          <LatestAssessment assessment={latest} />
          {kept ? <AssessAgainForm appId={latest.app_id} buildId={latest.build_id} keptUntil={keptUntil} /> : null}
          <History assessments={assessments} />
        </>
      )}
    </section>
  );
}
