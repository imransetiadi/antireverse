import type { Assessment, Build, Finding } from "@antireverse/protocol";
import { EnvironmentTag } from "@/components/environment-tag.tsx";
import { Icon } from "@/components/icons.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { ReverseResistance } from "@/features/assessments/reverse-resistance.tsx";
import { formatBytes, formatDateTime, formatOverhead } from "@/lib/format.ts";
import { t } from "@/lib/t.ts";
import { BuildFindings } from "./build-findings.tsx";
import { CANARY_KIND_LABEL, canaryCount, leakScanState } from "./canary.ts";
import { ProfileTag } from "./profile-tag.tsx";

// The budgets of the `balanced` profile (plan contract P4): a module is never shipped over either one.
const SIZE_BUDGET_PCT = 35;
const RUN_BUDGET_PCT = 15;

const SECTION = "flex flex-col gap-3";
const SECTION_TITLE = "heading-4";
const HEAD = "h-10 px-3 text-start caption-1 text-fg-muted";
const CELL = "h-10 px-3 py-2 align-middle";

/** A warning icon marking an over-budget cost, so the warning never rests on colour alone. */
function OverBudgetBadge() {
  return (
    <span
      data-testid="cost-overbudget"
      className="inline-flex h-6 items-center gap-1 rounded-control border border-sev-high px-2 caption-1 text-sev-high"
    >
      <Icon name="warning" />
      {t("build.cost.overBudget")}
    </span>
  );
}

/** One cost against its budget: a labelled figure and a bullet meter. Over budget reads in the warning style. */
function CostFigure({ id, label, pct, budget }: { id: string; label: string; pct: number | null; budget: number }) {
  const overBudget = pct !== null && pct > budget;
  const value = pct === null ? t("build.cost.none") : formatOverhead(pct);
  // The bar scales so both the value and the budget marker sit inside it, with a little headroom.
  const scale = Math.max(budget, pct ?? 0) * 1.25 || 1;
  const fill = pct === null ? 0 : Math.max(0, Math.min(100, (pct / scale) * 100));
  const threshold = Math.min(100, (budget / scale) * 100);
  return (
    <div data-testid={`cost-${id}`} data-overbudget={String(overBudget)} className="flex flex-col gap-2">
      <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
        <span className="text-fg-muted">{label}</span>
        <span className="flex items-center gap-2">
          {overBudget ? <OverBudgetBadge /> : null}
          <span data-testid="cost-value" className={`code-3 ${overBudget ? "text-sev-high" : "text-fg"}`}>
            {value}
          </span>
        </span>
      </div>
      <div className="relative h-2 rounded-full bg-muted" aria-hidden="true">
        <div
          className={`absolute inset-y-0 start-0 rounded-full ${overBudget ? "bg-sev-high" : "bg-primary"}`}
          style={{ width: `${fill}%` }}
        />
        <div className="absolute inset-y-0 w-0.5 bg-fg-muted" style={{ insetInlineStart: `${threshold}%` }} />
      </div>
      <span className="code-3 text-fg-subtle">{t("build.cost.budget", { budget })}</span>
    </div>
  );
}

/** One line of the transform summary: a label and its count or state. */
function TransformFigure({ id, label, value }: { id: string; label: string; value: string | number }) {
  return (
    <div
      data-testid={`transform-${id}`}
      className="flex items-baseline justify-between gap-3 border-border border-b py-2"
    >
      <span className="text-fg-muted">{label}</span>
      <span className="code-3">{value}</span>
    </div>
  );
}

/**
 * The Clone Beacon of a Build (slice 10): On with the number of allowed origins and the origins themselves,
 * or Off. Each origin is plain text that wraps — never a link. The beacon token is never shown: the API does
 * not return it.
 */
function BuildBeacon({ build }: { build: Build }) {
  const origins = build.beacon?.origins ?? [];
  const on = build.beacon !== undefined;
  const listId = "build-beacon-origins-title";
  let value = t("build.beacon.off");
  if (on) value = origins.length === 1 ? t("build.beacon.on.one") : t("build.beacon.on", { count: origins.length });
  return (
    <div className="flex flex-col gap-2">
      <div
        data-testid="build-beacon"
        data-status={on ? "on" : "off"}
        className="flex items-baseline justify-between gap-3 border-border border-b py-2"
      >
        <span className="text-fg-muted">{t("build.beacon")}</span>
        <span data-testid="build-beacon-value" className={`code-3 ${on ? "text-fg" : "text-fg-muted"}`}>
          {value}
        </span>
      </div>
      {on ? (
        <>
          <span id={listId} className="sr-only">
            {t("build.beacon.origins")}
          </span>
          <ul aria-labelledby={listId} data-testid="build-beacon-origins" className="flex list-none flex-col ps-0">
            {origins.map((origin) => (
              <li key={origin} data-testid="beacon-origin" className="break-all border-border border-b py-2 code-3">
                {origin}
              </li>
            ))}
          </ul>
        </>
      ) : (
        <p data-testid="build-beacon-off" className="text-fg-muted">
          {t("build.beacon.empty")}
        </p>
      )}
    </div>
  );
}

/**
 * The markers of a Build (SCR-07 MARKERS): the leak-scan outcome, the Clone Beacon, and the Canaries planted
 * in it, by kind and id. Canary values and the beacon token are never shown: the API does not return them.
 */
function BuildMarkers({ build }: { build: Build }) {
  const scan = leakScanState(build);
  const canaries = build.canaries ?? [];
  const caption = t("build.canaries.caption", { version: build.version });
  return (
    <section aria-labelledby="build-markers-title" className={`${SECTION} max-w-xl`} data-testid="build-markers">
      <h2 id="build-markers-title" className={SECTION_TITLE}>
        {t("build.markers")}
      </h2>
      <div
        data-testid="build-leak-scan"
        data-status={scan.status}
        className="flex items-baseline justify-between gap-3 border-border border-b py-2"
      >
        <span className="text-fg-muted">{t("build.leakScan")}</span>
        <span
          data-testid="build-leak-scan-value"
          className={`code-3 ${scan.status === "none" ? "text-fg-muted" : "text-fg"}`}
        >
          {scan.text}
        </span>
      </div>
      <BuildBeacon build={build} />
      <div data-testid="build-canaries" className="flex flex-col gap-2">
        <div className="flex flex-wrap items-baseline justify-between gap-x-3 gap-y-1">
          <h3 className="heading-5">{t("build.canaries")}</h3>
          <span data-testid="canary-count" className="code-3 text-fg-muted">
            {canaryCount(canaries.length)}
          </span>
        </div>
        {canaries.length === 0 ? (
          <p data-testid="canaries-empty" className="text-fg-muted">
            {t("build.canaries.empty")}
          </p>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full border-collapse text-start body-5">
              <caption className="sr-only">{caption}</caption>
              <thead>
                <tr className="border-border border-b">
                  <th scope="col" className={HEAD}>
                    {t("build.canaries.col.kind")}
                  </th>
                  <th scope="col" className={HEAD}>
                    {t("build.canaries.col.id")}
                  </th>
                </tr>
              </thead>
              <tbody>
                {canaries.map((canary) => (
                  <tr
                    key={canary.id}
                    data-testid="canary-row"
                    data-canary-id={canary.id}
                    data-kind={canary.kind}
                    className="border-border border-b"
                  >
                    <th scope="row" className={`${CELL} whitespace-nowrap text-start body-5`}>
                      <span data-testid="canary-kind">{t(CANARY_KIND_LABEL[canary.kind])}</span>
                    </th>
                    <td className={`${CELL} break-all`}>
                      <span data-testid="canary-id" className="code-3">
                        {canary.id}
                      </span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </section>
  );
}

/**
 * One Build (SCR-07): the version, profile and Environment; its Reverse resistance (slice 12a); the costs against
 * their budgets; the transform summary; its Findings (slice 19); the markers (leak scan, Canaries); and the artifact
 * list.
 */
export function BuildDetail({
  build,
  appName,
  findings,
  assessments,
}: {
  build: Build;
  appName: string;
  /**
   * Slice 19: the Build's Findings as the API filtered them (the section still counts only this Build's), null
   * when they could not be read. Without the prop the section is left out.
   */
  findings?: readonly Finding[] | null;
  /**
   * Slice 12a: the Build's Reverse Assessments, newest first, null when they could not be read. Without the prop
   * the section is left out.
   */
  assessments?: readonly Assessment[] | null;
}) {
  const registered = formatDateTime(build.registered_at);
  return (
    <>
      <PageHeader
        eyebrow={appName}
        title={t("builds.for", { version: build.version })}
        tags={
          <>
            <EnvironmentTag environment={build.environment} />
            <ProfileTag profile={build.profile} />
          </>
        }
      />
      <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
        <span className="code-3 text-fg-muted">
          <span className="sr-only">{t("build.id")} </span>
          <span data-testid="build-id">{build.build_id}</span>
        </span>
        <span className="text-fg-subtle">
          {t("build.registered")}{" "}
          <time dateTime={registered.iso} title={registered.iso}>
            {registered.text}
          </time>{" "}
          {t("build.col.created.zone")}
        </span>
      </p>

      {assessments === undefined ? null : <ReverseResistance assessments={assessments} />}

      <section aria-labelledby="build-cost-title" className={`${SECTION} max-w-xl`} data-testid="build-cost">
        <h2 id="build-cost-title" className={SECTION_TITLE}>
          {t("build.cost.title")}
        </h2>
        <CostFigure
          id="size"
          label={t("build.cost.size")}
          pct={build.costs.size_overhead_pct}
          budget={SIZE_BUDGET_PCT}
        />
        <CostFigure id="run" label={t("build.cost.run")} pct={build.costs.run_overhead_pct} budget={RUN_BUDGET_PCT} />
      </section>

      <section aria-labelledby="build-transform-title" className={`${SECTION} max-w-xl`} data-testid="build-transform">
        <h2 id="build-transform-title" className={SECTION_TITLE}>
          {t("build.transform.title")}
        </h2>
        <div className="flex flex-col">
          <TransformFigure id="mangled" label={t("build.transform.mangled")} value={build.transform.mangled} />
          <TransformFigure
            id="strings"
            label={t("build.transform.strings")}
            value={build.transform.strings_encrypted}
          />
          <TransformFigure
            id="mangleOnly"
            label={t("build.transform.mangleOnly")}
            value={build.transform.files_mangle_only}
          />
          <TransformFigure
            id="integrity"
            label={t("build.transform.integrity")}
            value={t(build.transform.integrity ? "build.transform.on" : "build.transform.off")}
          />
        </div>
      </section>

      {findings === undefined ? null : <BuildFindings build={build} findings={findings} />}

      <BuildMarkers build={build} />

      <section aria-labelledby="build-artifacts-title" className={SECTION} data-testid="build-artifacts">
        <h2 id="build-artifacts-title" className={SECTION_TITLE}>
          {t("build.artifacts")}
        </h2>
        <div className="overflow-x-auto">
          <table className="w-full border-collapse text-start body-5">
            <thead>
              <tr className="border-border border-b">
                <th scope="col" className={HEAD}>
                  {t("build.col.path")}
                </th>
                <th scope="col" className={`${HEAD} text-end`}>
                  {t("build.col.bytes")}
                </th>
                <th scope="col" className={HEAD}>
                  {t("build.col.hash")}
                </th>
              </tr>
            </thead>
            <tbody>
              {build.artifacts.map((artifact) => (
                <tr key={artifact.path} data-testid="artifact-row" className="border-border border-b">
                  <th scope="row" className={`${CELL} break-all text-start code-3`}>
                    <span data-testid="artifact-path">{artifact.path}</span>
                  </th>
                  <td className={`${CELL} text-end code-3`} data-testid="artifact-bytes">
                    {formatBytes(artifact.bytes)}
                  </td>
                  <td className={`${CELL} code-3 text-fg-muted`}>
                    <span data-testid="artifact-hash" className="code-3" title={artifact.sha256}>
                      {artifact.sha256.slice(0, 12)}
                    </span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  );
}
