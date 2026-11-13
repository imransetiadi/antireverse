"use client";

import type { Environment, SimulationResult, SimulationRuleResult } from "@antireverse/protocol";
import { useEffect, useId, useRef } from "react";
import { EmptyState } from "@/components/empty-state.tsx";
import { SubmitButton } from "@/components/submit-button.tsx";
import { formatCount, formatDateTime } from "@/lib/format.ts";
import { t } from "@/lib/t.ts";
import { clientsText, notSimulatedText, requestsText, unknownClientsText, wouldRefuse } from "./simulation.ts";
import { useSimulation } from "./simulation-context.tsx";
import { CELL, DATA, HEAD, STICKY } from "./table.ts";

const COLUMNS = [
  "policy.simulate.col.rule",
  "policy.simulate.col.refuse",
  "policy.simulate.col.clients",
  "policy.simulate.col.undecidable",
  "policy.simulate.col.already",
  "policy.simulate.col.routes",
] as const;

/** The kinds of refusal of a row that are not zero, in words. */
function kinds(row: SimulationRuleResult): string[] {
  const parts: [number, "block" | "signature" | "throttle"][] = [
    [row.would_block, "block"],
    [row.would_fail_signature, "signature"],
    [row.would_throttle, "throttle"],
  ];
  return parts
    .filter(([count]) => count > 0)
    .map(([count, kind]) => t(`policy.simulate.kind.${kind}`, { n: formatCount(count) }));
}

/** One Rule of the result: what it would refuse, whom that touches, and what the estimate could not judge. */
function ResultRow({ row, draft }: { row: SimulationRuleResult; draft: boolean }) {
  return (
    <tr data-testid="simulation-row" data-index={row.index} className="border-border border-b">
      <th scope="row" className={`${CELL} ${STICKY} min-w-32 break-words text-start body-4`}>
        <div className="flex flex-col items-start gap-1">
          {row.name}
          {draft ? (
            <span
              data-testid="simulation-draft"
              className="inline-flex h-6 items-center rounded-control border border-border-strong border-dashed px-2 caption-1 whitespace-nowrap text-fg"
            >
              {t("policy.simulate.draft.tag")}
            </span>
          ) : null}
        </div>
      </th>
      <td className={CELL}>
        <div className="flex flex-col items-start">
          <span data-testid="simulation-refuse" className="code-3">
            {formatCount(wouldRefuse(row))}
          </span>
          {kinds(row).map((kind) => (
            <span key={kind} data-testid="simulation-kind" className="body-5 whitespace-nowrap text-fg-muted">
              {kind}
            </span>
          ))}
        </div>
      </td>
      <td className={CELL}>
        <div className="flex flex-col items-start">
          <span data-testid="simulation-clients" className="code-3">
            {formatCount(row.clients_affected)}
          </span>
          {/* Refused requests without a client: how many clients they are cannot be said. */}
          {row.unknown_client_events > 0 ? (
            <span data-testid="simulation-unknown" className="body-5 whitespace-nowrap text-fg-muted">
              {unknownClientsText(row.unknown_client_events)}
            </span>
          ) : null}
        </div>
      </td>
      <td data-testid="simulation-undecidable" className={DATA}>
        {formatCount(row.undecidable)}
      </td>
      <td data-testid="simulation-already" className={DATA}>
        {formatCount(row.already_refused)}
      </td>
      <td data-testid="simulation-routes" className={`${CELL} min-w-48`}>
        {row.sample_routes.length === 0 ? (
          <span className="text-fg-muted">{t("policy.simulate.routes.none")}</span>
        ) : (
          <ul className="flex list-none flex-col gap-1">
            {row.sample_routes.map((sample) => (
              // A route template is never cut off: a long one wraps.
              <li key={`${sample.method} ${sample.route}`} data-testid="simulation-route" className="break-all code-3">
                {`${sample.method} ${sample.route} `}
                <span className="text-fg-muted">{formatCount(sample.count)}</span>
              </li>
            ))}
          </ul>
        )}
      </td>
    </tr>
  );
}

/** The figures of a simulation: the table per Rule, the totals and the notes about what the estimate leaves out. */
function Figures({ simulation, withDraft }: { simulation: SimulationResult; withDraft: boolean }) {
  const unknownClients =
    simulation.totals.unknown_client_events > 0 || simulation.rules.some((row) => row.unknown_client_events > 0);
  const notes = [
    ...(simulation.truncated ? [t("policy.simulate.truncated")] : []),
    ...(unknownClients ? [t("policy.simulate.unknown.note")] : []),
    ...simulation.not_simulated.map(notSimulatedText),
  ];
  return (
    <>
      <section
        aria-label={t("policy.simulate.table")}
        // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
        tabIndex={0}
        className="overflow-x-auto"
      >
        <table className="w-full border-collapse body-5">
          <caption className="sr-only">{t("policy.simulate.table")}</caption>
          <thead>
            <tr className="border-border border-b">
              {COLUMNS.map((column, index) => (
                <th key={column} scope="col" className={`${HEAD} ${index === 0 ? STICKY : ""}`}>
                  {t(column)}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {simulation.rules.map((row, position) => (
              <ResultRow key={row.index} row={row} draft={withDraft && position === simulation.rules.length - 1} />
            ))}
          </tbody>
        </table>
      </section>
      <div className="flex flex-col gap-1">
        <p data-testid="simulation-totals" className="body-4 text-fg">
          {t("policy.simulate.totals", {
            requests: requestsText(simulation.totals.would_refuse),
            clients: clientsText(simulation.totals.clients_affected),
          })}
        </p>
        {simulation.totals.unknown_client_events > 0 ? (
          <p data-testid="simulation-unknown-total" className="body-5 text-fg-muted">
            {unknownClientsText(simulation.totals.unknown_client_events, true)}
          </p>
        ) : null}
        {simulation.undecidable_events > 0 ? (
          <p data-testid="simulation-undecidable-events" className="body-5 text-fg-muted">
            {simulation.undecidable_events === 1
              ? t("policy.simulate.undecidable.one")
              : t("policy.simulate.undecidable", { n: formatCount(simulation.undecidable_events) })}
          </p>
        ) : null}
      </div>
      {notes.length > 0 ? (
        <ul className="flex list-none flex-col gap-1">
          {notes.map((note) => (
            <li key={note} data-testid="simulation-note" className="body-5 text-fg-muted">
              {note}
            </li>
          ))}
        </ul>
      ) : null}
    </>
  );
}

interface SimulationPanelProps {
  appId: string;
  environment: Environment;
  /** The version of the Policy the page shows. The form sends it back: another version is not simulated. */
  version: number;
  /** How many Rules the Policy holds: without one there is nothing to simulate here. */
  ruleCount: number;
}

/**
 * "Simulate" for the Rules the page shows, and the result of the last successful simulation of this page view: an
 * estimate from the recorded requests of the last 24 hours, never a promise. A simulation that failed since is
 * shown above it. When an answer arrives the panel takes the focus, so it is read where it appears, also after
 * "Simulate with this Rule" further down the page.
 */
export function SimulationPanel({ appId, environment, version, ruleCount }: SimulationPanelProps) {
  const simulation = useSimulation();
  const ref = useRef<HTMLElement>(null);
  const titleId = useId();
  const helpId = useId();
  const state = simulation?.state ?? null;

  // `state` is a new object with every answer, so the focus comes here each time. An answer that is only about
  // fields of the add-Rule form is not the panel's: the form's own summary takes the focus.
  useEffect(() => {
    if (state && (state.ok || state.errors.some((error) => error.path === ""))) ref.current?.focus();
  }, [state]);

  if (!simulation) return null;
  // A failure of the simulation as a whole; a refusal of a typed field is shown by the add-Rule form.
  const failures = state && !state.ok ? state.errors.filter((error) => error.path === "") : [];
  const run = simulation.run;
  const result = run?.simulation ?? null;

  return (
    <div className="flex flex-col gap-3">
      {ruleCount > 0 ? (
        <form action={simulation.action} className="flex flex-col items-start gap-1">
          <input type="hidden" name="appId" value={appId} />
          <input type="hidden" name="environment" value={environment} />
          <input type="hidden" name="expectedVersion" value={version} />
          <SubmitButton
            variant="secondary"
            disabled={simulation.pending}
            pendingLabel={t("policy.simulate.running")}
            aria-describedby={helpId}
            data-testid="simulate"
          >
            {t("policy.simulate")}
          </SubmitButton>
          <p id={helpId} className="body-5 text-fg-muted">
            {t("policy.simulate.help")}
          </p>
        </form>
      ) : null}
      {result || failures.length > 0 ? (
        <section
          ref={ref}
          tabIndex={-1}
          aria-labelledby={titleId}
          data-testid="simulation-result"
          className="flex flex-col gap-3 rounded-card border border-border p-4"
        >
          <h3 id={titleId} className="heading-6 text-fg">
            {t("policy.simulate.title")}
          </h3>
          {failures.map((failure) => (
            <p
              key={failure.message}
              role="alert"
              data-testid="simulation-error"
              className="body-4 text-sev-critical-text"
            >
              {failure.message}
            </p>
          ))}
          {result ? (
            <>
              <div className="flex flex-col gap-1">
                <p data-testid="simulation-caption" className="caption-1 text-fg-muted">
                  {t("policy.simulate.caption")}
                </p>
                {/* The promise of the replay (plan 11, A11), qualified by the notes below the figures; without
                    figures there are no notes, so no promise either. */}
                {result.events > 0 ? (
                  <p data-testid="simulation-promise" className="body-5 text-fg-muted">
                    {t("policy.simulate.promise")}
                  </p>
                ) : null}
                <p className="flex flex-wrap items-baseline gap-x-3 gap-y-1">
                  <span data-testid="simulation-period" className="code-3">
                    {t("policy.simulate.period", {
                      from: formatDateTime(result.period.from).text,
                      to: formatDateTime(result.period.to).text,
                    })}
                  </span>
                  <span data-testid="simulation-events" className="body-5 text-fg-muted">
                    {result.events === 1
                      ? t("policy.simulate.events.one")
                      : t("policy.simulate.events", { n: formatCount(result.events) })}
                  </span>
                </p>
                <p data-testid="simulation-ran" className="body-5 text-fg-muted">
                  {t("policy.simulate.ran", { time: formatDateTime(result.ran_at).text })}
                </p>
              </div>
              {result.events === 0 ? (
                <div data-testid="simulation-empty">
                  <EmptyState>{t("policy.simulate.empty")}</EmptyState>
                </div>
              ) : (
                <Figures simulation={result} withDraft={run?.withDraft === true} />
              )}
            </>
          ) : null}
        </section>
      ) : null}
    </div>
  );
}
