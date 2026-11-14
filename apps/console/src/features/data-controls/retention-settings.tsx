"use client";

import {
  EVENT_RETENTION_DAYS,
  type EventRetentionDays,
  type OrganizationRetention,
  type RetentionRun,
} from "@antireverse/protocol";
import { type FormEvent, useActionState, useEffect, useRef, useState } from "react";
import { type RetentionChangeState, updateRetentionAction } from "@/app/actions.ts";
import { ConfirmPanel, REASON_FIELD_ID, reasonLabel } from "@/components/confirm-panel.tsx";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { Select } from "@/components/input.tsx";
import { SubmitButton } from "@/components/submit-button.tsx";
import { CELL, HEAD, STICKY } from "@/features/policy/table.ts";
import { ROUTES } from "@/lib/routes.ts";
import { type MessageKey, t } from "@/lib/t.ts";
import { utcMinute, utcTime } from "./format.ts";

const NO_ERRORS: readonly SummaryError[] = [];
const SELECT_ID = "retention-days";
const DAY_MS = 86_400_000;
const COUNT = new Intl.NumberFormat("en-US");

/** The tables a run counts, in the order they are listed; any other is listed after them by its name. */
const TABLES: Readonly<Record<string, MessageKey>> = {
  events: "data.retention.table.events",
  containments: "data.retention.table.containments",
  incidents: "data.retention.table.incidents",
  detections: "data.retention.table.detections",
  alert_deliveries: "data.retention.table.alert_deliveries",
  assessments: "data.retention.table.assessments",
};
const ORDER = Object.keys(TABLES);
const rank = (table: string): number => (ORDER.includes(table) ? ORDER.indexOf(table) : ORDER.length);

interface RetentionSettingsProps {
  /** The Event retention and the fixed periods, as the API gave them. */
  retention: OrganizationRetention;
  /** The Organization's last run of the retention job, or null when none ran yet. */
  lastRun: RetentionRun | null;
}

/** What a step names: the period asked for and, roughly, the instant before which received Events go. */
interface Shortening {
  days: EventRetentionDays;
  before: string;
}

const shortening = (days: EventRetentionDays): Shortening => ({
  days,
  before: new Date(Date.now() - days * DAY_MS).toISOString(),
});

/**
 * Settings → Data controls → Retention (slice 18c): what is kept and for how long, the Event retention to choose, and
 * the last run of the daily job. A longer (or the same) period is saved at once. A shorter one opens the confirmation
 * step in place, which says what goes and asks for a reason; the step also opens when the API calls a save a
 * shortening (a tab that shows an older period). The outcome — the date before which Events go — is announced and
 * takes the focus.
 */
export function RetentionSettings({ retention, lastRun }: RetentionSettingsProps) {
  const [state, action, pending] = useActionState(updateRetentionAction, null);
  const errors = state && !state.ok ? state.errors : NO_ERRORS;
  const done = state?.ok ? state : null;
  const current = retention.event_retention_days;
  const [selected, setSelected] = useState<string>(String(current));
  const [confirming, setConfirming] = useState<Shortening | null>(null);
  // The action state whose step was closed with Cancel: it no longer opens the step.
  const [closedFor, setClosedFor] = useState<RetentionChangeState>(null);
  const saveRef = useRef<HTMLButtonElement>(null);
  const doneRef = useRef<HTMLParagraphElement>(null);

  // A save that came back: the step closes on success and opens for a shortening the API asked to confirm.
  useEffect(() => {
    if (state === null) return;
    if (state.ok) {
      setConfirming(null);
      doneRef.current?.focus();
    } else if (state.confirm !== undefined) {
      const days = state.confirm;
      setConfirming((open) => (open?.days === days ? open : shortening(days)));
    }
  }, [state]);

  const onSave = (event: FormEvent<HTMLFormElement>) => {
    const days = Number(selected);
    if ((EVENT_RETENTION_DAYS as readonly number[]).includes(days) && days < current) {
      event.preventDefault();
      setConfirming(shortening(days as EventRetentionDays));
    }
  };
  const closeStep = () => {
    setConfirming(null);
    setClosedFor(state);
    saveRef.current?.focus();
  };
  // The step the action state asks for is rendered from the state itself (review 18c, M1), so that it shows in the
  // server render too: without JavaScript, or before hydration, a shorter period posted by the form still asks.
  const asked = state && !state.ok && state.confirm !== undefined && state !== closedFor ? state.confirm : undefined;
  const open = confirming ?? (asked === undefined ? null : shortening(asked));

  const rows: [string, string][] = [
    [t("data.retention.row.events"), t("data.retention.row.events.kept", { days: current })],
    [t("data.retention.row.guard"), t("data.retention.row.guard.kept", { days: retention.guard_days })],
    [t("data.retention.row.blocks"), t("data.retention.row.blocks.kept", { days: current })],
    [t("data.retention.row.incidents"), t("data.retention.row.incidents.kept", { days: retention.evidence_days })],
    [t("data.retention.row.deliveries"), t("data.retention.row.deliveries.kept", { days: retention.evidence_days })],
    [t("data.retention.row.assessments"), t("data.retention.row.assessments.kept", { days: retention.evidence_days })],
    [t("data.retention.row.artifacts"), t("data.retention.row.artifacts.kept", { days: retention.artifact_days })],
    [t("data.retention.row.audit"), t("data.retention.lifetime")],
    [t("data.retention.row.builds"), t("data.retention.lifetime")],
  ];
  const caption = t("data.retention.caption");

  return (
    <div className="flex flex-col gap-3">
      <p className="max-w-3xl body-4 text-fg-muted">{t("data.retention.lead")}</p>
      <section
        aria-label={caption}
        // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
        tabIndex={0}
        className="max-w-3xl overflow-x-auto"
      >
        <table data-testid="retention-table" className="w-full border-collapse text-start body-5">
          <caption className="sr-only">{caption}</caption>
          <thead>
            <tr className="border-border border-b">
              <th scope="col" className={`${HEAD} ${STICKY}`}>
                {t("data.retention.col.data")}
              </th>
              <th scope="col" className={HEAD}>
                {t("data.retention.col.kept")}
              </th>
            </tr>
          </thead>
          <tbody>
            {rows.map(([what, kept]) => (
              <tr key={what} data-testid="retention-row" className="border-border border-b">
                <th scope="row" className={`${CELL} ${STICKY} text-start title-5 text-fg`}>
                  {what}
                </th>
                <td className={`${CELL} body-5 text-fg`}>{kept}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>

      <ErrorSummary
        errors={errors}
        fields={{
          event_retention_days: { id: SELECT_ID, label: t("data.retention.label") },
          reason: { id: REASON_FIELD_ID, label: reasonLabel(true) },
        }}
      />
      <form action={action} onSubmit={onSave} className="flex max-w-xl flex-wrap items-end gap-2">
        <div className="w-full max-w-xs">
          <Select
            id={SELECT_ID}
            name="event_retention_days"
            label={t("data.retention.label")}
            help={t("data.retention.help")}
            error={fieldError(errors, "event_retention_days")}
            value={selected}
            onChange={(event) => setSelected(event.target.value)}
            data-testid="retention-select"
          >
            {EVENT_RETENTION_DAYS.map((days) => (
              <option key={days} value={String(days)}>
                {t("data.retention.option", { days })}
              </option>
            ))}
          </Select>
        </div>
        <SubmitButton
          ref={saveRef}
          variant="secondary"
          disabled={pending}
          pendingLabel={t("data.retention.saving")}
          data-testid="retention-save"
        >
          {t("data.retention.save")}
        </SubmitButton>
      </form>

      {open !== null ? (
        <ConfirmPanel
          key={open.days}
          testId="retention-confirm"
          question={t("data.retention.confirm.question", { days: open.days })}
          note={t("data.retention.confirm.note", { days: open.days, date: utcMinute(open.before) })}
          confirmLabel={t("data.retention.confirm.submit")}
          pendingLabel={t("data.retention.confirm.pending")}
          cancelHref={ROUTES.dataControls()}
          onCancel={closeStep}
          action={action}
          busy={pending}
          reason={{
            required: true,
            error: fieldError(errors, "reason"),
            value: state && !state.ok ? state.reason : undefined,
          }}
        >
          <input type="hidden" name="event_retention_days" value={String(open.days)} />
          <input type="hidden" name="confirm" value="shorten" />
        </ConfirmPanel>
      ) : null}

      {/* Always present, so that the outcome is announced when it arrives. */}
      <div role="status" data-testid="retention-result">
        {done ? (
          <p
            ref={doneRef}
            tabIndex={-1}
            data-testid="retention-done"
            className="max-w-3xl rounded-card border border-border p-3 body-4 text-fg"
          >
            {t("data.retention.done", { days: done.days, date: utcTime(done.eventsRemovedBefore) })}
          </p>
        ) : null}
      </div>

      <LastRun run={lastRun} />
    </div>
  );
}

/** The Organization's last run of the retention job: when, whether it finished, and the rows removed per table. */
function LastRun({ run }: { run: RetentionRun | null }) {
  const counts = run ? Object.entries(run.counts).sort(([a], [b]) => rank(a) - rank(b) || a.localeCompare(b)) : [];
  return (
    <div data-testid="retention-last-run" className="flex max-w-3xl flex-col gap-1">
      <h3 className="heading-6">{t("data.retention.run.title")}</h3>
      {run === null ? (
        <p className="body-4 text-fg-muted">{t("data.retention.run.none")}</p>
      ) : (
        <>
          <p className="body-4 text-fg">{t("data.retention.run.at", { date: utcTime(run.ran_at) })}</p>
          {run.complete ? null : (
            <p data-testid="retention-incomplete" className="body-4 text-fg">
              {t("data.retention.run.incomplete")}
            </p>
          )}
          {counts.length === 0 ? (
            <p className="body-4 text-fg-muted">{t("data.retention.run.nothing")}</p>
          ) : (
            <ul className="flex list-none flex-col gap-1 body-4">
              {counts.map(([table, count]) => {
                // Own keys only: a table named like a member of Object.prototype is listed by its name (review 18c, L1).
                const label = Object.hasOwn(TABLES, table) ? TABLES[table] : undefined;
                return (
                  <li key={table} data-testid="retention-count">
                    {t("data.retention.run.count", {
                      table: label === undefined ? table : t(label),
                      count: COUNT.format(count),
                    })}
                  </li>
                );
              })}
            </ul>
          )}
          <p className="body-5 text-fg-muted">{t("data.retention.run.artifacts")}</p>
        </>
      )}
    </div>
  );
}
