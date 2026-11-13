"use client";

import { ACTOR_HASH_PATTERN } from "@antireverse/protocol";
import { useActionState, useEffect, useRef, useState } from "react";
import { eraseSubjectAction } from "@/app/actions.ts";
import { Button } from "@/components/button.tsx";
import { ConfirmPanel, REASON_FIELD_ID, reasonLabel } from "@/components/confirm-panel.tsx";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { Input } from "@/components/input.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { utcTime } from "./format.ts";
import type { DataQuery } from "./query.ts";

const NO_ERRORS: readonly SummaryError[] = [];
const INPUT_ID = "subject-input";
/** The protocol's actor hash pattern as a `pattern` attribute, which is anchored by the browser itself. */
const HASH_PATTERN = ACTOR_HASH_PATTERN.source.replace(/^\^/, "").replace(/\$$/, "");

/**
 * Where this tab keeps the typed hash while the export is sent (review 18b, L2): a refused export comes back to the
 * page with a notice only, and the field is filled again from here — the hash never enters an address. Read once and
 * removed when the page opens.
 */
export const SUBJECT_DRAFT_KEY = "airverse.data.subject";

function takeDraft(): string | null {
  try {
    const value = sessionStorage.getItem(SUBJECT_DRAFT_KEY);
    sessionStorage.removeItem(SUBJECT_DRAFT_KEY);
    return value;
  } catch {
    return null;
  }
}

function keepDraft(value: string): void {
  try {
    sessionStorage.setItem(SUBJECT_DRAFT_KEY, value);
  } catch {
    // Storage may be unavailable (private mode, blocked site data): the notice still shows, the field starts empty.
  }
}

/**
 * An end user's request (slice 18b), by actor hash. The hash stays in the page: Export posts it to the Console's route
 * handler, which streams the download; Erase opens the confirmation step in place (no address holds the hash), which
 * asks for a reason and sends the hash in the Server Action's form. The report of an erasure is announced and takes
 * the focus; it lists the active blocks kept until they end.
 */
export function SubjectRequest({ query }: { query: DataQuery }) {
  const [state, eraseAction, pending] = useActionState(eraseSubjectAction, null);
  const errors = state && !state.ok ? state.errors : NO_ERRORS;
  const report = state?.ok ? state.report : null;
  const [value, setValue] = useState("");
  const [invalid, setInvalid] = useState(false);
  const [confirming, setConfirming] = useState<string | null>(null);
  const inputRef = useRef<HTMLInputElement>(null);
  const eraseRef = useRef<HTMLButtonElement>(null);
  const reportRef = useRef<HTMLDivElement>(null);

  // What was typed before a refused export, from this tab only.
  useEffect(() => {
    const draft = takeDraft();
    if (draft !== null && query.subjectExport !== undefined) setValue(draft);
  }, [query.subjectExport]);
  useEffect(() => {
    if (!report) return;
    setConfirming(null);
    reportRef.current?.focus();
  }, [report]);

  const openErase = () => {
    const hash = value.trim();
    if (!ACTOR_HASH_PATTERN.test(hash)) {
      setInvalid(true);
      inputRef.current?.focus();
      return;
    }
    setInvalid(false);
    setConfirming(hash);
  };
  const closeErase = () => {
    setConfirming(null);
    eraseRef.current?.focus();
  };
  const fieldErrorText = invalid || query.subjectExport === "invalid" ? t("data.subject.invalid") : undefined;

  return (
    <div className="flex flex-col gap-3">
      <p id="subject-help" data-testid="subject-help" className="max-w-3xl body-4 text-fg-muted">
        {t("data.subject.lead")}
      </p>
      {/* A POST to the export's route handler: the hash travels in the body. Erase does not submit it. */}
      <form
        id="subject"
        method="post"
        action={ROUTES.subjectExport}
        aria-describedby="subject-help"
        onSubmit={() => keepDraft(value.trim())}
        className="flex max-w-xl flex-col gap-3"
      >
        <Input
          ref={inputRef}
          id={INPUT_ID}
          name="subject"
          label={t("data.subject.label")}
          help={t("data.subject.help")}
          error={fieldErrorText}
          value={value}
          onChange={(event) => {
            setValue(event.target.value);
            setInvalid(false);
          }}
          required
          aria-required="true"
          pattern={HASH_PATTERN}
          autoComplete="off"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          mono
          data-testid="subject-field"
        />
        <div className="flex flex-wrap gap-2">
          <Button type="submit" variant="secondary" data-testid="subject-export">
            {t("data.subject.export")}
          </Button>
          <Button ref={eraseRef} type="button" variant="secondary" onClick={openErase} data-testid="subject-erase">
            {t("data.subject.erase")}
          </Button>
        </div>
        {query.subjectExport === "failed" ? (
          <p role="alert" data-testid="subject-export-notice" className="body-5 text-sev-critical-text">
            {t("data.subject.export.failed")}
          </p>
        ) : null}
      </form>

      <ErrorSummary errors={errors} fields={{ reason: { id: REASON_FIELD_ID, label: reasonLabel(true) } }} />
      {confirming !== null ? (
        <ConfirmPanel
          testId="subject-confirm"
          question={t("data.subject.confirm.question", { hash: confirming })}
          note={t("data.subject.confirm.note")}
          confirmLabel={t("data.subject.confirm.submit")}
          pendingLabel={t("data.subject.confirm.pending")}
          cancelHref={ROUTES.dataControls()}
          onCancel={closeErase}
          action={eraseAction}
          busy={pending}
          reason={{ required: true, error: fieldError(errors, "reason"), value: state?.ok ? undefined : state?.reason }}
        >
          <input type="hidden" name="ip_hash" value={confirming} />
          {/* The confirmation: the actor hash named in the question. */}
          <input type="hidden" name="confirm" value={confirming} />
        </ConfirmPanel>
      ) : null}

      {/* Always present, so that the report is announced when it arrives. */}
      <div role="status" data-testid="subject-result">
        {report ? (
          <div
            ref={reportRef}
            tabIndex={-1}
            data-testid="subject-report"
            className="flex flex-col gap-2 rounded-card border border-border bg-surface p-3"
          >
            <h3 className="break-words heading-6">{t("data.subject.report.title", { hash: report.ip_hash })}</h3>
            <ul className="flex list-none flex-col gap-1 body-4">
              <li data-testid="subject-events-erased">
                {report.events_erased === 1
                  ? t("data.subject.report.events.one")
                  : t("data.subject.report.events", { count: report.events_erased })}
              </li>
              <li data-testid="subject-blocks-erased">
                {report.containments_erased === 1
                  ? t("data.subject.report.blocks.one")
                  : t("data.subject.report.blocks", { count: report.containments_erased })}
              </li>
            </ul>
            {report.active_containments.length === 0 ? (
              <p className="body-4 text-fg-muted">{t("data.subject.report.active.none")}</p>
            ) : (
              <>
                <p className="body-4">
                  {report.active_containments.length === 1
                    ? t("data.subject.report.active.one")
                    : t("data.subject.report.active", { count: report.active_containments.length })}
                </p>
                <ul data-testid="subject-active" className="flex list-none flex-col gap-1">
                  {report.active_containments.map((block) => (
                    <li key={block.id} className="flex flex-wrap gap-x-2">
                      <span className="code-2">{block.id}</span>
                      <span className="body-4 text-fg-muted">
                        {t("data.subject.report.until", { date: utcTime(block.expires_at) })}
                      </span>
                    </li>
                  ))}
                </ul>
              </>
            )}
          </div>
        ) : null}
      </div>
    </div>
  );
}
