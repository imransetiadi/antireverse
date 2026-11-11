"use client";

import { EXPOSURE_LIMITS, type Finding } from "@antireverse/protocol";
import { useActionState } from "react";
import { ignoreFindingAction, reopenFindingAction } from "@/app/actions.ts";
import { ButtonLink } from "@/components/button.tsx";
import { ConfirmPanel } from "@/components/confirm-panel.tsx";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { Input } from "@/components/input.tsx";
import { SubmitButton } from "@/components/submit-button.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { ignoreWindow, packageLabel } from "./format.ts";

const NO_ERRORS: readonly SummaryError[] = [];
const REASON_ID = "finding-reason";
const UNTIL_ID = "finding-until";

interface FindingActionsProps {
  finding: Finding;
  appName: string;
  /** True when the address asks for the ignore step. Ignored unless the Finding is open. */
  confirmIgnore: boolean;
  /** The render time, in ms: the ignore window (tomorrow to 90 days ahead, UTC) is counted from it. */
  now: number;
}

/** Reopen, for an ignored Finding: sent at once, as it only puts the Finding back where it was. */
function ReopenForm({ finding }: { finding: Finding }) {
  const [state, formAction, pending] = useActionState(reopenFindingAction, null);
  return (
    <div className="flex flex-col gap-3">
      <ErrorSummary errors={state?.errors ?? NO_ERRORS} fields={{}} />
      <form action={formAction}>
        <input type="hidden" name="findingId" value={finding.id} />
        <SubmitButton
          variant="secondary"
          disabled={pending}
          pendingLabel={t("finding.reopen.saving")}
          data-testid="finding-reopen"
        >
          {t("finding.reopen")}
        </SubmitButton>
      </form>
    </div>
  );
}

/**
 * Ignore, for an open Finding. Never one click: the control is a link to the confirmation step, and only that
 * step holds the form, with a reason and an end date (tomorrow up to 90 days ahead, 30 by default). The Server
 * Action checks the confirmation, the reason and the date again; the API alone decides.
 */
function IgnoreStep({ finding, appName, confirmIgnore, now }: FindingActionsProps) {
  const [state, formAction, pending] = useActionState(ignoreFindingAction, null);
  const errors = state?.errors ?? NO_ERRORS;
  const dates = ignoreWindow(now);
  const reasonLabel = t("finding.ignore.reason");
  const untilLabel = t("finding.ignore.until");

  if (!confirmIgnore) {
    return (
      <ButtonLink
        variant="secondary"
        href={ROUTES.finding(finding.id, { confirm: "ignore" })}
        scroll={false}
        prefetch={false}
        data-testid="finding-ignore"
        className="self-start"
      >
        {t("finding.ignore")}
      </ButtonLink>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <ErrorSummary
        errors={errors}
        fields={{ reason: { id: REASON_ID, label: reasonLabel }, until: { id: UNTIL_ID, label: untilLabel } }}
      />
      <ConfirmPanel
        testId="finding-confirm"
        question={t("finding.confirm.ignore", {
          advisory: finding.advisory_id,
          package: packageLabel(finding),
          app: appName,
          environment: finding.environment,
        })}
        note={t("finding.confirm.note")}
        confirmLabel={t("finding.ignore.submit")}
        pendingLabel={t("finding.ignore.saving")}
        cancelHref={ROUTES.finding(finding.id)}
        action={formAction}
        busy={pending}
      >
        <input type="hidden" name="findingId" value={finding.id} />
        {/* The confirmation: the Finding named in the question. */}
        <input type="hidden" name="confirm" value={finding.id} />
        {/* A refused submit starts the fields afresh from what was sent. */}
        <div key={JSON.stringify(state?.values ?? null)} className="flex w-full flex-wrap items-start gap-3">
          <div className="w-full max-w-md">
            <Input
              id={REASON_ID}
              name="reason"
              type="text"
              label={reasonLabel}
              help={t("finding.ignore.reason.help")}
              error={fieldError(errors, "reason")}
              defaultValue={state?.values.reason ?? ""}
              required
              aria-required="true"
              maxLength={EXPOSURE_LIMITS.ignoreReasonMax}
              autoComplete="off"
              data-testid="finding-ignore-reason-input"
            />
          </div>
          <div className="w-full max-w-xs">
            <Input
              id={UNTIL_ID}
              name="until"
              type="date"
              label={untilLabel}
              help={t("finding.ignore.until.help")}
              error={fieldError(errors, "until")}
              defaultValue={state?.values.until ?? dates.initial}
              min={dates.min}
              max={dates.max}
              required
              aria-required="true"
              mono
              data-testid="finding-ignore-until-input"
            />
          </div>
        </div>
      </ConfirmPanel>
    </div>
  );
}

/** The actions of a Finding: Ignore while open, Reopen while ignored, none once fixed. */
export function FindingActions(props: FindingActionsProps) {
  const { finding } = props;
  if (finding.status === "fixed") {
    return (
      <p data-testid="finding-fixed-note" className="text-fg-muted">
        {t("finding.fixed.note")}
      </p>
    );
  }
  if (finding.status === "ignored") return <ReopenForm finding={finding} />;
  return <IgnoreStep {...props} />;
}
