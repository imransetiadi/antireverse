"use client";

import type { Incident } from "@antireverse/protocol";
import { useActionState } from "react";
import { updateIncidentAction } from "@/app/actions.ts";
import { ButtonLink } from "@/components/button.tsx";
import { ConfirmPanel } from "@/components/confirm-panel.tsx";
import { ErrorSummary, type SummaryError } from "@/components/error-summary.tsx";
import { SubmitButton } from "@/components/submit-button.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

const NO_ERRORS: readonly SummaryError[] = [];

interface IncidentActionsProps {
  incident: Incident;
  appName: string;
  /** True when the address asks for the confirmation step of resolving. Ignored once resolved. */
  confirmResolve: boolean;
}

/**
 * The resolve question: a clone Incident names its origin; a Tampered Build Incident its Build's files; any other
 * its network (an em dash when unknown).
 */
function resolveQuestion(incident: Incident, appName: string): string {
  const named = { title: incident.title, app: appName, environment: incident.environment };
  if (incident.rule === "tampered-build") return t("incident.confirm.resolve.tamper", named);
  if (incident.origin !== null) return t("incident.confirm.resolve.clone", { ...named, origin: incident.origin });
  return t("incident.confirm.resolve", { ...named, network: incident.ip_prefix ?? t("incident.fact.none") });
}

/**
 * The status actions of an Incident. Acknowledge (only while open) is sent at once. Resolve (while open or
 * acknowledged) is never one click: the control is a link to the confirmation step, and only that step
 * holds a form that can send it; the Server Action refuses a resolve without the confirmation.
 */
export function IncidentActions({ incident, appName, confirmResolve }: IncidentActionsProps) {
  const [state, formAction, pending] = useActionState(updateIncidentAction, null);
  const errors = state?.errors ?? NO_ERRORS;

  if (incident.status === "resolved") {
    return (
      <p data-testid="incident-resolved-note" className="text-fg-muted">
        {t(
          incident.rule === "tampered-build"
            ? "incident.resolved.note.tamper"
            : incident.origin === null
              ? "incident.resolved.note"
              : "incident.resolved.note.clone",
        )}
      </p>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <ErrorSummary errors={errors} fields={{}} />
      <div className="flex flex-wrap items-center gap-2">
        {incident.status === "open" ? (
          <form action={formAction}>
            <input type="hidden" name="incidentId" value={incident.id} />
            <input type="hidden" name="status" value="acknowledged" />
            <SubmitButton
              variant="secondary"
              disabled={pending}
              pendingLabel={t("incident.saving")}
              data-testid="incident-acknowledge"
            >
              {t("incident.acknowledge")}
            </SubmitButton>
          </form>
        ) : null}
        {confirmResolve ? null : (
          <ButtonLink
            variant="secondary"
            href={ROUTES.incident(incident.id, { confirm: "resolve" })}
            scroll={false}
            prefetch={false}
            data-testid="incident-resolve"
          >
            {t("incident.resolve")}
          </ButtonLink>
        )}
      </div>
      {confirmResolve ? (
        <ConfirmPanel
          testId="incident-confirm"
          question={resolveQuestion(incident, appName)}
          note={t("incident.confirm.note")}
          confirmLabel={t("incident.resolve")}
          pendingLabel={t("incident.saving")}
          cancelHref={ROUTES.incident(incident.id)}
          action={formAction}
          busy={pending}
        >
          <input type="hidden" name="incidentId" value={incident.id} />
          <input type="hidden" name="status" value="resolved" />
          {/* The confirmation: the Incident named in the question. */}
          <input type="hidden" name="confirm" value={incident.id} />
        </ConfirmPanel>
      ) : null}
    </div>
  );
}
