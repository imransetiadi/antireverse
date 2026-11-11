"use client";

import type { Finding, PatchSummary } from "@antireverse/protocol";
import { type ReactNode, useActionState } from "react";
import { setPatchModeAction } from "@/app/actions.ts";
import { ButtonLink } from "@/components/button.tsx";
import { ConfirmPanel, TYPED_FIELD_ID } from "@/components/confirm-panel.tsx";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { SubmitButton } from "@/components/submit-button.tsx";
import { formatDateTime } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { NotShippedTag, PatchModeChip } from "./mode-chip.tsx";

const NO_ERRORS: readonly SummaryError[] = [];
const TERM = "caption-1 text-fg-muted";
const DATA = "code-3";

interface FindingPatchProps {
  finding: Finding;
  appName: string;
  /** The Finding's patch (`patchForFinding`), or null when none is available. */
  patch: PatchSummary | null;
  /** True when the address asks for the enforce step. Ignored unless the patch is active and in monitor. */
  confirmEnforce: boolean;
}

function Fact({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col items-start gap-1">
      <dt className={TERM}>{term}</dt>
      {children}
    </div>
  );
}

function LastHit({ iso }: { iso: string | null }) {
  if (iso === null) {
    return (
      <dd data-testid="patch-last-hit" className="text-fg-muted">
        {t("patch.lastHit.none")}
      </dd>
    );
  }
  const time = formatDateTime(iso);
  return (
    <dd>
      <time data-testid="patch-last-hit" dateTime={time.iso} title={time.iso} className={DATA}>
        {t("finding.time.utc", { time: time.text })}
      </time>
    </dd>
  );
}

/**
 * The patch's actions. Enforce is never one click: the control is a link to the confirmation step, and only that
 * step holds the form, with the patch id typed. Back to monitor reduces enforcement and is sent at once.
 */
function PatchActions({ finding, appName, patch, confirmEnforce }: FindingPatchProps & { patch: PatchSummary }) {
  const [state, formAction, pending] = useActionState(setPatchModeAction, null);
  const errors = state?.errors ?? NO_ERRORS;
  const typedLabel = t("patch.confirm.typed", { patch: patch.id });
  const hidden = (
    <>
      <input type="hidden" name="appId" value={finding.app_id} />
      <input type="hidden" name="environment" value={finding.environment} />
      <input type="hidden" name="patchId" value={patch.id} />
      <input type="hidden" name="findingId" value={finding.id} />
    </>
  );

  if (patch.mode === "enforce") {
    return (
      <div className="flex flex-col gap-3">
        <ErrorSummary errors={errors} fields={{}} />
        <form action={formAction}>
          {hidden}
          <input type="hidden" name="mode" value="monitor" />
          <SubmitButton
            variant="secondary"
            disabled={pending}
            pendingLabel={t("patch.saving")}
            data-testid="patch-monitor"
          >
            {t("patch.monitor")}
          </SubmitButton>
        </form>
      </div>
    );
  }

  if (!confirmEnforce) {
    return (
      <ButtonLink
        variant="secondary"
        href={ROUTES.finding(finding.id, { confirm: "enforce" })}
        scroll={false}
        prefetch={false}
        data-testid="patch-enforce"
        className="self-start"
      >
        {t("patch.enforce")}
      </ButtonLink>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      <ErrorSummary errors={errors} fields={{ confirm: { id: TYPED_FIELD_ID, label: typedLabel } }} />
      <ConfirmPanel
        testId="patch-confirm"
        question={t("patch.confirm.enforce", { patch: patch.title, app: appName, environment: finding.environment })}
        note={t("patch.confirm.note")}
        confirmLabel={t("patch.enforce.submit")}
        pendingLabel={t("patch.saving")}
        cancelHref={ROUTES.finding(finding.id)}
        action={formAction}
        busy={pending}
        // The typed confirmation: the patch id, sent as `confirm`.
        typed={{
          warning: t("patch.confirm.warning"),
          environment: patch.id,
          label: typedLabel,
          name: "confirm",
          error: fieldError(errors, "confirm"),
        }}
      >
        {hidden}
        <input type="hidden" name="mode" value="enforce" />
      </ConfirmPanel>
    </div>
  );
}

/**
 * The Finding's virtual patch (slice 20): none available, or its title and id, mode, hits in 24 h and last hit,
 * whether the bundle had room for it, and the actions to enforce it or go back to monitor. The note that
 * upgrading is the fix is always there.
 */
export function FindingPatch(props: FindingPatchProps) {
  const { patch } = props;
  if (patch === null) {
    return (
      <p data-testid="patch-none" className="text-fg-muted">
        {t("patch.none")}
      </p>
    );
  }
  return (
    <div className="flex flex-col gap-3">
      <dl
        data-testid="patch-facts"
        className="grid grid-cols-1 gap-x-6 gap-y-3 rounded-card border border-border bg-surface p-3 sm:grid-cols-2 lg:grid-cols-4"
      >
        <Fact term={t("patch.fact.patch")}>
          <dd className="flex min-w-0 flex-col gap-0.5">
            <span data-testid="patch-title" className="break-words">
              {patch.title}
            </span>
            <span data-testid="patch-id" className={`${DATA} break-all text-fg-muted`}>
              {patch.id}
            </span>
          </dd>
        </Fact>
        <Fact term={t("patch.fact.mode")}>
          <dd className="flex flex-wrap items-center gap-2">
            <PatchModeChip mode={patch.mode} />
            {patch.active && !patch.shipped ? <NotShippedTag /> : null}
          </dd>
        </Fact>
        <Fact term={t("patch.fact.hits")}>
          <dd data-testid="patch-hits" className={DATA}>
            {patch.hits_24h}
          </dd>
        </Fact>
        <Fact term={t("patch.fact.lastHit")}>
          <LastHit iso={patch.last_hit} />
        </Fact>
      </dl>
      {patch.active ? (
        <PatchActions {...props} patch={patch} />
      ) : (
        <p data-testid="patch-inactive" className="text-fg-muted">
          {t("patch.inactive")}
        </p>
      )}
    </div>
  );
}
