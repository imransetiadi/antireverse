"use client";

import { TIER_IDS, TIERS } from "@antireverse/protocol";
import { useActionState } from "react";
import { assessAgainAction } from "@/app/actions.ts";
import { ErrorSummary, fieldError } from "@/components/error-summary.tsx";
import { Select } from "@/components/input.tsx";
import { SubmitButton } from "@/components/submit-button.tsx";
import { formatCount, formatDateTime } from "@/lib/format.ts";
import { t } from "@/lib/t.ts";
import { formatDuration } from "./format.ts";

const TIER_ID = "assess-again-tier";

interface AssessAgainFormProps {
  appId: string;
  buildId: string;
  /** Until when the API keeps the uploaded bundle (ISO, in the future). */
  keptUntil: string;
}

/**
 * "Assess again" (slice 12a): a tier choice, each with its budget of tool calls and time, and a submit that asks
 * the API to assess the Build's kept bundle again. Nothing is uploaded. On success it names the queued Assessment;
 * the page, refreshed by the action, shows it as the latest.
 */
export function AssessAgainForm({ appId, buildId, keptUntil }: AssessAgainFormProps) {
  const [state, formAction] = useActionState(assessAgainAction, null);
  const errors = state && !state.ok ? state.errors : [];
  const queued = state?.ok ? state.assessment : null;
  return (
    <div data-testid="assess-again" className="flex max-w-xl flex-col gap-3">
      <form action={formAction} noValidate className="flex flex-col gap-3">
        <ErrorSummary errors={errors} fields={{ tier: { id: TIER_ID, label: t("assessment.again.tier") } }} />
        <input type="hidden" name="appId" value={appId} />
        <input type="hidden" name="buildId" value={buildId} />
        <Select
          id={TIER_ID}
          name="tier"
          label={t("assessment.again.tier")}
          help={t("assessment.again.help", { date: formatDateTime(keptUntil).text })}
          defaultValue={TIER_IDS[0]}
          error={fieldError(errors, "tier")}
          mono
        >
          {TIER_IDS.map((tier) => (
            <option key={tier} value={tier}>
              {t("assessment.again.option", {
                tier,
                calls: formatCount(TIERS[tier].calls),
                time: formatDuration(TIERS[tier].seconds),
              })}
            </option>
          ))}
        </Select>
        <div>
          <SubmitButton pendingLabel={t("assessment.again.submitting")} data-testid="assess-again-submit">
            {t("assessment.again")}
          </SubmitButton>
        </div>
      </form>
      {/* Always present, so that the answer is announced. */}
      <div role="status">
        {queued === null ? null : (
          <p data-testid="assess-again-queued" className="text-fg-muted">
            {t("assessment.again.queued", { id: queued.id, tier: queued.tier })}
          </p>
        )}
      </div>
    </div>
  );
}
