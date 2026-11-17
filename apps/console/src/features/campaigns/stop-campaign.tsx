"use client";

import type { Campaign } from "@antireverse/protocol";
import { useActionState } from "react";
import { stopCampaignAction } from "@/app/actions.ts";
import { ButtonLink } from "@/components/button.tsx";
import { ConfirmPanel, REASON_FIELD_ID, reasonLabel } from "@/components/confirm-panel.tsx";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

const NO_ERRORS: readonly SummaryError[] = [];

/**
 * The owner's stop of one Campaign, shown for as long as it is queued or running. Stop is a link to the one
 * confirmation step, which the address opens and which holds the only form that can stop: it asks for a reason and
 * works without client-side JavaScript. The Server Action refuses a stop without the confirmation or the reason.
 */
export function StopCampaign({
  campaign,
  confirmStop,
}: {
  campaign: Pick<Campaign, "id" | "host">;
  confirmStop: boolean;
}) {
  const [state, stopAction, pending] = useActionState(stopCampaignAction, null);
  const errors = state?.errors ?? NO_ERRORS;
  return (
    <div className="flex flex-col gap-3">
      <ErrorSummary errors={errors} fields={{ reason: { id: REASON_FIELD_ID, label: reasonLabel(true) } }} />
      {confirmStop ? (
        <ConfirmPanel
          testId="campaign-confirm"
          question={t("campaign.confirm.stop", { host: campaign.host })}
          note={t("campaign.confirm.note")}
          confirmLabel={t("campaign.stop")}
          pendingLabel={t("campaign.stopping")}
          cancelHref={ROUTES.campaign(campaign.id)}
          action={stopAction}
          busy={pending}
          reason={{ required: true, error: fieldError(errors, "reason"), value: state?.reason }}
        >
          <input type="hidden" name="campaignId" value={campaign.id} />
          {/* The confirmation: the Campaign named in the question. */}
          <input type="hidden" name="confirm" value={campaign.id} />
        </ConfirmPanel>
      ) : (
        <div className="flex flex-wrap items-center gap-3">
          <ButtonLink
            variant="destructive"
            href={ROUTES.campaign(campaign.id, { confirm: "stop" })}
            scroll={false}
            prefetch={false}
            data-testid="campaign-stop"
          >
            {t("campaign.stop")}
          </ButtonLink>
          <p className="body-5 text-fg-muted">{t("campaign.stop.help")}</p>
        </div>
      )}
    </div>
  );
}
