"use client";

import type { Target } from "@antireverse/protocol";
import { useActionState } from "react";
import { deleteTargetAction } from "@/app/actions.ts";
import { ButtonLink } from "@/components/button.tsx";
import { ConfirmPanel } from "@/components/confirm-panel.tsx";
import { ErrorSummary, type SummaryError } from "@/components/error-summary.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

const NO_ERRORS: readonly SummaryError[] = [];

interface RemoveTargetProps {
  target: Target;
  /** The host is in the scope of the current Rules of Engagement: it cannot be removed. */
  inScope: boolean;
  /** The address asks to confirm the removal. */
  confirmRemove: boolean;
}

/**
 * Removing is never one click: Remove is a link to the confirmation step, and only that step holds a form that
 * can send it. A host of the current scope offers no Remove at all, and says why.
 */
export function RemoveTarget({ target, inScope, confirmRemove }: RemoveTargetProps) {
  const [state, removeAction, pending] = useActionState(deleteTargetAction, null);
  const errors = state?.errors ?? NO_ERRORS;

  if (inScope) {
    return (
      <p data-testid="target-in-scope" className="body-4 text-fg-muted">
        {t("target.inScope")}
      </p>
    );
  }
  return (
    <div className="flex flex-col gap-3">
      <p className="body-5 text-fg-muted">{t("target.remove.help")}</p>
      <ErrorSummary errors={errors} fields={{}} />
      {confirmRemove ? (
        <ConfirmPanel
          testId="target-confirm"
          question={t("target.confirm.remove", { host: target.host })}
          note={t("target.confirm.note")}
          confirmLabel={t("target.remove")}
          pendingLabel={t("target.removing")}
          cancelHref={ROUTES.target(target.id)}
          action={removeAction}
          busy={pending}
        >
          <input type="hidden" name="targetId" value={target.id} />
          {/* The confirmation: the target named in the question. */}
          <input type="hidden" name="confirm" value={target.id} />
        </ConfirmPanel>
      ) : (
        <div>
          <ButtonLink
            variant="secondary"
            href={ROUTES.target(target.id, { confirm: "remove" })}
            scroll={false}
            prefetch={false}
            data-testid="target-remove"
          >
            {t("target.remove")}
          </ButtonLink>
        </div>
      )}
    </div>
  );
}
