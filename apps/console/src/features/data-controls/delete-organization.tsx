"use client";

import type { Organization, OrganizationDeletion } from "@antireverse/protocol";
import { useActionState } from "react";
import { cancelDeletionAction, requestDeletionAction } from "@/app/actions.ts";
import { ButtonLink } from "@/components/button.tsx";
import { ConfirmPanel, REASON_FIELD_ID, reasonLabel, TYPED_FIELD_ID } from "@/components/confirm-panel.tsx";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { utcMinute, utcTime } from "./format.ts";

const NO_ERRORS: readonly SummaryError[] = [];

interface DeleteOrganizationProps {
  /** The Organization; null while its deletion is pending (the API no longer names it). */
  organization: Organization | null;
  /** The pending deletion, or null. */
  deletion: OrganizationDeletion | null;
  /** When the data would be erased if the deletion were asked for now (the grace period from the API's constant). */
  erasedIfNow: string;
  /** The confirmation step the address opens. */
  step?: "delete" | "cancel" | undefined;
}

/**
 * The danger zone of Data controls (slice 18b). Without a pending deletion: what a deletion does, and a link to the
 * confirmation step, which asks for the Organization's name typed exactly and a reason. While pending: when the data
 * is erased, the deletion id (for the signed report after the purge), and Cancel deletion, which asks for a reason.
 */
export function DeleteOrganization({ organization, deletion, erasedIfNow, step }: DeleteOrganizationProps) {
  const [requestState, requestAction, requesting] = useActionState(requestDeletionAction, null);
  const [cancelState, cancelAction, cancelling] = useActionState(cancelDeletionAction, null);
  const errors = (deletion ? cancelState?.errors : requestState?.errors) ?? NO_ERRORS;

  return (
    <div
      data-testid="delete-organization"
      className="flex flex-col gap-3 rounded-card border border-destructive bg-surface p-3"
    >
      <ErrorSummary
        errors={errors}
        fields={{
          reason: { id: REASON_FIELD_ID, label: reasonLabel(true) },
          confirm_name: {
            id: TYPED_FIELD_ID,
            label: t("data.delete.confirm.typed", { name: organization?.name ?? "" }),
          },
        }}
      />
      {deletion ? (
        <>
          <p data-testid="deletion-status" className="max-w-3xl body-4 text-fg">
            {t("data.deletion.status", {
              requested: utcTime(deletion.requested_at),
              date: utcTime(deletion.purge_after),
            })}
          </p>
          <dl className="flex flex-col gap-1">
            <dt className="title-4 text-fg">{t("data.deletion.id")}</dt>
            <dd className="code-2 break-all text-fg" data-testid="deletion-id">
              {deletion.id}
            </dd>
            <dd className="body-5 text-fg-muted">{t("data.deletion.id.help", { id: deletion.id })}</dd>
          </dl>
          {step === "cancel" ? (
            <ConfirmPanel
              testId="cancel-confirm"
              question={t("data.cancel.confirm.question")}
              note={t("data.cancel.confirm.note")}
              confirmLabel={t("data.cancel.confirm.submit")}
              pendingLabel={t("data.cancel.confirm.pending")}
              cancelHref={ROUTES.dataControls()}
              cancelLabel={t("data.cancel.confirm.back")}
              action={cancelAction}
              busy={cancelling}
              reason={{ required: true, error: fieldError(errors, "reason"), value: cancelState?.reason }}
            >
              {null}
            </ConfirmPanel>
          ) : (
            <div>
              <ButtonLink
                variant="secondary"
                href={ROUTES.dataControls({ step: "cancel" })}
                scroll={false}
                prefetch={false}
                data-testid="deletion-cancel"
              >
                {t("data.deletion.cancel")}
              </ButtonLink>
            </div>
          )}
        </>
      ) : organization ? (
        <>
          <ul className="flex max-w-3xl list-disc flex-col gap-1 ps-4 body-4 text-fg">
            <li>{t("data.delete.effect.keys")}</li>
            <li>{t("data.delete.effect.erase", { date: utcMinute(erasedIfNow) })}</li>
            <li>{t("data.delete.effect.cancel")}</li>
            <li>{t("data.delete.effect.export")}</li>
          </ul>
          {step === "delete" ? (
            <ConfirmPanel
              testId="delete-confirm"
              question={t("data.delete.confirm.question", { name: organization.name })}
              note={t("data.delete.confirm.note", { date: utcMinute(erasedIfNow) })}
              confirmLabel={t("data.delete.confirm.submit")}
              pendingLabel={t("data.delete.confirm.pending")}
              cancelHref={ROUTES.dataControls()}
              action={requestAction}
              busy={requesting}
              typed={{
                warning: t("data.delete.confirm.warning", { date: utcMinute(erasedIfNow) }),
                environment: organization.name,
                label: t("data.delete.confirm.typed", { name: organization.name }),
                name: "confirm_name",
                error: fieldError(errors, "confirm_name"),
              }}
              reason={{ required: true, error: fieldError(errors, "reason"), value: requestState?.reason }}
            >
              {null}
            </ConfirmPanel>
          ) : (
            <div>
              <ButtonLink
                variant="secondary"
                href={ROUTES.dataControls({ step: "delete" })}
                scroll={false}
                prefetch={false}
                data-testid="delete-start"
              >
                {t("data.delete.start")}
              </ButtonLink>
            </div>
          )}
        </>
      ) : null}
    </div>
  );
}
