"use client";

import type { Containment } from "@antireverse/protocol";
import { useActionState, useId } from "react";
import { liftContainmentAction } from "@/app/actions.ts";
import { ButtonLink } from "@/components/button.tsx";
import { ConfirmPanel } from "@/components/confirm-panel.tsx";
import { EmptyState } from "@/components/empty-state.tsx";
import { ErrorSummary, type SummaryError } from "@/components/error-summary.tsx";
import { CELL, DATA, HEAD, STICKY } from "@/features/policy/table.ts";
import { formatDateTime } from "@/lib/format.ts";
import { t } from "@/lib/t.ts";
import { shortHash, shortId, targetText } from "./format.ts";
import { ContainmentStatusTag } from "./tags.tsx";

const COLUMNS = [
  "blocks.col.target",
  "blocks.col.status",
  "blocks.col.ends",
  "blocks.col.createdBy",
  "blocks.col.actions",
] as const;
const NO_ERRORS: readonly SummaryError[] = [];

/** When the block ends or ended, in words: Expires …, Expired … or Lifted … (UTC). */
function ends(containment: Containment): { text: string; iso: string } {
  if (containment.status === "lifted" && containment.lifted_at !== null) {
    const time = formatDateTime(containment.lifted_at);
    return { text: t("blocks.ends.lifted", { time: time.text }), iso: time.iso };
  }
  const time = formatDateTime(containment.expires_at);
  const key = containment.status === "expired" ? "blocks.ends.expired" : "blocks.ends.active";
  return { text: t(key, { time: time.text }), iso: time.iso };
}

/** The question before lifting: names the target, the Environment and the App, and what follows. */
function liftQuestion(containment: Containment, appName: string): string {
  const where = { environment: containment.environment, app: appName };
  return containment.target.kind === "actor"
    ? t("blocks.confirm.lift.actor", { ...where, actor: shortHash(containment.target.ip_hash) })
    : t("blocks.confirm.lift.network", { ...where, network: containment.target.ip_prefix });
}

interface BlockListProps {
  /** As the API returned them: newest first. */
  containments: readonly Containment[];
  /** The name of the App the blocks belong to. */
  appName: string;
  caption: string;
  /** What will appear here, for an empty list. */
  empty: string;
  /** The address of the screen: Lift links to `<base>?lift=<id>`, Cancel to `<base>`. */
  base: string;
  /** Where the Lift action goes back to: the Incident, or the App's containment page. */
  returnTo: { incidentId: string } | { appId: string };
  /** The block whose lifting the address asks to confirm, if any. */
  confirmLiftId: string | undefined;
}

/**
 * Blocks with their target, status (word and icon), end time and creator. Lifting is never one click: Lift
 * is a link to the confirmation step, offered for active blocks only, and only that step can send it.
 */
export function BlockList({ containments, appName, caption, empty, base, returnTo, confirmLiftId }: BlockListProps) {
  const [state, liftAction, pending] = useActionState(liftContainmentAction, null);
  const baseId = useId();
  const errors = state?.errors ?? NO_ERRORS;

  if (containments.length === 0) {
    return (
      <div data-testid="blocks-empty">
        <EmptyState>{empty}</EmptyState>
      </div>
    );
  }

  return (
    <div data-testid="block-list" className="flex flex-col gap-3">
      <ErrorSummary errors={errors} fields={{}} />
      <section
        aria-label={caption}
        // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
        tabIndex={0}
        className="overflow-x-auto"
      >
        <table className="w-full border-collapse body-5">
          <caption className="sr-only">{caption}</caption>
          <thead>
            <tr className="border-border border-b">
              {COLUMNS.map((column, index) => (
                <th key={column} scope="col" className={`${HEAD} ${index === 0 ? STICKY : ""}`}>
                  {t(column)}
                  {column === "blocks.col.ends" ? (
                    <span className="text-fg-subtle"> {t("incidents.col.zone")}</span>
                  ) : null}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {containments.map((containment) => {
              const targetId = `${baseId}-${containment.id}`;
              const confirming = containment.id === confirmLiftId && containment.status === "active";
              const end = ends(containment);
              const full =
                containment.target.kind === "actor" ? containment.target.ip_hash : containment.target.ip_prefix;
              return [
                <tr
                  key={containment.id}
                  data-testid="block-row"
                  data-block-id={containment.id}
                  data-status={containment.status}
                  data-kind={containment.target.kind}
                  className={confirming ? "" : "border-border border-b"}
                >
                  <th scope="row" id={targetId} className={`${CELL} ${STICKY} min-w-40 text-start body-5`}>
                    <span data-testid="block-target" title={full} className="break-all code-3">
                      {targetText(containment.target)}
                    </span>
                  </th>
                  <td className={`${CELL} whitespace-nowrap`}>
                    <ContainmentStatusTag status={containment.status} />
                  </td>
                  <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                    <time data-testid="block-ends" dateTime={end.iso} title={end.iso}>
                      {end.text}
                    </time>
                  </td>
                  <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                    <span data-testid="block-created-by" title={containment.created_by}>
                      {shortId(containment.created_by)}
                    </span>
                  </td>
                  <td className={CELL}>
                    {containment.status === "active" && !confirming ? (
                      <ButtonLink
                        variant="quiet"
                        href={`${base}?lift=${containment.id}`}
                        scroll={false}
                        prefetch={false}
                        aria-describedby={targetId}
                        data-testid="block-lift"
                      >
                        {t("blocks.lift")}
                      </ButtonLink>
                    ) : null}
                  </td>
                </tr>,
                confirming ? (
                  <tr key={`${containment.id}-confirm`} className="border-border border-b">
                    <td colSpan={COLUMNS.length} className="px-3 pt-1 pb-3">
                      <ConfirmPanel
                        testId="lift-confirm"
                        question={liftQuestion(containment, appName)}
                        note={t("blocks.confirm.lift.note")}
                        confirmLabel={t("blocks.lift")}
                        pendingLabel={t("blocks.lifting")}
                        cancelHref={base}
                        action={liftAction}
                        busy={pending}
                      >
                        <input type="hidden" name="containmentId" value={containment.id} />
                        {/* The confirmation: the block named in the question. */}
                        <input type="hidden" name="confirm" value={containment.id} />
                        {"incidentId" in returnTo ? (
                          <input type="hidden" name="incidentId" value={returnTo.incidentId} />
                        ) : (
                          <input type="hidden" name="appId" value={returnTo.appId} />
                        )}
                      </ConfirmPanel>
                    </td>
                  </tr>
                ) : null,
              ];
            })}
          </tbody>
        </table>
      </section>
    </div>
  );
}
