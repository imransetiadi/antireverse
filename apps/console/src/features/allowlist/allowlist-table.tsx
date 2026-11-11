"use client";

import { type AllowlistEntry, CONTAINMENT_LIMITS } from "@antireverse/protocol";
import { useActionState, useId } from "react";
import { deleteAllowlistEntryAction } from "@/app/actions.ts";
import { ButtonLink } from "@/components/button.tsx";
import { ConfirmPanel } from "@/components/confirm-panel.tsx";
import { EmptyState } from "@/components/empty-state.tsx";
import { ErrorSummary, type SummaryError } from "@/components/error-summary.tsx";
import { shortId } from "@/features/containment/format.ts";
import { CELL, DATA, HEAD, STICKY } from "@/features/policy/table.ts";
import { formatDateTime } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

const COLUMNS = [
  "allowlist.col.cidr",
  "allowlist.col.note",
  "allowlist.col.added",
  "allowlist.col.addedBy",
  "allowlist.col.actions",
] as const;
const NO_ERRORS: readonly SummaryError[] = [];

interface AllowlistTableProps {
  entries: readonly AllowlistEntry[];
  /** The range whose removal the address asks to confirm, if any. */
  confirmRemoveId: string | undefined;
}

/**
 * The never block list with its count against the limit. Removing is never one click: Remove is a link to
 * the confirmation step, and only that step holds a form that can send it.
 */
export function AllowlistTable({ entries, confirmRemoveId }: AllowlistTableProps) {
  const [state, removeAction, pending] = useActionState(deleteAllowlistEntryAction, null);
  const baseId = useId();
  const errors = state?.errors ?? NO_ERRORS;
  const caption = t("allowlist.caption");

  return (
    <div className="flex flex-col gap-3">
      <p data-testid="allowlist-count" className="code-3 text-fg-muted">
        {t("allowlist.count", { count: entries.length, max: CONTAINMENT_LIMITS.allowlistMax })}
      </p>
      {entries.length === 0 ? (
        <div data-testid="allowlist-empty">
          <EmptyState>{t("allowlist.empty")}</EmptyState>
        </div>
      ) : (
        <>
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
                      {column === "allowlist.col.added" ? (
                        <span className="text-fg-subtle"> {t("incidents.col.zone")}</span>
                      ) : null}
                    </th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {entries.map((entry) => {
                  const cidrId = `${baseId}-${entry.id}`;
                  const confirming = entry.id === confirmRemoveId;
                  const added = formatDateTime(entry.created_at);
                  return [
                    <tr
                      key={entry.id}
                      data-testid="allowlist-row"
                      data-entry-id={entry.id}
                      className={confirming ? "" : "border-border border-b"}
                    >
                      <th
                        scope="row"
                        id={cidrId}
                        data-testid="allowlist-cidr"
                        className={`${DATA} ${STICKY} min-w-40 break-all text-start`}
                      >
                        {entry.cidr}
                      </th>
                      <td
                        data-testid="allowlist-note"
                        className={`${CELL} min-w-32 break-words ${entry.note === "" ? "text-fg-subtle" : ""}`}
                      >
                        {entry.note === "" ? t("allowlist.note.none") : entry.note}
                      </td>
                      <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                        <time data-testid="allowlist-added" dateTime={added.iso} title={added.iso}>
                          {added.text}
                        </time>
                      </td>
                      <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                        <span data-testid="allowlist-added-by" title={entry.created_by}>
                          {shortId(entry.created_by)}
                        </span>
                      </td>
                      <td className={CELL}>
                        {confirming ? null : (
                          <ButtonLink
                            variant="quiet"
                            href={ROUTES.allowlist({ remove: entry.id })}
                            scroll={false}
                            prefetch={false}
                            aria-describedby={cidrId}
                            data-testid="allowlist-remove"
                          >
                            {t("allowlist.remove")}
                          </ButtonLink>
                        )}
                      </td>
                    </tr>,
                    confirming ? (
                      <tr key={`${entry.id}-confirm`} className="border-border border-b">
                        <td colSpan={COLUMNS.length} className="px-3 pt-1 pb-3">
                          <ConfirmPanel
                            testId="allowlist-confirm"
                            question={t("allowlist.confirm.remove", { cidr: entry.cidr })}
                            note={t("allowlist.confirm.note")}
                            confirmLabel={t("allowlist.remove")}
                            pendingLabel={t("allowlist.removing")}
                            cancelHref={ROUTES.allowlist()}
                            action={removeAction}
                            busy={pending}
                          >
                            <input type="hidden" name="entryId" value={entry.id} />
                            {/* The confirmation: the range named in the question. */}
                            <input type="hidden" name="confirm" value={entry.id} />
                          </ConfirmPanel>
                        </td>
                      </tr>
                    ) : null,
                  ];
                })}
              </tbody>
            </table>
          </section>
        </>
      )}
    </div>
  );
}
