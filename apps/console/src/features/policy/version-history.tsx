"use client";

import type { Environment, PolicyVersionSummary } from "@antireverse/protocol";
import { useActionState } from "react";
import { rollbackPolicyAction } from "@/app/actions.ts";
import { ButtonLink } from "@/components/button.tsx";
import { ConfirmPanel, REASON_FIELD_ID, reasonLabel, TYPED_FIELD_ID } from "@/components/confirm-panel.tsx";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { formatDateTime } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { CELL, DATA, HEAD, STICKY } from "./table.ts";

const COLUMNS = [
  "policy.history.col.version",
  "policy.history.col.published",
  "policy.history.col.rules",
  "policy.history.col.enforced",
  "policy.col.actions",
] as const;
const NO_ERRORS: readonly SummaryError[] = [];

interface VersionHistoryProps {
  appId: string;
  appName: string;
  environment: Environment;
  /** The version Shields apply now. A rollback sends it back: when the Policy moved on, it is refused. */
  currentVersion: number;
  /** Newest first, at most 20. */
  versions: readonly PolicyVersionSummary[];
  /** The version whose rollback the address asks to confirm, if any. */
  confirmVersion?: number | undefined;
  /** True when the version to confirm brings back a broad Enforce Rule: the stronger confirmation is asked. */
  confirmBroad?: boolean | undefined;
  /**
   * True when the version to confirm enforces a Rule that is not enforced now (slice 18a): the reason is then
   * required. It is offered, optional, for every other rollback.
   */
  confirmPromotes?: boolean | undefined;
}

/**
 * The published versions of a Policy, newest first. Rolling back is never one click: the control is a
 * link to the confirmation step, and only that step holds a form.
 */
export function VersionHistory({
  appId,
  appName,
  environment,
  currentVersion,
  versions,
  confirmVersion,
  confirmBroad = false,
  confirmPromotes = false,
}: VersionHistoryProps) {
  const [state, action] = useActionState(rollbackPolicyAction, null);
  const errors = state?.errors ?? NO_ERRORS;
  const caption = t("policy.history.caption", { app: appName, environment });

  return (
    <div className="flex flex-col gap-3">
      <ErrorSummary
        errors={errors}
        fields={{
          typedEnvironment: { id: TYPED_FIELD_ID, label: t("policy.confirm.typed", { environment }) },
          reason: { id: REASON_FIELD_ID, label: reasonLabel(confirmPromotes) },
        }}
      />
      {versions.length === 0 ? (
        <p className="text-fg-muted">{t("policy.history.none")}</p>
      ) : (
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
                    {column === "policy.history.col.published" ? (
                      <span className="text-fg-subtle"> {t("live.col.time.zone")}</span>
                    ) : null}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {versions.map(({ version, published_at, rule_count, enforced_count }) => {
                const published = formatDateTime(published_at);
                const current = version === currentVersion;
                // The current version has nothing to roll back to, whatever the address says.
                const confirming = version === confirmVersion && !current;
                return [
                  <tr
                    key={version}
                    data-testid="version-row"
                    data-version={version}
                    className={confirming ? "" : "border-border border-b"}
                  >
                    <th scope="row" className={`${DATA} ${STICKY} whitespace-nowrap text-start`}>
                      <span className="inline-flex items-center gap-2">
                        {t("policy.version", { version })}
                        {current ? (
                          <span
                            data-testid="version-current"
                            className="inline-flex h-6 items-center rounded-control border border-border-strong border-solid px-2 caption-1 text-fg-muted"
                          >
                            {t("policy.history.current")}
                          </span>
                        ) : null}
                      </span>
                    </th>
                    <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                      <time dateTime={published.iso} title={published.iso}>
                        {published.text}
                      </time>
                    </td>
                    <td className={DATA}>{rule_count}</td>
                    <td className={DATA}>{enforced_count}</td>
                    <td className={CELL}>
                      {current || confirming ? null : (
                        <ButtonLink
                          variant="secondary"
                          href={ROUTES.policy(appId, environment, { rollback: version })}
                          scroll={false}
                          prefetch={false}
                          data-testid="version-rollback"
                        >
                          {t("policy.rollback")}
                        </ButtonLink>
                      )}
                    </td>
                  </tr>,
                  confirming ? (
                    <tr key={`${version}-confirm`} className="border-border border-b">
                      <td colSpan={COLUMNS.length} className="px-3 pt-1 pb-3">
                        <ConfirmPanel
                          question={t("policy.confirm.rollback", { environment, version })}
                          confirmLabel={t("policy.rollback")}
                          cancelHref={ROUTES.policy(appId, environment)}
                          action={action}
                          reason={{
                            required: confirmPromotes,
                            error: fieldError(errors, "reason"),
                            value: state?.reason,
                          }}
                          typed={
                            confirmBroad
                              ? {
                                  warning: t("policy.confirm.broad.rollback"),
                                  environment,
                                  error: fieldError(errors, "typedEnvironment"),
                                }
                              : undefined
                          }
                        >
                          <input type="hidden" name="appId" value={appId} />
                          <input type="hidden" name="environment" value={environment} />
                          <input type="hidden" name="version" value={version} />
                          <input type="hidden" name="expectedVersion" value={currentVersion} />
                          {/* The confirmation: the Environment named in the question. */}
                          <input type="hidden" name="confirm" value={environment} />
                        </ConfirmPanel>
                      </td>
                    </tr>
                  ) : null,
                ];
              })}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
