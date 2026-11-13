"use client";

import { type Environment, isBroadPattern, type PolicyRule } from "@antireverse/protocol";
import { useActionState, useId, useMemo } from "react";
import { removeRuleAction, setRuleModeAction } from "@/app/actions.ts";
import { ButtonLink } from "@/components/button.tsx";
import { ConfirmPanel, REASON_FIELD_ID, reasonLabel, TYPED_FIELD_ID } from "@/components/confirm-panel.tsx";
import { EmptyState } from "@/components/empty-state.tsx";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { Icon } from "@/components/icons.tsx";
import { ModeTag } from "@/components/mode-tag.tsx";
import { SubmitButton } from "@/components/submit-button.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { limitText } from "./limit.ts";
import { estimateText, promotionEstimate } from "./simulation.ts";
import { useSimulation } from "./simulation-context.tsx";
import { CELL, DATA, HEAD, STICKY } from "./table.ts";

const COLUMNS = [
  "policy.rule.name",
  "policy.rule.path",
  "policy.rule.methods",
  "policy.col.mode",
  "policy.col.actions",
] as const;
const NO_ERRORS: readonly SummaryError[] = [];

interface RuleListProps {
  appId: string;
  appName: string;
  environment: Environment;
  /** The version the Rules are of. Every form sends it back: a change to another version is refused. */
  version: number;
  /** The Rules of the current version, in the order Shield checks them. */
  rules: readonly PolicyRule[];
  /** The Rule whose promotion the address asks to confirm, if any. */
  confirmRuleId?: string | undefined;
}

/**
 * The Rules of a Policy with their mode mark and their actions. Promoting to Enforce is never one click:
 * the control is a link to the confirmation step, and only that step holds a form that can send it.
 * Going back to Monitor and removing a Rule reduce enforcement and are sent at once.
 */
export function RuleList({ appId, appName, environment, version, rules, confirmRuleId }: RuleListProps) {
  const [modeState, modeAction, modePending] = useActionState(setRuleModeAction, null);
  const [removeState, removeAction, removePending] = useActionState(removeRuleAction, null);
  const baseId = useId();
  // Slice 11: the latest simulation of this page view, where the screen keeps one.
  const simulated = useSimulation()?.run ?? null;
  const busy = modePending || removePending;
  const modeErrors = modeState?.errors ?? NO_ERRORS;
  const removeErrors = removeState?.errors ?? NO_ERRORS;
  // One stable list: the summary takes the focus whenever a new refusal arrives, and only then.
  const errors = useMemo(() => [...modeErrors, ...removeErrors], [modeErrors, removeErrors]);
  const caption = t("policy.caption", { app: appName, environment });
  const typedLabel = t("policy.confirm.typed", { environment });

  return (
    <div className="flex flex-col gap-3">
      <ErrorSummary
        errors={errors}
        fields={{
          typedEnvironment: { id: TYPED_FIELD_ID, label: typedLabel },
          reason: { id: REASON_FIELD_ID, label: reasonLabel(true) },
        }}
      />
      {rules.length === 0 ? (
        <div data-testid="policy-empty">
          <EmptyState>{t("policy.none")}</EmptyState>
        </div>
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
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {rules.map((rule) => {
                const nameId = `${baseId}-${rule.id}`;
                // Only a Rule in Monitor mode can be promoted, whatever the address says.
                const confirming = rule.id === confirmRuleId && rule.mode === "monitor";
                // What promoting this Rule would do, from the last simulation of exactly these Rules.
                const estimate = confirming ? promotionEstimate(simulated, rules, rule) : null;
                return [
                  <tr
                    key={rule.id}
                    data-testid="rule-row"
                    data-rule-id={rule.id}
                    data-mode={rule.mode}
                    data-requires={rule.requires}
                    data-action={rule.action}
                    className={confirming ? "" : "border-border border-b"}
                  >
                    <th scope="row" id={nameId} className={`${CELL} ${STICKY} min-w-32 break-words text-start body-4`}>
                      {rule.name}
                    </th>
                    {/* A pattern is never cut off: a long one wraps. */}
                    <td className={`${CELL} min-w-48`}>
                      <div className="flex flex-col items-start gap-1">
                        <code data-testid="rule-path" className="break-all code-3">
                          {rule.path}
                        </code>
                        {rule.requires === "signature" ? (
                          <span
                            data-testid="rule-requires"
                            data-requires="signature"
                            className="inline-flex h-6 items-center gap-1 rounded-control border border-border-strong border-solid px-2 caption-1 whitespace-nowrap text-fg"
                          >
                            <Icon name="signature" />
                            {t("policy.rule.requires.tag")}
                          </span>
                        ) : null}
                        {/* Slice 08: the limit in words, with the glyph of the Throttled decision. */}
                        {rule.limit ? (
                          <span
                            data-testid="rule-limit"
                            className="inline-flex min-h-6 items-center gap-1 rounded-control border border-border-strong border-solid px-2 caption-1 text-fg"
                          >
                            <Icon name="hourglass-medium" />
                            {limitText(rule.limit)}
                          </span>
                        ) : null}
                        {/* Counters live in each Shield instance: with several, the effective limit is higher. */}
                        {rule.limit && rule.mode === "enforce" ? (
                          <span data-testid="rule-limit-note" className="body-5 text-fg-muted">
                            {t("policy.limit.instance")}
                          </span>
                        ) : null}
                      </div>
                    </td>
                    <td
                      data-testid="rule-methods"
                      className={`${rule.methods.length === 0 ? CELL : DATA} whitespace-nowrap`}
                    >
                      {rule.methods.length === 0 ? t("policy.rule.methods.all") : rule.methods.join(", ")}
                    </td>
                    <td className={`${CELL} whitespace-nowrap`}>
                      <ModeTag mode={rule.mode} />
                    </td>
                    <td className={CELL}>
                      <div className="flex flex-wrap items-center gap-2">
                        {rule.mode === "enforce" ? (
                          <form action={modeAction}>
                            <input type="hidden" name="appId" value={appId} />
                            <input type="hidden" name="environment" value={environment} />
                            <input type="hidden" name="ruleId" value={rule.id} />
                            <input type="hidden" name="mode" value="monitor" />
                            <input type="hidden" name="expectedVersion" value={version} />
                            <SubmitButton
                              variant="secondary"
                              disabled={busy}
                              pendingLabel={t("policy.publishing")}
                              aria-describedby={nameId}
                              data-testid="rule-demote"
                            >
                              {t("policy.rule.demote")}
                            </SubmitButton>
                          </form>
                        ) : confirming ? null : (
                          <ButtonLink
                            variant="secondary"
                            href={ROUTES.policy(appId, environment, { promote: rule.id })}
                            scroll={false}
                            prefetch={false}
                            aria-describedby={nameId}
                            data-testid="rule-promote"
                          >
                            {t("policy.rule.promote")}
                          </ButtonLink>
                        )}
                        <form action={removeAction}>
                          <input type="hidden" name="appId" value={appId} />
                          <input type="hidden" name="environment" value={environment} />
                          <input type="hidden" name="ruleId" value={rule.id} />
                          <input type="hidden" name="expectedVersion" value={version} />
                          <SubmitButton
                            variant="quiet"
                            disabled={busy}
                            pendingLabel={t("policy.publishing")}
                            aria-describedby={nameId}
                            data-testid="rule-remove"
                          >
                            {t("policy.rule.remove")}
                          </SubmitButton>
                        </form>
                      </div>
                    </td>
                  </tr>,
                  confirming ? (
                    <tr key={`${rule.id}-confirm`} className="border-border border-b">
                      <td colSpan={COLUMNS.length} className="px-3 pt-1 pb-3">
                        <ConfirmPanel
                          question={t(rule.limit ? "policy.confirm.promote.throttle" : "policy.confirm.promote", {
                            environment,
                            path: rule.path,
                          })}
                          confirmLabel={t("policy.rule.promote")}
                          cancelHref={ROUTES.policy(appId, environment)}
                          action={modeAction}
                          busy={busy}
                          // Slice 18a: promoting to Enforce is a sensitive change, recorded with its reason.
                          reason={{ required: true, error: fieldError(modeErrors, "reason"), value: modeState?.reason }}
                          estimate={
                            estimate && simulated
                              ? estimateText(estimate, simulated.simulation.ran_at, simulated.simulation.truncated)
                              : undefined
                          }
                          // Enforcing a pattern that starts with a wildcard can take the App offline.
                          typed={
                            isBroadPattern(rule.path)
                              ? {
                                  warning: t("policy.confirm.broad"),
                                  environment,
                                  error: fieldError(modeErrors, "typedEnvironment"),
                                }
                              : undefined
                          }
                        >
                          <input type="hidden" name="appId" value={appId} />
                          <input type="hidden" name="environment" value={environment} />
                          <input type="hidden" name="ruleId" value={rule.id} />
                          <input type="hidden" name="mode" value="enforce" />
                          <input type="hidden" name="expectedVersion" value={version} />
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
