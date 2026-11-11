"use client";

import type { Environment } from "@antireverse/protocol";
import { useActionState } from "react";
import { publishRuleAction } from "@/app/actions.ts";
import { Button } from "@/components/button.tsx";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { Input } from "@/components/input.tsx";
import { t } from "@/lib/t.ts";
import { RULE_METHODS } from "./methods.ts";

const NAME_ID = "rule-name";
const PATH_ID = "rule-path";
const METHODS_ID = "rule-methods";
const REQUIRES_ID = "rule-requires";
const NO_ERRORS: readonly SummaryError[] = [];

/**
 * Adds one Rule to the Policy of this App and Environment. The form has no mode: a new Rule always starts
 * in Monitor mode and is promoted from the Rule list, after a confirmation.
 */
export function AddRuleForm({
  appId,
  environment,
  version,
}: {
  appId: string;
  environment: Environment;
  /** The version of the Policy the page shows. The form sends it back: a change to another version is refused. */
  version: number;
}) {
  const [state, formAction, pending] = useActionState(publishRuleAction, null);
  const errors = state?.errors ?? NO_ERRORS;
  const methodsError = fieldError(errors, "methods");
  const checked = state?.values.methods ?? [];

  return (
    <form action={formAction} noValidate className="flex max-w-xl flex-col gap-4">
      <ErrorSummary
        errors={errors}
        fields={{
          name: { id: NAME_ID, label: t("policy.rule.name") },
          path: { id: PATH_ID, label: t("policy.rule.path") },
          // The link of the summary goes to the first control of the group.
          methods: { id: `${METHODS_ID}-${RULE_METHODS[0]}`, label: t("policy.rule.methods") },
        }}
      />
      <input type="hidden" name="appId" value={appId} />
      <input type="hidden" name="environment" value={environment} />
      <input type="hidden" name="expectedVersion" value={version} />
      <Input
        id={NAME_ID}
        name="name"
        label={t("policy.rule.name")}
        defaultValue={state?.values.name}
        error={fieldError(errors, "name")}
        autoComplete="off"
        aria-required="true"
      />
      <Input
        id={PATH_ID}
        name="path"
        label={t("policy.rule.path")}
        help={t("policy.rule.path.help")}
        mono
        defaultValue={state?.values.path}
        error={fieldError(errors, "path")}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
        aria-required="true"
      />
      <fieldset
        id={METHODS_ID}
        aria-describedby={`${methodsError ? `${METHODS_ID}-error ` : ""}${METHODS_ID}-help`}
        className="flex flex-col gap-1"
      >
        <legend className="title-4 text-fg">{t("policy.rule.methods")}</legend>
        <div className="flex flex-wrap gap-x-4">
          {RULE_METHODS.map((method) => (
            // The whole label is the target: 32 px high on pointer layouts, 48 px on touch layouts.
            <label
              key={method}
              className="inline-flex min-h-8 cursor-pointer items-center gap-2 code-2 pointer-coarse:min-h-12"
            >
              <input
                type="checkbox"
                id={`${METHODS_ID}-${method}`}
                name="methods"
                value={method}
                defaultChecked={checked.includes(method)}
                className="size-4 accent-primary"
              />
              {method}
            </label>
          ))}
        </div>
        <p id={`${METHODS_ID}-help`} className="body-5 text-fg-muted">
          {t("policy.rule.methods.help")}
        </p>
        {methodsError ? (
          <p id={`${METHODS_ID}-error`} className="body-5 text-sev-critical-text" data-testid={`${METHODS_ID}-error`}>
            {methodsError}
          </p>
        ) : null}
      </fieldset>
      {/* Slice 04: the Rule then blocks only the requests without a valid signature; its action stays block. */}
      <div className="flex flex-col gap-1">
        <label
          htmlFor={REQUIRES_ID}
          className="inline-flex min-h-8 cursor-pointer items-center gap-2 title-4 text-fg pointer-coarse:min-h-12"
        >
          <input
            type="checkbox"
            id={REQUIRES_ID}
            name="requires"
            value="signature"
            defaultChecked={state?.values.requires === true}
            aria-describedby={`${REQUIRES_ID}-help`}
            data-testid="rule-requires-signature"
            className="size-4 accent-primary"
          />
          {t("policy.rule.requires")}
        </label>
        <p id={`${REQUIRES_ID}-help`} className="body-5 text-fg-muted">
          {t("policy.rule.requires.help")}
        </p>
      </div>
      <div>
        <Button type="submit" disabled={pending}>
          {pending ? t("policy.rule.adding") : t("policy.rule.add")}
        </Button>
      </div>
    </form>
  );
}
