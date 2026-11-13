"use client";

import { INTENSITIES } from "@antireverse/protocol";
import { useActionState, useId } from "react";
import { checkAuthorizationAction } from "@/app/actions.ts";
import { ErrorSummary, fieldError } from "@/components/error-summary.tsx";
import { Input, Select } from "@/components/input.tsx";
import { SubmitButton } from "@/components/submit-button.tsx";
import { t } from "@/lib/t.ts";
import { AUTHORIZE_REASON_LABEL } from "./labels.ts";

const IDS = { host: "check-host", path: "check-path", intensity: "check-intensity", at: "check-at" } as const;

interface CheckTestFormProps {
  /** `YYYY-MM-DDTHH:MM` in UTC: the time the page was rendered. */
  defaultAt: string;
  /** The Organization's hosts, offered as suggestions. */
  hosts: readonly string[];
}

/**
 * The dry "Check a test" form: asks `authorize` whether a test of this host, path and intensity would be allowed at
 * that time, and shows Allowed or the rule that refuses it, in plain words. Nothing is started.
 */
export function CheckTestForm({ defaultAt, hosts }: CheckTestFormProps) {
  const [state, formAction] = useActionState(checkAuthorizationAction, null);
  const listId = useId();
  const errors = state && !state.ok ? state.errors : [];
  const values = state?.values ?? { host: "", path: "/", intensity: "passive", at: defaultAt };
  const result = state?.ok ? state.result : null;

  return (
    <div className="flex max-w-2xl flex-col gap-4">
      <form key={JSON.stringify(values)} action={formAction} noValidate className="flex flex-col gap-4">
        <ErrorSummary
          errors={errors}
          fields={{
            host: { id: IDS.host, label: t("check.host") },
            path: { id: IDS.path, label: t("check.path") },
            intensity: { id: IDS.intensity, label: t("check.intensity") },
            at: { id: IDS.at, label: t("check.at") },
          }}
        />
        <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
          <Input
            id={IDS.host}
            name="host"
            label={t("check.host")}
            defaultValue={values.host}
            error={fieldError(errors, "host")}
            list={listId}
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            mono
          />
          <Input
            id={IDS.path}
            name="path"
            label={t("check.path")}
            defaultValue={values.path}
            error={fieldError(errors, "path")}
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            mono
          />
          <Select
            id={IDS.intensity}
            name="intensity"
            label={t("check.intensity")}
            defaultValue={values.intensity}
            error={fieldError(errors, "intensity")}
            mono
          >
            {INTENSITIES.map((level) => (
              <option key={level} value={level}>
                {level}
              </option>
            ))}
          </Select>
          <Input
            id={IDS.at}
            name="at"
            type="datetime-local"
            label={t("check.at")}
            help={t("check.at.help")}
            defaultValue={values.at}
            error={fieldError(errors, "at")}
            mono
          />
        </div>
        <datalist id={listId}>
          {hosts.map((host) => (
            <option key={host} value={host} />
          ))}
        </datalist>
        <div>
          <SubmitButton pendingLabel={t("check.submitting")} data-testid="check-submit">
            {t("check.submit")}
          </SubmitButton>
        </div>
      </form>
      {/* Always present, so that the answer is announced. */}
      <div role="status">
        {result === null ? null : (
          <p
            data-testid="check-result"
            data-allowed={String(result.allowed)}
            className={`rounded-card border p-3 body-4 ${result.allowed ? "border-primary text-fg" : "border-sev-high text-fg"}`}
          >
            {result.allowed
              ? t("check.allowed", { id: result.roe_id })
              : t("check.refused", { reason: t(AUTHORIZE_REASON_LABEL[result.reason]) })}
          </p>
        )}
      </div>
    </div>
  );
}
