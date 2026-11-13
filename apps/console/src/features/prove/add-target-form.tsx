"use client";

import { useActionState } from "react";
import { createTargetAction } from "@/app/actions.ts";
import { Button } from "@/components/button.tsx";
import { ErrorSummary, fieldError } from "@/components/error-summary.tsx";
import { Input } from "@/components/input.tsx";
import { t } from "@/lib/t.ts";

const HOST_ID = "target-host-input";

/**
 * Adds a host. A success opens the host's page with the two ways to prove it; a refusal keeps what was typed and
 * explains it below the field and in the summary above the form.
 */
export function AddTargetForm() {
  const [state, formAction, pending] = useActionState(createTargetAction, null);
  const errors = state && !state.ok ? state.errors : [];
  const values = state && !state.ok ? state.values : undefined;

  return (
    <form key={values?.host ?? ""} action={formAction} noValidate className="flex max-w-xl flex-col gap-4">
      <ErrorSummary errors={errors} fields={{ host: { id: HOST_ID, label: t("targets.add.host") } }} />
      <Input
        id={HOST_ID}
        name="host"
        label={t("targets.add.host")}
        help={t("targets.add.host.help")}
        defaultValue={values?.host}
        error={fieldError(errors, "host")}
        autoComplete="off"
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        aria-required="true"
        mono
        data-testid="target-host-input"
      />
      <div>
        <Button type="submit" disabled={pending} data-testid="target-add">
          {pending ? t("targets.add.submitting") : t("targets.add.submit")}
        </Button>
      </div>
    </form>
  );
}
