"use client";

import Link from "next/link";
import { useActionState } from "react";
import { createOrganizationAction } from "@/app/actions.ts";
import { Button, ButtonLink } from "@/components/button.tsx";
import { ErrorSummary, fieldError } from "@/components/error-summary.tsx";
import { Input } from "@/components/input.tsx";
import { KeyReveal } from "@/components/key-reveal.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

const NAME_ID = "organization-name";

/**
 * Creates the Organization. On success the form gives way to the admin key, which exists only in this
 * component's action state: it is gone after a reload or a navigation and is never part of a URL.
 */
export function CreateOrganizationForm() {
  const [state, formAction, pending] = useActionState(createOrganizationAction, null);

  if (state?.ok) {
    return (
      <div className="flex flex-col gap-4">
        <p data-testid="organization-created" className="break-words">
          {t("onboarding.created", { organization: state.organization.name })}
        </p>
        <KeyReveal title={t("key.admin.title")} help={t("key.admin.help")} value={state.adminKey} testId="admin-key" />
        <div>
          <ButtonLink href={ROUTES.apps}>{t("key.continue")}</ButtonLink>
        </div>
      </div>
    );
  }

  const errors = state?.errors ?? [];
  return (
    <form action={formAction} noValidate className="flex flex-col gap-4">
      <ErrorSummary errors={errors} fields={{ name: { id: NAME_ID, label: t("onboarding.name") } }} />
      <Input
        id={NAME_ID}
        name="name"
        label={t("onboarding.name")}
        defaultValue={state?.values.name}
        error={fieldError(errors, "name")}
        autoComplete="organization"
        aria-required="true"
      />
      <div>
        <Button type="submit" disabled={pending}>
          {pending ? t("onboarding.submitting") : t("onboarding.submit")}
        </Button>
      </div>
      <p>
        <Link href={ROUTES.signIn}>{t("onboarding.signin")}</Link>
      </p>
    </form>
  );
}
