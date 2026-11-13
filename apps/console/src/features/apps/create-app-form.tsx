"use client";

import { ENVIRONMENTS, type Environment } from "@antireverse/protocol";
import { useActionState } from "react";
import { createAppAction } from "@/app/actions.ts";
import { Button, ButtonLink } from "@/components/button.tsx";
import { EnvironmentTag } from "@/components/environment-tag.tsx";
import { ErrorSummary, fieldError } from "@/components/error-summary.tsx";
import { Input, Select } from "@/components/input.tsx";
import { KeyReveal } from "@/components/key-reveal.tsx";
import { SetupGuide } from "@/features/setup/setup-guide.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { type MessageKey, t } from "@/lib/t.ts";

const NAME_ID = "app-name";
const ENVIRONMENT_ID = "app-environment";

const ENVIRONMENT_LABEL: Record<Environment, MessageKey> = {
  production: "environment.production",
  staging: "environment.staging",
  development: "environment.development",
};

/**
 * Creates an App. On success the form gives way to the Shield key (shown once, held only in this
 * component's action state), then the App's set-up steps with that key filled in (slice 16; the policy public key
 * is `null` when the API could not give it), and the ways to the Set up page, the live feed and the Policy.
 */
export function CreateAppForm({ apiUrl, policyPublicKey }: { apiUrl: string; policyPublicKey: string | null }) {
  const [state, formAction, pending] = useActionState(createAppAction, null);

  if (state?.ok) {
    return (
      <div className="flex flex-col gap-6">
        <p className="flex flex-wrap items-center gap-2">
          <span data-testid="app-created" className="break-words">
            {t("app.created", { app: state.app.name })}
          </span>
          <EnvironmentTag environment={state.environment} />
        </p>
        <KeyReveal
          title={t("key.shield.title")}
          help={t("key.shield.help")}
          value={state.shieldKey}
          testId="shield-key"
        />
        {/* The set-up of the new App, with the key filled in: the same steps as its Set up page, which cannot show
            the key again (slice 16). A redirect there would lose the key, which lives only in this action state. */}
        <SetupGuide
          app={state.app}
          initialSetup={{
            environment: state.environment,
            shield: { done_at: null },
            guard: { done_at: null },
            harden: { done_at: null },
          }}
          apiUrl={apiUrl}
          policyPublicKey={policyPublicKey}
          shieldKey={state.shieldKey}
        />
        <p className="body-5 text-fg-muted">{t("setup.created.later", { app: state.app.name })}</p>
        <div className="flex flex-wrap items-center gap-3">
          <ButtonLink href={ROUTES.setup(state.app.id, state.environment)} data-testid="setup-link">
            {t("setup.created.open")}
          </ButtonLink>
          <ButtonLink variant="secondary" href={ROUTES.live(state.app.id)} data-testid="live-link">
            {t("shield.live")}
          </ButtonLink>
          <ButtonLink
            variant="secondary"
            href={ROUTES.policy(state.app.id, state.environment)}
            data-testid="policy-link"
          >
            {t("nav.policy")}
          </ButtonLink>
        </div>
      </div>
    );
  }

  const errors = state?.errors ?? [];
  return (
    <form action={formAction} noValidate className="flex flex-col gap-4">
      <ErrorSummary
        errors={errors}
        fields={{
          name: { id: NAME_ID, label: t("app.name") },
          environment: { id: ENVIRONMENT_ID, label: t("app.environment") },
        }}
      />
      <Input
        id={NAME_ID}
        name="name"
        label={t("app.name")}
        defaultValue={state?.values.name}
        error={fieldError(errors, "name")}
        autoComplete="off"
        aria-required="true"
      />
      <Select
        id={ENVIRONMENT_ID}
        name="environment"
        label={t("app.environment")}
        help={t("app.environment.help")}
        defaultValue={state?.values.environment ?? "development"}
        error={fieldError(errors, "environment")}
      >
        {ENVIRONMENTS.map((environment) => (
          <option key={environment} value={environment}>
            {t(ENVIRONMENT_LABEL[environment])}
          </option>
        ))}
      </Select>
      <div>
        <Button type="submit" disabled={pending}>
          {pending ? t("app.creating") : t("app.create")}
        </Button>
      </div>
    </form>
  );
}
