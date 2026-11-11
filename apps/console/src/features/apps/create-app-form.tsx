"use client";

import { ENVIRONMENTS, type Environment } from "@antireverse/protocol";
import { useActionState } from "react";
import { createAppAction } from "@/app/actions.ts";
import { Button, ButtonLink } from "@/components/button.tsx";
import { EnvironmentTag } from "@/components/environment-tag.tsx";
import { ErrorSummary, fieldError } from "@/components/error-summary.tsx";
import { Icon } from "@/components/icons.tsx";
import { Input, Select } from "@/components/input.tsx";
import { KeyReveal } from "@/components/key-reveal.tsx";
import { Snippet } from "@/components/snippet.tsx";
import { PolicyKeySnippet } from "@/features/policy/policy-key-snippet.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { type MessageKey, t } from "@/lib/t.ts";
import { SHIELD_INSTALL, shieldEnvironmentLine, shieldExpressSnippet } from "./shield-snippet.ts";

const NAME_ID = "app-name";
const ENVIRONMENT_ID = "app-environment";

const ENVIRONMENT_LABEL: Record<Environment, MessageKey> = {
  production: "environment.production",
  staging: "environment.staging",
  development: "environment.development",
};

/**
 * Creates an App. On success the form gives way to the Shield key (shown once, held only in this
 * component's action state), the Express set-up with the policy public key (`null` when the API could not
 * give it), the monitor-mode sentence and the ways to the live feed and the Policy.
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
        <section aria-labelledby="shield-setup-title" className="flex flex-col gap-4">
          <h2 id="shield-setup-title" className="heading-4">
            {t("shield.setup.title")}
          </h2>
          <Snippet label={t("shield.setup.install")} code={SHIELD_INSTALL} />
          <Snippet label={t("shield.setup.env")} code={shieldEnvironmentLine(state.shieldKey)} />
          <div className="flex flex-col gap-1">
            {policyPublicKey ? (
              <PolicyKeySnippet publicKey={policyPublicKey} />
            ) : (
              <p data-testid="policy-key-unavailable">{t("policy.key.unavailable")}</p>
            )}
            <p className="body-5 text-fg-muted">{t("policy.key.help")}</p>
          </div>
          <Snippet label={t("shield.setup.code")} code={shieldExpressSnippet(apiUrl)} />
          <p data-testid="monitor-note">{t("shield.monitor")}</p>
        </section>
        <div className="flex flex-wrap items-center gap-3">
          <p className="flex items-center gap-2 text-fg-muted">
            <Icon name="circle-dashed" className="size-4 text-fg-subtle" />
            <span className="break-words">{t("live.waiting", { app: state.app.name })}</span>
          </p>
          <ButtonLink href={ROUTES.live(state.app.id)} data-testid="live-link">
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
