"use client";

import { ALERT_CHANNEL_KINDS } from "@antireverse/protocol";
import { useActionState, useState } from "react";
import { type CreateAlertChannelState, createAlertChannelAction } from "@/app/actions.ts";
import { Button } from "@/components/button.tsx";
import { ErrorSummary, fieldError } from "@/components/error-summary.tsx";
import { Input, Select } from "@/components/input.tsx";
import { KeyReveal } from "@/components/key-reveal.tsx";
import { t } from "@/lib/t.ts";
import { KIND_LABEL } from "./channel-list.tsx";

const KIND_ID = "channel-kind";
const NAME_ID = "channel-name";
const URL_ID = "channel-url";

/**
 * Adds a webhook or Slack channel. On success the form gives way to a confirmation and, for a webhook, the
 * signing secret — shown once, held only in this component's action state, never in an address or storage.
 * "Done" takes it off the screen for good. The URL is never shown back, not even after a refusal.
 */
export function AddChannelForm() {
  const [state, formAction, pending] = useActionState(createAlertChannelAction, null);
  const [dismissed, setDismissed] = useState<CreateAlertChannelState>(null);

  if (state?.ok && state !== dismissed) {
    return (
      <div className="flex flex-col gap-4">
        <p data-testid="channel-created" className="break-words">
          {t("alerts.added", { name: state.channel.name })}
        </p>
        {state.signingSecret ? (
          <KeyReveal
            title={t("alerts.secret.title")}
            help={t("alerts.secret.help")}
            value={state.signingSecret}
            testId="signing-secret"
          />
        ) : null}
        <div>
          <Button variant="secondary" onClick={() => setDismissed(state)} data-testid="channel-done">
            {t("alerts.done")}
          </Button>
        </div>
      </div>
    );
  }

  const errors = state && !state.ok ? state.errors : [];
  const values = state && !state.ok ? state.values : undefined;
  return (
    // A refusal remounts the form with what was sent back: the chosen kind and name, and an empty URL.
    <form
      key={values ? `${values.kind}\u0000${values.name}` : ""}
      action={formAction}
      noValidate
      className="flex max-w-xl flex-col gap-4"
    >
      <ErrorSummary
        errors={errors}
        fields={{
          kind: { id: KIND_ID, label: t("alerts.add.kind") },
          name: { id: NAME_ID, label: t("alerts.add.name") },
          url: { id: URL_ID, label: t("alerts.add.url") },
        }}
      />
      <Select
        id={KIND_ID}
        name="kind"
        label={t("alerts.add.kind")}
        defaultValue={values?.kind ?? "webhook"}
        error={fieldError(errors, "kind")}
      >
        {ALERT_CHANNEL_KINDS.map((kind) => (
          <option key={kind} value={kind}>
            {t(KIND_LABEL[kind])}
          </option>
        ))}
      </Select>
      <Input
        id={NAME_ID}
        name="name"
        label={t("alerts.add.name")}
        defaultValue={values?.name}
        error={fieldError(errors, "name")}
        autoComplete="off"
        aria-required="true"
      />
      <Input
        id={URL_ID}
        name="url"
        type="url"
        label={t("alerts.add.url")}
        help={t("alerts.add.url.help")}
        error={fieldError(errors, "url")}
        autoComplete="off"
        autoCapitalize="none"
        autoCorrect="off"
        spellCheck={false}
        aria-required="true"
        mono
      />
      <div>
        <Button type="submit" disabled={pending} data-testid="channel-add">
          {pending ? t("alerts.add.submitting") : t("alerts.add.submit")}
        </Button>
      </div>
    </form>
  );
}
