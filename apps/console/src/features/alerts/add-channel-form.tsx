"use client";

import { ALERT_CHANNEL_KINDS } from "@antireverse/protocol";
import { useActionState, useState } from "react";
import { type CreateAlertChannelState, createAlertChannelAction } from "@/app/actions.ts";
import { Button } from "@/components/button.tsx";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { Input, Select, Textarea } from "@/components/input.tsx";
import { KeyReveal } from "@/components/key-reveal.tsx";
import { t } from "@/lib/t.ts";
import { KIND_LABEL } from "./channel-list.tsx";

const KIND_ID = "channel-kind";
const NAME_ID = "channel-name";
const URL_ID = "channel-url";
const RECIPIENTS_ID = "channel-recipients";

type RefusedValues = Extract<CreateAlertChannelState, { ok: false }>["values"];

interface ChannelFieldsProps {
  errors: readonly SummaryError[];
  values: RefusedValues | undefined;
  smtpConfigured: boolean;
  pending: boolean;
}

/**
 * The fields of the form. The kind decides the rest: a URL for a webhook or Slack channel, recipients one per line
 * for an email channel. Email cannot be chosen when the service has no SMTP settings, and the kind says why.
 */
function ChannelFields({ errors, values, smtpConfigured, pending }: ChannelFieldsProps) {
  const [kind, setKind] = useState(values?.kind ?? "webhook");
  const email = kind === "email";
  return (
    <>
      <ErrorSummary
        errors={errors}
        fields={{
          kind: { id: KIND_ID, label: t("alerts.add.kind") },
          name: { id: NAME_ID, label: t("alerts.add.name") },
          url: { id: URL_ID, label: t("alerts.add.url") },
          recipients: { id: RECIPIENTS_ID, label: t("alerts.add.recipients") },
        }}
      />
      <Select
        id={KIND_ID}
        name="kind"
        label={t("alerts.add.kind")}
        value={kind}
        onChange={(event) => setKind(event.target.value)}
        {...(smtpConfigured ? {} : { help: t("alerts.add.smtp") })}
        error={fieldError(errors, "kind")}
      >
        {ALERT_CHANNEL_KINDS.map((option) => (
          <option key={option} value={option} disabled={option === "email" && !smtpConfigured}>
            {t(KIND_LABEL[option])}
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
      {email ? (
        <Textarea
          id={RECIPIENTS_ID}
          name="recipients"
          label={t("alerts.add.recipients")}
          help={t("alerts.add.recipients.help")}
          defaultValue={values?.recipients}
          error={fieldError(errors, "recipients")}
          rows={5}
          autoComplete="off"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          aria-required="true"
          mono
        />
      ) : (
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
      )}
      <div>
        <Button type="submit" disabled={pending} data-testid="channel-add">
          {pending ? t("alerts.add.submitting") : t("alerts.add.submit")}
        </Button>
      </div>
    </>
  );
}

/**
 * Adds a webhook, Slack or email channel. On success the form gives way to a confirmation and, for a webhook, the
 * signing secret — shown once, held only in this component's action state, never in an address or storage — or,
 * for an email channel, the note that each recipient must confirm first. "Done" takes it off the screen for good.
 * The URL is never shown back, not even after a refusal; recipients are, since they are not a secret.
 */
export function AddChannelForm({ smtpConfigured }: { smtpConfigured: boolean }) {
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
        {state.channel.kind === "email" ? (
          <p data-testid="channel-confirmation-note" className="text-fg-muted">
            {t("alerts.added.email")}
          </p>
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
    // A refusal remounts the fields with what was sent back: the chosen kind, the name and any recipients, and an
    // empty URL.
    <form
      key={values ? `${values.kind}\u0000${values.name}\u0000${values.recipients ?? ""}` : ""}
      action={formAction}
      noValidate
      className="flex max-w-xl flex-col gap-4"
    >
      <ChannelFields errors={errors} values={values} smtpConfigured={smtpConfigured} pending={pending} />
    </form>
  );
}
