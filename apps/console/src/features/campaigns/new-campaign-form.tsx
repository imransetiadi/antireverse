"use client";

import {
  AUDIT_LIMITS,
  type CampaignIntensity,
  campaignAuthorisationPhrase,
  type RulesOfEngagementVersion,
  STAND_IN_ENGINE,
  type Target,
} from "@antireverse/protocol";
import { useActionState, useState } from "react";
import { createCampaignAction, type NewCampaignValues } from "@/app/actions.ts";
import { Card } from "@/components/card.tsx";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { Input } from "@/components/input.tsx";
import { SubmitButton } from "@/components/submit-button.tsx";
import { windowText } from "@/features/prove/labels.ts";
import { formatDateTime } from "@/lib/format.ts";
import { t } from "@/lib/t.ts";
import { CampaignNotice } from "./campaign-notice.tsx";
import { campaignEffect, offeredIntensities } from "./labels.ts";

const IDS = {
  target: "campaign-target",
  intensity: "campaign-intensity",
  confirm: "campaign-confirm",
  staging: "campaign-staging",
  reason: "campaign-reason",
} as const;

const CHOICE = "inline-flex min-h-8 cursor-pointer items-center gap-2 pointer-coarse:min-h-12";
const BOX = "size-4 accent-primary";
const LEGEND = "title-4 text-fg";
const HELP = "body-5 text-fg-muted";
const ERROR = "body-5 text-sev-critical-text";

/** A number per action state, so that every answer mounts the fields anew — also two equal refusals in a row. */
const rounds = new WeakMap<object, number>();
let lastRound = 0;
function roundOf(state: object | null): number {
  if (state === null) return 0;
  let round = rounds.get(state);
  if (round === undefined) {
    lastRound += 1;
    round = lastRound;
    rounds.set(state, round);
  }
  return round;
}

function FieldsetError({ id, message }: { id: string; message: string | undefined }) {
  return message ? (
    <p id={`${id}-error`} data-testid={`${id}-error`} className={ERROR}>
      {message}
    </p>
  ) : null;
}

const described = (id: string, error: string | undefined): string =>
  [error ? `${id}-error` : null, `${id}-help`].filter(Boolean).join(" ");

interface FormProps {
  /** The targets a Campaign can be launched against: verified and in the scope of `rules`. At least one. */
  targets: readonly Target[];
  /** The current Rules of Engagement, which the Campaign is bound to. */
  rules: RulesOfEngagementVersion;
}

interface FieldsProps extends FormProps {
  values: NewCampaignValues;
  errors: readonly SummaryError[];
  reason: string;
}

// Mounted anew after every refusal (see `key` below), so that the refilled values are its starting state. The phrase
// and the staging declaration are never refilled: both are made again for every attempt.
function Fields({ targets, rules, values, errors, reason }: FieldsProps) {
  const intensities = offeredIntensities(rules.intensity);
  const [targetId, setTargetId] = useState(
    targets.some((target) => target.id === values.target) ? values.target : (targets[0]?.id ?? ""),
  );
  const [intensity, setIntensity] = useState<CampaignIntensity>(
    intensities.find((level) => level === values.intensity) ?? intensities[0] ?? "passive",
  );
  const error = (path: string) => fieldError(errors, path);
  const chosen = targets.find((target) => target.id === targetId);
  const signedAt = formatDateTime(rules.signed_at);

  return (
    <>
      <fieldset
        id={IDS.target}
        aria-describedby={described(IDS.target, error("target"))}
        className="flex flex-col gap-2"
      >
        <legend className={LEGEND}>{t("campaign.new.target")}</legend>
        {targets.map((target) => (
          <div key={target.id} className="flex flex-col">
            <label className={`${CHOICE} code-2`}>
              <input
                type="radio"
                name="target"
                value={target.id}
                checked={targetId === target.id}
                onChange={() => setTargetId(target.id)}
                aria-describedby={`campaign-phrase-${target.id}`}
                className={BOX}
              />
              {target.host}
            </label>
            <p id={`campaign-phrase-${target.id}`} className={`${HELP} ps-6`}>
              {t("campaign.new.target.phrase")}{" "}
              <code data-testid="campaign-phrase" data-target-id={target.id} className="code-3 text-fg">
                {campaignAuthorisationPhrase(target.host)}
              </code>
            </p>
          </div>
        ))}
        <p id={`${IDS.target}-help`} className={HELP}>
          {t("campaign.new.target.help")}
        </p>
        <FieldsetError id={IDS.target} message={error("target")} />
      </fieldset>

      <fieldset
        id={IDS.intensity}
        aria-describedby={described(IDS.intensity, error("intensity"))}
        className="flex flex-col gap-2"
      >
        <legend className={LEGEND}>{t("campaign.new.intensity")}</legend>
        <div className="flex flex-wrap gap-x-4">
          {intensities.map((level) => (
            <label key={level} className={`${CHOICE} code-2`}>
              <input
                type="radio"
                name="intensity"
                value={level}
                checked={intensity === level}
                onChange={() => setIntensity(level)}
                className={BOX}
              />
              {level}
            </label>
          ))}
        </div>
        <p id={`${IDS.intensity}-help`} className={HELP}>
          {t("campaign.new.intensity.help", { intensity: intensities.at(-1) ?? "passive" })}
        </p>
        <FieldsetError id={IDS.intensity} message={error("intensity")} />
      </fieldset>

      <section aria-labelledby="campaign-rules-title" className="flex flex-col gap-2">
        <h2 id="campaign-rules-title" className="heading-6">
          {t("campaign.new.rules.title")}
        </h2>
        <Card>
          <dl data-testid="campaign-rules" data-roe-id={rules.id} className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <div className="flex flex-col gap-1">
              <dt className="caption-1 text-fg-muted">{t("campaign.new.rules.window")}</dt>
              <dd data-testid="campaign-rules-window" className="body-4">
                {windowText(rules.window)}
              </dd>
            </div>
            <div className="flex flex-col gap-1">
              <dt className="caption-1 text-fg-muted">{t("campaign.new.rules.intensity")}</dt>
              <dd data-testid="campaign-rules-intensity" className="code-2">
                {rules.intensity}
              </dd>
            </div>
            <div className="flex flex-col gap-1">
              <dt className="caption-1 text-fg-muted">{t("campaign.new.rules.exclusions")}</dt>
              <dd>
                {rules.exclusions.length === 0 ? (
                  <span className="body-5 text-fg-muted">{t("roe.exclusions.none")}</span>
                ) : (
                  <ul className="flex list-none flex-col gap-1 code-3 break-all">
                    {rules.exclusions.map((path) => (
                      <li key={path} data-testid="campaign-rules-exclusion">
                        {path}
                      </li>
                    ))}
                  </ul>
                )}
              </dd>
            </div>
            <div className="flex flex-col gap-1">
              <dt className="caption-1 text-fg-muted">{t("campaign.fact.rules")}</dt>
              <dd className="flex flex-col gap-1">
                <span className="code-3 break-all">{rules.id}</span>
                <span className="body-5 text-fg-muted">{t("campaign.new.rules.signed", { time: signedAt.text })}</span>
              </dd>
            </div>
          </dl>
        </Card>
        <p className={HELP}>{t("campaign.new.rules.note")}</p>
      </section>

      <section aria-labelledby="campaign-effect-title" className="flex flex-col gap-2">
        <h2 id="campaign-effect-title" className="heading-6">
          {t("campaign.new.effect.title")}
        </h2>
        <p data-testid="campaign-effect" className="body-4 text-fg">
          {campaignEffect()}
        </p>
        <CampaignNotice engine={STAND_IN_ENGINE} notice="" />
      </section>

      <section
        aria-labelledby="campaign-authorise-title"
        className="flex flex-col gap-3 rounded-card border border-border-strong p-3"
      >
        <h2 id="campaign-authorise-title" className="heading-6">
          {t("campaign.new.authorise.title")}
        </h2>
        <p className="body-4 text-fg">
          {t("campaign.new.authorise.lead")}{" "}
          {chosen ? (
            <code data-testid="campaign-phrase-current" className="code-2 text-fg">
              {campaignAuthorisationPhrase(chosen.host)}
            </code>
          ) : null}
        </p>
        <div className="max-w-md">
          <Input
            id={IDS.confirm}
            name="confirm"
            label={t("campaign.new.confirm")}
            error={error("confirm")}
            required
            aria-required="true"
            maxLength={300}
            autoComplete="off"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            mono
          />
        </div>
        <div className="flex flex-col gap-1">
          <label className={`${CHOICE} title-4 text-fg`}>
            <input
              id={IDS.staging}
              type="checkbox"
              name="staging"
              value="on"
              required
              aria-required="true"
              aria-invalid={error("staging") ? true : undefined}
              aria-describedby={described(IDS.staging, error("staging"))}
              className={BOX}
            />
            {t("campaign.new.staging")}
          </label>
          <p id={`${IDS.staging}-help`} className={HELP}>
            {t("campaign.new.staging.help")}
          </p>
          <FieldsetError id={IDS.staging} message={error("staging")} />
        </div>
        <div className="max-w-xl">
          <Input
            id={IDS.reason}
            name="reason"
            label={t("reason.label")}
            help={t("reason.help")}
            error={error("reason")}
            required
            aria-required="true"
            maxLength={AUDIT_LIMITS.reasonMax}
            autoComplete="off"
            defaultValue={reason}
          />
        </div>
        <div>
          <SubmitButton pendingLabel={t("campaign.new.submitting")} data-testid="campaign-launch">
            {t("campaign.new.submit")}
          </SubmitButton>
        </div>
      </section>
    </>
  );
}

/**
 * Launches a Campaign: a target (only those given: verified, in scope), an intensity no higher than the signed one
 * and never full, the Rules of Engagement that apply, the effect in numbers, the typed phrase of the chosen target,
 * the staging declaration and a reason. Each target shows its own phrase, so the form works without client-side
 * JavaScript; the browser holds the submit back while the phrase, the declaration or the reason is missing, and the
 * Server Action checks everything again. A refusal keeps the target, the intensity and the reason.
 */
export function NewCampaignForm({ targets, rules }: FormProps) {
  const [state, formAction] = useActionState(createCampaignAction, null);
  const errors = state?.errors ?? [];
  const fields = {
    target: { id: IDS.target, label: t("campaign.new.target") },
    intensity: { id: IDS.intensity, label: t("campaign.new.intensity") },
    confirm: { id: IDS.confirm, label: t("campaign.new.confirm") },
    staging: { id: IDS.staging, label: t("campaign.new.staging") },
    reason: { id: IDS.reason, label: t("reason.label") },
  };
  return (
    <form action={formAction} className="flex max-w-2xl flex-col gap-6">
      <ErrorSummary errors={errors} fields={fields} />
      <Fields
        key={roundOf(state)}
        targets={targets}
        rules={rules}
        values={state?.values ?? { target: "", intensity: "" }}
        errors={errors}
        reason={state?.reason ?? ""}
      />
    </form>
  );
}
