"use client";

import { confirmationPhrase, INTENSITIES, type Intensity, type Target, WEEKDAYS } from "@antireverse/protocol";
import { useActionState, useState } from "react";
import { type RulesOfEngagementFormValues, signRulesOfEngagementAction } from "@/app/actions.ts";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { Input, Textarea } from "@/components/input.tsx";
import { SubmitButton } from "@/components/submit-button.tsx";
import { t } from "@/lib/t.ts";
import { DAY_LABEL, INTENSITY_HELP } from "./labels.ts";
import { TargetStatusChip } from "./target-status.tsx";

const IDS = {
  scope: "roe-scope",
  exclusions: "roe-exclusions",
  intensity: "roe-intensity",
  days: "roe-days",
  from: "roe-from",
  to: "roe-to",
  contacts: "roe-contacts",
  confirm: "roe-confirm",
} as const;

const EMPTY: RulesOfEngagementFormValues = {
  scope: [],
  exclusions: "",
  intensity: "passive",
  days: [],
  allDay: false,
  from: "",
  to: "",
  contacts: "",
};

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

const isIntensity = (value: string): value is Intensity => (INTENSITIES as readonly string[]).includes(value);

function FieldsetError({ id, message }: { id: string; message: string | undefined }) {
  return message ? (
    <p id={`${id}-error`} data-testid={`${id}-error`} className={ERROR}>
      {message}
    </p>
  ) : null;
}

/** `aria-describedby` of a fieldset: its error first, then its help. */
const described = (id: string, error: string | undefined, help = true): string | undefined =>
  [error ? `${id}-error` : null, help ? `${id}-help` : null].filter(Boolean).join(" ") || undefined;

interface FieldsProps {
  targets: readonly Target[];
  values: RulesOfEngagementFormValues;
  errors: readonly SummaryError[];
}

// Mounted anew after every refusal (see `key` below), so that the refilled values are its starting state.
function RoeFields({ targets, values, errors }: FieldsProps) {
  const [intensity, setIntensity] = useState<Intensity>(isIntensity(values.intensity) ? values.intensity : "passive");
  const [allDay, setAllDay] = useState(values.allDay);
  const error = (path: string) => fieldError(errors, path);

  return (
    <>
      <fieldset id={IDS.scope} aria-describedby={described(IDS.scope, error("scope"))} className="flex flex-col gap-1">
        <legend className={LEGEND}>{t("roe.scope")}</legend>
        <div className="flex flex-col">
          {targets.map((target) => {
            const verified = target.status === "verified";
            return (
              <label
                key={target.id}
                className={`${CHOICE} code-2 ${verified ? "" : "cursor-not-allowed text-fg-muted"}`}
              >
                <input
                  type="checkbox"
                  name="scope"
                  value={target.id}
                  defaultChecked={verified && values.scope.includes(target.id)}
                  disabled={!verified}
                  className={BOX}
                />
                {target.host}
                {verified ? null : <TargetStatusChip status={target.status} />}
              </label>
            );
          })}
        </div>
        <p id={`${IDS.scope}-help`} className={HELP}>
          {t("roe.form.scope.help")}
        </p>
        <FieldsetError id={IDS.scope} message={error("scope")} />
      </fieldset>

      <Textarea
        id={IDS.exclusions}
        name="exclusions"
        label={t("roe.exclusions")}
        help={t("roe.form.exclusions.help")}
        defaultValue={values.exclusions}
        error={error("exclusions")}
        rows={4}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
        mono
      />

      <fieldset
        id={IDS.intensity}
        aria-describedby={described(IDS.intensity, error("intensity"), false)}
        className="flex flex-col gap-2"
      >
        <legend className={LEGEND}>{t("roe.intensity")}</legend>
        {INTENSITIES.map((level) => (
          <div key={level} className="flex flex-col">
            <label className={`${CHOICE} code-2`}>
              <input
                type="radio"
                name="intensity"
                value={level}
                checked={intensity === level}
                onChange={() => setIntensity(level)}
                aria-describedby={`roe-intensity-help-${level}`}
                className={BOX}
              />
              {level}
            </label>
            <p
              id={`roe-intensity-help-${level}`}
              data-testid={`roe-intensity-help-${level}`}
              className={`${HELP} ps-6`}
            >
              {t(INTENSITY_HELP[level])}
            </p>
          </div>
        ))}
        <FieldsetError id={IDS.intensity} message={error("intensity")} />
      </fieldset>

      <fieldset
        id={IDS.days}
        aria-describedby={described(IDS.days, error("days"), false)}
        className="flex flex-col gap-1"
      >
        <legend className={LEGEND}>{t("roe.form.days")}</legend>
        <div className="flex flex-wrap gap-x-4">
          {WEEKDAYS.map((day) => (
            <label key={day} className={`${CHOICE} body-4`}>
              <input
                type="checkbox"
                name="days"
                value={day}
                defaultChecked={values.days.includes(day)}
                className={BOX}
              />
              {t(DAY_LABEL[day])}
            </label>
          ))}
        </div>
        <FieldsetError id={IDS.days} message={error("days")} />
      </fieldset>

      <div className="flex flex-col gap-2">
        <label className={`${CHOICE} title-4 text-fg`}>
          <input
            type="checkbox"
            name="allDay"
            value="on"
            checked={allDay}
            onChange={(event) => setAllDay(event.target.checked)}
            className={BOX}
          />
          {t("roe.form.allDay")}
        </label>
        <div className="grid max-w-md grid-cols-2 gap-3">
          <Input
            id={IDS.from}
            name="from"
            label={t("roe.form.from")}
            defaultValue={values.from}
            error={error("from")}
            disabled={allDay}
            placeholder="09:00"
            inputMode="numeric"
            autoComplete="off"
            mono
          />
          <Input
            id={IDS.to}
            name="to"
            label={t("roe.form.to")}
            defaultValue={values.to}
            error={error("to")}
            disabled={allDay}
            placeholder="17:00"
            inputMode="numeric"
            autoComplete="off"
            mono
          />
        </div>
        <p className={HELP}>{t("roe.form.hours.help")}</p>
      </div>

      <Textarea
        id={IDS.contacts}
        name="contacts"
        label={t("roe.contacts")}
        help={t("roe.form.contacts.help")}
        defaultValue={values.contacts}
        error={error("contacts")}
        rows={3}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
        mono
      />

      <section
        aria-labelledby="roe-sign-title"
        className="flex flex-col gap-3 rounded-card border border-border-strong p-3"
      >
        <h2 id="roe-sign-title" className="heading-6">
          {t("roe.form.sign.title")}
        </h2>
        <p data-testid="roe-immutable-note" className="body-5 text-fg-muted">
          {t("roe.immutable")}
        </p>
        <p className="body-4 text-fg">
          {t("roe.form.sign.lead")}{" "}
          <code data-testid="roe-phrase" className="code-2 text-fg">
            {confirmationPhrase(intensity)}
          </code>
        </p>
        <div className="max-w-md">
          <Input
            id={IDS.confirm}
            name="confirm"
            label={t("roe.form.confirm")}
            error={error("confirm")}
            autoComplete="off"
            autoCapitalize="none"
            autoCorrect="off"
            spellCheck={false}
            aria-required="true"
            mono
          />
        </div>
        <div>
          <SubmitButton pendingLabel={t("roe.form.submitting")} data-testid="roe-sign">
            {t("roe.form.submit")}
          </SubmitButton>
        </div>
      </section>
    </>
  );
}

/**
 * Writes and signs a new Rules of Engagement version. Only verified hosts can be put in scope. The phrase to type
 * follows the chosen intensity and is shown exactly; the Server Action checks it again and alone decides. A refusal
 * keeps everything but the phrase and explains each field below it and in the summary above the form.
 */
export function RoeForm({ targets }: { targets: readonly Target[] }) {
  const [state, formAction] = useActionState(signRulesOfEngagementAction, null);
  const errors = state && !state.ok ? state.errors : [];
  const values = state && !state.ok ? state.values : EMPTY;
  const fields = {
    scope: { id: IDS.scope, label: t("roe.scope") },
    exclusions: { id: IDS.exclusions, label: t("roe.exclusions") },
    intensity: { id: IDS.intensity, label: t("roe.intensity") },
    days: { id: IDS.days, label: t("roe.form.days") },
    from: { id: IDS.from, label: t("roe.form.from") },
    to: { id: IDS.to, label: t("roe.form.to") },
    contacts: { id: IDS.contacts, label: t("roe.contacts") },
    confirm: { id: IDS.confirm, label: t("roe.form.confirm") },
  };

  return (
    <form action={formAction} noValidate className="flex max-w-2xl flex-col gap-6">
      <ErrorSummary errors={errors} fields={fields} />
      <RoeFields key={roundOf(state)} targets={targets} values={values} errors={errors} />
    </form>
  );
}
