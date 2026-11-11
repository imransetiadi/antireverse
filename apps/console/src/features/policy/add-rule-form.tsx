"use client";

import { type Environment, LIMIT_COUNTS, LIMIT_KEYS, LIMIT_LIMITS, RULE_ACTIONS } from "@antireverse/protocol";
import { useActionState, useState } from "react";
import { type PublishRuleState, publishRuleAction } from "@/app/actions.ts";
import { Button } from "@/components/button.tsx";
import { ErrorSummary, fieldError, type SummaryError } from "@/components/error-summary.tsx";
import { Input } from "@/components/input.tsx";
import { t } from "@/lib/t.ts";
import { EMPTY_LIMIT, LIMIT_FIELDS, type LimitDraft, LOGIN_PROTECTION, wholeNumber, windowText } from "./limit.ts";
import { RULE_METHODS } from "./methods.ts";
import { useSimulation } from "./simulation-context.tsx";

const NAME_ID = "rule-name";
const PATH_ID = "rule-path";
const METHODS_ID = "rule-methods";
const REQUIRES_ID = "rule-requires";
const ACTION_ID = "rule-action";
const PRESET_ID = "rule-preset-login";
const LIMIT_REQUESTS_ID = "rule-limit-requests";
const LIMIT_WINDOW_ID = "rule-limit-window";
const LIMIT_KEY_ID = "rule-limit-key";
const LIMIT_COUNT_ID = "rule-limit-count";
const SIMULATE_ID = "rule-simulate";
const NO_ERRORS: readonly SummaryError[] = [];

type RuleActionChoice = (typeof RULE_ACTIONS)[number];

/** The controls the form holds in state: the ones that decide what else it shows, and the ones a preset fills. */
interface Draft {
  methods: readonly string[];
  action: RuleActionChoice;
  requires: boolean;
  limit: LimitDraft;
}

/** What the form holds as an action sent it back. */
type RuleValues = NonNullable<PublishRuleState>["values"];

/** The latest answer the form follows: of adding the Rule, or of simulating with it. */
interface Answer {
  values: RuleValues | undefined;
  errors: readonly SummaryError[];
}

/** What the controls show: nothing chosen at first, and after an answer what was sent. */
function draftOf(values: RuleValues | undefined): Draft {
  return {
    methods: values?.methods ?? [],
    action: values?.action === "throttle" ? "throttle" : "block",
    requires: values?.requires === true,
    limit: values?.limit ?? EMPTY_LIMIT,
  };
}

/**
 * One choice of a few: radios in a group named by its legend, with an optional help line. The whole label is the target:
 * 32 px high on pointer layouts, 48 px on touch layouts.
 */
function Choice<T extends string>({
  id,
  name,
  legend,
  help,
  options,
  value,
  onChange,
}: {
  id: string;
  name: string;
  legend: string;
  help?: string;
  options: readonly { value: T; label: string }[];
  /** The chosen value; a value that is none of the options chooses nothing. */
  value: string;
  onChange: (value: T) => void;
}) {
  return (
    <fieldset id={id} aria-describedby={help ? `${id}-help` : undefined} className="flex flex-col gap-1">
      <legend className="title-4 text-fg">{legend}</legend>
      <div className="flex flex-wrap gap-x-4">
        {options.map((option) => (
          <label
            key={option.value}
            className="inline-flex min-h-8 cursor-pointer items-center gap-2 body-4 pointer-coarse:min-h-12"
          >
            <input
              type="radio"
              id={`${id}-${option.value}`}
              name={name}
              value={option.value}
              checked={value === option.value}
              onChange={() => onChange(option.value)}
              className="size-4 accent-primary"
            />
            {option.label}
          </label>
        ))}
      </div>
      {help ? (
        <p id={`${id}-help`} className="body-5 text-fg-muted">
          {help}
        </p>
      ) : null}
    </fieldset>
  );
}

/**
 * Adds one Rule to the Policy of this App and Environment. The form has no mode: a new Rule always starts
 * in Monitor mode and is promoted from the Rule list, after a confirmation. Slice 08: the Rule blocks, or
 * throttles with a limit; a limit and a signature requirement never go together.
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
  // Slice 11: where the screen keeps a simulation, the Rule being typed can be simulated with the current Rules.
  const simulation = useSimulation();
  const simulated = simulation?.state?.withDraft ? simulation.state : null;
  const [answer, setAnswer] = useState<Answer>({ values: undefined, errors: NO_ERRORS });
  const { errors } = answer;
  const methodsError = fieldError(errors, "methods");
  const [draft, setDraft] = useState(() => draftOf(undefined));
  // The controls below are mounted anew with every answer of the action. React resets a form after its action,
  // which puts a checkbox and a radio back to the state they were mounted with: mounted anew, that state is
  // the one the answer brought back.
  const [filled, setFilled] = useState(0);
  // A refusal brings back what was sent: the controls follow it, once per answer of the action.
  const [answered, setAnswered] = useState(state);
  if (answered !== state) {
    setAnswered(state);
    setAnswer({ values: state?.values, errors: state?.errors ?? NO_ERRORS });
    setDraft(draftOf(state?.values));
    setFilled(filled + 1);
  }
  // A simulation with this Rule brings back what was typed as well, and a refusal of one of its fields. A failure
  // of the simulation as a whole is not about the form: the result panel shows it.
  const [simulatedAnswer, setSimulatedAnswer] = useState(simulated);
  if (simulatedAnswer !== simulated) {
    setSimulatedAnswer(simulated);
    if (simulated) {
      const refused = simulated.ok ? NO_ERRORS : simulated.errors.filter((error) => error.path !== "");
      setAnswer({ values: simulated.values, errors: refused });
      setDraft(draftOf(simulated.values));
      setFilled(filled + 1);
    }
  }
  const busy = pending || simulation?.pending === true;
  const throttle = draft.action === "throttle";
  const setLimit = (change: Partial<LimitDraft>) =>
    setDraft((current) => ({ ...current, limit: { ...current.limit, ...change } }));
  const windowSeconds = wholeNumber(draft.limit.window, LIMIT_LIMITS.windowSecondsMax);

  return (
    <form action={formAction} noValidate className="flex max-w-xl flex-col gap-4">
      <ErrorSummary
        errors={errors}
        fields={{
          name: { id: NAME_ID, label: t("policy.rule.name") },
          path: { id: PATH_ID, label: t("policy.rule.path") },
          // The link of the summary goes to the first control of the group.
          methods: { id: `${METHODS_ID}-${RULE_METHODS[0]}`, label: t("policy.rule.methods") },
          [LIMIT_FIELDS.requests]: { id: LIMIT_REQUESTS_ID, label: t("policy.rule.limit.requests") },
          [LIMIT_FIELDS.window]: { id: LIMIT_WINDOW_ID, label: t("policy.rule.limit.window") },
        }}
      />
      {/* Slice 08: a preset fills the controls and sends nothing; the name and the path stay the admin's. */}
      <div className="flex flex-col items-start gap-1">
        <Button
          variant="secondary"
          aria-describedby={`${PRESET_ID}-help`}
          data-testid={PRESET_ID}
          onClick={() =>
            setDraft((current) => ({
              ...current,
              methods: LOGIN_PROTECTION.methods,
              action: LOGIN_PROTECTION.action,
              limit: LOGIN_PROTECTION.limit,
            }))
          }
        >
          {t("policy.rule.preset.login")}
        </Button>
        <p id={`${PRESET_ID}-help`} className="body-5 text-fg-muted">
          {t("policy.rule.preset.login.help")}
        </p>
      </div>
      <input type="hidden" name="appId" value={appId} />
      <input type="hidden" name="environment" value={environment} />
      <input type="hidden" name="expectedVersion" value={version} />
      <Input
        id={NAME_ID}
        name="name"
        label={t("policy.rule.name")}
        defaultValue={answer.values?.name}
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
        defaultValue={answer.values?.path}
        error={fieldError(errors, "path")}
        autoComplete="off"
        autoCapitalize="none"
        spellCheck={false}
        aria-required="true"
      />
      <div key={filled} className="contents">
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
                  checked={draft.methods.includes(method)}
                  onChange={(event) => {
                    const on = event.target.checked;
                    setDraft((current) => ({
                      ...current,
                      methods: RULE_METHODS.filter((one) => (one === method ? on : current.methods.includes(one))),
                    }));
                  }}
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
        <Choice
          id={ACTION_ID}
          name="action"
          legend={t("policy.rule.action")}
          help={t("policy.rule.action.help")}
          options={RULE_ACTIONS.map((action) => ({ value: action, label: t(`policy.rule.action.${action}`) }))}
          value={draft.action}
          onChange={(action) => setDraft((current) => ({ ...current, action }))}
        />
        {throttle ? (
          <div data-testid="rule-limit-fields" className="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <Input
              id={LIMIT_REQUESTS_ID}
              name={LIMIT_FIELDS.requests}
              label={t("policy.rule.limit.requests")}
              help={t("policy.rule.limit.requests.help")}
              mono
              inputMode="numeric"
              value={draft.limit.requests}
              onChange={(event) => setLimit({ requests: event.target.value })}
              error={fieldError(errors, LIMIT_FIELDS.requests)}
              autoComplete="off"
              aria-required="true"
            />
            <Input
              id={LIMIT_WINDOW_ID}
              name={LIMIT_FIELDS.window}
              label={t("policy.rule.limit.window")}
              help={t("policy.rule.limit.window.help")}
              // The window in readable words, as it is typed: 300 reads 5 min.
              hint={windowSeconds === null ? undefined : windowText(windowSeconds)}
              mono
              inputMode="numeric"
              value={draft.limit.window}
              onChange={(event) => setLimit({ window: event.target.value })}
              error={fieldError(errors, LIMIT_FIELDS.window)}
              autoComplete="off"
              aria-required="true"
            />
            <Choice
              id={LIMIT_KEY_ID}
              name={LIMIT_FIELDS.key}
              legend={t("policy.rule.limit.key")}
              help={t("policy.rule.limit.key.help")}
              options={LIMIT_KEYS.map((key) => ({ value: key, label: t(`policy.rule.limit.key.${key}`) }))}
              value={draft.limit.key}
              onChange={(key) => setLimit({ key })}
            />
            <Choice
              id={LIMIT_COUNT_ID}
              name={LIMIT_FIELDS.count}
              legend={t("policy.rule.limit.count")}
              options={LIMIT_COUNTS.map((count) => ({ value: count, label: t(`policy.rule.limit.count.${count}`) }))}
              value={draft.limit.count}
              onChange={(count) => setLimit({ count })}
            />
          </div>
        ) : null}
        {/* Slice 04: the Rule then blocks only the requests without a valid signature; its action stays block.
            Slice 08: a Rule with a limit never carries a requirement, so the box is unavailable with Throttle. */}
        <div className="flex flex-col gap-1">
          <label
            htmlFor={REQUIRES_ID}
            className={`inline-flex min-h-8 items-center gap-2 title-4 text-fg pointer-coarse:min-h-12 ${
              throttle ? "cursor-not-allowed opacity-60" : "cursor-pointer"
            }`}
          >
            <input
              type="checkbox"
              id={REQUIRES_ID}
              name="requires"
              value="signature"
              checked={draft.requires && !throttle}
              disabled={throttle}
              onChange={(event) => {
                const requires = event.target.checked;
                setDraft((current) => ({ ...current, requires }));
              }}
              aria-describedby={`${throttle ? `${REQUIRES_ID}-unavailable ` : ""}${REQUIRES_ID}-help`}
              data-testid="rule-requires-signature"
              className="size-4 accent-primary"
            />
            {t("policy.rule.requires")}
          </label>
          <p id={`${REQUIRES_ID}-help`} className="body-5 text-fg-muted">
            {t("policy.rule.requires.help")}
          </p>
          {throttle ? (
            <p id={`${REQUIRES_ID}-unavailable`} className="body-5 text-fg-muted">
              {t("policy.rule.requires.unavailable")}
            </p>
          ) : null}
        </div>
      </div>
      <div className="flex flex-col items-start gap-1">
        <div className="flex flex-wrap items-center gap-2">
          <Button type="submit" disabled={busy}>
            {pending ? t("policy.rule.adding") : t("policy.rule.add")}
          </Button>
          {simulation ? (
            // The same fields go to the simulation instead of the publish.
            <Button
              type="submit"
              variant="secondary"
              formAction={simulation.draftAction}
              disabled={busy}
              aria-describedby={`${SIMULATE_ID}-help`}
              data-testid={SIMULATE_ID}
            >
              {simulation.pending ? t("policy.simulate.running") : t("policy.simulate.draft")}
            </Button>
          ) : null}
        </div>
        {simulation ? (
          <p id={`${SIMULATE_ID}-help`} className="body-5 text-fg-muted">
            {t("policy.simulate.draft.help")}
          </p>
        ) : null}
      </div>
    </form>
  );
}
