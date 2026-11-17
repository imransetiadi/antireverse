"use client";

import type { ProveOperatorState } from "@antireverse/protocol";
import { useActionState } from "react";
import { type OpsProveState, proveSwitchAction } from "@/app/ops/actions.ts";
import { Icon } from "@/components/icons.tsx";
import { Input } from "@/components/input.tsx";
import { SubmitButton } from "@/components/submit-button.tsx";
import { formatDateTime } from "@/lib/format.ts";
import type { OpsProveDone } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

/** The length the API allows a reason (`ProveOperatorRequestSchema`). */
const REASON_MAX = 500;
/** The shape of an Organization id, as an input pattern. */
const ORGANIZATION_PATTERN = "org_[0-9a-f]{24}";

const FACT = "flex flex-col gap-1 rounded-card border border-border bg-surface p-3";
const FORM = "flex flex-col gap-3 rounded-card border border-border-strong p-3";

/** A number per action state, so that every answer mounts the fields anew with what was typed. */
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

const errorOf = (state: OpsProveState, path: "" | "reason" | "organization"): string | undefined =>
  state?.errors.find((error) => error.path === path)?.message;

function FormError({ state }: { state: OpsProveState }) {
  const message = errorOf(state, "");
  return message ? (
    <p role="alert" className="body-5 text-sev-critical-text">
      {message}
    </p>
  ) : null;
}

function ReasonField({ id, state }: { id: string; state: OpsProveState }) {
  return (
    <div className="max-w-xl">
      <Input
        id={id}
        name="reason"
        label={t("ops.prove.reason")}
        help={t("ops.prove.reason.help")}
        error={errorOf(state, "reason")}
        required
        aria-required="true"
        maxLength={REASON_MAX}
        autoComplete="off"
        defaultValue={state?.values.reason ?? ""}
      />
    </div>
  );
}

/** What the last change did, said once after it. */
function doneText(done: { change: OpsProveDone; stopped?: number | undefined }): string {
  const stopped = done.stopped ?? 0;
  if (done.change === "kill") return t("ops.prove.done.kill", { stopped });
  if (done.change === "suspend") return t("ops.prove.done.suspend", { stopped });
  return t(done.change === "enable" ? "ops.prove.done.enable" : "ops.prove.done.resume");
}

interface ProveSwitchProps {
  state: ProveOperatorState;
  /** The change that was just made, from the address. */
  done?: { change: OpsProveDone; stopped?: number | undefined } | undefined;
}

/**
 * The operator's switches of Pentest Campaigns (slice 15a): whether the service has them on, the kill switch, the
 * suspended Organizations and how many Campaigns are queued or running; Stop all (or Enable again once stopped), and
 * Suspend or Resume for one Organization by id. Every change needs a reason — the browser holds the submit back while
 * it is empty, and the Server Action checks it again — and each form posts without client-side JavaScript.
 */
export function ProveSwitch({ state, done }: ProveSwitchProps) {
  const [globalState, globalAction] = useActionState(proveSwitchAction, null);
  const [organizationState, organizationAction] = useActionState(proveSwitchAction, null);
  const killedAt = state.killed_at === null ? null : formatDateTime(state.killed_at);

  return (
    <div className="flex flex-col gap-4">
      {done ? (
        <p role="status" data-testid="prove-done" className="max-w-3xl rounded-card border border-border p-3">
          {doneText(done)}
        </p>
      ) : null}

      <dl className="grid grid-cols-1 gap-3 md:grid-cols-2 lg:grid-cols-4">
        <div className={FACT}>
          <dt className="body-4 text-fg-muted">{t("ops.prove.enabled")}</dt>
          <dd data-testid="prove-enabled" data-enabled={state.enabled} className="body-4 text-fg">
            {t(state.enabled ? "ops.prove.enabled.on" : "ops.prove.enabled.off")}
          </dd>
        </div>
        <div className={FACT}>
          <dt className="body-4 text-fg-muted">{t("ops.prove.killed")}</dt>
          <dd
            data-testid="prove-killed"
            data-killed={state.killed}
            className={`inline-flex items-center gap-1 body-4 ${state.killed ? "text-sev-critical-text" : "text-fg"}`}
          >
            <Icon name={state.killed ? "prohibit" : "check"} />
            {state.killed ? t("ops.prove.killed.on", { time: killedAt?.text ?? "" }) : t("ops.prove.killed.off")}
          </dd>
        </div>
        <div className={FACT}>
          <dt className="body-4 text-fg-muted">{t("ops.prove.active")}</dt>
          <dd data-testid="prove-active" className="heading-3 text-fg tabular-nums">
            {state.active}
          </dd>
        </div>
        <div className={FACT}>
          <dt className="body-4 text-fg-muted">{t("ops.prove.suspended")}</dt>
          <dd data-testid="prove-suspended">
            {state.suspended.length === 0 ? (
              <span className="body-4 text-fg">{t("ops.prove.suspended.none")}</span>
            ) : (
              <ul className="flex list-none flex-col gap-1">
                {state.suspended.map((entry) => (
                  <li
                    key={entry.organization_id}
                    data-testid="prove-suspended-organization"
                    className="flex flex-col gap-0.5"
                  >
                    <span className="code-3 break-all text-fg">{entry.organization_id}</span>
                    <span className="body-5 text-fg-muted">
                      {t("ops.prove.suspended.since", { time: formatDateTime(entry.suspended_at).text })}
                    </span>
                  </li>
                ))}
              </ul>
            )}
          </dd>
        </div>
      </dl>

      <form action={globalAction} data-testid="prove-global-form" className={FORM}>
        <h3 className="heading-6">{t(state.killed ? "ops.prove.enable.title" : "ops.prove.kill.title")}</h3>
        <p className="max-w-3xl body-5 text-fg-muted">
          {t(state.killed ? "ops.prove.enable.help" : "ops.prove.kill.help")}
        </p>
        <FormError state={globalState} />
        <ReasonField key={roundOf(globalState)} id="prove-reason" state={globalState} />
        <div>
          {state.killed ? (
            <SubmitButton name="change" value="enable" pendingLabel={t("ops.prove.sending")}>
              {t("ops.prove.enable.submit")}
            </SubmitButton>
          ) : (
            <SubmitButton name="change" value="kill" variant="destructive" pendingLabel={t("ops.prove.sending")}>
              {t("ops.prove.kill.submit")}
            </SubmitButton>
          )}
        </div>
      </form>

      <form action={organizationAction} data-testid="prove-organization-form" className={FORM}>
        <h3 className="heading-6">{t("ops.prove.organization.title")}</h3>
        <p className="max-w-3xl body-5 text-fg-muted">{t("ops.prove.organization.help")}</p>
        <FormError state={organizationState} />
        <div key={roundOf(organizationState)} className="flex flex-col gap-3">
          <div className="max-w-md">
            <Input
              id="prove-organization"
              name="organization"
              label={t("ops.prove.organization.id")}
              error={errorOf(organizationState, "organization")}
              required
              aria-required="true"
              pattern={ORGANIZATION_PATTERN}
              autoComplete="off"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              defaultValue={organizationState?.values.organization ?? ""}
              mono
            />
          </div>
          <ReasonField id="prove-organization-reason" state={organizationState} />
        </div>
        <div className="flex flex-wrap gap-2">
          <SubmitButton name="change" value="suspend" variant="destructive" pendingLabel={t("ops.prove.sending")}>
            {t("ops.prove.suspend.submit")}
          </SubmitButton>
          <SubmitButton name="change" value="resume" variant="secondary" pendingLabel={t("ops.prove.sending")}>
            {t("ops.prove.resume.submit")}
          </SubmitButton>
        </div>
      </form>
    </div>
  );
}
