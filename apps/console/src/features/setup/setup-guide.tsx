"use client";

import type { AppSetup } from "@antireverse/protocol";
import { type ReactNode, useEffect, useId, useRef, useState } from "react";
import { Icon } from "@/components/icons.tsx";
import { Snippet } from "@/components/snippet.tsx";
import {
  guardScriptSnippet,
  hardenCommand,
  SHIELD_INSTALL,
  shieldEnvironmentLine,
  shieldExpressSnippet,
  shieldNodeHttpSnippet,
} from "@/features/apps/shield-snippet.ts";
import { PolicyKeySnippet } from "@/features/policy/policy-key-snippet.tsx";
import { formatDateTime } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { type MessageKey, t } from "@/lib/t.ts";
import { currentStep, SETUP_STEPS, type SetupStepId } from "./setup-state.ts";
import { ShieldWatcher } from "./shield-watcher.tsx";
import { useSetupProgress } from "./use-setup-progress.ts";

type Framework = "express" | "node";

const STEP_TITLE: Record<SetupStepId, MessageKey> = {
  shield: "setup.step.shield",
  guard: "setup.step.guard",
  harden: "setup.step.harden",
};
const WAITING: Record<SetupStepId, MessageKey> = {
  shield: "setup.waiting.shield",
  guard: "setup.waiting.guard",
  harden: "setup.waiting.harden",
};
const RECEIVED: Record<SetupStepId, MessageKey> = {
  shield: "setup.received.shield",
  guard: "setup.received.guard",
  harden: "setup.received.harden",
};
const TROUBLE: Record<SetupStepId, readonly MessageKey[]> = {
  shield: [
    "setup.trouble.shield.key",
    "setup.trouble.shield.first",
    "setup.trouble.shield.reach",
    "setup.trouble.shield.policy",
    "setup.trouble.shield.batch",
  ],
  guard: [
    "setup.trouble.guard.shield",
    "setup.trouble.guard.policy",
    "setup.trouble.guard.headers",
    "setup.trouble.guard.origin",
    "setup.trouble.guard.app",
  ],
  harden: [
    "setup.trouble.harden.register",
    "setup.trouble.harden.key",
    "setup.trouble.harden.app",
    "setup.trouble.harden.leak",
    "setup.trouble.harden.reach",
  ],
};

interface SetupGuideProps {
  app: { id: string; name: string };
  /** The set-up the server read when the page was rendered. */
  initialSetup: AppSetup;
  /** Base URL of the Airverse API, for the snippets. Not a secret. */
  apiUrl: string;
  /** Null when the API could not give it. */
  policyPublicKey: string | null;
  /** The Shield key, right after the App was created only; it lives in the creating action's state. */
  shieldKey?: string | undefined;
  /** Runs when the API no longer accepts the session. Default: go to sign-in. */
  onSessionExpired?: () => void;
}

function goToSignIn(): void {
  window.location.assign(ROUTES.signInExpired);
}

/**
 * SCR-01: the three set-up steps of an App, in their fixed order, each a disclosure. The first step not done opens;
 * a done step shows when it was done. One polite status region says what the page is waiting for and announces a
 * step that turns done while the page is open. Shield's step follows the live event stream; Guard and Harden are
 * asked for every 5 s (useSetupProgress).
 */
export function SetupGuide({
  app,
  initialSetup,
  apiUrl,
  policyPublicKey,
  shieldKey,
  onSessionExpired = goToSignIn,
}: SetupGuideProps) {
  const { setup, shieldSeen } = useSetupProgress(app.id, initialSetup, { onSessionExpired });
  const current = currentStep(setup);
  const [open, setOpen] = useState<ReadonlySet<SetupStepId>>(() => new Set(current ? [current] : []));
  // The steps done when the page was rendered: only a step that turns done afterwards is announced.
  const doneAtStart = useRef(new Set(SETUP_STEPS.filter((step) => initialSetup[step].done_at !== null)));
  // The steps that turned done at the last change, in step order: each one is announced.
  const [received, setReceived] = useState<readonly SetupStepId[]>([]);
  const seen = useRef(new Set(doneAtStart.current));
  // Each step's panel, to know whether focus is inside it when the step turns done.
  const panels = useRef(new Map<SetupStepId, HTMLElement>());

  useEffect(() => {
    const newlyDone = SETUP_STEPS.filter((step) => setup[step].done_at !== null && !seen.current.has(step));
    if (newlyDone.length === 0) return;
    for (const step of newlyDone) seen.current.add(step);
    setReceived(newlyDone);
    // The step that turned done closes and the next one not done opens — unless focus is inside the step (on its Copy
    // button, say): closing would unmount the focused element and drop focus to the page. It stays open, shown as done,
    // until the person closes it (review F1).
    const focused = typeof document === "undefined" ? null : document.activeElement;
    setOpen((previous) => {
      const next = new Set(previous);
      for (const step of newlyDone) if (!panels.current.get(step)?.contains(focused)) next.delete(step);
      if (current) next.add(current);
      return next;
    });
  }, [setup, current]);

  const toggle = (step: SetupStepId): void =>
    setOpen((previous) => {
      const next = new Set(previous);
      if (next.has(step)) next.delete(step);
      else next.add(step);
      return next;
    });

  const waiting = current ? t(WAITING[current], { app: app.name }) : t("setup.allDone");
  const statusText = [...received.map((step) => `${t(RECEIVED[step])}.`), waiting].join(" ");
  const watchShield = setup.shield.done_at === null && typeof EventSource !== "undefined";
  const values = { apiUrl, appId: app.id, environment: setup.environment };

  return (
    <div className="flex flex-col gap-4">
      <p className="caption-1 text-fg-muted">
        {current ? t("setup.position", { step: SETUP_STEPS.indexOf(current) + 1 }) : t("setup.complete")}
      </p>
      <p
        role="status"
        aria-live="polite"
        aria-atomic="true"
        data-testid="setup-status"
        className="flex min-h-6 items-center gap-2 body-4"
      >
        <Icon
          name={current ? "circle-dashed" : "check-circle"}
          className={`size-4 shrink-0 ${current ? "text-fg-subtle" : "text-primary"}`}
        />
        <span className="break-words">{statusText}</span>
      </p>
      {watchShield ? (
        <ShieldWatcher
          appId={app.id}
          environment={setup.environment}
          onFirstEvent={shieldSeen}
          onSessionExpired={onSessionExpired}
        />
      ) : null}
      <ol aria-label={t("setup.steps")} className="flex flex-col gap-3">
        {SETUP_STEPS.map((step, index) => (
          <StepItem
            key={step}
            step={step}
            number={index + 1}
            doneAt={setup[step].done_at}
            open={open.has(step)}
            onToggle={() => toggle(step)}
            panelRef={(element) => {
              if (element) panels.current.set(step, element);
              else panels.current.delete(step);
            }}
            trouble={TROUBLE[step].map((key) => t(key, values))}
          >
            {step === "shield" ? (
              <ShieldStep apiUrl={apiUrl} policyPublicKey={policyPublicKey} shieldKey={shieldKey} />
            ) : step === "guard" ? (
              <GuardStep appId={app.id} apiUrl={apiUrl} />
            ) : (
              <HardenStep appId={app.id} apiUrl={apiUrl} environment={setup.environment} />
            )}
          </StepItem>
        ))}
      </ol>
    </div>
  );
}

interface StepItemProps {
  step: SetupStepId;
  number: number;
  doneAt: string | null;
  open: boolean;
  onToggle: () => void;
  panelRef: (element: HTMLDivElement | null) => void;
  trouble: string[];
  children: ReactNode;
}

/** One step: a heading whose button opens and closes the step, its state, and the step's content when open. */
function StepItem({ step, number, doneAt, open, onToggle, panelRef, trouble, children }: StepItemProps) {
  const panelId = useId();
  const time = doneAt === null ? null : formatDateTime(doneAt);
  return (
    <li className="rounded-card border border-border bg-surface">
      <h2 className="heading-5">
        <button
          type="button"
          data-step={step}
          aria-expanded={open}
          aria-controls={panelId}
          onClick={onToggle}
          className="press flex w-full flex-wrap items-center gap-3 rounded-card px-4 py-3 text-start hover:bg-muted pointer-coarse:min-h-12"
        >
          <span
            aria-hidden="true"
            className={`inline-flex size-6 shrink-0 items-center justify-center rounded-full border caption-1 ${
              doneAt === null ? "border-border-strong text-fg-muted" : "border-primary bg-primary text-on-primary"
            }`}
          >
            {doneAt === null ? number : <Icon name="check" className="size-4" />}
          </span>
          <span className="min-w-0 flex-1 break-words">{t(STEP_TITLE[step])}</span>
          {/* A space, so that the button's name reads "Add Shield Done …", not "Add ShieldDone …". */}{" "}
          <span className="body-5 text-fg-muted">
            {time === null ? (
              t("setup.notDone")
            ) : (
              <>
                {t("setup.done")} <time dateTime={time.iso}>{`${time.text} UTC`}</time>
              </>
            )}
          </span>
          <Icon name={open ? "minus" : "plus"} className="size-4 shrink-0 text-fg-subtle" />
        </button>
      </h2>
      <div id={panelId} ref={panelRef} hidden={!open} className="flex flex-col gap-4 border-border border-t px-4 py-4">
        {open ? (
          <>
            {children}
            <Trouble causes={trouble} />
          </>
        ) : null}
      </div>
    </li>
  );
}

/** "Having trouble?": the common causes of a step that does not turn done, each with how to check it. */
function Trouble({ causes }: { causes: string[] }) {
  const [open, setOpen] = useState(false);
  const listId = useId();
  return (
    <div className="flex flex-col gap-2">
      <div>
        <button
          type="button"
          aria-expanded={open}
          aria-controls={listId}
          onClick={() => setOpen((value) => !value)}
          className="press inline-flex items-center gap-2 rounded-control px-1 py-1 title-4 text-fg-muted hover:text-fg pointer-coarse:min-h-12"
        >
          <Icon name="question" className="size-4" />
          {t("setup.trouble")}
        </button>
      </div>
      <ul id={listId} hidden={!open} className="flex list-disc flex-col gap-1 ps-6 body-5 text-fg-muted">
        {causes.map((cause) => (
          <li key={cause} className="break-words">
            {cause}
          </li>
        ))}
      </ul>
    </div>
  );
}

function ShieldStep({
  apiUrl,
  policyPublicKey,
  shieldKey,
}: {
  apiUrl: string;
  policyPublicKey: string | null;
  shieldKey: string | undefined;
}) {
  const [framework, setFramework] = useState<Framework>("express");
  const legendId = useId();
  const titleId = useId();
  const name = useId();
  const title = framework === "express" ? t("shield.setup.title") : t("setup.node.title");

  return (
    <>
      <div className="flex flex-col gap-2">
        <div role="radiogroup" aria-labelledby={legendId} className="flex flex-wrap items-center gap-4">
          <span id={legendId} className="caption-1 text-fg-muted">
            {t("setup.framework")}
          </span>
          {(["express", "node"] as const).map((option) => (
            <label key={option} className="inline-flex items-center gap-2 body-4 pointer-coarse:min-h-12">
              <input
                type="radio"
                name={name}
                value={option}
                checked={framework === option}
                onChange={() => setFramework(option)}
                className="size-4 accent-primary"
              />
              {t(option === "express" ? "setup.framework.express" : "setup.framework.node")}
            </label>
          ))}
        </div>
        <p className="body-5 text-fg-muted">{t("setup.framework.unsupported")}</p>
      </div>
      <section aria-labelledby={titleId} className="flex flex-col gap-4">
        <h3 id={titleId} className="heading-6">
          {title}
        </h3>
        <div className="flex flex-col gap-1">
          <Snippet label={t("shield.setup.install")} code={SHIELD_INSTALL} />
          <p className="body-5 text-fg-muted">{t("setup.unpublished")}</p>
        </div>
        {shieldKey ? (
          <Snippet label={t("shield.setup.env")} code={shieldEnvironmentLine(shieldKey)} />
        ) : (
          <p className="body-4">{t("setup.key.gone")}</p>
        )}
        <div className="flex flex-col gap-1">
          {policyPublicKey ? (
            <PolicyKeySnippet publicKey={policyPublicKey} />
          ) : (
            <p data-testid="policy-key-unavailable">{t("policy.key.unavailable")}</p>
          )}
          <p className="body-5 text-fg-muted">{t("policy.key.help")}</p>
        </div>
        {framework === "express" ? (
          <Snippet label={t("shield.setup.code")} code={shieldExpressSnippet(apiUrl)} />
        ) : (
          <div className="flex flex-col gap-1">
            <Snippet label={t("setup.node.code")} code={shieldNodeHttpSnippet(apiUrl)} />
            <p className="body-5 text-fg-muted">{t("setup.node.route")}</p>
          </div>
        )}
        <p data-testid="monitor-note">{t("shield.monitor")}</p>
      </section>
    </>
  );
}

function GuardStep({ appId, apiUrl }: { appId: string; apiUrl: string }) {
  const titleId = useId();
  const optionsId = useId();
  const options: ReadonlyArray<[string, MessageKey]> = [
    ["appId", "setup.guard.option.appId"],
    ["endpoint", "setup.guard.option.endpoint"],
    ["storage", "setup.guard.option.storage"],
  ];
  return (
    <section aria-labelledby={titleId} className="flex flex-col gap-4">
      <h3 id={titleId} className="heading-6">
        {t("setup.guard.title")}
      </h3>
      <p className="body-4">{t("setup.guard.lead")}</p>
      <div className="flex flex-col gap-1">
        <Snippet label={t("setup.guard.script")} code={guardScriptSnippet(appId, apiUrl)} />
        <p className="body-5 text-fg-muted">{t("setup.guard.serve")}</p>
      </div>
      <div className="flex flex-col gap-2">
        <h4 id={optionsId} className="caption-1 text-fg-muted">
          {t("setup.guard.options")}
        </h4>
        <dl aria-labelledby={optionsId} className="grid grid-cols-1 gap-x-4 gap-y-1 sm:grid-cols-[auto_1fr]">
          {options.map(([option, help]) => (
            <div key={option} className="contents">
              <dt className="code-3">{option}</dt>
              <dd className="body-5 text-fg-muted">{t(help)}</dd>
            </div>
          ))}
        </dl>
      </div>
    </section>
  );
}

function HardenStep({ appId, apiUrl, environment }: { appId: string; apiUrl: string; environment: string }) {
  const titleId = useId();
  return (
    <section aria-labelledby={titleId} className="flex flex-col gap-4">
      <h3 id={titleId} className="heading-6">
        {t("setup.harden.title")}
      </h3>
      <p className="body-4">{t("setup.harden.lead")}</p>
      <p className="body-5 text-fg-muted">{t("setup.harden.key")}</p>
      <div className="flex flex-col gap-1">
        <Snippet label={t("setup.harden.command")} code={hardenCommand({ endpoint: apiUrl, appId, environment })} />
        <p className="body-5 text-fg-muted">{t("setup.harden.where")}</p>
      </div>
    </section>
  );
}
