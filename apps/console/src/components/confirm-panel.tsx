"use client";

import { AUDIT_LIMITS } from "@antireverse/protocol";
import { type ReactNode, useEffect, useId, useRef } from "react";
import { t } from "@/lib/t.ts";
import { Button, ButtonLink } from "./button.tsx";
import { Input } from "./input.tsx";
import { SubmitButton } from "./submit-button.tsx";

interface ConfirmPanelProps {
  /** The question. It names the object and the Environment and states the effect (UIUX.md §8). */
  question: string;
  /** The words of the button that confirms. */
  confirmLabel: string;
  /** Where "Cancel" goes: the same screen without the confirmation step. */
  cancelHref: string;
  /** The words of that link. Default: "Cancel" (slice 18b: "Keep it scheduled" where the change is a cancellation). */
  cancelLabel?: string | undefined;
  /**
   * Slice 18b: a step opened in the page rather than by an address closes with this instead of following
   * `cancelHref` — "Cancel" is then a button, and nothing of the step enters an address.
   */
  onCancel?: (() => void) | undefined;
  /** The Server Action the confirmation is sent to. */
  action: (formData: FormData) => void;
  /** True while another form of the screen is being submitted. */
  busy?: boolean;
  /** The hidden fields of the change, the confirmation among them. */
  children: ReactNode;
  /**
   * The stronger confirmation of a change that can take the App offline: a warning in the destructive style
   * and a field in which the person types `environment` — the Environment, or another value the question
   * named, such as a network prefix (then with its own `label` and field `name`). The browser holds the
   * submit back until it matches (also without JavaScript); the Server Action checks it again and alone decides.
   */
  typed?:
    | {
        warning: string;
        environment: string;
        error?: string | undefined;
        /** Default: "Type <environment> to confirm". */
        label?: string | undefined;
        /** Default: `typedEnvironment`. */
        name?: string | undefined;
      }
    | undefined;
  /**
   * What is known about the effect before it happens, e.g. the estimate of a Policy simulation. Shown between the
   * question and the note, and read with them; nothing is shown without one.
   */
  estimate?: string | undefined;
  /** What follows from the change and how it is undone. Default: the Policy's "publishes a new version" note. */
  note?: string | undefined;
  /** What the confirm button reads while it is being sent. Default: "Publishing…". */
  pendingLabel?: string | undefined;
  /** `data-testid` of the step. Default: `policy-confirm`. */
  testId?: string | undefined;
  /**
   * The reason of the change (slice 18a), recorded in the audit log: a one-line field named `reason`. `required` for a
   * sensitive change — the browser then holds the submit back while it is empty, and the Server Action checks it
   * again — optional otherwise. No field without this prop.
   */
  reason?: { required: boolean; error?: string | undefined; value?: string | undefined } | undefined;
}

/** The id of the typed Environment field. One confirmation step is open at a time. */
export const TYPED_FIELD_ID = "confirm-typed";

/** The id of the reason field (slice 18a). One confirmation step is open at a time. */
export const REASON_FIELD_ID = "confirm-reason";

/** The visible label of the reason field: the summary of errors names the field with it. */
export const reasonLabel = (required: boolean): string => t(required ? "reason.label" : "reason.label.optional");

/** `value` as a `pattern` that matches exactly that text (the attribute is compiled with the `v` flag). */
const exactly = (value: string): string => value.replace(/[.*+?^${}()|[\]\\/]/g, "\\$&");

/**
 * The confirmation step of a wide-impact change, in the page instead of over it: it is rendered by the
 * server for an address, so it works with the keyboard and without client-side JavaScript. Nothing here
 * makes the change safe — the Server Action refuses a change that arrives without the confirmation.
 * When it appears it takes the focus, so that it is read first and Tab reaches Cancel, then the button.
 */
export function ConfirmPanel({
  question,
  confirmLabel,
  cancelHref,
  cancelLabel,
  onCancel,
  action,
  busy = false,
  children,
  typed,
  estimate,
  note,
  pendingLabel,
  testId = "policy-confirm",
  reason,
}: ConfirmPanelProps) {
  const ref = useRef<HTMLDivElement>(null);
  const questionId = useId();
  const noteId = useId();
  const warningId = useId();
  const estimateId = useId();
  const describedBy = [typed ? warningId : null, estimate ? estimateId : null, noteId].filter(Boolean).join(" ");

  useEffect(() => {
    ref.current?.focus();
  }, []);

  return (
    <div
      ref={ref}
      tabIndex={-1}
      role="alertdialog"
      aria-modal="false"
      aria-labelledby={questionId}
      aria-describedby={describedBy}
      data-testid={testId}
      className="flex flex-col gap-3 rounded-card border border-destructive bg-surface-raised p-3"
    >
      <p id={questionId} data-testid="confirm-question" className="break-words heading-6 text-fg">
        {question}
      </p>
      {typed ? (
        <p
          id={warningId}
          data-testid="confirm-broad"
          className="rounded-control border-2 border-destructive px-3 py-2 heading-6 text-fg"
        >
          {typed.warning}
        </p>
      ) : null}
      {estimate ? (
        <p id={estimateId} data-testid="confirm-estimate" className="body-4 text-fg">
          {estimate}
        </p>
      ) : null}
      <p id={noteId} className="body-5 text-fg-muted">
        {note ?? t("policy.confirm.undo")}
      </p>
      <form action={action} className="flex flex-wrap items-end gap-2">
        {children}
        {reason ? (
          <div className="w-full max-w-xl" data-testid="confirm-reason-field">
            <Input
              id={REASON_FIELD_ID}
              name="reason"
              type="text"
              label={reasonLabel(reason.required)}
              help={t("reason.help")}
              error={reason.error}
              required={reason.required}
              aria-required={reason.required ? "true" : undefined}
              maxLength={AUDIT_LIMITS.reasonMax}
              autoComplete="off"
              // The reason as typed before a refusal: the step shows it again (React resets the form after an action).
              defaultValue={reason.value ?? ""}
              data-testid="confirm-reason"
            />
          </div>
        ) : null}
        {typed ? (
          <div className="w-full max-w-xs" data-testid="confirm-typed-field">
            <Input
              id={TYPED_FIELD_ID}
              name={typed.name ?? "typedEnvironment"}
              type="text"
              label={typed.label ?? t("policy.confirm.typed", { environment: typed.environment })}
              labelTestId="confirm-typed-label"
              error={typed.error}
              required
              aria-required="true"
              pattern={exactly(typed.environment)}
              autoComplete="off"
              autoCapitalize="none"
              autoCorrect="off"
              spellCheck={false}
              mono
              data-testid="confirm-typed"
            />
          </div>
        ) : null}
        {onCancel ? (
          <Button variant="secondary" onClick={onCancel} data-testid="confirm-cancel">
            {cancelLabel ?? t("cancel")}
          </Button>
        ) : (
          <ButtonLink
            variant="secondary"
            href={cancelHref}
            scroll={false}
            prefetch={false}
            data-testid="confirm-cancel"
          >
            {cancelLabel ?? t("cancel")}
          </ButtonLink>
        )}
        <SubmitButton
          variant="destructive"
          disabled={busy}
          pendingLabel={pendingLabel ?? t("policy.publishing")}
          data-testid="confirm-submit"
        >
          {confirmLabel}
        </SubmitButton>
      </form>
    </div>
  );
}
