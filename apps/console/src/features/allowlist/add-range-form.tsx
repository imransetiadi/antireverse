"use client";

import { CONTAINMENT_LIMITS } from "@antireverse/protocol";
import { useActionState } from "react";
import { createAllowlistEntryAction } from "@/app/actions.ts";
import { Button } from "@/components/button.tsx";
import { ErrorSummary, fieldError } from "@/components/error-summary.tsx";
import { Input } from "@/components/input.tsx";
import { t } from "@/lib/t.ts";

const CIDR_ID = "allowlist-cidr";
const NOTE_ID = "allowlist-note";

/**
 * Adds a range to the never block list. A refusal keeps what was typed and explains it below the field —
 * for a range in another spelling or with host bits set, with the canonical form to use. A success is
 * announced politely and the form starts empty again; the list above shows the new range.
 */
export function AddRangeForm() {
  const [state, formAction, pending] = useActionState(createAllowlistEntryAction, null);
  const errors = state && !state.ok ? state.errors : [];
  const values = state && !state.ok ? state.values : undefined;

  return (
    <div className="flex max-w-xl flex-col gap-4">
      {/* Always present, so that a new range is announced. */}
      <p role="status" data-testid={state?.ok ? "allowlist-added-status" : undefined} className="body-5">
        {state?.ok ? t("allowlist.added", { cidr: state.entry.cidr }) : null}
      </p>
      {/* A new key after each submit: a refusal refills the fields, a success empties them. */}
      <form
        key={values ? `${values.cidr}\u0000${values.note}` : state?.ok ? state.entry.id : ""}
        action={formAction}
        noValidate
        className="flex flex-col gap-4"
      >
        <ErrorSummary
          errors={errors}
          fields={{
            cidr: { id: CIDR_ID, label: t("allowlist.add.cidr") },
            note: { id: NOTE_ID, label: t("allowlist.add.note") },
          }}
        />
        <Input
          id={CIDR_ID}
          name="cidr"
          label={t("allowlist.add.cidr")}
          help={t("allowlist.add.cidr.help")}
          defaultValue={values?.cidr}
          error={fieldError(errors, "cidr")}
          autoComplete="off"
          autoCapitalize="none"
          autoCorrect="off"
          spellCheck={false}
          aria-required="true"
          mono
          data-testid="allowlist-cidr-input"
        />
        <Input
          id={NOTE_ID}
          name="note"
          label={t("allowlist.add.note")}
          help={t("allowlist.add.note.help")}
          defaultValue={values?.note}
          error={fieldError(errors, "note")}
          maxLength={CONTAINMENT_LIMITS.noteMax}
          autoComplete="off"
          data-testid="allowlist-note-input"
        />
        <div>
          <Button type="submit" disabled={pending} data-testid="allowlist-add">
            {pending ? t("allowlist.add.submitting") : t("allowlist.add.submit")}
          </Button>
        </div>
      </form>
    </div>
  );
}
