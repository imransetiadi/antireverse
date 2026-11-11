"use client";

import { useEffect, useRef } from "react";
import { t } from "@/lib/t.ts";

export interface SummaryError {
  /** The field's `name`, or `""` for the form as a whole. */
  path: string;
  message: string;
}

interface ErrorSummaryProps {
  errors: readonly SummaryError[];
  /** For each field `name`: the id of its control and its visible label. */
  fields: Readonly<Record<string, { id: string; label: string }>>;
}

/**
 * What stopped a submit, above the form. It receives focus after a failed submit (UIUX.md §12) and links
 * each entry to its field; the same message is also shown below that field.
 */
export function ErrorSummary({ errors, fields }: ErrorSummaryProps) {
  const ref = useRef<HTMLDivElement>(null);

  // `errors` is a new array after every failed submit, so focus returns here each time.
  useEffect(() => {
    if (errors.length > 0) ref.current?.focus();
  }, [errors]);

  if (errors.length === 0) return null;
  return (
    <div
      ref={ref}
      tabIndex={-1}
      role="alert"
      data-testid="error-summary"
      className="flex flex-col gap-1 rounded-card border border-sev-critical-text p-3"
    >
      <p className="heading-6 text-sev-critical-text">{t("error.summary")}</p>
      <ul className="flex list-none flex-col gap-1">
        {errors.map((error) => {
          const field = fields[error.path];
          return (
            <li key={`${error.path}:${error.message}`}>
              {field ? (
                <a href={`#${field.id}`}>{t("error.summary.item", { field: field.label, message: error.message })}</a>
              ) : (
                error.message
              )}
            </li>
          );
        })}
      </ul>
    </div>
  );
}

/** The message for one field, to show below it. */
export function fieldError(errors: readonly SummaryError[], path: string): string | undefined {
  return errors.find((error) => error.path === path)?.message;
}
