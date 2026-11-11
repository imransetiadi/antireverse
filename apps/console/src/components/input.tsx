import type { ComponentProps, ReactNode } from "react";

// The same height as a button: 8 px vertical and 12 px horizontal padding, a 20 px line and the border.
// 48 px high on touch layouts.
const CONTROL =
  "w-full rounded-control border border-border-strong bg-bg px-3 py-2 text-fg placeholder:text-fg-subtle " +
  "hover:border-fg-muted pointer-coarse:min-h-12 disabled:cursor-not-allowed disabled:opacity-60 " +
  "aria-invalid:border-sev-critical-text";
// Body text, or Geist Mono for a value that is an identifier or a pattern; 16 px on touch layouts either way.
const TYPE = "body-4 pointer-coarse:body-3";
const MONO_TYPE = "code-2 pointer-coarse:code-1";

interface FieldShellProps {
  id: string;
  label: string;
  labelTestId?: string | undefined;
  help?: string | undefined;
  /** A short line under the help that follows the value, e.g. a window in readable words. */
  hint?: string | undefined;
  error?: string | undefined;
  children: ReactNode;
}

/** A visible label above the control, the help text and the error below it, both linked to the control. */
function FieldShell({ id, label, labelTestId, help, hint, error, children }: FieldShellProps) {
  return (
    <div className="flex flex-col gap-1">
      <label htmlFor={id} className="title-4 text-fg" data-testid={labelTestId}>
        {label}
      </label>
      {children}
      {help ? (
        <p id={`${id}-help`} className="body-5 text-fg-muted">
          {help}
        </p>
      ) : null}
      {hint ? (
        <p id={`${id}-hint`} className="code-3 text-fg-muted" data-testid={`${id}-hint`}>
          {hint}
        </p>
      ) : null}
      {error ? (
        <p id={`${id}-error`} className="body-5 text-sev-critical-text" data-testid={`${id}-error`}>
          {error}
        </p>
      ) : null}
    </div>
  );
}

function describedBy(id: string, help?: string, error?: string, hint?: string): string | undefined {
  const ids = [error ? `${id}-error` : null, help ? `${id}-help` : null, hint ? `${id}-hint` : null].filter(Boolean);
  return ids.length > 0 ? ids.join(" ") : undefined;
}

type InputProps = Omit<ComponentProps<"input">, "id"> & {
  id: string;
  label: string;
  /** The value is an identifier, a key, a range or a pattern: set it in Geist Mono. */
  mono?: boolean | undefined;
  help?: string | undefined;
  /** A short line under the help that follows the value as it is typed. */
  hint?: string | undefined;
  error?: string | undefined;
  labelTestId?: string | undefined;
};

export function Input({ id, label, help, hint, error, labelTestId, mono = false, className, ...rest }: InputProps) {
  return (
    <FieldShell id={id} label={label} labelTestId={labelTestId} help={help} hint={hint} error={error}>
      <input
        id={id}
        className={`${CONTROL} ${mono ? MONO_TYPE : TYPE} ${className ?? ""}`.trim()}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(id, help, error, hint)}
        {...rest}
      />
    </FieldShell>
  );
}

type SelectProps = Omit<ComponentProps<"select">, "id"> & {
  id: string;
  label: string;
  help?: string;
  error?: string;
  /** The options are identifiers: set them in Geist Mono. */
  mono?: boolean | undefined;
};

export function Select({ id, label, help, error, mono = false, className, children, ...rest }: SelectProps) {
  return (
    <FieldShell id={id} label={label} help={help} error={error}>
      <select
        id={id}
        className={`${CONTROL} ${mono ? MONO_TYPE : TYPE} ${className ?? ""}`.trim()}
        aria-invalid={error ? true : undefined}
        aria-describedby={describedBy(id, help, error)}
        {...rest}
      >
        {children}
      </select>
    </FieldShell>
  );
}
