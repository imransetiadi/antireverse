import Link from "next/link";
import type { ComponentProps } from "react";

export type ButtonVariant = "primary" | "secondary" | "quiet" | "destructive";

// Main buttons: 8 px vertical and 12 px horizontal padding around button-md type (36 px plus the border); every
// variant has a border, transparent where it is not drawn, so all buttons are the same height. 48 px high on
// touch layouts. Press feedback (opacity, a 2 % settle) comes from the press utility (UIUX.md §4.4).
const BASE =
  "press inline-flex min-w-8 shrink-0 items-center justify-center gap-2 rounded-control border px-3 py-2 button-md " +
  "no-underline whitespace-nowrap pointer-coarse:min-h-12 pointer-coarse:px-4 " +
  "disabled:cursor-not-allowed disabled:opacity-60";

const VARIANTS: Record<ButtonVariant, string> = {
  primary: "border-transparent bg-primary text-on-primary hover:opacity-85 disabled:hover:opacity-60",
  secondary:
    "border-border-strong bg-transparent text-fg hover:bg-muted active:bg-surface-raised disabled:hover:bg-transparent",
  quiet: "border-transparent bg-transparent text-fg-muted hover:bg-muted hover:text-fg active:bg-surface-raised",
  // The button that confirms a destructive or wide-impact change: always black text on the destructive
  // colour — white fails contrast (UIUX.md §4.1, §8).
  destructive: "border-transparent bg-destructive text-on-destructive hover:opacity-85 disabled:hover:opacity-60",
};

export function buttonClass(variant: ButtonVariant = "primary", extra = ""): string {
  return `${BASE} ${VARIANTS[variant]} ${extra}`.trim();
}

type ButtonProps = ComponentProps<"button"> & { variant?: ButtonVariant };

export function Button({ variant = "primary", className, type = "button", ...rest }: ButtonProps) {
  return <button type={type} className={buttonClass(variant, className)} {...rest} />;
}

type ButtonLinkProps = ComponentProps<typeof Link> & { variant?: ButtonVariant };

/** A navigation that looks like a button. It stays a link: it goes somewhere and changes nothing. */
export function ButtonLink({ variant = "primary", className, ...rest }: ButtonLinkProps) {
  return <Link className={buttonClass(variant, className)} {...rest} />;
}
