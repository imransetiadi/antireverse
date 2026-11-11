"use client";

import type { ComponentProps } from "react";
import { useFormStatus } from "react-dom";
import { Button, type ButtonVariant } from "./button.tsx";

type SubmitButtonProps = Omit<ComponentProps<"button">, "type"> & {
  variant?: ButtonVariant;
  /** What the button reads while its own form is being submitted. */
  pendingLabel: string;
};

/**
 * The submit button of a form whose screen holds several forms. While its own form is being submitted it
 * shows progress; `disabled` lets the screen hold every other button still meanwhile.
 */
export function SubmitButton({ pendingLabel, disabled, children, ...rest }: SubmitButtonProps) {
  const { pending } = useFormStatus();
  return (
    <Button type="submit" disabled={pending || disabled} {...rest}>
      {pending ? pendingLabel : children}
    </Button>
  );
}
