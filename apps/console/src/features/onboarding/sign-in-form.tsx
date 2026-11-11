"use client";

import { useActionState, useEffect, useRef } from "react";
import { signInAction } from "@/app/actions.ts";
import { Button } from "@/components/button.tsx";
import { Input } from "@/components/input.tsx";
import { t } from "@/lib/t.ts";

const KEY_ID = "admin-key-input";

/** Signs in with a pasted admin key. The field is never refilled: a refused key is typed again. */
export function SignInForm() {
  const [state, formAction, pending] = useActionState(signInAction, null);
  const input = useRef<HTMLInputElement>(null);

  // After a refused submit, focus returns to the one field; its error is linked to it.
  useEffect(() => {
    if (state && !state.ok) input.current?.focus();
  }, [state]);

  return (
    <form action={formAction} noValidate className="flex flex-col gap-4">
      <Input
        ref={input}
        id={KEY_ID}
        name="key"
        type="password"
        label={t("signin.key")}
        error={state?.message}
        autoComplete="current-password"
        spellCheck={false}
        aria-required="true"
        mono
      />
      <div>
        <Button type="submit" disabled={pending}>
          {pending ? t("signin.submitting") : t("signin.submit")}
        </Button>
      </div>
    </form>
  );
}
