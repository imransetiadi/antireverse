"use client";

import { useActionState, useEffect, useRef } from "react";
import { opsSignInAction } from "@/app/ops/actions.ts";
import { Button } from "@/components/button.tsx";
import { Input } from "@/components/input.tsx";
import { t } from "@/lib/t.ts";

/** Signs in with the operator token (slice 18d). The field is never refilled: a refused token is typed again. */
export function OpsSignInForm() {
  const [state, formAction, pending] = useActionState(opsSignInAction, null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (state && !state.ok) input.current?.focus();
  }, [state]);

  return (
    <form action={formAction} noValidate className="flex flex-col gap-4">
      <Input
        ref={input}
        id="ops-token-input"
        name="token"
        type="password"
        label={t("ops.signin.token")}
        error={state?.message}
        autoComplete="off"
        spellCheck={false}
        aria-required="true"
        mono
      />
      <div>
        <Button type="submit" disabled={pending}>
          {pending ? t("ops.signin.submitting") : t("ops.signin.submit")}
        </Button>
      </div>
    </form>
  );
}
