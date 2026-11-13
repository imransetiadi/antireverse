"use client";

import type { VerifyResult } from "@antireverse/protocol";
import { useActionState } from "react";
import { verifyTargetAction } from "@/app/actions.ts";
import { SubmitButton } from "@/components/submit-button.tsx";
import { formatDateTime } from "@/lib/format.ts";
import { t } from "@/lib/t.ts";
import { DNS_FAILURE_LABEL, FILE_FAILURE_LABEL } from "./labels.ts";

function Outcome({ result }: { result: VerifyResult }) {
  const time = formatDateTime(result.checked_at).text;
  if (result.verified) {
    return (
      <p data-testid="verify-result" className="body-4 text-fg">
        {t(result.method === "dns" ? "target.verify.passed.dns" : "target.verify.passed.file", { time })}
      </p>
    );
  }
  return (
    <div data-testid="verify-result" className="flex flex-col gap-1">
      <p data-testid="verify-headline" className="heading-6 text-fg">
        {t("target.verify.failed", { time })}
      </p>
      <ul className="flex list-none flex-col gap-1 body-5 text-fg-muted">
        <li data-testid="verify-dns">{t("target.verify.dns", { reason: t(DNS_FAILURE_LABEL[result.dns]) })}</li>
        <li data-testid="verify-file">{t("target.verify.file", { reason: t(FILE_FAILURE_LABEL[result.file]) })}</li>
      </ul>
    </div>
  );
}

/** "Verify now" and the outcome of the last check made from this page: the method that passed, or why each failed. */
export function VerifyPanel({ targetId }: { targetId: string }) {
  const [state, formAction] = useActionState(verifyTargetAction, null);
  return (
    <div className="flex flex-col gap-3">
      <form action={formAction} className="flex flex-wrap items-center gap-3">
        <input type="hidden" name="targetId" value={targetId} />
        <SubmitButton pendingLabel={t("target.verify.submitting")} data-testid="target-verify">
          {t("target.verify.submit")}
        </SubmitButton>
        <span className="body-5 text-fg-muted">{t("target.verify.help")}</span>
      </form>
      {/* Always present, so that the outcome is announced. */}
      <div role="status">{state?.ok ? <Outcome result={state.result} /> : null}</div>
      {state && !state.ok ? (
        <p role="alert" data-testid="verify-error" className="body-5 text-sev-critical-text">
          {state.message}
        </p>
      ) : null}
    </div>
  );
}
