"use client";

import { useState, useTransition } from "react";
import { type VerifyAuditChainState, verifyAuditChainAction } from "@/app/actions.ts";
import { Button } from "@/components/button.tsx";
import { t } from "@/lib/t.ts";
import { ChainStatus } from "./chain-status.tsx";

/**
 * "Verify chain" on a filtered view of the audit log (slice 18a): the chain is checked only when asked, so that
 * filtering does not use up the API's limit, which verify shares with Export. The result shows in place.
 */
export function ChainCheck() {
  const [state, setState] = useState<VerifyAuditChainState | null>(null);
  const [pending, startTransition] = useTransition();
  const verify = () =>
    startTransition(async () => {
      setState(await verifyAuditChainAction());
    });

  return (
    <div className="flex flex-col items-start gap-2">
      {state === null ? (
        <p id="audit-verify-help" className="body-5 text-fg-muted">
          {t("audit.chain.verify.help")}
        </p>
      ) : state.ok ? (
        <div className="w-full">
          <ChainStatus result={state.result} />
        </div>
      ) : (
        <div className="w-full">
          <ChainStatus result={null} limited={state.limited} />
        </div>
      )}
      <Button
        variant="secondary"
        onClick={verify}
        disabled={pending}
        aria-describedby={state === null ? "audit-verify-help" : undefined}
        data-testid="audit-verify"
      >
        {pending ? t("audit.chain.verifying") : t("audit.chain.verify")}
      </Button>
    </div>
  );
}
