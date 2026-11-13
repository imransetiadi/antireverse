import type { AuditVerifyResponse } from "@antireverse/protocol";
import { Icon } from "@/components/icons.tsx";
import { t } from "@/lib/t.ts";

const BOX = "flex items-start gap-2 rounded-card border p-3";

interface ChainStatusProps {
  /** The API's verification and signed head, or null when it could not be read. */
  result: AuditVerifyResponse | null;
  /** Set when the API refused the check for being asked too often (429), with its Retry-After in seconds. */
  limited?: { retryAfter: number | undefined } | undefined;
}

/** The signed chain head beside the status: which entry the API signed, and with which audit key. */
function SignedHead({ signed }: { signed: AuditVerifyResponse["signed_head"] }) {
  return (
    <p data-testid="audit-signed-head" className="body-5 text-fg-muted">
      {t("audit.head.signed", { seq: signed.head.seq })} <span className="code-3 text-fg">{signed.key_id}</span>
    </p>
  );
}

/**
 * The chain status of the audit log (slice 18a): verified with its count, or the first entry at which the chain no
 * longer holds (`AUDIT_VERIFY_DOC`), as recomputed by the API, with the signed head beside it. A broken chain is an
 * alert in the destructive style with what to do. The words carry the meaning; the icon repeats it.
 */
export function ChainStatus({ result, limited }: ChainStatusProps) {
  if (result === null) {
    const text =
      limited === undefined
        ? t("audit.chain.unknown")
        : limited.retryAfter === undefined
          ? t("audit.chain.limited.soon")
          : t("audit.chain.limited", { seconds: Math.max(1, limited.retryAfter) });
    return (
      <p role="status" data-testid="audit-chain" className={`${BOX} border-border-strong text-fg-muted`}>
        {text}
      </p>
    );
  }
  const { verify, signed_head: signed } = result;
  if (!verify.valid && verify.first_broken_seq !== null) {
    const seq = verify.first_broken_seq;
    return (
      <div className="flex flex-col gap-1">
        <div role="alert" data-testid="audit-chain" data-valid="false" className={`${BOX} border-destructive`}>
          <Icon name="warning-octagon" className="mt-0.5 size-4 shrink-0 text-sev-critical-text" />
          <div className="flex flex-col gap-1">
            <p data-testid="audit-chain-text" className="heading-6 text-sev-critical-text">
              {t("audit.chain.broken", { seq })}
            </p>
            <p className="body-5 text-fg">{t("audit.chain.broken.help", { seq })}</p>
          </div>
        </div>
        <SignedHead signed={signed} />
      </div>
    );
  }
  const text =
    verify.entries === 0
      ? t("audit.chain.empty")
      : verify.entries === 1
        ? t("audit.chain.valid.one")
        : t("audit.chain.valid", { count: verify.entries });
  return (
    <div className="flex flex-col gap-1">
      <p role="status" data-testid="audit-chain" data-valid="true" className={`${BOX} border-border text-fg`}>
        <Icon name="shield-check" className="mt-0.5 size-4 shrink-0 text-primary" />
        <span data-testid="audit-chain-text">{text}</span>
      </p>
      <SignedHead signed={signed} />
    </div>
  );
}
