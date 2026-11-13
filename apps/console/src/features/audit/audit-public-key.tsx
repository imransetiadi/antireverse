import type { AuditPublicKeyResponse } from "@antireverse/protocol";
import { CopyButton } from "@/components/copy-button.tsx";
import { t } from "@/lib/t.ts";

/**
 * "Verify an export" (slice 18a): the public half of the API's audit key, so that an auditor can check the signed
 * head on the first line of an export, and how the chain is computed. Null when the key could not be read.
 */
export function AuditPublicKey({ publicKey }: { publicKey: AuditPublicKeyResponse | null }) {
  return (
    <section aria-labelledby="audit-key-title" className="flex max-w-3xl flex-col gap-3">
      <h2 id="audit-key-title" className="heading-4">
        {t("audit.key.title")}
      </h2>
      <p className="text-fg-muted">{t("audit.key.lead")}</p>
      {publicKey === null ? (
        <p data-testid="audit-public-key-missing" className="text-fg-muted">
          {t("audit.key.missing")}
        </p>
      ) : (
        <dl className="flex flex-col gap-3 rounded-card border border-border bg-surface p-3">
          <div className="flex flex-col gap-0.5">
            <dt className="caption-1 text-fg-muted">{t("audit.key.id")}</dt>
            <dd data-testid="audit-key-id" className="code-3">
              {publicKey.key_id}
            </dd>
          </div>
          <div className="flex flex-col gap-1">
            <dt id="audit-public-key-label" className="caption-1 text-fg-muted">
              {`${t("audit.key.public")} · ${publicKey.algorithm}`}
            </dt>
            <dd className="flex flex-wrap items-center gap-2">
              <code data-testid="audit-public-key" className="min-w-0 break-all code-3">
                {publicKey.public_key}
              </code>
              <CopyButton value={publicKey.public_key} describedBy="audit-public-key-label" />
            </dd>
          </div>
        </dl>
      )}
    </section>
  );
}
