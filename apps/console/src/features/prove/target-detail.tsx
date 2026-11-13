import type { Target, TargetVerification } from "@antireverse/protocol";
import { Card } from "@/components/card.tsx";
import { CopyButton } from "@/components/copy-button.tsx";
import { formatDateTime } from "@/lib/format.ts";
import { t } from "@/lib/t.ts";
import { METHOD_LABEL } from "./labels.ts";
import { RemoveTarget } from "./remove-target.tsx";
import { TargetStatusChip } from "./target-status.tsx";
import { VerifyPanel } from "./verify-panel.tsx";

const SECTION = "flex flex-col gap-3";
const SECTION_TITLE = "heading-4";

/** One value to publish: its label, the value in Geist Mono and a copy button described by the label. */
function CopyValue({ id, label, value, copy = true }: { id: string; label: string; value: string; copy?: boolean }) {
  return (
    <div className="flex flex-col gap-1">
      <span id={`${id}-label`} className="caption-1 text-fg-muted">
        {label}
      </span>
      <div className="flex items-start gap-2">
        <code
          data-testid={id}
          className="min-w-0 flex-1 break-all rounded-control border border-border-strong bg-bg px-3 py-2 code-3"
        >
          {value}
        </code>
        {copy ? <CopyButton value={value} describedBy={`${id}-label`} /> : null}
      </div>
    </div>
  );
}

function Fact({ label, iso, testId }: { label: string; iso: string | null; testId: string }) {
  const time = iso === null ? null : formatDateTime(iso);
  return (
    <div className="flex flex-col gap-1">
      <dt className="caption-1 text-fg-muted">{label}</dt>
      <dd data-testid={testId} className="code-3">
        {time === null ? (
          <span className="text-fg-subtle">{t("targets.never")}</span>
        ) : (
          <time dateTime={time.iso} title={time.iso}>
            {time.text} {t("targets.zone")}
          </time>
        )}
      </dd>
    </div>
  );
}

interface TargetDetailProps {
  target: Target;
  verification: TargetVerification;
  /** The host is in the scope of the current Rules of Engagement. */
  inScope: boolean;
  /** The address asks to confirm the removal. */
  confirmRemove: boolean;
}

/** One host: its status and checks, the two ways to prove it with copy buttons, Verify, and Remove. */
export function TargetDetail({ target, verification, inScope, confirmRemove }: TargetDetailProps) {
  return (
    <>
      <section aria-labelledby="target-facts-title" className={SECTION}>
        <h2 id="target-facts-title" className="sr-only">
          {t("target.facts")}
        </h2>
        <div className="flex flex-wrap items-center gap-3">
          <TargetStatusChip status={target.status} />
          <span className="body-5 text-fg-muted">
            {t(target.method === null ? "target.method.none" : METHOD_LABEL[target.method])}
          </span>
        </div>
        {target.status === "lapsed" && target.lapsed_reason !== null ? (
          <p data-testid="target-lapsed-reason" className="body-4 break-words text-fg">
            {t("targets.lapsed", { reason: target.lapsed_reason })}
          </p>
        ) : null}
        <dl className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <Fact label={t("targets.col.verified")} iso={target.verified_at} testId="target-verified-at" />
          <Fact label={t("targets.col.checked")} iso={target.last_checked_at} testId="target-checked-at" />
          <Fact label={t("target.added")} iso={target.created_at} testId="target-created-at" />
        </dl>
      </section>

      <section aria-labelledby="target-prove-title" className={SECTION}>
        <h2 id="target-prove-title" className={SECTION_TITLE}>
          {t("target.prove.title")}
        </h2>
        <p className="text-fg-muted">{t("target.prove.lead")}</p>
        <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
          <Card>
            <div data-testid="prove-dns" className="flex flex-col gap-3">
              <h3 className="heading-6">{t("target.prove.dns")}</h3>
              <p className="body-5 text-fg-muted">{t("target.prove.dns.help")}</p>
              <CopyValue id="prove-dns-name" label={t("target.prove.dns.name")} value={verification.dns_name} />
              <CopyValue id="prove-dns-type" label={t("target.prove.dns.type")} value="TXT" copy={false} />
              <CopyValue id="prove-dns-value" label={t("target.prove.dns.value")} value={verification.dns_value} />
            </div>
          </Card>
          <Card>
            <div data-testid="prove-file" className="flex flex-col gap-3">
              <h3 className="heading-6">{t("target.prove.file")}</h3>
              <p className="body-5 text-fg-muted">{t("target.prove.file.help")}</p>
              <CopyValue id="prove-file-url" label={t("target.prove.file.url")} value={verification.file_url} />
              <CopyValue
                id="prove-file-content"
                label={t("target.prove.file.content")}
                value={verification.file_content}
              />
            </div>
          </Card>
        </div>
      </section>

      <section aria-labelledby="target-verify-title" className={SECTION}>
        <h2 id="target-verify-title" className={SECTION_TITLE}>
          {t("target.verify.title")}
        </h2>
        <VerifyPanel targetId={target.id} />
      </section>

      <section aria-labelledby="target-remove-title" className={SECTION}>
        <h2 id="target-remove-title" className={SECTION_TITLE}>
          {t("target.remove.title")}
        </h2>
        <RemoveTarget target={target} inScope={inScope} confirmRemove={confirmRemove} />
      </section>
    </>
  );
}

/**
 * TargetDetail as the target's page renders it. Opening or closing the removal step starts the actions afresh; a
 * re-render after a check (revalidatePath sends the changed target) does not, so the check's outcome stays on screen.
 */
export function TargetView(props: TargetDetailProps) {
  return <TargetDetail key={String(props.confirmRemove)} {...props} />;
}
