import type { RulesOfEngagementVersion, Target } from "@antireverse/protocol";
import type { ReactNode } from "react";
import { Card } from "@/components/card.tsx";
import { shortId } from "@/features/containment/format.ts";
import { formatDateTime } from "@/lib/format.ts";
import { t } from "@/lib/t.ts";
import { INTENSITY_HELP, shortHash, windowText } from "./labels.ts";

/** The host of each target id in scope, or the id marked as removed when the target is gone. */
export function scopeHosts(scope: readonly string[], targets: readonly Target[]): string[] {
  return scope.map((id) => targets.find((target) => target.id === id)?.host ?? t("roe.removed", { id }));
}

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="flex flex-col gap-1">
      <dt className="caption-1 text-fg-muted">{label}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}

const LIST = "flex list-none flex-col gap-1 code-3 break-all";

/** One signed version in full: what may be tested, when and how hard, who signed it, when, and its content hash. */
export function RoeVersionCard({
  version,
  targets,
}: {
  version: RulesOfEngagementVersion;
  targets: readonly Target[];
}) {
  const signedAt = formatDateTime(version.signed_at);
  return (
    <Card>
      <div data-testid="roe-current" data-roe-id={version.id} className="flex flex-col gap-4">
        <dl className="grid grid-cols-1 gap-4 md:grid-cols-2">
          <Field label={t("roe.scope")}>
            <ul className={LIST}>
              {scopeHosts(version.scope, targets).map((host) => (
                <li key={host} data-testid="roe-scope-host">
                  {host}
                </li>
              ))}
            </ul>
          </Field>
          <Field label={t("roe.exclusions")}>
            {version.exclusions.length === 0 ? (
              <p data-testid="roe-exclusions-none" className="body-5 text-fg-muted">
                {t("roe.exclusions.none")}
              </p>
            ) : (
              <ul className={LIST}>
                {version.exclusions.map((path) => (
                  <li key={path} data-testid="roe-exclusion">
                    {path}
                  </li>
                ))}
              </ul>
            )}
          </Field>
          <Field label={t("roe.intensity")}>
            <p className="flex flex-col gap-1">
              <span data-testid="roe-intensity" className="code-2">
                {version.intensity}
              </span>
              <span className="body-5 text-fg-muted">{t(INTENSITY_HELP[version.intensity])}</span>
            </p>
          </Field>
          <Field label={t("roe.window")}>
            <span data-testid="roe-window" className="body-4">
              {windowText(version.window)}
            </span>
          </Field>
          <Field label={t("roe.contacts")}>
            <ul className={LIST}>
              {version.contacts.map((contact) => (
                <li key={contact} data-testid="roe-contact">
                  {contact}
                </li>
              ))}
            </ul>
          </Field>
          <Field label={t("roe.signedBy")}>
            <span data-testid="roe-signed-by" title={version.signed_by} className="code-3">
              {shortId(version.signed_by)}
            </span>
          </Field>
          <Field label={`${t("roe.signedAt")} ${t("targets.zone")}`}>
            <time data-testid="roe-signed-at" dateTime={signedAt.iso} title={signedAt.iso} className="code-3">
              {signedAt.text}
            </time>
          </Field>
          <Field label={t("roe.hash")}>
            <span data-testid="roe-hash" title={version.content_sha256} className="code-3">
              {shortHash(version.content_sha256)}
            </span>
          </Field>
        </dl>
        <p data-testid="roe-immutable" className="body-5 text-fg-muted">
          {t("roe.immutable")}
        </p>
      </div>
    </Card>
  );
}
