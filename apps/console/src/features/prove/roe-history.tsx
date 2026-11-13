import type { RulesOfEngagementVersion, Target } from "@antireverse/protocol";
import { EmptyState } from "@/components/empty-state.tsx";
import { shortId } from "@/features/containment/format.ts";
import { CELL, DATA, HEAD, STICKY } from "@/features/policy/table.ts";
import { formatDateTime } from "@/lib/format.ts";
import { t } from "@/lib/t.ts";
import { shortHash, windowText } from "./labels.ts";
import { scopeHosts } from "./roe-version.tsx";

const COLUMNS = [
  "roe.col.signedAt",
  "roe.col.intensity",
  "roe.col.scope",
  "roe.col.window",
  "roe.col.signedBy",
  "roe.col.hash",
] as const;

/** Every signed version, newest first; the first is current. Versions are never changed, so there is no action. */
export function RoeHistory({
  versions,
  targets,
}: {
  versions: readonly RulesOfEngagementVersion[];
  targets: readonly Target[];
}) {
  if (versions.length === 0) {
    return (
      <div data-testid="roe-history-empty">
        <EmptyState>{t("roe.history.empty")}</EmptyState>
      </div>
    );
  }
  const caption = t("roe.history.caption");
  return (
    <section
      aria-label={caption}
      // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
      tabIndex={0}
      className="overflow-x-auto"
    >
      <table className="w-full border-collapse body-5">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr className="border-border border-b">
            {COLUMNS.map((column, index) => (
              <th key={column} scope="col" className={`${HEAD} ${index === 0 ? STICKY : ""}`}>
                {t(column)}
                {column === "roe.col.signedAt" ? <span className="text-fg-subtle"> {t("targets.zone")}</span> : null}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {versions.map((version, index) => {
            const signedAt = formatDateTime(version.signed_at);
            return (
              <tr key={version.id} data-testid="roe-row" data-roe-id={version.id} className="border-border border-b">
                <th scope="row" className={`${DATA} ${STICKY} whitespace-nowrap text-start`}>
                  <span className="flex flex-col items-start gap-1">
                    <time dateTime={signedAt.iso} title={signedAt.iso}>
                      {signedAt.text}
                    </time>
                    {index === 0 ? (
                      <span
                        data-testid="roe-row-current"
                        className="inline-flex h-6 items-center rounded-control border border-primary px-2 caption-1 text-primary"
                      >
                        {t("roe.current")}
                      </span>
                    ) : null}
                  </span>
                </th>
                <td className={`${DATA} whitespace-nowrap`}>{version.intensity}</td>
                <td className={`${DATA} min-w-40 break-all`} data-testid="roe-row-scope">
                  {scopeHosts(version.scope, targets).join(", ")}
                </td>
                <td className={`${CELL} min-w-40`} data-testid="roe-row-window">
                  {windowText(version.window)}
                </td>
                <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                  <span title={version.signed_by}>{shortId(version.signed_by)}</span>
                </td>
                <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                  <span title={version.content_sha256}>{shortHash(version.content_sha256)}</span>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}
