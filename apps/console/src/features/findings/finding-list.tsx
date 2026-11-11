import type { Finding } from "@antireverse/protocol";
import Link from "next/link";
import { EmptyState } from "@/components/empty-state.tsx";
import { SeverityBadge } from "@/components/severity-badge.tsx";
import { CELL, DATA, HEAD, STICKY } from "@/features/policy/table.ts";
import { formatDateTime } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { type MessageKey, t } from "@/lib/t.ts";
import { cveSummary, packageLabel, suggestedFix } from "./format.ts";
import { SOURCE_LABEL } from "./labels.ts";
import { type FindingQuery, isFiltered } from "./query.ts";
import { FindingStatusTag } from "./status-tag.tsx";

interface FindingListProps {
  /** As the API returned them (newest first), already narrowed by advisory and Build. */
  findings: readonly Finding[];
  /** App id → App name, on the Organization's list: the App column shows then. An App not in it shows its id. */
  appNames?: ReadonlyMap<string, string> | undefined;
  /** The filters of the address: an empty list then says nothing matches, and a narrowed list says to what. */
  query: FindingQuery;
  /** The same list without any filter. */
  clearHref: string;
  caption?: string | undefined;
}

/** The advisory id and its first CVE alias, with the number of further CVE aliases. */
function AdvisoryCell({ finding }: { finding: Finding }) {
  const { first, more } = cveSummary(finding.aliases);
  return (
    <td className={`${CELL} min-w-40`}>
      <span data-testid="finding-advisory" className="block break-all code-3">
        {finding.advisory_id}
      </span>
      {first === null ? null : (
        <span className="flex flex-wrap items-baseline gap-x-2 text-fg-muted">
          <span data-testid="finding-cve" className="break-all code-3">
            {first}
          </span>
          {more > 0 ? (
            <span data-testid="finding-cve-more" className="caption-1">
              {t("findings.aliases.more", { count: more })}
            </span>
          ) : null}
        </span>
      )}
    </td>
  );
}

/** The scope a list is narrowed to beyond the filter rows: one advisory or one Build. */
function Scope({ query, clearHref }: { query: FindingQuery; clearHref: string }) {
  if (query.advisory === undefined && query.build === undefined) return null;
  return (
    <p data-testid="findings-scope" className="flex flex-wrap items-baseline gap-x-3 gap-y-1 body-5 text-fg-muted">
      {query.advisory === undefined ? null : <span>{t("findings.scope.advisory", { advisory: query.advisory })}</span>}
      {query.build === undefined ? null : <span>{t("findings.scope.build", { build: query.build })}</span>}
      <Link href={clearHref}>{t("findings.filter.clear")}</Link>
    </p>
  );
}

/** SCR-10 for slice 19: Findings, one row each, linking to the Finding page. */
export function FindingList({ findings, appNames, query, clearHref, caption = t("findings.title") }: FindingListProps) {
  if (findings.length === 0) {
    return (
      <div data-testid="findings-empty">
        {isFiltered(query) ? (
          <EmptyState action={<Link href={clearHref}>{t("findings.filter.clear")}</Link>}>
            {t("findings.empty.filtered")}
          </EmptyState>
        ) : (
          <EmptyState icon="shield-check" action={<p className="body-5 text-fg-muted">{t("findings.empty.how")}</p>}>
            {t("findings.empty")}
          </EmptyState>
        )}
      </div>
    );
  }

  const columns: MessageKey[] = [
    "findings.col.severity",
    "findings.col.package",
    ...(appNames === undefined ? [] : (["findings.col.app"] as MessageKey[])),
    "findings.col.advisory",
    "findings.col.source",
    "findings.col.status",
    "findings.col.fixedIn",
    "findings.col.lastSeen",
  ];

  return (
    <>
      <Scope query={query} clearHref={clearHref} />
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
              {columns.map((column, index) => (
                <th key={column} scope="col" className={`${HEAD} ${index === 0 ? STICKY : ""}`}>
                  {t(column)}
                  {column === "findings.col.lastSeen" ? (
                    <span className="text-fg-subtle"> {t("findings.col.zone")}</span>
                  ) : null}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {findings.map((finding) => {
              const lastSeen = formatDateTime(finding.last_seen);
              const fix = suggestedFix(finding);
              return (
                <tr
                  key={finding.id}
                  data-testid="finding-row"
                  data-finding-id={finding.id}
                  data-status={finding.status}
                  data-severity={finding.severity}
                  data-source={finding.source}
                  className="border-border border-b"
                >
                  <td className={`${CELL} ${STICKY} whitespace-nowrap`}>
                    <SeverityBadge severity={finding.severity} />
                  </td>
                  <th scope="row" className={`${CELL} min-w-40 text-start`}>
                    <Link href={ROUTES.finding(finding.id)} data-testid="finding-link" className="break-all code-3">
                      {packageLabel(finding)}
                    </Link>
                  </th>
                  {appNames === undefined ? null : (
                    <td data-testid="finding-app" className={`${CELL} min-w-32 break-words`}>
                      {appNames.get(finding.app_id) ?? <span className="code-3">{finding.app_id}</span>}
                    </td>
                  )}
                  <AdvisoryCell finding={finding} />
                  <td data-testid="finding-source" className={`${CELL} whitespace-nowrap`}>
                    {t(SOURCE_LABEL[finding.source])}
                  </td>
                  <td className={`${CELL} whitespace-nowrap`}>
                    <FindingStatusTag status={finding.status} />
                  </td>
                  <td className={`${CELL} whitespace-nowrap`}>
                    {fix === null ? (
                      <span data-testid="finding-fixed-in" className="text-fg-muted">
                        {t("findings.fix.none")}
                      </span>
                    ) : (
                      <span data-testid="finding-fixed-in" className="code-3">
                        {fix}
                      </span>
                    )}
                  </td>
                  <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                    <time data-testid="finding-last-seen" dateTime={lastSeen.iso} title={lastSeen.iso}>
                      {lastSeen.text}
                    </time>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </section>
    </>
  );
}
