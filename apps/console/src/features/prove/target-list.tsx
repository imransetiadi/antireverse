import { TARGET_LIMITS, type Target } from "@antireverse/protocol";
import Link from "next/link";
import { EmptyState } from "@/components/empty-state.tsx";
import { CELL, DATA, HEAD, STICKY } from "@/features/policy/table.ts";
import { formatDateTime } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { METHOD_LABEL } from "./labels.ts";
import { TargetStatusChip } from "./target-status.tsx";

const COLUMNS = [
  "targets.col.host",
  "targets.col.status",
  "targets.col.method",
  "targets.col.verified",
  "targets.col.checked",
] as const;
const TIMED = new Set<string>(["targets.col.verified", "targets.col.checked"]);

function When({ iso, testId }: { iso: string | null; testId: string }) {
  if (iso === null) {
    return (
      <span data-testid={testId} className="text-fg-subtle">
        {t("targets.never")}
      </span>
    );
  }
  const time = formatDateTime(iso);
  return (
    <time data-testid={testId} dateTime={time.iso} title={time.iso}>
      {time.text}
    </time>
  );
}

/** The Organization's hosts with their status, how they were proven and when they were last checked. */
export function TargetList({ targets }: { targets: readonly Target[] }) {
  const caption = t("targets.caption");
  return (
    <div className="flex flex-col gap-3">
      <p data-testid="targets-count" className="code-3 text-fg-muted">
        {t("targets.count", { count: targets.length, max: TARGET_LIMITS.targetsPerOrganization })}
      </p>
      {targets.length === 0 ? (
        <div data-testid="targets-empty">
          <EmptyState>{t("targets.empty")}</EmptyState>
        </div>
      ) : (
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
                    {TIMED.has(column) ? <span className="text-fg-subtle"> {t("targets.zone")}</span> : null}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {targets.map((target) => (
                <tr
                  key={target.id}
                  data-testid="target-row"
                  data-target-id={target.id}
                  className="border-border border-b"
                >
                  <th scope="row" className={`${DATA} ${STICKY} min-w-40 break-all text-start`}>
                    <Link href={ROUTES.target(target.id)} data-testid="target-host">
                      {target.host}
                    </Link>
                  </th>
                  <td className={`${CELL} min-w-40`}>
                    <div className="flex flex-col items-start gap-1">
                      <TargetStatusChip status={target.status} />
                      {target.status === "lapsed" && target.lapsed_reason !== null ? (
                        <p data-testid="target-lapsed-reason" className="body-5 break-words text-fg-muted">
                          {t("targets.lapsed", { reason: target.lapsed_reason })}
                        </p>
                      ) : null}
                    </div>
                  </td>
                  <td className={`${CELL} whitespace-nowrap`}>
                    <span data-testid="target-method" className={target.method === null ? "text-fg-subtle" : ""}>
                      {t(target.method === null ? "target.method.none" : METHOD_LABEL[target.method])}
                    </span>
                  </td>
                  <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                    <When iso={target.verified_at} testId="target-verified-at" />
                  </td>
                  <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                    <When iso={target.last_checked_at} testId="target-checked-at" />
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </section>
      )}
    </div>
  );
}
