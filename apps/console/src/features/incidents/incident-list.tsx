import type { Incident, IncidentStatus } from "@antireverse/protocol";
import Link from "next/link";
import { EmptyState } from "@/components/empty-state.tsx";
import { SeverityBadge } from "@/components/severity-badge.tsx";
import { ContainedTag } from "@/features/containment/tags.tsx";
import { CELL, DATA, HEAD, STICKY } from "@/features/policy/table.ts";
import { formatDateTime } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { IncidentStatusTag, STATUS_LABEL } from "./status-tag.tsx";

const COLUMNS = [
  "incidents.col.severity",
  "incidents.col.title",
  "incidents.col.app",
  "incidents.col.status",
  "incidents.col.lastSeen",
] as const;

interface IncidentListProps {
  /** As the API returned them: newest first by last seen. */
  incidents: readonly Incident[];
  /** App id → App name. An App that is not in it is shown by its id. */
  appNames: ReadonlyMap<string, string>;
  /** The status filter of the address, if any: an empty list then says so and offers to clear it. */
  status: IncidentStatus | undefined;
  caption?: string | undefined;
  /**
   * The ids of the Incidents with an active block: their rows carry the Contained marker. Null when the
   * blocks could not be loaded — the list then says the marker is missing rather than showing none.
   */
  contained?: ReadonlySet<string> | null;
}

const NONE: ReadonlySet<string> = new Set();

/** SCR-04: the Incidents of the Organization, one row each, linking to the Incident page. */
export function IncidentList({
  incidents,
  appNames,
  status,
  caption = t("incidents.title"),
  contained = NONE,
}: IncidentListProps) {
  if (incidents.length === 0) {
    return (
      <div data-testid="incidents-empty">
        {status === undefined ? (
          <EmptyState action={<Link href={ROUTES.alerts()}>{t("incidents.empty.action")}</Link>}>
            {t("incidents.empty")}
          </EmptyState>
        ) : (
          <EmptyState action={<Link href={ROUTES.incidents()}>{t("incidents.filter.clear")}</Link>}>
            {t("incidents.empty.filtered", { status: t(STATUS_LABEL[status]) })}
          </EmptyState>
        )}
      </div>
    );
  }

  return (
    <>
      {contained === null ? (
        <p role="status" data-testid="incidents-contained-unknown" className="body-5 text-fg-muted">
          {t("incidents.contained.unknown")}
        </p>
      ) : null}
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
                  {column === "incidents.col.lastSeen" ? (
                    <span className="text-fg-subtle"> {t("incidents.col.zone")}</span>
                  ) : null}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {incidents.map((incident) => {
              const lastSeen = formatDateTime(incident.last_seen);
              const isContained = contained?.has(incident.id) === true;
              return (
                <tr
                  key={incident.id}
                  data-testid="incident-row"
                  data-incident-id={incident.id}
                  data-status={incident.status}
                  data-severity={incident.severity}
                  data-contained={isContained}
                  className="border-border border-b"
                >
                  <td className={`${CELL} ${STICKY} whitespace-nowrap`}>
                    <SeverityBadge severity={incident.severity} />
                  </td>
                  <th scope="row" className={`${CELL} min-w-40 break-words text-start body-4`}>
                    <span className="flex flex-wrap items-center gap-2">
                      <Link href={ROUTES.incident(incident.id)} data-testid="incident-link">
                        {incident.title}
                      </Link>
                      {isContained ? <ContainedTag /> : null}
                    </span>
                    {/* A clone Incident names the origin of the copy: plain text, never a link. */}
                    {incident.origin === null ? null : (
                      <span data-testid="incident-origin" className="mt-0.5 block break-all code-3 text-fg-muted">
                        {incident.origin}
                      </span>
                    )}
                  </th>
                  <td data-testid="incident-app" className={`${CELL} min-w-32 break-words`}>
                    {appNames.get(incident.app_id) ?? <span className="code-3">{incident.app_id}</span>}
                  </td>
                  <td className={`${CELL} whitespace-nowrap`}>
                    <IncidentStatusTag status={incident.status} />
                  </td>
                  <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                    <time data-testid="incident-last-seen" dateTime={lastSeen.iso} title={lastSeen.iso}>
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
