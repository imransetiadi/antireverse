import { INCIDENT_STATUSES, type IncidentStatus } from "@antireverse/protocol";
import Link from "next/link";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { STATUS_LABEL } from "./status-tag.tsx";

// The current filter is carried by `aria-current`, a solid bar under the word and its weight — not by colour.
const TAB =
  "press -mb-px inline-flex h-8 items-center border-b-2 px-3 no-underline pointer-coarse:h-12 pointer-coarse:px-4 hover:text-fg";
const CURRENT = "border-primary heading-6 text-fg";
const OTHER = "border-transparent title-4 text-fg-muted";

const FILTERS: ReadonlyArray<{ id: "all" | IncidentStatus; status: IncidentStatus | undefined }> = [
  { id: "all", status: undefined },
  ...INCIDENT_STATUSES.map((status) => ({ id: status, status })),
];

/** All · Open · Acknowledged · Resolved, as links: the filter lives in the address (UIUX.md §5). */
export function StatusFilter({ current }: { current: IncidentStatus | undefined }) {
  return (
    <nav aria-label={t("incidents.filter")} className="flex flex-wrap gap-1 border-border border-b">
      {FILTERS.map(({ id, status }) => (
        <Link
          key={id}
          href={ROUTES.incidents(status)}
          aria-current={status === current ? "page" : undefined}
          data-testid={`incident-filter-${id}`}
          className={`${TAB} ${status === current ? CURRENT : OTHER}`}
        >
          {status === undefined ? t("incidents.filter.all") : t(STATUS_LABEL[status])}
        </Link>
      ))}
    </nav>
  );
}
