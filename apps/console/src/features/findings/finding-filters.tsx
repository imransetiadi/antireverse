import { FINDING_SEVERITIES, FINDING_SOURCES, FINDING_STATUSES } from "@antireverse/protocol";
import Link from "next/link";
import { type MessageKey, t } from "@/lib/t.ts";
import { SEVERITY_LABEL, SOURCE_LABEL, STATUS_LABEL } from "./labels.ts";
import type { FindingQuery } from "./query.ts";

// The current filter is carried by `aria-current`, a solid bar under the word and its weight — not by colour.
const TAB =
  "press -mb-px inline-flex h-8 items-center border-b-2 px-3 no-underline pointer-coarse:h-12 pointer-coarse:px-4 hover:text-fg";
const CURRENT = "border-primary heading-6 text-fg";
const OTHER = "border-transparent title-4 text-fg-muted";

type Dimension = "severity" | "status" | "source";

const GROUPS: ReadonlyArray<{
  dimension: Dimension;
  label: MessageKey;
  options: ReadonlyArray<{ value: string; label: MessageKey }>;
}> = [
  {
    dimension: "severity",
    label: "findings.filter.severity",
    options: FINDING_SEVERITIES.map((value) => ({ value, label: SEVERITY_LABEL[value] })),
  },
  {
    dimension: "status",
    label: "findings.filter.status",
    options: FINDING_STATUSES.map((value) => ({ value, label: STATUS_LABEL[value] })),
  },
  {
    dimension: "source",
    label: "findings.filter.source",
    options: FINDING_SOURCES.map((value) => ({ value, label: SOURCE_LABEL[value] })),
  },
];

interface FindingFiltersProps {
  query: FindingQuery;
  /** The list address for a query: the Organization's list or one App's. */
  href: (query: FindingQuery) => string;
}

/**
 * Severity, status and source, each as a row of links: All and every value. The filters live in the address
 * (UIUX.md §5); each link changes its own filter and keeps the others, the advisory and the Build among them.
 */
export function FindingFilters({ query, href }: FindingFiltersProps) {
  return (
    <div className="flex flex-col gap-2">
      {GROUPS.map(({ dimension, label, options }) => {
        const current = query[dimension];
        return (
          <nav key={dimension} aria-label={t(label)} className="flex flex-wrap gap-1 border-border border-b">
            {[{ value: undefined, label: "findings.filter.all" as MessageKey }, ...options].map((option) => (
              <Link
                key={option.value ?? "all"}
                href={href({ ...query, [dimension]: option.value })}
                aria-current={option.value === current ? "page" : undefined}
                data-testid={`finding-filter-${dimension}-${option.value ?? "all"}`}
                className={`${TAB} ${option.value === current ? CURRENT : OTHER}`}
              >
                {t(option.label)}
              </Link>
            ))}
          </nav>
        );
      })}
    </div>
  );
}
