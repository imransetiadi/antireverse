import type { Environment, PatchSummary } from "@antireverse/protocol";
import Link from "next/link";
import { EmptyState } from "@/components/empty-state.tsx";
import { CELL, DATA, HEAD, STICKY } from "@/features/policy/table.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { NotShippedTag, PatchModeChip } from "./mode-chip.tsx";

const COLUMNS = [
  "policy.patches.col.patch",
  "policy.patches.col.mode",
  "policy.patches.col.hits",
  "policy.patches.col.finding",
] as const;

interface PolicyPatchesProps {
  environment: Environment;
  /** Every patch of the catalog for this App and Environment; null when they could not be read. */
  patches: readonly PatchSummary[] | null;
}

/**
 * The virtual patches active in this App and Environment (slice 20), with their mode, hits in 24 h and a link to
 * the Finding that activates them, where the mode is changed. Read only: nothing is sent from here.
 */
export function PolicyPatches({ environment, patches }: PolicyPatchesProps) {
  if (patches === null) {
    return <p data-testid="policy-patches-unavailable">{t("patch.unavailable")}</p>;
  }
  const active = patches.filter((patch) => patch.active);
  if (active.length === 0) {
    return (
      <div data-testid="policy-patches-none">
        <EmptyState>{t("policy.patches.none", { environment })}</EmptyState>
      </div>
    );
  }
  const caption = t("policy.patches.caption", { environment });
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
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {active.map((patch) => (
            <tr
              key={patch.id}
              data-testid="policy-patch-row"
              data-patch-id={patch.id}
              className="border-border border-b"
            >
              <th scope="row" className={`${CELL} ${STICKY} min-w-48 text-start`}>
                <span className="flex min-w-0 flex-col gap-0.5">
                  <span data-testid="patch-title" className="break-words body-4">
                    {patch.title}
                  </span>
                  <span className="break-all code-3 text-fg-muted">{patch.id}</span>
                </span>
              </th>
              <td className={CELL}>
                <span className="flex flex-wrap items-center gap-2">
                  <PatchModeChip mode={patch.mode} />
                  {patch.shipped ? null : <NotShippedTag />}
                </span>
              </td>
              <td data-testid="patch-hits" className={DATA}>
                {patch.hits_24h}
              </td>
              <td className={CELL}>
                <span className="flex flex-wrap gap-x-3 gap-y-1">
                  {patch.findings.map((findingId, index) => (
                    <Link key={findingId} href={ROUTES.finding(findingId)} data-testid="patch-finding-link">
                      {patch.findings.length === 1
                        ? t("policy.patches.finding")
                        : t("policy.patches.finding.n", { n: index + 1 })}
                    </Link>
                  ))}
                </span>
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </section>
  );
}
