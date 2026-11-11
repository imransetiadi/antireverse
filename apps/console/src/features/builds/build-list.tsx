import type { Build } from "@antireverse/protocol";
import Link from "next/link";
import { EmptyState } from "@/components/empty-state.tsx";
import { formatDateTime, formatOverhead } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { ProfileTag } from "./profile-tag.tsx";

const COLUMNS = [
  "build.col.version",
  "build.col.profile",
  "build.col.equivalence",
  "build.col.size",
  "build.col.run",
  "build.col.canaries",
  "build.col.created",
] as const;

const HEAD = "h-10 px-3 text-start caption-1 text-fg-muted whitespace-nowrap";
const CELL = "h-10 px-3 py-2 align-middle";
const DATA = `${CELL} code-3 whitespace-nowrap`;

/** The equivalence result of a Build: a word, never colour alone. */
function Equivalence({ result }: { result: Build["equivalence"] }) {
  const tone = result === "passed" ? "text-fg" : "text-fg-muted";
  return (
    <span data-testid="build-equivalence" data-equivalence={result} className={tone}>
      {t(result === "passed" ? "build.equivalence.passed" : "build.equivalence.skipped")}
    </span>
  );
}

/**
 * The Builds of one App, newest first (the API returns them in that order). Each row links to the Build.
 * An empty list says what will appear and how to make it appear.
 */
export function BuildList({ appId, appName, builds }: { appId: string; appName: string; builds: readonly Build[] }) {
  if (builds.length === 0) {
    return (
      <EmptyState>
        <span data-testid="builds-empty">{t("builds.empty")}</span>
      </EmptyState>
    );
  }
  const caption = t("builds.caption", { app: appName });
  return (
    <section aria-label={caption} className="overflow-x-auto">
      <table className="w-full border-collapse text-start body-5">
        <caption className="sr-only">{caption}</caption>
        <thead>
          <tr className="border-border border-b">
            {COLUMNS.map((column) => (
              <th key={column} scope="col" className={HEAD}>
                {t(column)}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {builds.map((build) => {
            const created = formatDateTime(build.created_at);
            return (
              <tr
                key={build.build_id}
                data-testid="build-row"
                data-build-id={build.build_id}
                className="border-border border-b"
              >
                <th scope="row" className={`${CELL} text-start body-5`}>
                  <Link
                    href={ROUTES.build(appId, build.build_id)}
                    aria-label={t("builds.for", { version: build.version })}
                    data-testid="build-link"
                    className="code-3"
                  >
                    {build.version}
                  </Link>
                </th>
                <td className={CELL}>
                  <ProfileTag profile={build.profile} />
                </td>
                <td className={CELL}>
                  <Equivalence result={build.equivalence} />
                </td>
                <td className={DATA} data-testid="build-size">
                  {formatOverhead(build.costs.size_overhead_pct)}
                </td>
                <td className={`${DATA} text-fg-muted`} data-testid="build-run">
                  {build.costs.run_overhead_pct === null
                    ? t("build.cost.none")
                    : formatOverhead(build.costs.run_overhead_pct)}
                </td>
                <td className={DATA} data-testid="build-canaries">
                  {build.canaries === undefined ? t("build.cost.none") : build.canaries.length}
                </td>
                <td className={`${DATA} text-fg-subtle`}>
                  <time dateTime={created.iso} title={created.iso}>
                    {created.text}
                  </time>
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}
