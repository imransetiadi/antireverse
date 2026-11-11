import { type Build, FINDING_SEVERITIES, type Finding } from "@antireverse/protocol";
import Link from "next/link";
import { SeverityBadge } from "@/components/severity-badge.tsx";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";

interface BuildFindingsProps {
  build: Build;
  /** The Build's Findings as the API filtered them (`build_id`); null when they could not be read. */
  findings: readonly Finding[] | null;
}

/**
 * The Findings of one Build (slice 19): how many components its lockfile listed, its open Findings counted by
 * severity (each as a badge and a number, never colour alone), and a link to its Findings in the list.
 */
export function BuildFindings({ build, findings }: BuildFindingsProps) {
  const open = (findings ?? []).filter((finding) => finding.build_id === build.build_id && finding.status === "open");
  return (
    <section
      aria-labelledby="build-findings-title"
      className="flex max-w-xl flex-col gap-3"
      data-testid="build-findings"
    >
      <h2 id="build-findings-title" className="heading-4">
        {t("build.findings")}
      </h2>
      <p
        data-testid="build-components"
        className={build.component_count === undefined ? "text-fg-muted" : "code-3 text-fg"}
      >
        {build.component_count === undefined
          ? t("build.components.none")
          : t("build.components", { count: build.component_count })}
      </p>
      {findings === null ? (
        <p data-testid="build-findings-unavailable" className="text-fg-muted">
          {t("build.findings.unavailable")}
        </p>
      ) : (
        <>
          <span id="build-findings-open" className="caption-1 text-fg-muted">
            {t("build.findings.open")}
          </span>
          <ul aria-labelledby="build-findings-open" className="flex list-none flex-wrap gap-3 ps-0">
            {FINDING_SEVERITIES.map((severity) => (
              <li
                key={severity}
                data-testid="build-findings-count"
                data-severity={severity}
                className="inline-flex items-center gap-2"
              >
                <SeverityBadge severity={severity} testId="build-findings-severity" />
                <span className="code-3">{open.filter((finding) => finding.severity === severity).length}</span>
              </li>
            ))}
          </ul>
          {open.length === 0 ? (
            <p data-testid="build-findings-none" className="text-fg-muted">
              {t("build.findings.none")}
            </p>
          ) : null}
        </>
      )}
      <Link
        href={ROUTES.appFindings(build.app_id, { build: build.build_id })}
        data-testid="build-findings-link"
        className="self-start"
      >
        {t("build.findings.link")}
      </Link>
    </section>
  );
}
