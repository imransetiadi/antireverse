import type { Advisory, Build, Finding, PatchSummary } from "@antireverse/protocol";
import Link from "next/link";
import type { ReactNode } from "react";
import { EnvironmentTag } from "@/components/environment-tag.tsx";
import { Icon } from "@/components/icons.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { SeverityBadge } from "@/components/severity-badge.tsx";
import { FindingPatch } from "@/features/patches/finding-patch.tsx";
import { patchForFinding } from "@/features/patches/query.ts";
import { formatDateTime } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { FindingActions } from "./finding-actions.tsx";
import { affectedRanges, osvUrl, packageLabel, suggestedFix } from "./format.ts";
import { FindingStatusTag } from "./status-tag.tsx";

interface FindingDetailProps {
  finding: Finding;
  /** The advisory as the API returned it with the Finding: summary, aliases, affected ranges, fixes. */
  advisory: Advisory;
  appName: string;
  /** The Build a build Finding was found in, when it could be read; null otherwise (the id is shown then). */
  build: Build | null;
  /** True when the address asks for the ignore step. */
  confirmIgnore: boolean;
  /**
   * The virtual patches of the Finding's App and Environment (slice 20); null when they could not be read.
   * Default: none.
   */
  patches?: readonly PatchSummary[] | null | undefined;
  /** True when the address asks for the step that enforces the Finding's patch. */
  confirmEnforce?: boolean | undefined;
  /** The render time, in ms. */
  now: number;
}

const SECTION = "flex flex-col gap-3";
const SECTION_TITLE = "heading-4";
const TERM = "caption-1 text-fg-muted";
const DATA = "code-3";

function Fact({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col items-start gap-1">
      <dt className={TERM}>{term}</dt>
      {children}
    </div>
  );
}

function Time({ iso, testId }: { iso: string; testId?: string }) {
  const time = formatDateTime(iso);
  return (
    <time data-testid={testId} dateTime={time.iso} title={time.iso} className={DATA}>
      {t("finding.time.utc", { time: time.text })}
    </time>
  );
}

/** Where the component was found: the Build (by version when it was read, else by id), or a running server. */
function WhereFound({ finding, build }: { finding: Finding; build: Build | null }) {
  if (finding.build_id === null) {
    return (
      <dd data-testid="fact-where" className="break-words">
        {t("finding.source.runtime.in", { environment: finding.environment })}
      </dd>
    );
  }
  const known = build !== null && build.build_id === finding.build_id ? build : null;
  return (
    <dd data-testid="fact-where" className="flex min-w-0 flex-col gap-0.5">
      <Link
        href={ROUTES.build(finding.app_id, finding.build_id)}
        data-testid="fact-build-link"
        className={known === null ? `${DATA} break-all` : "break-words"}
      >
        {known === null ? finding.build_id : t("builds.for", { version: known.version })}
      </Link>
      {known === null ? null : (
        <span data-testid="fact-build-id" className={`${DATA} break-all text-fg-muted`}>
          {finding.build_id}
        </span>
      )}
    </dd>
  );
}

/** Why, until when and with which admin key an ignored Finding is ignored. */
function IgnoreFacts({ finding }: { finding: Finding }) {
  if (finding.ignore === null) return null;
  return (
    <dl
      data-testid="finding-ignore-facts"
      className="grid grid-cols-1 gap-x-6 gap-y-3 rounded-card border border-border border-dashed bg-surface p-3 sm:grid-cols-3"
    >
      <Fact term={t("finding.ignored.reason")}>
        <dd data-testid="finding-ignore-reason" className="break-words">
          {finding.ignore.reason}
        </dd>
      </Fact>
      <Fact term={t("finding.ignored.until")}>
        <dd>
          <Time iso={finding.ignore.until} testId="finding-ignore-until" />
        </dd>
      </Fact>
      <Fact term={t("finding.ignored.by")}>
        <dd data-testid="finding-ignore-by" className={`${DATA} break-all`}>
          {finding.ignore.by}
        </dd>
      </Fact>
    </dl>
  );
}

/**
 * One Finding: the advisory's severity, id and summary; the actions (Ignore with a reason and an end date, or
 * Reopen); the facts (package, development dependency, App, Environment, where it was found, first and last
 * seen, aliases); the affected versions; and the fix. The advisory's own page is a plain link to osv.dev —
 * the Console never looks anything up there itself.
 */
export function FindingDetail({
  finding,
  advisory,
  appName,
  build,
  confirmIgnore,
  patches = [],
  confirmEnforce = false,
  now,
}: FindingDetailProps) {
  const { ranges, versions } = affectedRanges(advisory, finding.package);
  const fix = suggestedFix(finding);

  return (
    <>
      <PageHeader
        eyebrow={
          <Link href={ROUTES.findings()} data-testid="finding-back">
            {t("findings.title")}
          </Link>
        }
        title={finding.advisory_id}
        tags={
          <>
            <SeverityBadge severity={finding.severity} testId="finding-severity" />
            <FindingStatusTag status={finding.status} />
          </>
        }
      />
      <div className="flex flex-col gap-2">
        {finding.summary === "" ? null : (
          <p data-testid="finding-summary" className="break-words body-3">
            {finding.summary}
          </p>
        )}
        <p>
          <a
            href={osvUrl(finding.advisory_id)}
            target="_blank"
            rel="noreferrer noopener"
            data-testid="finding-osv-link"
            className="inline-flex items-center gap-1"
          >
            {t("finding.osv")}
            <Icon name="arrow-square-out" />
            <span className="sr-only"> {t("finding.osv.newTab")}</span>
          </a>
        </p>
      </div>

      <section aria-labelledby="finding-actions-title" className={SECTION}>
        <h2 id="finding-actions-title" className={SECTION_TITLE}>
          {t("finding.actions")}
        </h2>
        <IgnoreFacts finding={finding} />
        <FindingActions finding={finding} appName={appName} confirmIgnore={confirmIgnore} now={now} />
      </section>

      <section aria-labelledby="finding-patch-title" data-testid="finding-patch" className={SECTION}>
        <h2 id="finding-patch-title" className={SECTION_TITLE}>
          {t("patch.title")}
        </h2>
        <p data-testid="patch-note" className="text-fg-muted">
          {t("patch.note")}
        </p>
        {patches === null ? (
          <p data-testid="patch-unavailable">{t("patch.unavailable")}</p>
        ) : (
          <FindingPatch
            finding={finding}
            appName={appName}
            patch={patchForFinding(patches, finding)}
            confirmEnforce={confirmEnforce}
          />
        )}
      </section>

      <section aria-labelledby="finding-facts-title" className={SECTION}>
        <h2 id="finding-facts-title" className={SECTION_TITLE}>
          {t("finding.facts")}
        </h2>
        <dl
          data-testid="finding-facts"
          className="grid grid-cols-1 gap-x-6 gap-y-3 rounded-card border border-border bg-surface p-3 sm:grid-cols-2 lg:grid-cols-4"
        >
          <Fact term={t("finding.fact.package")}>
            <dd data-testid="fact-package" className={`${DATA} break-all`}>
              {packageLabel(finding)}
            </dd>
          </Fact>
          <Fact term={t("finding.fact.dev")}>
            <dd data-testid="fact-dev">{t(finding.dev ? "finding.fact.dev.yes" : "finding.fact.dev.no")}</dd>
          </Fact>
          <Fact term={t("finding.fact.app")}>
            <dd data-testid="fact-app" className="break-words">
              {appName}
            </dd>
          </Fact>
          <Fact term={t("finding.fact.environment")}>
            <dd>
              <EnvironmentTag environment={finding.environment} />
            </dd>
          </Fact>
          <Fact term={t("finding.fact.where")}>
            <WhereFound finding={finding} build={build} />
          </Fact>
          <Fact term={t("finding.fact.firstSeen")}>
            <dd>
              <Time iso={finding.first_seen} testId="fact-first-seen" />
            </dd>
          </Fact>
          <Fact term={t("finding.fact.lastSeen")}>
            <dd>
              <Time iso={finding.last_seen} testId="fact-last-seen" />
            </dd>
          </Fact>
          <Fact term={t("finding.fact.aliases")}>
            <dd data-testid="fact-aliases" className="flex min-w-0 flex-wrap gap-x-2">
              {finding.aliases.length === 0
                ? t("finding.fact.none")
                : finding.aliases.map((alias) => (
                    <span key={alias} data-testid="fact-alias" className={`${DATA} break-all`}>
                      {alias}
                    </span>
                  ))}
            </dd>
          </Fact>
        </dl>
      </section>

      <section aria-labelledby="finding-affected-title" className={`${SECTION} max-w-xl`}>
        <h2 id="finding-affected-title" className={SECTION_TITLE}>
          {t("finding.affected")}
        </h2>
        {ranges.length === 0 && versions.length === 0 ? (
          <p className="text-fg-muted">{t("finding.affected.none")}</p>
        ) : (
          <ul data-testid="finding-ranges" className="flex list-none flex-col ps-0">
            {ranges.map((range) => (
              <li key={range ?? "all"} data-testid="finding-range" className="border-border border-b py-2 code-3">
                {range ?? t("finding.affected.all")}
              </li>
            ))}
            {versions.length === 0 ? null : (
              <li data-testid="finding-listed-versions" className="break-words border-border border-b py-2 code-3">
                {t("finding.affected.versions", { versions: versions.join(", ") })}
              </li>
            )}
          </ul>
        )}
      </section>

      <section aria-labelledby="finding-fix-title" className={`${SECTION} max-w-xl`}>
        <h2 id="finding-fix-title" className={SECTION_TITLE}>
          {t("finding.fix")}
        </h2>
        {fix === null ? (
          <p data-testid="finding-fix-none" className="text-fg-muted">
            {t("finding.fix.none")}
          </p>
        ) : (
          <p data-testid="finding-fix-suggestion" className="heading-6">
            {t("finding.fix.suggestion", { version: fix })}
          </p>
        )}
        {finding.fixed_versions.length === 0 ? null : (
          <div className="flex flex-col gap-1">
            <span className={TERM}>{t("finding.fix.versions")}</span>
            <ul className="flex list-none flex-wrap gap-2 ps-0">
              {finding.fixed_versions.map((version) => (
                <li
                  key={version}
                  data-testid="finding-fixed-version"
                  className="rounded-control border border-border px-2 code-3"
                >
                  {version}
                </li>
              ))}
            </ul>
          </div>
        )}
      </section>
    </>
  );
}
