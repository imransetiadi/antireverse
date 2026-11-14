import {
  type Build,
  type Containment,
  DETECTION_RULES,
  type Detection,
  type Incident,
  type StoredEvent,
} from "@antireverse/protocol";
import Link from "next/link";
import { CopyButton } from "@/components/copy-button.tsx";
import { EmptyState } from "@/components/empty-state.tsx";
import { EnvironmentTag } from "@/components/environment-tag.tsx";
import { PageHeader } from "@/components/page-header.tsx";
import { SeverityBadge } from "@/components/severity-badge.tsx";
import { CANARY_KIND_LABEL } from "@/features/builds/canary.ts";
import { ActorList, type IncidentActor } from "@/features/containment/actor-list.tsx";
import { BlockList } from "@/features/containment/block-list.tsx";
import { ContainmentBar } from "@/features/containment/containment-bar.tsx";
import { expiryText } from "@/features/containment/format.ts";
import type { BlockRequest } from "@/features/containment/query.ts";
import { ContainedTag } from "@/features/containment/tags.tsx";
import { ClientNote, EventRow, EventTableHead } from "@/features/live-feed/event-row.tsx";
import { formatDateTime, formatTime } from "@/lib/format.ts";
import { ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { IncidentActions } from "./incident-actions.tsx";
import { IncidentStatusTag } from "./status-tag.tsx";

interface IncidentDetailProps {
  incident: Incident;
  /** As the API returned them. The timeline shows them oldest first (UIUX.md §8: newest last). */
  detections: readonly Detection[];
  /** Events as stored, newest first. */
  evidence: readonly StoredEvent[];
  appName: string;
  /** True when the address asks for the confirmation step of resolving. */
  confirmResolve: boolean;
  /**
   * For a Canary, clone or Tampered Build Incident: the Build it names, as the API returned it, which gives the
   * Canary's kind, the Build's version and (slice 21a) the registered hash of the tampered file. Null when it
   * could not be read: the facts then show the ids only.
   */
  canaryBuild?: Build | null;
  /** The keyed address hashes in the evidence with their request counts (slice 09). */
  actors: readonly IncidentActor[];
  /** The blocks created from the Incident, newest first. */
  containments: readonly Containment[];
  /** The time of the render, in ms: the confirmation states the expiry from it. */
  now: number;
  /** The block the address asks to confirm, if any. */
  block?: BlockRequest | null;
  /** The block whose lifting the address asks to confirm, if any. */
  confirmLiftId?: string | undefined;
  /** Virtual patch titles by id (slice 20), to name the patch of an Event in the evidence. */
  patchTitles?: Readonly<Record<string, string>> | undefined;
}

const SECTION = "flex flex-col gap-3";
const SECTION_TITLE = "heading-4";
const TERM = "caption-1 text-fg-muted";
const DATA = "code-3";

const ruleTitle = (key: string): string => DETECTION_RULES.find((rule) => rule.key === key)?.title ?? key;

function Time({ iso, testId }: { iso: string; testId?: string }) {
  const time = formatDateTime(iso);
  return (
    <time data-testid={testId} dateTime={time.iso} title={time.iso} className={DATA}>
      {t("incident.time.utc", { time: time.text })}
    </time>
  );
}

/** The Build an Incident names, when it was read and is that Build; otherwise null. */
const knownBuild = (buildId: string | null, build: Build | null): Build | null =>
  build !== null && build.build_id === buildId ? build : null;

/**
 * The Build a Canary or clone Incident names, linked: by version with its id when the Build was read, by id
 * alone otherwise. Nothing when the Incident names no Build.
 */
function BuildFact({ appId, buildId, build }: { appId: string; buildId: string | null; build: Build | null }) {
  if (buildId === null) return null;
  const known = knownBuild(buildId, build);
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <dt className={TERM}>{t("incident.fact.build")}</dt>
      <dd className="flex min-w-0 flex-col gap-0.5">
        <Link
          href={ROUTES.build(appId, buildId)}
          data-testid="fact-build-link"
          className={known === null ? `${DATA} break-all` : "break-words"}
        >
          {known === null ? buildId : t("builds.for", { version: known.version })}
        </Link>
        {known === null ? null : (
          <span data-testid="fact-build-id" className={`${DATA} break-all text-fg-muted`}>
            {buildId}
          </span>
        )}
      </dd>
    </div>
  );
}

/**
 * The Canary of a Canary Incident (kind word and id) and the Build it was planted in, linked. The kind and
 * version come from the Build when it was read; without it, the ids alone. Never the Canary's value.
 */
function CanaryFacts({
  appId,
  canaryId,
  buildId,
  build,
}: {
  appId: string;
  canaryId: string;
  buildId: string | null;
  build: Build | null;
}) {
  const kind = knownBuild(buildId, build)?.canaries?.find((canary) => canary.id === canaryId)?.kind;
  return (
    <>
      <div className="flex min-w-0 flex-col gap-1">
        <dt className={TERM}>{t("incident.fact.canary")}</dt>
        <dd data-testid="fact-canary" className="flex min-w-0 flex-wrap items-baseline gap-x-2">
          {kind === undefined ? null : <span data-testid="fact-canary-kind">{t(CANARY_KIND_LABEL[kind])}</span>}
          <span data-testid="fact-canary-id" className={`${DATA} break-all`}>
            {canaryId}
          </span>
        </dd>
      </div>
      <BuildFact appId={appId} buildId={buildId} build={build} />
    </>
  );
}

/**
 * The origin of a clone Incident: plain monospace text that wraps, with a Copy button — never a link, as it
 * names a suspected copy of the App (possibly a phishing site).
 */
function OriginFact({ origin }: { origin: string | null }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <dt className={TERM}>{t("incident.fact.origin")}</dt>
      <dd data-testid="fact-origin" className="flex min-w-0 flex-wrap items-start gap-2">
        <span data-testid="fact-origin-value" className={`${DATA} min-w-0 flex-1 select-all break-all`}>
          {origin ?? t("incident.fact.none")}
        </span>
        {origin === null ? null : <CopyButton value={origin} />}
      </dd>
    </div>
  );
}

/** A SHA-256 for display: its first 12 characters and an ellipsis. The full value goes in `title` and to Copy. */
const shortSha = (sha256: string): string => `${sha256.slice(0, 12)}…`;

/**
 * One hash of a Tampered Build Incident: shortened monospace text with the full value as its title and a Copy
 * button for it; "Not available" when there is none to show.
 */
function HashFact({ label, testId, sha256 }: { label: string; testId: string; sha256: string | null }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <dt className={TERM}>{label}</dt>
      <dd data-testid={testId} className="flex min-w-0 flex-wrap items-start gap-2">
        {sha256 === null ? (
          <span className="text-fg-muted">{t("incident.fact.hash.unavailable")}</span>
        ) : (
          <>
            <span data-testid={`${testId}-value`} title={sha256} className={`${DATA} min-w-0 flex-1 select-all`}>
              {shortSha(sha256)}
            </span>
            <CopyButton value={sha256} />
          </>
        )}
      </dd>
    </div>
  );
}

/**
 * The facts of a Tampered Build Incident (slice 21a): the Build, the file whose bytes changed, the hash the Build
 * registered for it (read from the Build; not available when the Build could not be read or does not list the
 * file) and the hash a browser observed.
 */
function TamperFacts({ incident, build }: { incident: Incident; build: Build | null }) {
  const path = incident.artifact_path ?? null;
  const registered =
    path === null
      ? null
      : (knownBuild(incident.build_id, build)?.artifacts.find((artifact) => artifact.path === path)?.sha256 ?? null);
  return (
    <>
      <BuildFact appId={incident.app_id} buildId={incident.build_id} build={build} />
      <div className="flex min-w-0 flex-col gap-1">
        <dt className={TERM}>{t("incident.fact.file")}</dt>
        <dd data-testid="fact-file" className={`${DATA} break-all`}>
          {path ?? t("incident.fact.none")}
        </dd>
      </div>
      <HashFact label={t("incident.fact.registeredHash")} testId="fact-registered-hash" sha256={registered} />
      <HashFact
        label={t("incident.fact.observedHash")}
        testId="fact-observed-hash"
        sha256={incident.observed_sha256 ?? null}
      />
    </>
  );
}

/**
 * SCR-05: one Incident — its severity, title and status, the containment bar (first: containing is the
 * primary action), the status actions, the facts, its Actors and blocks, the timeline of its Detections and
 * the Events behind it. A clone Incident (slice 10) is about a copy of the App served elsewhere: its facts
 * name the origin and the Build, its timeline is the reports with the reporter's network, and it has no
 * containment, Actors, blocks or Events — a note says where to act instead. A Tampered Build Incident (slice 21a)
 * is about files of a Build that reached browsers changed: its facts name the Build, the file and both hashes, its
 * timeline is the reports with the page's origin (plain text, never a link) and the reporter's network, and it
 * has no containment, Actors, blocks or Events either — a note says why.
 */
export function IncidentDetail({
  incident,
  detections,
  evidence,
  appName,
  confirmResolve,
  canaryBuild = null,
  actors,
  containments,
  now,
  block = null,
  confirmLiftId,
  patchTitles,
}: IncidentDetailProps) {
  const timeline = [...detections].sort((a, b) => a.detected_at.localeCompare(b.detected_at));
  const clone = incident.rule === "clone-origin";
  const tamper = incident.rule === "tampered-build";
  /** Reported from a browser rather than counted from Events: no network of its own, no Actors, no evidence. */
  const reported = clone || tamper;
  const network = incident.ip_prefix ?? t("incident.fact.none");
  const evidenceCaption = t("incident.evidence.caption", { network, app: appName });

  return (
    <>
      <PageHeader
        // A breadcrumb back to the list. Not the identifier: the eyebrow is set in capitals.
        eyebrow={
          <Link href={ROUTES.incidents()} data-testid="incident-back">
            {t("incidents.title")}
          </Link>
        }
        title={incident.title}
        tags={
          <>
            <SeverityBadge severity={incident.severity} testId="incident-severity" />
            <IncidentStatusTag status={incident.status} />
            {containments.some((containment) => containment.status === "active") ? <ContainedTag /> : null}
          </>
        }
      />

      <section aria-labelledby="incident-contain-title" className={SECTION}>
        <h2 id="incident-contain-title" className={SECTION_TITLE}>
          {t("containment.title")}
        </h2>
        {reported ? (
          <p
            data-testid={tamper ? "containment-tamper-note" : "containment-clone-note"}
            className="rounded-card border border-border bg-surface p-3 text-fg-muted"
          >
            {t(tamper ? "incident.tamper.containment" : "incident.clone.containment")}
          </p>
        ) : (
          <ContainmentBar
            incident={incident}
            appName={appName}
            actors={actors}
            block={block}
            expiry={block === null ? null : expiryText(now, block.ttl)}
          />
        )}
      </section>

      <section aria-labelledby="incident-actions-title" className={SECTION}>
        <h2 id="incident-actions-title" className={SECTION_TITLE}>
          {t("incident.actions")}
        </h2>
        <IncidentActions incident={incident} appName={appName} confirmResolve={confirmResolve} />
      </section>

      <section aria-labelledby="incident-facts-title" className={SECTION}>
        <h2 id="incident-facts-title" className={SECTION_TITLE}>
          {t("incident.facts")}
        </h2>
        <dl
          data-testid="incident-facts"
          className="grid grid-cols-1 gap-x-6 gap-y-3 rounded-card border border-border bg-surface p-3 sm:grid-cols-2 lg:grid-cols-4"
        >
          <div className="flex min-w-0 flex-col gap-1">
            <dt className={TERM}>{t("incident.fact.app")}</dt>
            <dd data-testid="fact-app" className="break-words">
              {appName}
            </dd>
          </div>
          <div className="flex min-w-0 flex-col items-start gap-1">
            <dt className={TERM}>{t("incident.fact.environment")}</dt>
            <dd>
              <EnvironmentTag environment={incident.environment} />
            </dd>
          </div>
          {clone ? (
            <OriginFact origin={incident.origin} />
          ) : tamper ? null : (
            <div className="flex min-w-0 flex-col gap-1">
              <dt className={TERM}>{t("incident.fact.network")}</dt>
              <dd data-testid="fact-network" className={`${DATA} break-all`}>
                {network}
              </dd>
            </div>
          )}
          <div className="flex min-w-0 flex-col gap-1">
            <dt className={TERM}>{t("incident.fact.rule")}</dt>
            <dd data-testid="fact-rule">{ruleTitle(incident.rule)}</dd>
          </div>
          {incident.advisory_id === null ? null : (
            <div className="flex min-w-0 flex-col gap-1">
              <dt className={TERM}>{t("incident.fact.advisory")}</dt>
              <dd>
                {/* A vulnerable component (slice 19) or exploit attempt (slice 20) Incident: its advisory's Findings. */}
                <Link
                  href={ROUTES.findings({ advisory: incident.advisory_id })}
                  data-testid="fact-advisory-link"
                  className={`${DATA} break-all`}
                >
                  {incident.advisory_id}
                </Link>
              </dd>
            </div>
          )}
          {clone ? <BuildFact appId={incident.app_id} buildId={incident.build_id} build={canaryBuild} /> : null}
          {tamper ? <TamperFacts incident={incident} build={canaryBuild} /> : null}
          {incident.canary_id === null ? null : (
            <CanaryFacts
              appId={incident.app_id}
              canaryId={incident.canary_id}
              buildId={incident.build_id}
              build={canaryBuild}
            />
          )}
          <div className="flex min-w-0 flex-col gap-1">
            <dt className={TERM}>{t("incident.fact.firstSeen")}</dt>
            <dd>
              <Time iso={incident.first_seen} testId="fact-first-seen" />
            </dd>
          </div>
          <div className="flex min-w-0 flex-col gap-1">
            <dt className={TERM}>{t("incident.fact.lastSeen")}</dt>
            <dd>
              <Time iso={incident.last_seen} testId="fact-last-seen" />
            </dd>
          </div>
          <div className="flex min-w-0 flex-col gap-1">
            <dt className={TERM}>{t(tamper ? "incident.fact.reports" : "incident.fact.detections")}</dt>
            <dd data-testid="fact-detections" className={DATA}>
              {incident.detection_count}
            </dd>
          </div>
        </dl>
        {/* A cap dropped distinct hashes while this Incident was open: what is listed is not all that was reported. */}
        {tamper && incident.detections_capped === true ? (
          <p data-testid="incident-capped-note" className="body-5 text-fg-muted">
            {t("incident.tamper.capped")}
          </p>
        ) : null}
      </section>

      {reported ? null : (
        <>
          <section aria-labelledby="incident-actors-title" className={SECTION}>
            <h2 id="incident-actors-title" className={SECTION_TITLE}>
              {t("actors.title")}
            </h2>
            <p className="text-fg-muted">{t("actors.lead")}</p>
            <ActorList actors={actors} />
          </section>

          <section aria-labelledby="incident-blocks-title" className={SECTION}>
            <h2 id="incident-blocks-title" className={SECTION_TITLE}>
              {t("blocks.title")}
            </h2>
            <BlockList
              containments={containments}
              appName={appName}
              caption={t("blocks.caption.incident")}
              empty={t("blocks.empty")}
              base={ROUTES.incident(incident.id)}
              returnTo={{ incidentId: incident.id }}
              confirmLiftId={confirmLiftId}
            />
          </section>
        </>
      )}

      <section aria-labelledby="incident-timeline-title" className={SECTION}>
        <h2 id="incident-timeline-title" className={SECTION_TITLE}>
          {t("incident.timeline")}
        </h2>
        {timeline.length === 0 ? (
          <p className="text-fg-muted">{t("incident.detection.none")}</p>
        ) : (
          <ol data-testid="incident-timeline" className="flex list-none flex-col ps-0">
            {timeline.map((detection) => (
              <li
                key={detection.id}
                data-testid="detection-item"
                data-detection-id={detection.id}
                className="relative flex flex-col gap-0.5 py-2 ps-6"
              >
                {/* The rail: a drawn 2 px line, not a border, centred under the markers. */}
                <span aria-hidden="true" className="absolute inset-y-0 start-1 ms-px w-0.5 bg-border" />
                {/* A filled dot marks a system action (UIUX.md §8 Timeline). */}
                <span
                  aria-hidden="true"
                  className="absolute start-0 top-3 inline-block size-3 rounded-full bg-fg-muted"
                />
                <span className="title-4">{t("incident.detection.title", { rule: ruleTitle(detection.rule) })}</span>
                <span data-testid="detection-time" className={`${DATA} text-fg-muted`}>
                  {t("incident.detection.at", { time: formatDateTime(detection.detected_at).text })}
                </span>
                {tamper ? (
                  <>
                    <span className="flex flex-wrap items-baseline gap-x-2 body-5 text-fg-muted">
                      <span>{t("incident.detection.file")}</span>
                      <span data-testid="detection-file" className={`${DATA} break-all`}>
                        {detection.artifact_path ?? t("incident.fact.none")}
                      </span>
                    </span>
                    <span className="flex flex-wrap items-baseline gap-x-2 body-5 text-fg-muted">
                      <span>{t("incident.detection.observed")}</span>
                      {(detection.observed_sha256 ?? null) === null ? (
                        <span>{t("incident.fact.none")}</span>
                      ) : (
                        <span
                          data-testid="detection-observed"
                          title={detection.observed_sha256 ?? undefined}
                          className={DATA}
                        >
                          {shortSha(detection.observed_sha256 ?? "")}
                        </span>
                      )}
                    </span>
                    {/* The page's origin: plain text, never a link — a report can name any origin. */}
                    <span className="flex flex-wrap items-baseline gap-x-2 body-5 text-fg-muted">
                      <span>{t("incident.detection.origin")}</span>
                      <span data-testid="detection-origin" className={`${DATA} select-all break-all`}>
                        {detection.origin ?? t("incident.fact.none")}
                      </span>
                    </span>
                  </>
                ) : null}
                {reported ? (
                  <span className="flex flex-wrap items-baseline gap-x-2 body-5 text-fg-muted">
                    <span>{t("incident.detection.reporter")}</span>
                    <span data-testid="detection-reporter" className={`${DATA} break-all`}>
                      {detection.ip_prefix ?? t("incident.detection.reporter.unknown")}
                    </span>
                  </span>
                ) : (
                  <span className="body-5 text-fg-muted">
                    {t("incident.detection.window", {
                      count: detection.count,
                      start: formatTime(detection.window_start).text,
                      end: formatTime(detection.window_end).text,
                    })}
                  </span>
                )}
              </li>
            ))}
          </ol>
        )}
      </section>

      {reported ? null : (
        <section aria-labelledby="incident-evidence-title" data-testid="incident-evidence" className={SECTION}>
          <h2 id="incident-evidence-title" className={SECTION_TITLE}>
            {t("incident.evidence")}
          </h2>
          <p className="text-fg-muted">{t("incident.evidence.lead")}</p>
          {/* Slice 18c: the retention job removes old Events; a static note, so the page makes no extra request. */}
          <p data-testid="evidence-retention" className="max-w-3xl body-5 text-fg-muted">
            {t("incident.evidence.retention")}
            <Link href={ROUTES.dataControls()} prefetch={false}>
              {t("incident.evidence.retention.link")}
            </Link>
            .
          </p>
          {evidence.length === 0 ? (
            <div data-testid="evidence-empty">
              <EmptyState>{t("incident.evidence.none")}</EmptyState>
            </div>
          ) : (
            <>
              <ClientNote />
              <section
                aria-label={evidenceCaption}
                // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
                tabIndex={0}
                className="overflow-x-auto"
              >
                <table className="w-full border-collapse body-5">
                  <caption className="sr-only">{evidenceCaption}</caption>
                  <EventTableHead />
                  <tbody>
                    {evidence.map((event) => (
                      <EventRow key={event.event_id} event={event} patchTitles={patchTitles} />
                    ))}
                  </tbody>
                </table>
              </section>
            </>
          )}
        </section>
      )}
    </>
  );
}
