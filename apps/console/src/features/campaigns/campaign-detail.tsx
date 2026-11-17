import {
  CAMPAIGN_LIMITS,
  type Campaign,
  type CampaignFinding,
  type CampaignReport,
  type CampaignRequest,
  campaignChecksSentence,
} from "@antireverse/protocol";
import Link from "next/link";
import type { ReactNode } from "react";
import { buttonClass } from "@/components/button.tsx";
import { Card } from "@/components/card.tsx";
import { Icon } from "@/components/icons.tsx";
import { SeverityBadge } from "@/components/severity-badge.tsx";
import { CELL, DATA, HEAD } from "@/features/policy/table.ts";
import { formatBytes, formatDateTime, formatLatency } from "@/lib/format.ts";
import { type CampaignNotice as PageNotice, ROUTES } from "@/lib/routes.ts";
import { t } from "@/lib/t.ts";
import { AutoRefresh } from "./auto-refresh.tsx";
import { CampaignNotice, EngineTag } from "./campaign-notice.tsx";
import { CampaignStatusChip, FindingStateChip } from "./campaign-status.tsx";
import { endReasonText, isActive, LOCATION_LABEL, REFUSAL_LABEL, SEND_FAILURE_LABEL } from "./labels.ts";
import { StopCampaign } from "./stop-campaign.tsx";

/** How often the page of a queued or running Campaign reads its data again. */
export const REFRESH_SECONDS = 5;

const SECTION = "flex flex-col gap-3";
const SECTION_TITLE = "heading-4";
const MONO = "code-3 break-all";

function Fact({ term, children }: { term: string; children: ReactNode }) {
  return (
    <div className="flex min-w-0 flex-col gap-1">
      <dt className="caption-1 text-fg-muted">{term}</dt>
      <dd className="min-w-0">{children}</dd>
    </div>
  );
}

function When({ iso, none, testId }: { iso: string | null; none: string; testId?: string }) {
  if (iso === null) {
    return (
      <span data-testid={testId} className="body-5 text-fg-subtle">
        {none}
      </span>
    );
  }
  const time = formatDateTime(iso);
  return (
    <time data-testid={testId} dateTime={time.iso} title={time.iso} className="code-3">
      {time.text}
    </time>
  );
}

/** Why the Campaign is where it is: what it waits for or does, or why it ended, in a plain sentence. */
function whyText(campaign: Campaign): string {
  if (campaign.end_reason !== null) return endReasonText(campaign.end_reason);
  if (campaign.status === "running") return t("campaign.end.active.running", { seconds: REFRESH_SECONDS });
  return t("campaign.end.active.queued");
}

function Facts({ campaign }: { campaign: Campaign }) {
  const { stop } = campaign;
  return (
    <Card>
      <dl data-testid="campaign-facts" className="grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
        <Fact term={t("campaign.fact.status")}>
          <CampaignStatusChip status={campaign.status} />
        </Fact>
        <div className="md:col-span-1 lg:col-span-2">
          <Fact term={t("campaign.fact.why")}>
            <span data-testid="campaign-why" className="body-4 text-fg">
              {whyText(campaign)}
            </span>
          </Fact>
        </div>
        <Fact term={t("campaign.fact.target")}>
          <Link href={ROUTES.target(campaign.target_id)} className={MONO}>
            {campaign.host}
          </Link>
        </Fact>
        <Fact term={t("campaign.fact.intensity")}>
          <span className="code-2">{campaign.intensity}</span>
        </Fact>
        <Fact term={t("campaign.engine")}>
          <EngineTag engine={campaign.engine} />
        </Fact>
        <Fact term={t("campaign.fact.rules")}>
          <span data-testid="campaign-roe" title={campaign.roe_sha256} className={MONO}>
            {campaign.roe_id}
          </span>
        </Fact>
        <Fact term={t("campaign.fact.requests")}>
          <span data-testid="campaign-requests" className="code-3">
            {t("campaigns.requests", { sent: campaign.requests_sent, refused: campaign.requests_refused })}
          </span>
        </Fact>
        <Fact term={t("campaign.fact.bytes")}>
          <span className="code-3">{formatBytes(campaign.response_bytes)}</span>
        </Fact>
        <Fact term={`${t("campaign.fact.created")} ${t("campaigns.zone")}`}>
          <When iso={campaign.created_at} none={t("campaign.fact.never")} />
        </Fact>
        <Fact term={`${t("campaign.fact.started")} ${t("campaigns.zone")}`}>
          <When
            iso={campaign.started_at}
            none={t(isActive(campaign.status) ? "campaign.fact.notYet" : "campaign.fact.never")}
            testId="campaign-started"
          />
        </Fact>
        <Fact term={`${t("campaign.fact.finished")} ${t("campaigns.zone")}`}>
          <When iso={campaign.finished_at} none={t("campaign.fact.notYet")} testId="campaign-finished" />
        </Fact>
        <div className="md:col-span-2 lg:col-span-3">
          <Fact term={t("campaign.fact.staging")}>
            <span data-testid="campaign-staging" className="body-5 break-words text-fg">
              {t("campaign.fact.staging.value", { key: campaign.created_by })}
            </span>
          </Fact>
        </div>
        {stop === null ? null : (
          <div className="md:col-span-2 lg:col-span-3">
            <Fact term={t("campaign.fact.stop")}>
              <span data-testid="campaign-stop-request" className="body-5 break-words text-fg">
                {t("campaign.fact.stop.value", {
                  key: stop.requested_by,
                  time: formatDateTime(stop.requested_at).text,
                  reason: stop.reason,
                })}
              </span>
            </Fact>
          </div>
        )}
      </dl>
    </Card>
  );
}

/**
 * What one Finding rests on, as the gate redacted it. Everything here is text of the tested system: it is rendered as
 * text only — never as HTML and never as a link — and the excerpt sits in a block that scrolls inside itself.
 */
function Evidence({ finding }: { finding: CampaignFinding }) {
  const { evidence } = finding;
  const headers = Object.entries(evidence.headers);
  return (
    <div className="flex flex-col gap-3">
      <p className="body-5 text-fg-muted">{t("campaign.evidence.note")}</p>
      <dl className="grid grid-cols-1 gap-3 md:grid-cols-2">
        <Fact term={t("campaign.evidence.request")}>
          <code data-testid="finding-request" className={MONO}>{`${evidence.method} ${evidence.target}`}</code>
        </Fact>
        <Fact term={t("campaign.evidence.status")}>
          <span data-testid="finding-status" className="code-3">
            {evidence.status}
          </span>
        </Fact>
        {evidence.location === null ? null : (
          <Fact term={t("campaign.evidence.location")}>
            <span data-testid="finding-location" className="body-5 text-fg">
              {t(LOCATION_LABEL[evidence.location])}
            </span>
          </Fact>
        )}
        <Fact term={t("campaign.evidence.hash")}>
          <span data-testid="finding-hash" className={MONO}>
            {evidence.body_sha256}
          </span>
        </Fact>
        <div className="md:col-span-2">
          <Fact term={t("campaign.evidence.headers")}>
            {headers.length === 0 ? (
              <span data-testid="finding-headers" className="body-5 text-fg-muted">
                {t("campaign.evidence.headers.none")}
              </span>
            ) : (
              <ul data-testid="finding-headers" className={`flex list-none flex-col gap-1 ${MONO}`}>
                {headers.map(([name, value]) => (
                  <li key={name}>{`${name}: ${value}`}</li>
                ))}
              </ul>
            )}
          </Fact>
        </div>
      </dl>
      <div className="flex flex-col gap-1">
        <p className="caption-1 text-fg-muted">{t("campaign.evidence.excerpt")}</p>
        {evidence.excerpt.length === 0 ? (
          <p data-testid="finding-excerpt-none" className="body-5 text-fg-muted">
            {t("campaign.evidence.excerpt.none")}
          </p>
        ) : (
          <section
            aria-label={t("campaign.evidence.excerpt.label", { id: finding.check_id })}
            // biome-ignore lint/a11y/noNoninteractiveTabindex: a scrollable region must be reachable by keyboard
            tabIndex={0}
            className="max-h-24 overflow-auto rounded-control border border-border-strong bg-bg px-3 py-2"
          >
            <pre data-testid="finding-excerpt" className="code-3 break-all whitespace-pre-wrap">
              {evidence.excerpt}
            </pre>
          </section>
        )}
        {evidence.truncated ? (
          <p data-testid="finding-truncated" className="body-5 text-fg-muted">
            {t("campaign.evidence.truncated")}
          </p>
        ) : null}
      </div>
    </div>
  );
}

function Findings({ findings, active }: { findings: readonly CampaignFinding[]; active: boolean }) {
  if (findings.length === 0) {
    return (
      <p data-testid="campaign-findings-empty" className="body-4 text-fg-muted">
        {t(active ? "campaign.findings.empty.active" : "campaign.findings.empty.ended")}
      </p>
    );
  }
  return (
    <>
      <p data-testid="campaign-findings-count" className="code-3 text-fg-muted">
        {findings.length === 1
          ? t("campaign.findings.count.one")
          : t("campaign.findings.count", { count: findings.length })}
      </p>
      <ul className="flex list-none flex-col gap-3">
        {findings.map((finding) => (
          <li key={`${finding.check_id}:${finding.path}`}>
            <Card>
              <article
                data-testid="campaign-finding"
                data-check-id={finding.check_id}
                data-severity={finding.severity}
                className="flex flex-col gap-3"
              >
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={finding.severity} />
                  <FindingStateChip state={finding.state} />
                  <span className="code-3 text-fg-muted">{t("campaign.finding.check", { id: finding.check_id })}</span>
                </div>
                <h3 className="break-words heading-6">{finding.title}</h3>
                <p className="body-5 text-fg-muted">
                  {t("campaign.finding.path")} <code className={`${MONO} text-fg`}>{finding.path}</code>
                </p>
                <p className="body-5 text-fg-muted">
                  {t("campaign.finding.seen", {
                    first: formatDateTime(finding.first_seen_at).text,
                    last: formatDateTime(finding.last_seen_at).text,
                  })}
                </p>
                <Evidence finding={finding} />
              </article>
            </Card>
          </li>
        ))}
      </ul>
    </>
  );
}

const REQUEST_COLUMNS = [
  "campaign.requests.col.seq",
  "campaign.requests.col.time",
  "campaign.requests.col.request",
  "campaign.requests.col.outcome",
  "campaign.requests.col.result",
  "campaign.requests.col.bytes",
  "campaign.requests.col.ms",
] as const;

/** What came of a request: its status, why no response came, or why the gate refused the probe. */
function resultText(request: CampaignRequest): string {
  if (request.outcome === "refused") {
    return t("campaign.requests.reason", {
      reason: request.reason === null ? t("campaign.requests.unknown") : t(REFUSAL_LABEL[request.reason]),
    });
  }
  // Slice 15a, second review: the row was written and a stop came before the request went out.
  if (request.outcome === "not_sent") return t("campaign.requests.notSent.result");
  if (request.status !== null) return t("campaign.requests.status", { status: request.status });
  return t("campaign.requests.noResponse", {
    failure: request.failure === null ? t("campaign.requests.unknown") : t(SEND_FAILURE_LABEL[request.failure]),
  });
}

/** Every probe the engine asked for, oldest first: sent with its answer, or refused with the reason. Text only. */
function RequestLog({ requests }: { requests: readonly CampaignRequest[] }) {
  if (requests.length === 0) {
    return (
      <p data-testid="campaign-requests-empty" className="body-4 text-fg-muted">
        {t("campaign.requests.empty")}
      </p>
    );
  }
  const caption = t("campaign.requests.caption");
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
            {REQUEST_COLUMNS.map((column) => (
              <th key={column} scope="col" className={HEAD}>
                {t(column)}
                {column === "campaign.requests.col.time" ? (
                  <span className="text-fg-subtle"> {t("campaigns.zone")}</span>
                ) : null}
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {requests.map((request) => {
            const at = formatDateTime(request.at);
            const refused = request.outcome === "refused";
            return (
              <tr
                key={request.seq}
                data-testid="request-row"
                data-outcome={request.outcome}
                className="border-border border-b"
              >
                <td className={`${DATA} text-fg-muted`}>{request.seq}</td>
                <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                  <time dateTime={at.iso} title={at.iso}>
                    {at.text}
                  </time>
                </td>
                <td data-testid="request-target" className={`${DATA} min-w-40 break-all`}>
                  {`${request.method ?? t("campaign.requests.unknown")} ${request.target ?? ""}`.trim()}
                </td>
                <td className={`${CELL} whitespace-nowrap`}>
                  <span
                    data-testid="request-outcome"
                    className={`inline-flex items-center gap-1 caption-1 ${refused ? "text-sev-medium" : "text-fg"}`}
                  >
                    <Icon name={refused || request.outcome === "not_sent" ? "prohibit" : "check"} />
                    {t(
                      refused
                        ? "campaign.requests.refused"
                        : request.outcome === "not_sent"
                          ? "campaign.requests.notSent"
                          : "campaign.requests.sent",
                    )}
                  </span>
                </td>
                <td data-testid="request-result" className={`${CELL} min-w-40`}>
                  {resultText(request)}
                </td>
                <td className={`${DATA} whitespace-nowrap text-fg-muted`}>{formatBytes(request.bytes)}</td>
                <td className={`${DATA} whitespace-nowrap text-fg-muted`}>
                  {refused ? "" : formatLatency(request.ms)}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </section>
  );
}

function checksText(campaign: Campaign): string {
  if (campaign.checks !== null) return campaignChecksSentence(campaign.checks);
  return t(isActive(campaign.status) ? "campaign.checks.pending" : "campaign.checks.none");
}

interface CampaignViewProps {
  /** The Campaign with its Findings and limits, as the API's report holds them. */
  report: CampaignReport;
  /** Its request log, oldest first. */
  requests: readonly CampaignRequest[];
  /** The address asks to confirm the stop. */
  confirmStop: boolean;
  /** What the page says once after a change. */
  notice?: PageNotice | undefined;
}

/**
 * One Campaign: what it is and is not, its status and why, the Stop button for as long as it is queued or running,
 * its checks, its Findings with redacted evidence, its request log and its report. While it is active the page reads
 * its data again every few seconds — through the router, or through a meta refresh without JavaScript (not while the
 * stop step is open: a reload would empty the reason).
 */
export function CampaignView({ report, requests, confirmStop, notice }: CampaignViewProps) {
  const { campaign } = report;
  const active = isActive(campaign.status);
  return (
    <>
      {active ? <AutoRefresh seconds={REFRESH_SECONDS} /> : null}
      {active && !confirmStop ? (
        <noscript>
          <meta httpEquiv="refresh" content={String(REFRESH_SECONDS)} />
        </noscript>
      ) : null}
      <CampaignNotice engine={report.engine} notice={report.notice} />
      {notice === "ended" ? (
        <p
          role="status"
          data-testid="campaign-notice-ended"
          className="max-w-3xl rounded-card border border-border p-3"
        >
          {t("campaign.notice.ended")}
        </p>
      ) : null}
      {notice === "report-failed" ? (
        <p
          role="alert"
          data-testid="campaign-notice-report"
          className="max-w-3xl rounded-card border border-sev-medium p-3"
        >
          {t("campaign.notice.reportFailed")}
        </p>
      ) : null}

      <section aria-labelledby="campaign-facts-title" className={SECTION}>
        <h2 id="campaign-facts-title" className={SECTION_TITLE}>
          {t("campaign.facts")}
        </h2>
        <Facts campaign={campaign} />
        {active ? (
          <>
            <StopCampaign campaign={{ id: campaign.id, host: campaign.host }} confirmStop={confirmStop} />
            <div>
              <Link href={ROUTES.campaign(campaign.id)} prefetch={false} data-testid="campaign-refresh">
                {t("campaign.refresh")}
              </Link>
            </div>
          </>
        ) : null}
      </section>

      <section aria-labelledby="campaign-checks-title" className={SECTION}>
        <h2 id="campaign-checks-title" className={SECTION_TITLE}>
          {t("campaign.checks.title")}
        </h2>
        <p data-testid="campaign-checks" className="body-4 text-fg">
          {checksText(campaign)}
        </p>
      </section>

      <section aria-labelledby="campaign-findings-title" className={SECTION}>
        <h2 id="campaign-findings-title" className={SECTION_TITLE}>
          {t("campaign.findings.title")}
        </h2>
        {report.findings_dropped > 0 ? (
          <p
            role="alert"
            data-testid="campaign-findings-dropped"
            className="max-w-3xl rounded-card border border-sev-high p-3 body-4 text-fg"
          >
            {t("campaign.findings.dropped", { count: report.findings_dropped })}
          </p>
        ) : null}
        <Findings findings={report.findings} active={active} />
      </section>

      <section aria-labelledby="campaign-requests-title" className={SECTION}>
        <h2 id="campaign-requests-title" className={SECTION_TITLE}>
          {t("campaign.requests.title")}
        </h2>
        <p data-testid="campaign-requests-lead" className="body-5 text-fg-muted">
          {t("campaign.requests.lead", { max: CAMPAIGN_LIMITS.storedRequestsMax })}
        </p>
        <RequestLog requests={requests} />
      </section>

      <section aria-labelledby="campaign-report-title" data-testid="campaign-report" className={SECTION}>
        <h2 id="campaign-report-title" className={SECTION_TITLE}>
          {t("campaign.report.title")}
        </h2>
        <CampaignNotice engine={report.engine} notice={report.notice} />
        <p className="max-w-3xl body-5 text-fg-muted">{t("campaign.report.lead")}</p>
        <div>
          {/* A plain link to the route handler: it checks the session and answers with the file; a refusal comes back here. */}
          <a
            href={ROUTES.campaignReport(campaign.id)}
            data-testid="campaign-report-download"
            className={buttonClass("secondary")}
          >
            {t("campaign.report.download")}
          </a>
        </div>
        <div className="flex flex-col gap-1">
          <h3 className="heading-6">{t("campaign.report.limits")}</h3>
          <ul className="flex max-w-3xl list-disc flex-col gap-1 ps-4 body-5 text-fg-muted">
            {report.limits.map((limit) => (
              <li key={limit} data-testid="campaign-report-limit">
                {limit}
              </li>
            ))}
          </ul>
        </div>
      </section>
    </>
  );
}
