import type { Environment, IncidentStatus } from "@antireverse/protocol";
import type { ConfirmOutcome } from "@/features/alerts/confirm-result.ts";
import type { AuditQuery } from "@/features/audit/query.ts";
import type { BlockRequest } from "@/features/containment/query.ts";
import type { FindingQuery } from "@/features/findings/query.ts";

/**
 * The confirmation step of the Policy screen: the Rule to promote or the version to roll back to — one
 * at a time, or none.
 */
export type PolicyConfirmation =
  | { promote?: never; rollback?: never }
  | { promote: string; rollback?: never }
  | { promote?: never; rollback: number };

function policy(appId: string, environment?: Environment, confirmation: PolicyConfirmation = {}): string {
  const query = new URLSearchParams();
  if (environment !== undefined) query.set("environment", environment);
  if (confirmation.promote !== undefined) query.set("promote", confirmation.promote);
  if (confirmation.rollback !== undefined) query.set("rollback", String(confirmation.rollback));
  const search = query.toString();
  return `/apps/${appId}/policy${search ? `?${search}` : ""}`;
}

/** The Incident list, optionally filtered by status. */
function incidents(status?: IncidentStatus): string {
  return status === undefined ? "/incidents" : `/incidents?status=${status}`;
}

/**
 * One Incident. Each option opens one confirmation step: `confirm: "resolve"` before resolving, `block` before
 * blocking an Actor or the network (the same address the containment bar's form sends), `lift` before lifting
 * that block.
 */
function incident(
  incidentId: string,
  options: { confirm?: "resolve"; block?: BlockRequest; lift?: string } = {},
): string {
  const query = new URLSearchParams();
  if (options.confirm === "resolve") query.set("confirm", "resolve");
  if (options.block !== undefined) {
    query.set("contain", options.block.kind);
    if (options.block.kind === "actor") query.set("actor", options.block.ipHash);
    query.set("ttl", String(options.block.ttl));
  }
  if (options.lift !== undefined) query.set("lift", options.lift);
  const search = query.toString();
  return `/incidents/${incidentId}${search ? `?${search}` : ""}`;
}

/** The active blocks of an App. With `lift` it opens the step that asks before that block is lifted. */
function containment(appId: string, options: { lift?: string } = {}): string {
  return `/apps/${appId}/containment${options.lift === undefined ? "" : `?lift=${options.lift}`}`;
}

/** The never block list. With `remove` it opens the step that asks before that range is removed. */
function allowlist(options: { remove?: string } = {}): string {
  return options.remove === undefined ? "/settings/allowlist" : `/settings/allowlist?remove=${options.remove}`;
}

/** The alert-channel settings. With `remove` it opens the step that asks before that channel is removed. */
function alerts(options: { remove?: string } = {}): string {
  return options.remove === undefined ? "/settings/alerts" : `/settings/alerts?remove=${options.remove}`;
}

/** The audit log (slice 18a), optionally filtered: `?action=&app=&from=&to=`, in a fixed order. */
function audit(query: AuditQuery = {}): string {
  const search = new URLSearchParams();
  if (query.action !== undefined) search.set("action", query.action);
  if (query.app !== undefined) search.set("app", query.app);
  if (query.from !== undefined) search.set("from", query.from);
  if (query.to !== undefined) search.set("to", query.to);
  const text = search.toString();
  return `/settings/audit${text ? `?${text}` : ""}`;
}

/** The filters of a Finding list as a query string, in a fixed order; empty without filters. */
function findingSearch(query: FindingQuery): string {
  const search = new URLSearchParams();
  if (query.severity !== undefined) search.set("severity", query.severity);
  if (query.status !== undefined) search.set("status", query.status);
  if (query.source !== undefined) search.set("source", query.source);
  if (query.advisory !== undefined) search.set("advisory", query.advisory);
  if (query.build !== undefined) search.set("build", query.build);
  const text = search.toString();
  return text ? `?${text}` : "";
}

/** The Organization's Findings, optionally filtered. */
function findings(query: FindingQuery = {}): string {
  return `/findings${findingSearch(query)}`;
}

/** The Findings of one App, optionally filtered. */
function appFindings(appId: string, query: FindingQuery = {}): string {
  return `/apps/${appId}/findings${findingSearch(query)}`;
}

/**
 * One Finding. With `confirm: "ignore"` it opens the step that asks for a reason and a date before ignoring; with
 * `confirm: "enforce"` the step that asks for the typed patch id before enforcing its virtual patch.
 */
function finding(findingId: string, options: { confirm?: "ignore" | "enforce" } = {}): string {
  return `/findings/${findingId}${options.confirm === undefined ? "" : `?confirm=${options.confirm}`}`;
}

/** One Verified Target. With `confirm: "remove"` it opens the step that asks before the target is removed. */
function target(targetId: string, options: { confirm?: "remove" } = {}): string {
  return `/prove/targets/${targetId}${options.confirm === "remove" ? "?confirm=remove" : ""}`;
}

// The Console's addresses. None of them ever carries a key, a signing secret or a channel URL.
export const ROUTES = {
  home: "/",
  signIn: "/sign-in",
  /** Sign-in after the API stopped accepting the saved key. */
  signInExpired: "/sign-in?reason=expired",
  apps: "/apps",
  newApp: "/apps/new",
  live: (appId: string): string => `/apps/${appId}/live`,
  /** The Set up page of an App (slice 16, SCR-01). Without an Environment it shows the App's own. */
  setup: (appId: string, environment?: Environment): string =>
    `/apps/${appId}/setup${environment === undefined ? "" : `?environment=${environment}`}`,
  /** The Builds of an App, newest first. */
  builds: (appId: string): string => `/apps/${appId}/builds`,
  /** One Build of an App. */
  build: (appId: string, buildId: string): string => `/apps/${appId}/builds/${buildId}`,
  /**
   * The Policy of an App. Without an Environment the screen shows development. With a confirmation it
   * opens the step that asks before a Rule is promoted or a version is rolled back.
   */
  policy,
  incidents,
  incident,
  containment,
  alerts,
  allowlist,
  audit,
  /** The NDJSON export of the audit log, through the Console's route handler that checks the session. */
  auditExport: "/api/audit/export",
  /**
   * Where a confirmation link ends up after "Confirm email" (slice 06b): the outcome only, never the token. Public.
   */
  alertConfirmDone: (result: ConfirmOutcome): string => `/alerts/confirm/done?result=${result}`,
  findings,
  appFindings,
  finding,
  /** The Organization's Verified Targets (slice 14). */
  targets: "/prove/targets",
  target,
  /** The current Rules of Engagement, their history and the dry "Check a test" form. */
  rulesOfEngagement: "/prove/rules-of-engagement",
  /** The form that writes and signs a new Rules of Engagement version. */
  newRulesOfEngagement: "/prove/rules-of-engagement/new",
  /** The list proxy the live feed reads whenever its stream opens. */
  events: (appId: string): string => `/api/apps/${appId}/events`,
  /** The set-up proxy the Set up page polls every 5 s. */
  setupApi: (appId: string, environment: Environment): string => `/api/apps/${appId}/setup?environment=${environment}`,
  /** The stream proxy the browser's EventSource connects to. */
  stream: (appId: string): string => `/api/apps/${appId}/events/stream`,
} as const;
