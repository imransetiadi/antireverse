import {
  CAMPAIGN_INTENSITIES,
  CAMPAIGN_LIMITS,
  type CampaignEndReason,
  type CampaignFindingState,
  type CampaignIntensity,
  type CampaignLocation,
  type CampaignRefusalReason,
  type CampaignSendFailure,
  type CampaignStatus,
  type Intensity,
  intensityRank,
  isPathExcluded,
  type RulesOfEngagementVersion,
  type Target,
  VERIFICATION_FILE_PATH,
} from "@antireverse/protocol";
import { type MessageKey, t } from "@/lib/t.ts";

// The words of Pentest Campaigns (slice 15a). Pure: the same on the server and in the browser. Each record is over a
// closed list of the protocol, so a new status or reason fails to compile until it has words.

export const STATUS_LABEL: Readonly<Record<CampaignStatus, MessageKey>> = {
  queued: "campaign.status.queued",
  running: "campaign.status.running",
  completed: "campaign.status.completed",
  stopped: "campaign.status.stopped",
  refused: "campaign.status.refused",
  failed: "campaign.status.failed",
  interrupted: "campaign.status.interrupted",
};

export const STATUS_HELP: Readonly<Record<CampaignStatus, MessageKey>> = {
  queued: "campaign.status.help.queued",
  running: "campaign.status.help.running",
  completed: "campaign.status.help.completed",
  stopped: "campaign.status.help.stopped",
  refused: "campaign.status.help.refused",
  failed: "campaign.status.help.failed",
  interrupted: "campaign.status.help.interrupted",
};

/** True while a Campaign can still send: the Stop button shows and the page refreshes. */
export const isActive = (status: CampaignStatus): boolean => status === "queued" || status === "running";

export const END_REASON_LABEL: Readonly<Record<CampaignEndReason, MessageKey>> = {
  checks_complete: "campaign.end.checks_complete",
  operator_kill: "campaign.end.operator_kill",
  organization_suspended: "campaign.end.organization_suspended",
  owner_stop: "campaign.end.owner_stop",
  deletion_pending: "campaign.end.deletion_pending",
  malformed_probe: "campaign.end.malformed_probe",
  method_not_allowed: "campaign.end.method_not_allowed",
  path_not_canonical: "campaign.end.path_not_canonical",
  query_not_canonical: "campaign.end.query_not_canonical",
  not_in_catalog: "campaign.end.not_in_catalog",
  target_unknown: "campaign.end.target_unknown",
  target_not_verified: "campaign.end.target_not_verified",
  no_rules_of_engagement: "campaign.end.no_rules_of_engagement",
  out_of_scope: "campaign.end.out_of_scope",
  intensity_exceeds: "campaign.end.intensity_exceeds",
  outside_window: "campaign.end.outside_window",
  rules_replaced: "campaign.end.rules_replaced",
  request_budget: "campaign.end.request_budget",
  time_budget: "campaign.end.time_budget",
  byte_budget: "campaign.end.byte_budget",
  verification_path_excluded: "campaign.end.verification_path_excluded",
  rules_too_old: "campaign.end.rules_too_old",
  campaigns_disabled: "campaign.end.campaigns_disabled",
  target_not_reachable: "campaign.end.target_not_reachable",
  refusal_limit: "campaign.end.refusal_limit",
  target_unhealthy: "campaign.end.target_unhealthy",
  target_rate_limited: "campaign.end.target_rate_limited",
  target_unavailable: "campaign.end.target_unavailable",
  engine_error: "campaign.end.engine_error",
  api_restart: "campaign.end.api_restart",
  api_shutdown: "campaign.end.api_shutdown",
};

/** The numbers an end reason may name, all from the protocol's fixed limits. */
const LIMIT_VALUES = {
  requests: CAMPAIGN_LIMITS.requestsMax,
  minutes: CAMPAIGN_LIMITS.wallTimeS / 60,
  days: CAMPAIGN_LIMITS.roeMaxAgeDays,
  refusals: CAMPAIGN_LIMITS.refusalsMax,
  failures: CAMPAIGN_LIMITS.consecutiveFailuresMax,
} as const;

/** Why a Campaign ended, in a plain sentence. */
export const endReasonText = (reason: CampaignEndReason): string => t(END_REASON_LABEL[reason], LIMIT_VALUES);

/** Why the gate refused a probe, in a few words. */
export const REFUSAL_LABEL: Readonly<Record<CampaignRefusalReason, MessageKey>> = {
  operator_kill: "campaign.refusal.operator_kill",
  organization_suspended: "campaign.refusal.organization_suspended",
  owner_stop: "campaign.refusal.owner_stop",
  deletion_pending: "campaign.refusal.deletion_pending",
  malformed_probe: "campaign.refusal.malformed_probe",
  method_not_allowed: "campaign.refusal.method_not_allowed",
  path_not_canonical: "campaign.refusal.path_not_canonical",
  query_not_canonical: "campaign.refusal.query_not_canonical",
  not_in_catalog: "campaign.refusal.not_in_catalog",
  target_unknown: "campaign.refusal.target_unknown",
  target_not_verified: "campaign.refusal.target_not_verified",
  no_rules_of_engagement: "campaign.refusal.no_rules_of_engagement",
  out_of_scope: "campaign.refusal.out_of_scope",
  path_excluded: "campaign.refusal.path_excluded",
  intensity_exceeds: "campaign.refusal.intensity_exceeds",
  outside_window: "campaign.refusal.outside_window",
  rules_replaced: "campaign.refusal.rules_replaced",
  request_budget: "campaign.refusal.request_budget",
  time_budget: "campaign.refusal.time_budget",
  byte_budget: "campaign.refusal.byte_budget",
  concurrent_request: "campaign.refusal.concurrent_request",
  campaign_ended: "campaign.refusal.campaign_ended",
};

/** Why a sent request has no response. */
export const SEND_FAILURE_LABEL: Readonly<Record<CampaignSendFailure, MessageKey>> = {
  timeout: "campaign.failure.timeout",
  connect_failed: "campaign.failure.connect_failed",
  tls_failed: "campaign.failure.tls_failed",
  aborted: "campaign.failure.aborted",
  invalid_response: "campaign.failure.invalid_response",
  read_limit: "campaign.failure.read_limit",
};

export const FINDING_STATE_LABEL: Readonly<Record<CampaignFindingState, MessageKey>> = {
  unverified: "campaign.finding.state.unverified",
  confirmed: "campaign.finding.state.confirmed",
};

export const FINDING_STATE_HELP: Readonly<Record<CampaignFindingState, MessageKey>> = {
  unverified: "campaign.finding.state.help.unverified",
  confirmed: "campaign.finding.state.help.confirmed",
};

/** Where a redirect pointed; it was never followed. */
export const LOCATION_LABEL: Readonly<Record<CampaignLocation, MessageKey>> = {
  "same-host": "campaign.evidence.location.same-host",
  "other-host": "campaign.evidence.location.other-host",
};

/** What a Campaign does, in the numbers of the protocol's fixed limits. */
export function campaignEffect(): string {
  return t("campaign.effect", {
    requests: CAMPAIGN_LIMITS.requestsMax,
    rate: Math.round(1000 / CAMPAIGN_LIMITS.minSpacingMs),
    minutes: CAMPAIGN_LIMITS.wallTimeS / 60,
  });
}

const DAY_MS = 86_400_000;

/** Why the form has nothing to offer. */
export type NotEligible =
  | "no-targets"
  | "no-verified"
  | "no-rules"
  | "rules-too-old"
  | "none-in-scope"
  | "verification-path-excluded";

export type Eligibility = { kind: "ok"; targets: Target[] } | { kind: "none"; why: NotEligible };

/**
 * The targets a Campaign can be launched against now: verified, and in the scope of the current Rules of Engagement,
 * which were signed at most 90 days ago and do not exclude the ownership file every Campaign reads at its start.
 * Otherwise the first reason nothing qualifies. The API checks all of it again (and that the last ownership check is
 * recent) and alone decides.
 */
export function eligibility(
  targets: readonly Target[],
  current: Pick<RulesOfEngagementVersion, "scope" | "signed_at" | "exclusions"> | null,
  nowMs: number,
): Eligibility {
  if (targets.length === 0) return { kind: "none", why: "no-targets" };
  const verified = targets.filter((target) => target.status === "verified");
  if (verified.length === 0) return { kind: "none", why: "no-verified" };
  if (current === null) return { kind: "none", why: "no-rules" };
  if (!(nowMs - Date.parse(current.signed_at) <= CAMPAIGN_LIMITS.roeMaxAgeDays * DAY_MS)) {
    return { kind: "none", why: "rules-too-old" };
  }
  const inScope = verified.filter((target) => current.scope.includes(target.id));
  if (inScope.length === 0) return { kind: "none", why: "none-in-scope" };
  if (isPathExcluded(VERIFICATION_FILE_PATH, current.exclusions)) {
    return { kind: "none", why: "verification-path-excluded" };
  }
  return { kind: "ok", targets: inScope };
}

/** The intensities the form offers: passive and safe-active, never full, and never more than was signed. */
export function offeredIntensities(signed: Intensity): CampaignIntensity[] {
  return CAMPAIGN_INTENSITIES.filter((intensity) => intensityRank(intensity) <= intensityRank(signed));
}
