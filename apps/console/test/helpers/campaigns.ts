import {
  CAMPAIGN_REPORT_LIMITS,
  CAMPAIGN_STAND_IN_NOTICE,
  type Campaign,
  type CampaignFinding,
  type CampaignReport,
  type CampaignRequest,
  campaignChecksSentence,
  EXAMPLE_CAMPAIGN,
  type ProveOperatorState,
  STAND_IN_ENGINE,
} from "@antireverse/protocol";

// Slice 15a: synthetic Campaigns, Findings, request log rows and operator states for the Console's tests.

export const completed: Campaign = EXAMPLE_CAMPAIGN;
export const campaignId = completed.id;

export const queued: Campaign = {
  ...completed,
  id: "cmp_aaaaaaaaaaaaaaaaaaaaaaaa",
  status: "queued",
  end_reason: null,
  requests_sent: 0,
  requests_refused: 0,
  response_bytes: 0,
  checks: null,
  started_at: null,
  finished_at: null,
};

export const running: Campaign = {
  ...queued,
  id: "cmp_bbbbbbbbbbbbbbbbbbbbbbbb",
  status: "running",
  requests_sent: 4,
  response_bytes: 2048,
  started_at: "2026-11-16T10:00:01.000Z",
};

export const stopped: Campaign = {
  ...completed,
  id: "cmp_cccccccccccccccccccccccc",
  status: "stopped",
  end_reason: "owner_stop",
  checks: { ran: 2, reported: 1, inconclusive: 0, skipped: 4 },
  stop: {
    requested_at: "2026-11-16T10:00:05.000Z",
    requested_by: "key_0123456789abcdef01234567",
    reason: "Wrong window",
  },
};

export const refused: Campaign = {
  ...queued,
  id: "cmp_dddddddddddddddddddddddd",
  status: "refused",
  end_reason: "target_not_reachable",
  finished_at: "2026-11-16T10:00:02.000Z",
};

const evidence = {
  method: "GET" as const,
  target: "/api/admin/reports",
  status: 200,
  headers: { "content-type": "application/json" },
  excerpt: '{"reports":[{"owner":"[redacted-email]","key":"[redacted-key]"}]}',
  truncated: false,
  location: null,
};

export const highFinding: CampaignFinding = {
  check_id: "RW-03",
  path: "/api/admin/reports",
  title: "Admin data without authentication",
  severity: "high",
  state: "confirmed",
  evidence,
  first_seen_at: "2026-11-16T10:00:04.000Z",
  last_seen_at: "2026-11-16T10:00:05.000Z",
};

export const lowFinding: CampaignFinding = {
  check_id: "RW-06",
  path: "/go",
  title: "Redirect to another host",
  severity: "low",
  state: "unverified",
  evidence: {
    ...evidence,
    target: "/go?to=elsewhere",
    status: 302,
    headers: {},
    excerpt: "",
    truncated: true,
    location: "other-host",
  },
  first_seen_at: "2026-11-16T10:00:08.000Z",
  last_seen_at: "2026-11-16T10:00:08.000Z",
};

export const sentRequest: CampaignRequest = {
  seq: 1,
  at: "2026-11-16T10:00:02.000Z",
  method: "GET",
  target: "/",
  outcome: "sent",
  reason: null,
  status: 200,
  failure: null,
  bytes: 512,
  ms: 23,
  asked_chars: null,
};

export const refusedRequest: CampaignRequest = {
  seq: 2,
  at: "2026-11-16T10:00:03.000Z",
  method: "GET",
  target: "/admin/users",
  outcome: "refused",
  reason: "path_excluded",
  status: null,
  failure: null,
  bytes: 0,
  ms: 0,
  asked_chars: 256,
};

export const failedRequest: CampaignRequest = {
  seq: 3,
  at: "2026-11-16T10:00:04.000Z",
  method: "GET",
  target: "/slow",
  outcome: "sent",
  reason: null,
  status: null,
  failure: "timeout",
  bytes: 0,
  ms: 5000,
  asked_chars: null,
};

export function reportOf(campaign: Campaign, findings: CampaignFinding[] = []): CampaignReport {
  return {
    campaign,
    engine: STAND_IN_ENGINE,
    notice: CAMPAIGN_STAND_IN_NOTICE,
    summary: campaign.checks === null ? null : campaignChecksSentence(campaign.checks),
    checks: campaign.checks,
    findings,
    findings_dropped: campaign.findings_dropped,
    limits: [...CAMPAIGN_REPORT_LIMITS],
  };
}

export const ORG_ID = "org_0123456789abcdef01234567";

export function operatorState(overrides: Partial<ProveOperatorState> = {}): ProveOperatorState {
  return { enabled: true, killed: false, killed_at: null, suspended: [], active: 0, stopped: 0, ...overrides };
}
