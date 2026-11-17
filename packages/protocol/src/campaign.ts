// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { ID_PATTERNS } from "./constants.ts";
import { AUTHORIZE_REASONS, exclusionMatchPath, type INTENSITIES, normaliseHost, normaliseTestPath } from "./prove.ts";
import { deepFreeze, isoDateTime, text } from "./shared.ts";

// The Pentest Campaign contract (slice 15a, D-105). A Campaign is an authorised, scoped test an Organization runs
// against its own Verified Target under the Rules of Engagement it signed. In this slice the engine is a scripted
// stand-in: it measures the pipeline and its safety controls and is not a penetration test, and every Campaign,
// report and screen says so (`CAMPAIGN_STAND_IN_NOTICE`). The engine's only capability is a probe
// `{ method, path, query }`: a host, a scheme, a port, a body, headers and cookies are not expressible. The API's
// request gate builds the URL from the Campaign's own Target and is the only code that sends Campaign traffic.

/** The budgets and caps of a Campaign, fixed in code (ticket 15a). No setting, variable or request changes them. */
export const CAMPAIGN_LIMITS = deepFreeze({
  /** Requests sent per Campaign. */
  requestsMax: 60,
  /** Seconds from the start to the end of a Campaign. */
  wallTimeS: 300,
  /** Milliseconds between the starts of two requests: 1 request per second, one at a time. */
  minSpacingMs: 1000,
  /** Response bytes read per Campaign, in all. */
  responseBytesMax: 2 * 1024 * 1024,
  /** Bytes of one response read at most; the connection is then dropped. */
  responseReadBytesMax: 64 * 1024,
  /** Milliseconds of one request, connection to last byte. */
  requestTimeoutMs: 5000,
  /** Refused probes that end a Campaign. */
  refusalsMax: 20,
  /** Failures in a row (no response, or a 5xx) that end a Campaign. */
  consecutiveFailuresMax: 5,
  /** Campaigns queued or running per Organization. */
  runningPerOrganization: 1,
  /** Campaigns running against one host, across Organizations. */
  runningPerHost: 1,
  /** Campaigns running in all. */
  runningInAll: 2,
  /** Campaigns created per Organization in 24 hours. */
  createdPerOrganizationPerDay: 5,
  /** Campaigns created per Target in 24 hours. */
  createdPerTargetPerDay: 3,
  /** Days after which signed Rules of Engagement no longer cover a new Campaign. */
  roeMaxAgeDays: 90,
  /** Rows of the request log kept per Campaign. */
  storedRequestsMax: 200,
  /** Bytes of a Finding's evidence excerpt. */
  excerptBytesMax: 2048,
  /** Bytes of one response's headers read at most; a response with more is a failed request. They count as read. */
  responseHeaderBytesMax: 16_384,
  /** Characters of a request target (`path?query`, after encoding) at most. */
  requestTargetMax: 1024,
  /** Characters of a probe's path. */
  pathMax: 512,
  /** Parameters of a probe's query. */
  queryParamsMax: 8,
  /** Characters of a query parameter's name. */
  queryNameMax: 64,
  /** Characters of a query parameter's value. */
  queryValueMax: 512,
  /** Findings kept per Campaign. */
  findingsMax: 50,
  /** Characters of a Finding's title. */
  titleMax: 120,
  /** Campaigns of a list response. */
  listed: 50,
  /** Days a Campaign, its request log and its Findings are kept after it ends. */
  retentionDays: 395,
} as const);

/** The environment variable that turns Campaigns on (`1`). Unset: none can be created. */
export const CAMPAIGNS_VARIABLE = "AR_PROVE_CAMPAIGNS";

/** Shown with every Campaign, report and screen while the engine is the scripted stand-in. Never reworded. */
export const CAMPAIGN_STAND_IN_NOTICE =
  "Scripted checks. They measure the pipeline and its safety controls. This is not a penetration test.";

/** Which engine ran a Campaign. `model` names the AI model; the stand-in has none. */
export const CampaignEngineSchema = z.object({
  name: text(64).min(1),
  version: text(32).min(1),
  model: text(64).min(1),
});
export type CampaignEngine = z.infer<typeof CampaignEngineSchema>;

/** The scripted stand-in of slice 15a: no AI model, no spend. */
export const STAND_IN_ENGINE: CampaignEngine = deepFreeze({ name: "stand-in", version: "1", model: "stand-in" });

/** The intensities a Campaign may have in this slice: never `full`. */
export const CAMPAIGN_INTENSITIES = [
  "passive",
  "safe-active",
] as const satisfies readonly (typeof INTENSITIES)[number][];
export type CampaignIntensity = (typeof CAMPAIGN_INTENSITIES)[number];

/** queued → running → completed, stopped, refused, failed or interrupted. An ended Campaign never runs again. */
export const CAMPAIGN_STATUSES = [
  "queued",
  "running",
  "completed",
  "stopped",
  "refused",
  "failed",
  "interrupted",
] as const;
export type CampaignStatus = (typeof CAMPAIGN_STATUSES)[number];

export const CAMPAIGN_METHODS = ["GET", "HEAD"] as const;
export type CampaignMethod = (typeof CAMPAIGN_METHODS)[number];

/**
 * Why the gate refused a probe, in the order the gate checks. A refused probe is never sent; it is logged with its
 * reason. `concurrent_request`: the engine asked for a second request while one was in flight. `campaign_ended`: the
 * Campaign had already ended (not logged).
 */
export const CAMPAIGN_REFUSAL_REASONS = [
  "operator_kill",
  "organization_suspended",
  "owner_stop",
  "deletion_pending",
  "malformed_probe",
  "method_not_allowed",
  "path_not_canonical",
  "query_not_canonical",
  ...AUTHORIZE_REASONS,
  "rules_replaced",
  "request_budget",
  "time_budget",
  "byte_budget",
  "concurrent_request",
  "campaign_ended",
] as const;
export type CampaignRefusalReason = (typeof CAMPAIGN_REFUSAL_REASONS)[number];

/** The refusals that end the Campaign at once: they hold for every further probe, not for this one only. */
export const FATAL_CAMPAIGN_REFUSALS = [
  "operator_kill",
  "organization_suspended",
  "owner_stop",
  "deletion_pending",
  "target_unknown",
  "target_not_verified",
  "no_rules_of_engagement",
  "out_of_scope",
  "intensity_exceeds",
  "outside_window",
  "rules_replaced",
  "request_budget",
  "time_budget",
  "byte_budget",
] as const satisfies readonly CampaignRefusalReason[];
export type FatalCampaignRefusal = (typeof FATAL_CAMPAIGN_REFUSALS)[number];

/** Why a Campaign ended: a fixed list, never an engine's or a target's own words. */
export const CAMPAIGN_END_REASONS = [
  /** The engine ran every check it had. */
  "checks_complete",
  ...FATAL_CAMPAIGN_REFUSALS,
  /**
   * A start check: the Rules of Engagement exclude the ownership file's path (`/.well-known/…`), so ownership cannot
   * be checked without breaking them. The owner must sign Rules that do not exclude it.
   */
  "verification_path_excluded",
  /** A start check: the Rules of Engagement were signed more than 90 days ago. */
  "rules_too_old",
  /** A start check: Campaigns are not enabled on this service. */
  "campaigns_disabled",
  /** A start check: the host did not resolve, or an address it resolves to is not public. */
  "target_not_reachable",
  /** 20 probes were refused. */
  "refusal_limit",
  /** Five failures in a row. */
  "target_unhealthy",
  /** The target answered 429. */
  "target_rate_limited",
  /** The target answered 503 with Retry-After. */
  "target_unavailable",
  "engine_error",
  /** The API restarted, or shut down, while the Campaign was running. It is never resumed. */
  "api_restart",
  "api_shutdown",
] as const;
export type CampaignEndReason = (typeof CAMPAIGN_END_REASONS)[number];

const STOPPED: readonly CampaignEndReason[] = [
  "owner_stop",
  "operator_kill",
  "organization_suspended",
  "deletion_pending",
];

/** The status an end reason gives. `started`: the Campaign passed its start checks (a probe may have been sent). */
export function statusOfEndReason(
  reason: CampaignEndReason,
  started: boolean,
): Exclude<CampaignStatus, "queued" | "running"> {
  if (reason === "checks_complete") return "completed";
  if (STOPPED.includes(reason)) return "stopped";
  if (reason === "api_restart" || reason === "api_shutdown") return "interrupted";
  // Something of ours failed: never "refused", which says the Campaign was not allowed.
  if (reason === "engine_error") return "failed";
  return started ? "failed" : "refused";
}

// --- Probes ----------------------------------------------------------------------------------------------

// Unreserved characters and `/` only: no percent-encoding, no `\`, `;`, `:`, `@`, `?`, `#`, space or control.
const PATH_CHARACTERS = /^\/[A-Za-z0-9\-._~/]*$/;
const QUERY_NAME = /^[A-Za-z0-9_.-]+$/;
const CONTROL =
  // biome-ignore lint/suspicious/noControlCharactersInRegex: refusing control characters is the point.
  /[\u0000-\u001f\u007f-\u009f\u2028\u2029]|[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;

/**
 * The path as the gate sends it, or null. Canonical means that the form that is authorised is the form that is sent
 * and the form any server reads: it starts with one `/`, holds only `A-Z a-z 0-9 - . _ ~ /` (so nothing is
 * percent-encoded and there is no query, fragment, parameter, backslash or authority), has no empty, `.` or `..`
 * segment and no segment ending in a dot, and both `normaliseTestPath` and `exclusionMatchPath` leave it as it is
 * (apart from the letter case the exclusion match folds).
 */
export function canonicalCampaignPath(path: unknown): string | null {
  if (typeof path !== "string" || path.length === 0 || path.length > CAMPAIGN_LIMITS.pathMax) return null;
  if (!PATH_CHARACTERS.test(path)) return null;
  const segments = path.split("/").slice(1);
  for (const [index, segment] of segments.entries()) {
    if (segment === "" && index !== segments.length - 1) return null;
    if (segment === "." || segment === ".." || segment.endsWith(".")) return null;
  }
  if (normaliseTestPath(path) !== path) return null;
  if (exclusionMatchPath(path) !== path.toLowerCase()) return null;
  return path;
}

/** RFC 3986 unreserved characters stay; everything else is percent-encoded as UTF-8. */
function encodeQueryValue(value: string): string {
  return encodeURIComponent(value).replace(/[!'()*]/g, (c) => `%${c.charCodeAt(0).toString(16).toUpperCase()}`);
}

/**
 * The query string of a probe (without `?`), or null: at most 8 parameters, names over `A-Z a-z 0-9 _ . -`, values
 * of at most 512 characters without control characters, each value percent-encoded by the gate. An empty or absent
 * query is the empty string.
 */
export function canonicalCampaignQuery(query: unknown): string | null {
  if (query === undefined) return "";
  if (typeof query !== "object" || query === null || Array.isArray(query)) return null;
  const prototype = Object.getPrototypeOf(query);
  if (prototype !== Object.prototype && prototype !== null) return null;
  const entries = Object.entries(query as Record<string, unknown>);
  if (entries.length > CAMPAIGN_LIMITS.queryParamsMax) return null;
  const parts: string[] = [];
  for (const [name, value] of entries) {
    if (name.length === 0 || name.length > CAMPAIGN_LIMITS.queryNameMax || !QUERY_NAME.test(name)) return null;
    if (typeof value !== "string" || value.length > CAMPAIGN_LIMITS.queryValueMax || CONTROL.test(value)) return null;
    parts.push(`${name}=${encodeQueryValue(value)}`);
  }
  return parts.join("&");
}

/** What an engine may ask for: nothing else is expressible (strict: an unknown member is refused). */
export const CampaignProbeSchema = z.strictObject({
  method: z.enum(CAMPAIGN_METHODS),
  path: z.string().max(CAMPAIGN_LIMITS.pathMax),
  query: z.record(z.string(), z.string()).optional(),
});
export type CampaignProbe = z.infer<typeof CampaignProbeSchema>;

/** The request target the gate sends for a probe (`path` or `path?query`), or null when it is not canonical. */
export function campaignRequestTarget(probe: CampaignProbe): string | null {
  const path = canonicalCampaignPath(probe.path);
  const query = canonicalCampaignQuery(probe.query);
  if (path === null || query === null) return null;
  const target = query === "" ? path : `${path}?${query}`;
  return target.length > CAMPAIGN_LIMITS.requestTargetMax ? null : target;
}

/** Where a redirect points, which is all that is kept of a Location header: it is never followed. */
export const CAMPAIGN_LOCATIONS = ["same-host", "other-host"] as const;
export type CampaignLocation = (typeof CAMPAIGN_LOCATIONS)[number];

/**
 * Why a sent request has no response. `aborted`: a stop cut it off in flight. `invalid_response`: the target answered
 * with a status outside 100–599 or with more than 16 KB of headers; nothing of it is handed on.
 */
export const CAMPAIGN_SEND_FAILURES = [
  "timeout",
  "connect_failed",
  "tls_failed",
  "aborted",
  "invalid_response",
] as const;
export type CampaignSendFailure = (typeof CAMPAIGN_SEND_FAILURES)[number];

/**
 * What the gate hands an engine for a probe. A response is redacted before the engine sees it: `headers` is an
 * allowlist with cookie values removed, `body` at most 64 KB of text with keys, tokens, emails, card-like numbers and
 * high-entropy strings replaced.
 */
export type CampaignExchange =
  | {
      ok: true;
      seq: number;
      status: number;
      headers: Record<string, string>;
      body: string;
      /** The body was longer than the 64 KB read: `body` holds its beginning only. */
      truncated: boolean;
      location: CampaignLocation | null;
      /**
       * The body was not text (a NUL in it, or UTF-16) and was withheld whole: `body` is a fixed marker. A check that
       * needed the body cannot tell: it is inconclusive, never clean.
       */
      withheld: boolean;
    }
  | { ok: false; refused: CampaignRefusalReason; fatal: boolean }
  | { ok: false; seq: number; error: CampaignSendFailure };

// --- The Campaign ----------------------------------------------------------------------------------------

/** The exact phrase an admin types to launch a Campaign: `I authorise a test of <host>`. */
export function campaignAuthorisationPhrase(host: string): string {
  if (normaliseHost(host) !== host) throw new TypeError("A target host must be a normalised public DNS name.");
  return `I authorise a test of ${host}`;
}

/**
 * Body of `POST /v1/campaigns`. `confirm` must be `campaignAuthorisationPhrase(<the target's host>)` (the API checks
 * it against the target). `staging` is the declaration that the target is a staging system, not production: it must
 * be `true`; it is stored with the Campaign and its audit entry and is not verified technically. The request also
 * needs a reason (`X-Airverse-Reason`).
 */
export const CreateCampaignRequestSchema = z.object({
  target_id: z.string().regex(ID_PATTERNS.tgt, "Expected a target id."),
  intensity: z.enum(CAMPAIGN_INTENSITIES, "Must be passive or safe-active: full is not available."),
  confirm: z.string().max(300),
  staging: z.literal(true, "Declare that the target is a staging system: staging must be true."),
});
export type CreateCampaignRequest = z.infer<typeof CreateCampaignRequestSchema>;

const count = () => z.int().min(0).max(Number.MAX_SAFE_INTEGER);

/**
 * What the checks came to. `ran`: got an answer that could be judged. `reported`: those of them that reported a
 * Finding. `inconclusive`: got an answer whose body could not be read as text or in full (withheld as not text, or
 * cut at 64 KB), so the check could not tell — never counted as ran. `skipped`: did not run, or got no answer.
 */
export const CampaignChecksSchema = z.object({
  ran: count(),
  reported: count(),
  inconclusive: count(),
  skipped: count(),
});
export type CampaignChecks = z.infer<typeof CampaignChecksSchema>;

/**
 * The one sentence a report says about its checks. It never says that no vulnerabilities were found, and it says
 * how many checks could not tell, and why.
 */
export function campaignChecksSentence(checks: CampaignChecks): string {
  const { ran, reported, inconclusive, skipped } = checks;
  const unread =
    inconclusive === 0
      ? ""
      : ` ${inconclusive} ${inconclusive === 1 ? "was" : "were"} inconclusive (${inconclusive} ${
          inconclusive === 1 ? "response" : "responses"
        } could not be read as text or in full),`;
  return `${ran} ${ran === 1 ? "check" : "checks"} ran, ${reported} reported a finding,${unread} ${skipped} ${
    skipped === 1 ? "was" : "were"
  } skipped.`;
}

export const CampaignSchema = z.object({
  id: z.string().regex(ID_PATTERNS.cmp),
  target_id: z.string().regex(ID_PATTERNS.tgt),
  /** The target's host when the Campaign was created. */
  host: z.string(),
  /** The Rules of Engagement version bound at creation: a later version ends the Campaign. */
  roe_id: z.string().regex(ID_PATTERNS.roe),
  roe_sha256: z.string().regex(/^[0-9a-f]{64}$/),
  intensity: z.enum(CAMPAIGN_INTENSITIES),
  engine: CampaignEngineSchema,
  /** `CAMPAIGN_STAND_IN_NOTICE` while the engine is the stand-in. */
  notice: z.string(),
  status: z.enum(CAMPAIGN_STATUSES),
  /** Null while queued or running. */
  end_reason: z.enum(CAMPAIGN_END_REASONS).nullable(),
  /** The creator's declaration that the target is a staging system. Not verified technically. */
  staging_declared: z.literal(true),
  /** The id of the admin key that created the Campaign. */
  created_by: z.string().regex(ID_PATTERNS.key),
  requests_sent: count(),
  requests_refused: count(),
  response_bytes: count(),
  /** Null until the Campaign ended. */
  checks: CampaignChecksSchema.nullable(),
  /**
   * Findings the engine reported that could not be stored. Any makes the Campaign end as failed (`engine_error`): a
   * report never silently lacks a Finding.
   */
  findings_dropped: count(),
  /** The owner's stop request, if any: when, by which admin key, and why. */
  stop: z
    .object({ requested_at: isoDateTime(), requested_by: z.string().regex(ID_PATTERNS.key), reason: text(500).min(1) })
    .nullable(),
  created_at: isoDateTime(),
  started_at: isoDateTime().nullable(),
  finished_at: isoDateTime().nullable(),
});
export type Campaign = z.infer<typeof CampaignSchema>;

/** 202 of `POST /v1/campaigns`, 200 of `GET /v1/campaigns/:id` and of `POST /v1/campaigns/:id/stop`. */
export const CampaignResponseSchema = z.object({ campaign: CampaignSchema });
export type CampaignResponse = z.infer<typeof CampaignResponseSchema>;

/**
 * 200 of `GET /v1/campaigns`: the newest 50, and whether a Campaign can be created now. `enabled` is false when the
 * service has Campaigns off; `blocked` says why none can start although they are on.
 */
export const ListCampaignsResponseSchema = z.object({
  campaigns: z.array(CampaignSchema).max(CAMPAIGN_LIMITS.listed),
  enabled: z.boolean(),
  blocked: z.enum(["operator_kill", "organization_suspended"]).nullable(),
  notice: z.string(),
});
export type ListCampaignsResponse = z.infer<typeof ListCampaignsResponseSchema>;

/** One row of a Campaign's request log. It never holds a body. */
export const CampaignRequestSchema = z.object({
  seq: z.int().min(1).max(CAMPAIGN_LIMITS.storedRequestsMax),
  at: isoDateTime(),
  /** Null when the probe was too malformed to have one. */
  method: z.string().max(16).nullable(),
  /** The request target as sent (`path` or `path?query`); for a refused probe, what it asked for, shortened. */
  target: z.string().max(1024).nullable(),
  /**
   * `sending`: the row is written before the request goes out, so a request that reached the target is always in the
   * log; it becomes `sent` with the result. A row still `sending` after the Campaign ended was sent, and its result
   * could not be recorded. `not_sent`: the row was written and a stop arrived before the request went out; it never
   * left and does not count as sent. The first row of a started Campaign is the ownership check's GET of the
   * verification file.
   */
  outcome: z.enum(["sending", "sent", "not_sent", "refused"]),
  /** Why a probe was refused; null for a sent one. */
  reason: z.enum(CAMPAIGN_REFUSAL_REASONS).nullable(),
  /** The response's status; null when refused or when no response came. */
  status: z.int().min(100).max(599).nullable(),
  /** Why a sent request has no response. */
  failure: z.enum(CAMPAIGN_SEND_FAILURES).nullable(),
  /** Bytes the connection read: the TLS handshake, any 1xx responses, the headers and the body, failed or not. */
  bytes: count(),
  ms: count(),
});
export type CampaignRequest = z.infer<typeof CampaignRequestSchema>;

export const ListCampaignRequestsResponseSchema = z.object({
  requests: z.array(CampaignRequestSchema).max(CAMPAIGN_LIMITS.storedRequestsMax),
});
export type ListCampaignRequestsResponse = z.infer<typeof ListCampaignRequestsResponseSchema>;

export const CAMPAIGN_SEVERITIES = ["high", "medium", "low"] as const;
export type CampaignSeverity = (typeof CAMPAIGN_SEVERITIES)[number];

/** `unverified` until one automatic repeat of the probe shows the same thing; then `confirmed`. */
export const CAMPAIGN_FINDING_STATES = ["unverified", "confirmed"] as const;
export type CampaignFindingState = (typeof CAMPAIGN_FINDING_STATES)[number];

/** What a Finding rests on: the request, and the response as the gate redacted it. Never a whole body. */
export const CampaignEvidenceSchema = z.object({
  method: z.enum(CAMPAIGN_METHODS),
  target: z.string().max(4096),
  status: z.int().min(100).max(599),
  /** An allowlist of response headers; a cookie's value is never among them. */
  headers: z.record(z.string(), z.string()),
  /** At most 2 KB of the redacted body. */
  excerpt: z.string(),
  /**
   * SHA-256 (hex) of the body as kept: the bytes read (at most 64 KB), decoded and redacted. Never of the raw body,
   * so that the hash cannot be used to test guesses of what was redacted.
   */
  body_sha256: z.string().regex(/^[0-9a-f]{64}$/),
  truncated: z.boolean(),
  location: z.enum(CAMPAIGN_LOCATIONS).nullable(),
});
export type CampaignEvidence = z.infer<typeof CampaignEvidenceSchema>;

export const CampaignFindingSchema = z.object({
  check_id: z.string().regex(/^[A-Z]{2}-[0-9]{2}$/),
  path: z.string().max(CAMPAIGN_LIMITS.pathMax),
  title: text(CAMPAIGN_LIMITS.titleMax).min(1),
  severity: z.enum(CAMPAIGN_SEVERITIES),
  state: z.enum(CAMPAIGN_FINDING_STATES),
  evidence: CampaignEvidenceSchema,
  first_seen_at: isoDateTime(),
  last_seen_at: isoDateTime(),
});
export type CampaignFinding = z.infer<typeof CampaignFindingSchema>;

export const ListCampaignFindingsResponseSchema = z.object({
  findings: z.array(CampaignFindingSchema).max(CAMPAIGN_LIMITS.findingsMax),
  engine: CampaignEngineSchema,
  notice: z.string(),
});
export type ListCampaignFindingsResponse = z.infer<typeof ListCampaignFindingsResponseSchema>;

/** The limits a report states, so that nobody reads more into it than it holds. */
export const CAMPAIGN_REPORT_LIMITS = deepFreeze([
  "The checks are a fixed script against the seeded weaknesses of the reference target. They say nothing about real exposure.",
  "Only GET and HEAD requests were sent, without a body, cookies or credentials. Nothing behind a sign-in was tested.",
  "The request gate is application code in the API: there is no separate machine or egress proxy between the engine and the network.",
  "That the target is a staging system is a declaration by the admin key that created the Campaign. It was not verified.",
] as const);

/** 200 of `GET /v1/campaigns/:id/report`. */
export const CampaignReportSchema = z.object({
  campaign: CampaignSchema,
  engine: CampaignEngineSchema,
  notice: z.string(),
  /** `campaignChecksSentence`, or null while the Campaign has not ended. */
  summary: z.string().nullable(),
  checks: CampaignChecksSchema.nullable(),
  findings: z.array(CampaignFindingSchema).max(CAMPAIGN_LIMITS.findingsMax),
  /** Findings reported but not stored (see `CampaignSchema`). */
  findings_dropped: count(),
  limits: z.array(z.string()),
});
export type CampaignReport = z.infer<typeof CampaignReportSchema>;
export const CampaignReportResponseSchema = z.object({ report: CampaignReportSchema });
export type CampaignReportResponse = z.infer<typeof CampaignReportResponseSchema>;

// --- Operator ----------------------------------------------------------------------------------------------

/** Body of the operator routes that stop, re-enable or suspend: why. */
export const ProveOperatorRequestSchema = z.object({ reason: text(500).trim().min(1) });
export type ProveOperatorRequest = z.infer<typeof ProveOperatorRequestSchema>;

/** 200 of `GET /v1/ops/prove` and of every operator change. */
export const ProveOperatorStateSchema = z.object({
  /** Whether the service has Campaigns on (`AR_PROVE_CAMPAIGNS`). */
  enabled: z.boolean(),
  /** The global kill switch: every Campaign was stopped and none can be created or started. */
  killed: z.boolean(),
  killed_at: isoDateTime().nullable(),
  /** Organizations whose Campaigns are suspended. */
  suspended: z.array(z.object({ organization_id: z.string().regex(ID_PATTERNS.org), suspended_at: isoDateTime() })),
  /** Campaigns queued or running now. */
  active: count(),
  /** Campaigns this change stopped (0 for a read). */
  stopped: count(),
});
export type ProveOperatorState = z.infer<typeof ProveOperatorStateSchema>;

/** A Campaign that completed, for documentation and tests. Synthetic and deeply frozen. */
export const EXAMPLE_CAMPAIGN: Campaign = deepFreeze({
  id: "cmp_0123456789abcdef01234567",
  target_id: "tgt_0123456789abcdef01234567",
  host: "shop.acme-shop.io",
  roe_id: "roe_0123456789abcdef01234567",
  roe_sha256: "fb90b621f043ffa777aa343210f540b709b08ab7046c7efb4723947bee5d0135",
  intensity: "safe-active",
  engine: { name: "stand-in", version: "1", model: "stand-in" },
  notice: CAMPAIGN_STAND_IN_NOTICE,
  status: "completed",
  end_reason: "checks_complete",
  staging_declared: true,
  created_by: "key_0123456789abcdef01234567",
  requests_sent: 13,
  requests_refused: 0,
  response_bytes: 4096,
  checks: { ran: 6, reported: 6, inconclusive: 0, skipped: 0 },
  findings_dropped: 0,
  stop: null,
  created_at: "2026-11-16T10:00:00.000Z",
  started_at: "2026-11-16T10:00:01.000Z",
  finished_at: "2026-11-16T10:00:14.000Z",
});
