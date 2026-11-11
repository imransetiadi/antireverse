// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { OriginSchema } from "./beacon.ts";
import { EXAMPLE_CANARIES } from "./canaries.ts";
import { ENVIRONMENTS, ID_PATTERNS } from "./constants.ts";
import { ActorHashSchema, CONTAINMENT_LIMITS, ContainmentSchema } from "./containment.ts";
import { IP_PREFIX_PATTERN, StoredEventSchema } from "./events.ts";
import { AdvisoryIdSchema, EXAMPLE_FINDING } from "./exposure.ts";
import { deepFreeze, isoDateTime, text, trimmedText } from "./shared.ts";

// The detection contract: Detections (one managed rule's threshold crossed by one network prefix, or, for
// `clone-origin`, one Clone Beacon report of a foreign origin), the
// Incidents that group them, and the alert channels that are told when an Incident opens. Every object schema
// is a plain `z.object`, which strips unknown keys. A channel URL can itself be a secret (a Slack webhook URL),
// so no response schema has a `url` field: a channel shows only its host and the URL's last 4 characters.
//
// Times: `isoDateTime()` (years 2000..2099) for times taken from Events (`window_start`, `window_end`,
// `first_seen`, `last_seen`), which a client controls; plain `z.iso.datetime()` for times the API stamps
// itself (`detected_at`, `created_at`, `updated_at`, `at`), as `registered_at` in build.ts.

export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

export const INCIDENT_STATUSES = ["open", "acknowledged", "resolved"] as const;
export type IncidentStatus = (typeof INCIDENT_STATUSES)[number];

export const ALERT_CHANNEL_KINDS = ["webhook", "slack"] as const;
export type AlertChannelKind = (typeof ALERT_CHANNEL_KINDS)[number];

/**
 * The managed detection rules. A rule counts matching Events per (Organization, App, Environment, rule,
 * `actor.ip_prefix`) in a sliding window of `window_s` seconds; reaching `threshold` records one Detection.
 * `canary-touched` counts Event signals `canary.touched:<cny id>` and adds the Canary id to the counting key.
 * `clone-origin` counts Clone Beacon reports, not Events, per (App, Environment, origin): one report records
 * the Detection, at most one per Build and origin per `window_s`.
 * `vulnerable-component` counts new Critical or High Findings (slice 19), not Events, per (App, Environment,
 * advisory). Its Incident takes the Finding's severity (critical or high), so for this rule alone the
 * Incident's severity may differ from the table's `severity`, which is the rule's nominal level.
 * Deeply frozen: no consumer can change a threshold at run time.
 */
export const DETECTION_RULES = deepFreeze([
  { key: "blocked-burst", title: "Blocked burst", severity: "high", threshold: 20, window_s: 300 },
  { key: "failed-signin-burst", title: "Failed sign-in burst", severity: "medium", threshold: 30, window_s: 300 },
  { key: "canary-touched", title: "Canary used", severity: "high", threshold: 1, window_s: 300 },
  { key: "clone-origin", title: "Clone detected", severity: "high", threshold: 1, window_s: 3600 },
  { key: "vulnerable-component", title: "Vulnerable component", severity: "high", threshold: 1, window_s: 3600 },
] as const satisfies readonly {
  key: string;
  title: string;
  severity: Severity;
  threshold: number;
  window_s: number;
}[]);
export type DetectionRule = (typeof DETECTION_RULES)[number];
export type DetectionRuleKey = DetectionRule["key"];

export const INCIDENT_LIMITS = {
  /** Incidents returned by the Incident list. */
  listed: 50,
  /** Detections returned with one Incident. */
  detectionsListed: 100,
  /** Events returned as evidence with one Incident. */
  evidence: 20,
  /** Alert channels per Organization. Enforced by the API. */
  channelsMax: 10,
  /** Characters of an alert channel URL. */
  urlMax: 2048,
  /** Characters of an alert channel name (after trimming) and of an Incident title. */
  nameMax: 80,
} as const;

/** Characters of a host name (RFC 1035 limit of a textual name). */
const HOST_MAX = 253;

const RULE_KEYS = DETECTION_RULES.map((rule) => rule.key) as [DetectionRuleKey, ...DetectionRuleKey[]];

const AppIdSchema = z.string().regex(ID_PATTERNS.app);
const EnvironmentSchema = z.enum(ENVIRONMENTS);
const RuleKeySchema = z.enum(RULE_KEYS);
/**
 * The network prefix of a Detection or Incident. Event-counting rules always have one (Events with
 * `ip_prefix: null` are never counted); a `clone-origin` Detection has the reporter's prefix or null, and a
 * `clone-origin` Incident null.
 */
const IpPrefixSchema = z.string().regex(IP_PREFIX_PATTERN).nullable();
/** The foreign origin a `clone-origin` Detection or Incident is about; null for every other rule. */
const IncidentOriginSchema = OriginSchema.nullable();
/** The advisory a `vulnerable-component` Incident is about; null for every other rule. */
const IncidentAdvisoryIdSchema = AdvisoryIdSchema.nullable();
/** The Canary a `canary-touched` Detection or Incident is about; null for every other rule. */
const CanaryIdSchema = z.string().regex(ID_PATTERNS.cny).nullable();
const CountSchema = z.int().min(0);
/** `whsec_` followed by 32 random bytes as 43 base64url characters (`generateSigningSecret` of the server entry). */
const SigningSecretSchema = z.string().regex(/^whsec_[A-Za-z0-9_-]{43}$/);

/** One threshold crossing of a managed rule by one network prefix of one App Environment. */
export const DetectionSchema = z.object({
  id: z.string().regex(ID_PATTERNS.dtc),
  rule: RuleKeySchema,
  app_id: AppIdSchema,
  environment: EnvironmentSchema,
  ip_prefix: IpPrefixSchema,
  /** Events counted in the window. */
  count: CountSchema,
  /** `ts` of the oldest and newest counted Event. */
  window_start: isoDateTime(),
  window_end: isoDateTime(),
  detected_at: z.iso.datetime(),
  canary_id: CanaryIdSchema,
  origin: IncidentOriginSchema,
});
export type Detection = z.infer<typeof DetectionSchema>;

/**
 * Detections of one (App, Environment, rule, prefix) — for `clone-origin`, of one (App, Environment, origin) —
 * grouped while the Incident is open or acknowledged.
 */
export const IncidentSchema = z.object({
  id: z.string().regex(ID_PATTERNS.inc),
  app_id: AppIdSchema,
  environment: EnvironmentSchema,
  rule: RuleKeySchema,
  severity: z.enum(SEVERITIES),
  title: text(INCIDENT_LIMITS.nameMax).min(1),
  status: z.enum(INCIDENT_STATUSES),
  ip_prefix: IpPrefixSchema,
  /** `window_start` of the first and `window_end` of the latest Detection. */
  first_seen: isoDateTime(),
  last_seen: isoDateTime(),
  detection_count: CountSchema,
  created_at: z.iso.datetime(),
  updated_at: z.iso.datetime(),
  canary_id: CanaryIdSchema,
  /** The Build the Canary or the Clone Beacon was planted in; null for every other rule. */
  build_id: z.string().regex(ID_PATTERNS.bld).nullable(),
  origin: IncidentOriginSchema,
  advisory_id: IncidentAdvisoryIdSchema,
});
export type Incident = z.infer<typeof IncidentSchema>;

/** 200 of `GET /v1/incidents`: newest first by `last_seen`, at most `INCIDENT_LIMITS.listed`. */
export const ListIncidentsResponseSchema = z.object({
  incidents: z.array(IncidentSchema).max(INCIDENT_LIMITS.listed),
});
export type ListIncidentsResponse = z.infer<typeof ListIncidentsResponseSchema>;

/** 200 of `GET /v1/incidents/:incidentId`: the Incident, its Detections and Events as stored (the allowlist). */
export const IncidentDetailResponseSchema = z.object({
  incident: IncidentSchema,
  detections: z.array(DetectionSchema).max(INCIDENT_LIMITS.detectionsListed),
  evidence: z.array(StoredEventSchema).max(INCIDENT_LIMITS.evidence),
  /**
   * The Actors of the Incident's evidence window with their Event counts: most Events first, then by hash,
   * at most `CONTAINMENT_LIMITS.actorsListed`.
   */
  actors: z.array(z.object({ ip_hash: ActorHashSchema, events: z.int().min(1) })).max(CONTAINMENT_LIMITS.actorsListed),
  /** The Containments created from the Incident, newest first. */
  containments: z.array(ContainmentSchema),
});
export type IncidentDetailResponse = z.infer<typeof IncidentDetailResponseSchema>;

/** Body of `PATCH /v1/incidents/:incidentId`. Which transition is allowed is the API's decision (else 409). */
export const UpdateIncidentRequestSchema = z.object({
  status: z.enum(["acknowledged", "resolved"]),
});
export type UpdateIncidentRequest = z.infer<typeof UpdateIncidentRequestSchema>;

/** An alert channel as the API returns it. Never its URL and never its signing secret. */
export const AlertChannelSchema = z.object({
  id: z.string().regex(ID_PATTERNS.chn),
  kind: z.enum(ALERT_CHANNEL_KINDS),
  name: text(INCIDENT_LIMITS.nameMax).min(1),
  /** The host of the URL, for recognition. */
  host: text(HOST_MAX).min(1),
  /** The last 4 characters of the URL. */
  url_last4: z.string().length(4),
  active: z.boolean(),
  created_at: z.iso.datetime(),
});
export type AlertChannel = z.infer<typeof AlertChannelSchema>;

function isHttpUrl(value: string): boolean {
  try {
    const { protocol } = new URL(value);
    return protocol === "http:" || protocol === "https:";
  } catch {
    return false;
  }
}

/**
 * Body of `POST /v1/alert-channels`. The URL must parse with an `http:` or `https:` scheme; whether `http:`
 * and private addresses are allowed is the API's decision (SSRF guard), not this schema's.
 */
export const CreateAlertChannelRequestSchema = z.object({
  kind: z.enum(ALERT_CHANNEL_KINDS),
  name: trimmedText(INCIDENT_LIMITS.nameMax),
  url: text(INCIDENT_LIMITS.urlMax).min(1).refine(isHttpUrl, "Must be an http: or https: URL."),
});
export type CreateAlertChannelRequestInput = z.input<typeof CreateAlertChannelRequestSchema>;
export type CreateAlertChannelRequest = z.infer<typeof CreateAlertChannelRequestSchema>;

/** 201 of `POST /v1/alert-channels`. A webhook channel's `signing_secret` is returned exactly once. */
export const CreateAlertChannelResponseSchema = z
  .object({
    channel: AlertChannelSchema,
    signing_secret: SigningSecretSchema.optional(),
  })
  .refine((response) => (response.channel.kind === "webhook") === (response.signing_secret !== undefined), {
    message: "A webhook channel carries its signing secret once; a Slack channel carries none.",
    path: ["signing_secret"],
  });
export type CreateAlertChannelResponse = z.infer<typeof CreateAlertChannelResponseSchema>;

/** 200 of `GET /v1/alert-channels`. */
export const ListAlertChannelsResponseSchema = z.object({ channels: z.array(AlertChannelSchema) });
export type ListAlertChannelsResponse = z.infer<typeof ListAlertChannelsResponseSchema>;

/** One attempt to deliver an alert. It records no URL, no secret and no response body. */
export const AlertDeliverySchema = z.object({
  id: z.string().regex(ID_PATTERNS.dlv),
  channel_id: z.string().regex(ID_PATTERNS.chn),
  /** Null for a test alert. */
  incident_id: z.string().regex(ID_PATTERNS.inc).nullable(),
  /** 1 for the first attempt. */
  attempt: z.int().min(1),
  /** `delivered` for a 2xx response, else `failed`. */
  outcome: z.enum(["delivered", "failed"]),
  /** Null when no response arrived (refused, timed out, network error). */
  status_code: z.int().min(100).max(599).nullable(),
  at: z.iso.datetime(),
});
export type AlertDelivery = z.infer<typeof AlertDeliverySchema>;

/** 200 of `POST /v1/alert-channels/:channelId/test`. */
export const TestAlertChannelResponseSchema = z.object({ delivery: AlertDeliverySchema });
export type TestAlertChannelResponse = z.infer<typeof TestAlertChannelResponseSchema>;

/**
 * The JSON body a webhook channel receives, signed in `AR-Signature`. `incident.opened` carries the Incident
 * and its Console link; a `test` alert carries null for both.
 */
export const WebhookAlertPayloadSchema = z
  .object({
    type: z.enum(["incident.opened", "test"]),
    incident: IncidentSchema.nullable(),
    console_url: z.url().nullable(),
  })
  .refine((payload) => payload.type === "test" || (payload.incident !== null && payload.console_url !== null), {
    message: "An incident.opened alert carries the Incident and its Console URL.",
  });
export type WebhookAlertPayload = z.infer<typeof WebhookAlertPayloadSchema>;

// Documented examples, reused by the tests of every workspace. They are synthetic and deeply frozen:
// build a variant by spreading, e.g. `{ ...EXAMPLE_INCIDENT, status: "resolved" }`.

/** The Detection that opened `EXAMPLE_INCIDENT`: 20 blocked requests from one /24 in the App of `EXAMPLE_POLICY`. */
export const EXAMPLE_DETECTION: Detection = deepFreeze({
  id: "dtc_0123456789abcdef01234567",
  rule: "blocked-burst",
  app_id: "app_89abcdef0123456789abcdef",
  environment: "development",
  ip_prefix: "203.0.113.0/24",
  count: 20,
  window_start: "2026-11-10T08:18:00.000Z",
  window_end: "2026-11-10T08:19:59.000Z",
  detected_at: "2026-11-10T08:20:00.000Z",
  canary_id: null,
  origin: null,
});

/** An open Incident holding `EXAMPLE_DETECTION`. */
export const EXAMPLE_INCIDENT: Incident = deepFreeze({
  id: "inc_0123456789abcdef01234567",
  app_id: "app_89abcdef0123456789abcdef",
  environment: "development",
  rule: "blocked-burst",
  severity: "high",
  title: "Blocked burst",
  status: "open",
  ip_prefix: "203.0.113.0/24",
  first_seen: "2026-11-10T08:18:00.000Z",
  last_seen: "2026-11-10T08:19:59.000Z",
  detection_count: 1,
  created_at: "2026-11-10T08:20:00.000Z",
  updated_at: "2026-11-10T08:20:00.000Z",
  canary_id: null,
  build_id: null,
  origin: null,
  advisory_id: null,
});

/** An open Canary Incident: one request used the decoy key of `EXAMPLE_CANARIES`, planted in `EXAMPLE_BUILD`. */
export const EXAMPLE_CANARY_INCIDENT: Incident = deepFreeze({
  id: "inc_89abcdef0123456789abcdef",
  app_id: "app_89abcdef0123456789abcdef",
  environment: "development",
  rule: "canary-touched",
  severity: "high",
  title: "Canary used",
  status: "open",
  ip_prefix: "203.0.113.0/24",
  first_seen: "2026-11-10T09:00:00.000Z",
  last_seen: "2026-11-10T09:00:00.000Z",
  detection_count: 1,
  created_at: "2026-11-10T09:00:01.000Z",
  updated_at: "2026-11-10T09:00:01.000Z",
  canary_id: EXAMPLE_CANARIES[0]?.id ?? null,
  build_id: "bld_0123456789abcdef01234567",
  origin: null,
  advisory_id: null,
});

/** An open clone Incident: a copy of `EXAMPLE_BUILD` reported itself from a foreign origin. No prefix. */
export const EXAMPLE_CLONE_INCIDENT: Incident = deepFreeze({
  id: "inc_fedcba9876543210fedcba98",
  app_id: "app_89abcdef0123456789abcdef",
  environment: "development",
  rule: "clone-origin",
  severity: "high",
  title: "Clone detected",
  status: "open",
  ip_prefix: null,
  first_seen: "2026-11-10T10:00:00.000Z",
  last_seen: "2026-11-10T10:00:00.000Z",
  detection_count: 1,
  created_at: "2026-11-10T10:00:01.000Z",
  updated_at: "2026-11-10T10:00:01.000Z",
  canary_id: null,
  build_id: "bld_0123456789abcdef01234567",
  origin: "https://clone.example",
  advisory_id: null,
});

/**
 * An open vulnerable-component Incident: `EXAMPLE_FINDING` (High) in `EXAMPLE_BUILD`. No prefix: it comes from
 * a Finding, not from traffic.
 */
export const EXAMPLE_FINDING_INCIDENT: Incident = deepFreeze({
  id: "inc_00112233445566778899aabb",
  app_id: EXAMPLE_FINDING.app_id,
  environment: EXAMPLE_FINDING.environment,
  rule: "vulnerable-component",
  severity: "high",
  title: "Vulnerable component",
  status: "open",
  ip_prefix: null,
  first_seen: "2026-11-10T08:30:01.000Z",
  last_seen: "2026-11-10T08:30:01.000Z",
  detection_count: 1,
  created_at: "2026-11-10T08:30:02.000Z",
  updated_at: "2026-11-10T08:30:02.000Z",
  canary_id: null,
  build_id: EXAMPLE_FINDING.build_id,
  origin: null,
  advisory_id: EXAMPLE_FINDING.advisory_id,
});

/** A webhook channel as the API returns it: host and last 4 characters only, never the URL. */
export const EXAMPLE_ALERT_CHANNEL: AlertChannel = deepFreeze({
  id: "chn_0123456789abcdef01234567",
  kind: "webhook",
  name: "Ops webhook",
  host: "hooks.example.com",
  url_last4: "k/ar",
  active: true,
  created_at: "2026-11-10T08:00:00.000Z",
});
