// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { EventAttestationSchema } from "./attestation.ts";
import {
  ACTOR_HASH_PATTERN,
  DECISION_ACTIONS,
  DECISION_MODES,
  ENVIRONMENTS,
  ID_PATTERNS,
  LIMITS,
  PROTOCOL_VERSION,
} from "./constants.ts";
import { PATCH_BODY_STATES, PATCH_ID_PATTERN } from "./patches.ts";
import { deepFreeze, HttpMethodSchema, isoDateTime, text } from "./shared.ts";
import { EventSignatureSchema } from "./signature.ts";

// Every object schema below is a plain `z.object`, which strips unknown keys. That is the privacy
// allowlist: a key that is not named here never reaches storage. The allowlist covers values too: free text is
// bounded and storable (no control characters, no lone surrogates: `text` in shared.ts), and the only network
// information that passes is a /24 or /48 prefix and the keyed hash of the address (`iph_` and 32 hex
// characters), which only the holder of the Shield key can compute.

const OCTET = "(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
/** IPv4 `a.b.c.0/24`, or IPv6 as three lowercase groups without leading zeros followed by `::/48`. */
export const IP_PREFIX_PATTERN = new RegExp(
  `^(?:${OCTET}\\.${OCTET}\\.${OCTET}\\.0/24|(?:0|[1-9a-f][0-9a-f]{0,3}):(?:0|[1-9a-f][0-9a-f]{0,3}):(?:0|[1-9a-f][0-9a-f]{0,3})::/48)$`,
);

const RequestSchema = z.object({
  /** The HTTP method in uppercase, e.g. `GET`. */
  method: HttpMethodSchema,
  /** The route template, or `UNMATCHED_ROUTE`. Never the concrete URL. */
  route: text(LIMITS.routeMax).min(1),
  status: z.int().min(100).max(599),
  latency_ms: z.number().min(0).max(600_000),
});

const DecisionSchema = z.object({
  /**
   * `throttle` (slice 08) is the decision of a limit Rule whose client is over the limit: `rule_id` names the Rule,
   * `mode` is the Rule's (enforce: answered 429; monitor: the response is unchanged), and `containment_id` and
   * `patch_id` are null. The value has been part of `DECISION_ACTIONS` since slice 01, so Events of every age parse.
   */
  action: z.enum(DECISION_ACTIONS),
  mode: z.enum(DECISION_MODES),
  rule_id: text(64).min(1).nullable(),
  policy_version: z.int().min(0),
  /**
   * The Containment that blocked the request (then `action` is block, `mode` enforce and `rule_id` null);
   * null otherwise. Optional on the wire: a Shield from before slice 09 does not send it, and absent means null.
   */
  containment_id: z.string().regex(ID_PATTERNS.cnt).nullable().default(null),
  /**
   * The Virtual patch that decided the request (slice 20); null otherwise. A patch decision has `action` block,
   * `mode` as the bundle shipped the patch (monitor or enforce), `rule_id` null and `containment_id` null — except a
   * patch whose body was never checked (`patch_body` "unchecked", amendment A6 F2): it did not block, so `action` is
   * allow and `mode` monitor, and it never counts as an exploit attempt or a hit. As for
   * `containment_id`, the schema does not enforce that combination. Optional on the wire: a Shield from before
   * slice 20 does not send it, and absent means null.
   */
  patch_id: z.string().regex(PATCH_ID_PATTERN).nullable().default(null),
  /**
   * Whether the body condition of the patch in `patch_id` was checked (`verifyBody`) or not ("unchecked": the patch
   * was recorded with action allow, mode monitor, and the request passed); null when `patch_id` is null. A patch without a body condition records
   * "checked". As for `patch_id`, the schema does not enforce the combination. Optional on the wire: absent means
   * null.
   */
  patch_body: z.enum(PATCH_BODY_STATES).nullable().default(null),
  /**
   * The failure-counting limit Rule (a `limit_rules` entry with `count: "failures"`, slice 08 amendment A7) that
   * matched the request; null otherwise. Set whether or not it throttled: on a request the application answered (a
   * 401 or 403 it counted, or any other status) and on a request that Rule refused (then also `rule_id`). With more
   * than one such Rule matching, the first in bundle order. Detection counts Credential stuffing from it (D-064).
   * Shield sends it always (an id or null). Absent — a Shield from before amendment A7 — stays absent when parsed,
   * so that Detection can tell an older Shield (it falls back to its coverage guess) from a Shield that found no
   * such Rule (null).
   */
  limit_rule_id: z.string().regex(ID_PATTERNS.rul).nullable().optional(),
});

/**
 * The random id of the Shield process that sent an Event (slice 11, amendment A9): 32 lowercase hex characters, the
 * same id the process sends with its component inventory. Limit counters live in one Shield process, so a replay of
 * limit Rules counts per instance id and client.
 */
export const SHIELD_INSTANCE_ID_PATTERN = /^[0-9a-f]{32}$/;

const ActorSchema = z.object({
  /** IPv4 `a.b.c.0/24` or IPv6 `a:b:c::/48`; null when the address is unknown. */
  ip_prefix: z.string().regex(IP_PREFIX_PATTERN).nullable(),
  /**
   * The actor hash of the client address (`actorHash` of the server entry, the same form as `ActorHashSchema`
   * of containment.ts); null when the address is unknown. Optional on the wire: a Shield from before slice 09
   * does not send it, and absent means null.
   */
  ip_hash: z.string().regex(ACTOR_HASH_PATTERN).nullable().default(null),
});

const SignalSchema = z.object({
  id: text(64).min(1),
  confidence: z.number().min(0).max(1),
});

/**
 * One Event as Shield sends it. The inferred type is the parsed form: `actor.ip_hash`,
 * `decision.containment_id`, `decision.patch_id`, `decision.patch_body`, `attestation` and `signature` are always present (null when an older Shield left
 * them out).
 */
export const ShieldEventSchema = z.object({
  event_id: z.uuidv7(),
  /** ISO-8601 UTC datetime, the form `Date#toISOString` produces. */
  ts: isoDateTime(),
  type: z.literal("request.decision"),
  surface: z.literal("api"),
  request: RequestSchema,
  decision: DecisionSchema,
  actor: ActorSchema,
  signals: z.array(SignalSchema).max(32),
  /**
   * The Attestation Token of the request as Shield verified it (slice 03); null when a Shield from before slice 03
   * sent the Event (absent means null). Never the token itself.
   */
  attestation: EventAttestationSchema.nullable().default(null),
  /**
   * The request signature as Shield verified it, and whether the body was bound (slice 04); null when a Shield
   * from before slice 04 sent the Event (absent means null). Never the header, the nonce or the hash.
   */
  signature: EventSignatureSchema.nullable().default(null),
  /**
   * The Shield process that sent the Event (amendment A9): `SHIELD_INSTANCE_ID_PATTERN`, one id per process for its
   * lifetime. Shield sends it on every Event. A Shield from before A9 does not; absent stays absent when parsed (no
   * default), so a reader can tell such an Event apart and never assume which process counted it.
   */
  instance_id: z.string().regex(SHIELD_INSTANCE_ID_PATTERN).optional(),
});
export type ShieldEvent = z.infer<typeof ShieldEventSchema>;

/** The body of `POST /v1/events`. */
export const EventBatchSchema = z.object({
  protocol: z.literal(PROTOCOL_VERSION),
  sdk: z.object({ name: text(32), version: text(32) }),
  events: z.array(ShieldEventSchema).min(1).max(LIMITS.batchMax),
});
export type EventBatch = z.infer<typeof EventBatchSchema>;

/** An Event as the API stores and returns it: Organization, App and Environment come from the Shield key. */
export const StoredEventSchema = ShieldEventSchema.extend({
  organization_id: z.string().regex(ID_PATTERNS.org),
  app_id: z.string().regex(ID_PATTERNS.app),
  environment: z.enum(ENVIRONMENTS),
  received_at: z.iso.datetime(),
});
export type StoredEvent = z.infer<typeof StoredEventSchema>;

// Documented examples, reused by the tests of every workspace. They are synthetic and deeply frozen:
// build a variant by spreading, e.g. `{ ...EXAMPLE_SHIELD_EVENT, request: { ...EXAMPLE_SHIELD_EVENT.request, status: 404 } }`.

/** A valid Event exactly as Shield sends it in Monitor mode. `event_id` carries the same instant as `ts`. */
export const EXAMPLE_SHIELD_EVENT: ShieldEvent = deepFreeze({
  event_id: "01a1c486-c94b-7c3a-9f21-5d8e6a0b1c2d",
  ts: "2026-11-10T08:15:30.123Z",
  type: "request.decision",
  surface: "api",
  request: { method: "GET", route: "/api/products/:id", status: 200, latency_ms: 3.25 },
  decision: {
    action: "allow",
    mode: "monitor",
    rule_id: null,
    policy_version: 0,
    containment_id: null,
    patch_id: null,
    patch_body: null,
    limit_rule_id: null,
  },
  actor: { ip_prefix: "203.0.113.0/24", ip_hash: null },
  signals: [],
  attestation: null,
  signature: null,
});

/** A valid body of `POST /v1/events` holding `EXAMPLE_SHIELD_EVENT`. */
export const EXAMPLE_EVENT_BATCH: EventBatch = deepFreeze({
  protocol: PROTOCOL_VERSION,
  sdk: { name: "shield-node", version: "0.0.0" },
  events: [EXAMPLE_SHIELD_EVENT],
});

/** `EXAMPLE_SHIELD_EVENT` as the API returns it after ingest. */
export const EXAMPLE_STORED_EVENT: StoredEvent = deepFreeze({
  ...EXAMPLE_SHIELD_EVENT,
  organization_id: "org_0123456789abcdef01234567",
  app_id: "app_89abcdef0123456789abcdef",
  environment: "development",
  received_at: "2026-11-10T08:15:30.456Z",
});
