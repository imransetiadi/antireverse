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
  action: z.enum(DECISION_ACTIONS),
  mode: z.enum(DECISION_MODES),
  rule_id: text(64).min(1).nullable(),
  policy_version: z.int().min(0),
  /**
   * The Containment that blocked the request (then `action` is block, `mode` enforce and `rule_id` null);
   * null otherwise. Optional on the wire: a Shield from before slice 09 does not send it, and absent means null.
   */
  containment_id: z.string().regex(ID_PATTERNS.cnt).nullable().default(null),
});

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
 * `decision.containment_id`, `attestation` and `signature` are always present (null when an older Shield left
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
  decision: { action: "allow", mode: "monitor", rule_id: null, policy_version: 0, containment_id: null },
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
