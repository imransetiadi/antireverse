// Isomorphic: this module is safe for browsers. It must not import a Node built-in.

/** Version of the wire contract between Shield and the API. Sent as `protocol` in every batch. */
export const PROTOCOL_VERSION = 1;

export const ENVIRONMENTS = ["production", "staging", "development"] as const;
export type Environment = (typeof ENVIRONMENTS)[number];

/** The `request.route` of a request that matched no route template. */
export const UNMATCHED_ROUTE = "(unmatched)";

export const LIMITS = {
  /** Events per batch. */
  batchMax: 500,
  /** Bytes of an ingest request body. */
  bodyBytesMax: 262_144,
  /** Characters of `request.route`. */
  routeMax: 256,
  /** Characters of an Organization or App name, after trimming. */
  nameMax: 80,
  /** Events returned by the Event list when no `limit` is given. */
  listDefault: 50,
  /** Largest `limit` of the Event list. */
  listMax: 200,
  /** Concurrent live streams per Organization. */
  streamsPerOrganization: 20,
} as const;

export const DECISION_ACTIONS = ["allow", "monitor", "challenge", "throttle", "block", "deceive"] as const;
export type DecisionAction = (typeof DECISION_ACTIONS)[number];

export const DECISION_MODES = ["monitor", "enforce"] as const;
export type DecisionMode = (typeof DECISION_MODES)[number];

/** Identifiers are `<prefix>_<24 lowercase hex characters>` (12 random bytes). */
export const ID_PATTERNS = {
  org: /^org_[0-9a-f]{24}$/,
  app: /^app_[0-9a-f]{24}$/,
  key: /^key_[0-9a-f]{24}$/,
  rul: /^rul_[0-9a-f]{24}$/,
  bld: /^bld_[0-9a-f]{24}$/,
  inc: /^inc_[0-9a-f]{24}$/,
  dtc: /^dtc_[0-9a-f]{24}$/,
  chn: /^chn_[0-9a-f]{24}$/,
  dlv: /^dlv_[0-9a-f]{24}$/,
  cny: /^cny_[0-9a-f]{24}$/,
  cnt: /^cnt_[0-9a-f]{24}$/,
  alw: /^alw_[0-9a-f]{24}$/,
  fnd: /^fnd_[0-9a-f]{24}$/,
  /** A Verified Target (slice 14). */
  tgt: /^tgt_[0-9a-f]{24}$/,
  /** A signed Rules of Engagement version (slice 14). */
  roe: /^roe_[0-9a-f]{24}$/,
  /** A recipient of an email alert channel (slice 06b). */
  rcp: /^rcp_[0-9a-f]{24}$/,
  /** A Reverse Assessment (slice 12a). */
  asm: /^asm_[0-9a-f]{24}$/,
  /** An audit entry (slice 18a). */
  aud: /^aud_[0-9a-f]{24}$/,
} as const;
export type IdPrefix = keyof typeof ID_PATTERNS;

/**
 * An actor hash: `iph_` followed by 32 lowercase hex characters, the keyed hash of a client address
 * (`actorHash` of the server entry). It is derived, never generated, so it is not one of `ID_PATTERNS`.
 */
export const ACTOR_HASH_PATTERN = /^iph_[0-9a-f]{32}$/;

/** The Environment as it appears inside a Shield key: `ark_<tag>_<secret>`. */
export const SHIELD_KEY_ENVIRONMENT_TAGS = {
  production: "prod",
  staging: "stg",
  development: "dev",
} as const satisfies Record<Environment, string>;

/** Admin key: `aro_` followed by 32 random bytes as 43 base64url characters. */
export const ADMIN_KEY_PATTERN = /^aro_[A-Za-z0-9_-]{43}$/;

/** Shield key: `ark_<prod|stg|dev>_` followed by 32 random bytes as 43 base64url characters. */
export const SHIELD_KEY_PATTERN = /^ark_(prod|stg|dev)_[A-Za-z0-9_-]{43}$/;
