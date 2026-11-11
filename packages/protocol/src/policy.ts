// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { ATTESTATION_LIMITS, BundleAttestationKeySchema } from "./attestation.ts";
import { CANARY_LIMITS, CanarySchema } from "./canaries.ts";
import { DECISION_MODES, ENVIRONMENTS, ID_PATTERNS } from "./constants.ts";
import { ActorHashSchema, CidrSchema, CONTAINMENT_LIMITS } from "./containment.ts";
import { IP_PREFIX_PATTERN } from "./events.ts";
import { BundlePatchSchema, PATCH_LIMITS } from "./patches.ts";
import { deepFreeze, HttpMethodSchema, RULE_PATH_MAX, RULE_PATH_PATTERN, trimmedText } from "./shared.ts";

// The Policy contract: Rules as the Console sends and the API stores them (plain, with a requirement, or with a
// limit), and the signed bundle Shield applies. Every object schema is a plain `z.object`, which strips unknown keys. Shield validates the
// bundle by hand, without zod: a bound that changes here must change in Shield as well.

/**
 * What a Rule does to a matching request. `throttle` (slice 08) is the action of a Rule with a `limit`, and of no
 * other Rule: the request is refused only while its client is over the limit.
 */
export const RULE_ACTIONS = ["block", "throttle"] as const;
export type RuleAction = (typeof RULE_ACTIONS)[number];

/**
 * What a Rule may require of a matching request (slice 04). A Rule with a requirement matches only when the
 * requirement is NOT met: for `signature`, a signature status other than valid, or a body neither checked nor
 * absent. Such a Rule travels in the bundle's `signature_rules`, never in `rules` (plan 04 amendment A1).
 */
export const RULE_REQUIREMENTS = ["signature"] as const;
export type RuleRequirement = (typeof RULE_REQUIREMENTS)[number];

export const POLICY_LIMITS = {
  /** Rules per Policy. */
  rulesMax: 50,
  /** Characters of a path pattern. */
  pathMax: RULE_PATH_MAX,
  /** Methods per Rule. An empty list means every method. */
  methodsMax: 8,
  /** Characters of a Rule name, after trimming. */
  nameMax: 80,
  /** Bytes of a bundle string. */
  bundleBytesMax: 65_536,
  /** Versions returned by the version list. */
  versionsListed: 20,
} as const;

/** The whole body of a block response (status 403, `content-type: application/json`). */
export const BLOCK_RESPONSE_BODY = '{"error":"request_blocked"}';

// Limits (slice 08, D-063). Shield mirrors these constants: a value that changes here must change in Shield as well.

/**
 * What a limit counts per: `ip` is the client address as Shield derives it (IPv6 by /64); `device` is the attested
 * device when the Attestation Token is valid, else the address.
 */
export const LIMIT_KEYS = deepFreeze(["ip", "device"] as const);
export type LimitKey = (typeof LIMIT_KEYS)[number];

/**
 * What a limit counts: `requests` counts every matching request when it is decided; `failures` counts the responses
 * that close with a status of `LIMIT_FAILURE_STATUSES`.
 */
export const LIMIT_COUNTS = deepFreeze(["requests", "failures"] as const);
export type LimitCount = (typeof LIMIT_COUNTS)[number];

export const LIMIT_LIMITS = deepFreeze({
  /** Largest `requests` of a limit; the smallest is 1. */
  requestsMax: 100_000,
  /** Largest `window_s` of a limit, in seconds; the smallest is 1. */
  windowSecondsMax: 3_600,
} as const);

/** The response statuses a `count: "failures"` limit counts. Fixed in slice 08: a Rule cannot choose them. */
export const LIMIT_FAILURE_STATUSES = deepFreeze([401, 403] as const);

/** The whole body of a throttle response (status 429 with `Retry-After`, `content-type: application/json`). */
export const RATE_LIMITED_RESPONSE_BODY = '{"error":"rate_limited"}';

/**
 * A path pattern of 1..256 characters: `/` alone, or `/`-separated segments without a trailing slash.
 * A segment is literal text over `A-Z a-z 0-9 . _ ~ -`, or a single star (exactly one segment), or, as the
 * last segment only, two stars (zero or more segments). Examples: `/login`, `/api/admin/**`, and
 * `/api/users/` + star + `/export`. Defined in shared.ts, which patches.ts (Virtual patches) shares.
 */
export const PATH_PATTERN = RULE_PATH_PATTERN;

const BASE64URL_ED25519_SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const BASE64URL_ED25519_PUBLIC_KEY = /^[A-Za-z0-9_-]{43}$/;

const AppIdSchema = z.string().regex(ID_PATTERNS.app);
const EnvironmentSchema = z.enum(ENVIRONMENTS);
const VersionSchema = z.int().min(0);
const PublishedVersionSchema = z.int().min(1);
const RuleCountSchema = z.int().min(0).max(POLICY_LIMITS.rulesMax);
/** The first 16 hex characters of the SHA-256 of the raw public key (`keyIdOf` of the server entry). */
const KeyIdSchema = z.string().regex(/^[0-9a-f]{16}$/);

/**
 * The limit of a Rule (slice 08): at most `requests` per sliding window of `window_s` seconds, counted per `key`.
 * With `count: "failures"` only failed responses count, and a request is refused once the failures in the window
 * reach `requests`. As a client sends it and as the API stores it, `count` defaults to requests.
 */
const RuleLimitSchema = z.object({
  requests: z.int().min(1).max(LIMIT_LIMITS.requestsMax),
  window_s: z.int().min(1).max(LIMIT_LIMITS.windowSecondsMax),
  key: z.enum(LIMIT_KEYS),
  count: z.enum(LIMIT_COUNTS).default("requests"),
});
export type RuleLimit = z.infer<typeof RuleLimitSchema>;

/** The members of a Rule, before the checks that span members (`checkRuleLimit`). */
const PolicyRuleObjectSchema = z.object({
  id: z.string().regex(ID_PATTERNS.rul),
  /** Shown in the Console only: a name is not part of the bundle. */
  name: trimmedText(POLICY_LIMITS.nameMax),
  path: z
    .string()
    .regex(
      PATH_PATTERN,
      `Must be a path pattern of at most ${POLICY_LIMITS.pathMax} characters, such as /api/admin/**: literal segments, * for one segment, a final ** for everything below.`,
    ),
  /** The methods the Rule applies to, each once; an empty list means every method. */
  methods: z
    .array(HttpMethodSchema)
    .max(POLICY_LIMITS.methodsMax)
    .refine((methods) => new Set(methods).size === methods.length, "Must not list a method twice."),
  action: z.enum(RULE_ACTIONS),
  mode: z.enum(DECISION_MODES),
  /**
   * Optional (slice 04): absent means no requirement. Policy level only: a bundle entry never carries it, the
   * API puts a Rule with a requirement in `signature_rules` instead.
   */
  requires: z.enum(RULE_REQUIREMENTS).optional(),
  /**
   * Optional (slice 08): absent means no limit. A Rule has a limit exactly when its action is throttle, and a Rule
   * with a limit has no requirement. The API puts such a Rule in the bundle's `limit_rules`, never in `rules`.
   */
  limit: RuleLimitSchema.optional(),
});

/**
 * The checks of slice 08 that span members: limit present ⇔ action throttle, and never a limit beside a
 * requirement. The messages name no value of the Rule.
 */
function checkRuleLimit(
  rule: { action: RuleAction; requires?: RuleRequirement | undefined; limit?: RuleLimit | undefined },
  ctx: z.RefinementCtx,
): void {
  const hasLimit = rule.limit !== undefined;
  if (hasLimit && rule.action !== "throttle") {
    ctx.addIssue({ code: "custom", path: ["action"], message: "A Rule with a limit must have the action throttle." });
  }
  if (!hasLimit && rule.action === "throttle") {
    ctx.addIssue({ code: "custom", path: ["limit"], message: "A Rule with the action throttle must have a limit." });
  }
  if (hasLimit && rule.requires !== undefined) {
    ctx.addIssue({
      code: "custom",
      path: ["requires"],
      message: "A Rule must not have both a requirement and a limit.",
    });
  }
}

/** One Rule of a Policy, complete: as the API stores and returns it. */
export const PolicyRuleSchema = PolicyRuleObjectSchema.superRefine(checkRuleLimit);
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

/**
 * A Rule as a client sends it for publishing. Without `id` the API assigns one; `methods` defaults to every
 * method and `mode` to monitor. `action` defaults to throttle when a `limit` is sent and to block otherwise
 * (slice 08), so the default never contradicts the limit; an action that is sent is checked as it is.
 * The defaulting is a transform: this schema has no `.shape`, `.extend` or `.omit`.
 */
export const PolicyRuleInputSchema = PolicyRuleObjectSchema.extend({
  id: PolicyRuleObjectSchema.shape.id.optional(),
  methods: PolicyRuleObjectSchema.shape.methods.default([]),
  action: PolicyRuleObjectSchema.shape.action.optional(),
  mode: PolicyRuleObjectSchema.shape.mode.default("monitor"),
})
  .transform((rule) => ({
    ...rule,
    action: rule.action ?? (rule.limit === undefined ? ("block" as const) : ("throttle" as const)),
  }))
  .superRefine(checkRuleLimit);
/** What a client may send: only `name` and `path` are required. */
export type PolicyRuleInput = z.input<typeof PolicyRuleInputSchema>;
/** What the API works with after parsing: everything is set except, possibly, `id`. */
export type ParsedPolicyRuleInput = z.infer<typeof PolicyRuleInputSchema>;

/** Body of `PUT /v1/apps/:appId/policies/:environment`: the Rules of the next version, in order. */
export const PublishPolicyRequestSchema = z.object({
  rules: z.array(PolicyRuleInputSchema).max(POLICY_LIMITS.rulesMax),
  /**
   * The version this edit was based on. When given and no longer current, the API refuses the publish (409)
   * instead of silently undoing someone else's change.
   */
  expected_version: z.int().min(0).optional(),
  /**
   * Acknowledges that an Enforce Rule with a broad pattern (see `isBroadPattern`) may block most of the App's
   * traffic. Without it the API refuses such a publish. The pattern of a lone double star in Enforce mode is
   * refused even with it.
   */
  allow_broad: z.boolean().optional(),
});
export type PublishPolicyRequestInput = z.input<typeof PublishPolicyRequestSchema>;
export type PublishPolicyRequest = z.infer<typeof PublishPolicyRequestSchema>;

/** The Policy of one App and Environment. Version 0 is the built-in Policy: no Rules, never published. */
export const PolicySchema = z.object({
  app_id: AppIdSchema,
  environment: EnvironmentSchema,
  version: VersionSchema,
  rules: z.array(PolicyRuleSchema).max(POLICY_LIMITS.rulesMax),
  published_at: z.iso.datetime().nullable(),
});
export type Policy = z.infer<typeof PolicySchema>;

/** 200 of `GET` and 201 of `PUT /v1/apps/:appId/policies/:environment`, 201 of `.../rollback`. */
export const PolicyResponseSchema = z.object({ policy: PolicySchema });
export type PolicyResponse = z.infer<typeof PolicyResponseSchema>;

/** 200 of `GET /v1/apps/:appId/policies/:environment/versions`: newest first, at most 20. */
export const PolicyVersionsResponseSchema = z.object({
  versions: z
    .array(
      z.object({
        version: PublishedVersionSchema,
        published_at: z.iso.datetime(),
        rule_count: RuleCountSchema,
        /** How many of the Rules are in Enforce mode. */
        enforced_count: RuleCountSchema,
      }),
    )
    .max(POLICY_LIMITS.versionsListed),
});
export type PolicyVersionsResponse = z.infer<typeof PolicyVersionsResponseSchema>;
export type PolicyVersionSummary = PolicyVersionsResponse["versions"][number];

/** Body of `POST /v1/apps/:appId/policies/:environment/rollback`: the published version whose Rules return. */
export const RollbackPolicyRequestSchema = z.object({
  version: PublishedVersionSchema,
  /** As on a publish: the version the rollback was decided on; a stale one is refused with 409. */
  expected_version: z.int().min(0).optional(),
  /** As on a publish: acknowledges broad Enforce Rules in the version brought back. */
  allow_broad: z.boolean().optional(),
});

/**
 * A pattern whose first segment is a wildcard (a single star, or a double star): enforced, it blocks most or
 * all of an App's traffic. The owner decided on 2026-11-10 that enforcing one needs a stronger confirmation.
 */
export function isBroadPattern(path: string): boolean {
  const first = path.split("/")[1];
  return first === "*" || first === "**";
}
export type RollbackPolicyRequest = z.infer<typeof RollbackPolicyRequestSchema>;

const BlockIdSchema = z.string().regex(ID_PATTERNS.cnt);

/**
 * One active Containment as Shield enforces it: its id (recorded in the Event), what it blocks and when it
 * ends. Shield stops enforcing at `expires_at` by its own clock, also when it cannot reach the API.
 */
const BundleBlockSchema = z.discriminatedUnion("kind", [
  z.object({ id: BlockIdSchema, kind: z.literal("actor"), ip_hash: ActorHashSchema, expires_at: z.iso.datetime() }),
  z.object({
    id: BlockIdSchema,
    kind: z.literal("prefix"),
    ip_prefix: z.string().regex(IP_PREFIX_PATTERN),
    expires_at: z.iso.datetime(),
  }),
]);
export type BundleBlock = z.infer<typeof BundleBlockSchema>;

/**
 * A Rule as a bundle carries it: without its name (shown in the Console only) and without `requires` (the member
 * it sits in says that). An older Shield would read a `requires` it does not know as a plain block Rule, so a
 * bundle entry never has one: the schema strips it.
 */
const BundleRuleSchema = PolicyRuleObjectSchema.omit({ name: true, requires: true }).extend({
  /** Block only: a throttle Rule travels in `limit_rules` (slice 08). */
  action: z.literal("block"),
  /**
   * Never present (slice 08): an entry of `rules` or `signature_rules` that carries a limit is refused, not
   * stripped, so a limit Rule put in the wrong member can never be enforced as a plain block.
   */
  limit: z.never("A Rule with a limit belongs in limit_rules.").optional(),
});

/**
 * A limit Rule as a bundle carries it (slice 08): a bundle Rule with the action throttle and its limit, complete —
 * a bundle has no defaults, so `count` is always written.
 */
const BundleLimitRuleSchema = PolicyRuleObjectSchema.omit({ name: true, requires: true }).extend({
  action: z.literal("throttle"),
  limit: RuleLimitSchema.extend({ count: z.enum(LIMIT_COUNTS) }),
});

/**
 * What a bundle string holds once parsed as JSON. The signature covers the string exactly as transmitted,
 * so verify first and parse afterwards, and never serialise a payload again to check a signature.
 */
export const BundlePayloadSchema = z
  .object({
    format: z.literal(1),
    /** The first 32 hex characters of the SHA-256 of the Shield key (`bundleAudience` of the server entry). */
    audience: z.string().regex(/^[0-9a-f]{32}$/),
    /**
     * Random per database of the API. Versions are comparable only within one epoch: after a reset of the
     * database the versions restart, and Shield accepts the new epoch instead of refusing it as a replay.
     */
    epoch: z.string().regex(/^[0-9a-f]{32}$/),
    app_id: AppIdSchema,
    environment: EnvironmentSchema,
    version: VersionSchema,
    issued_at: z.iso.datetime(),
    /** `issued_at` plus 7 days. After it Shield reports the Policy as stale. */
    not_after: z.iso.datetime(),
    /** The Rules without a requirement and without a limit, in order, without their names. */
    rules: z.array(BundleRuleSchema).max(POLICY_LIMITS.rulesMax),
    /**
     * The Rules that require a signed request (`requires: "signature"` in the Policy), in Policy order, in the
     * form of `rules` (plan 04 amendment A1). Optional: a bundle from before slice 04 has none, and an older Shield
     * strips the field, so it never turns a requirement into a plain block. Together with `rules` and
     * `limit_rules` at most `POLICY_LIMITS.rulesMax`.
     */
    signature_rules: z.array(BundleRuleSchema).max(POLICY_LIMITS.rulesMax).optional(),
    /**
     * The Rules with a limit (action throttle), in Policy order, each a bundle Rule plus its `limit` (slice 08).
     * Optional: a bundle from before slice 08 has none, and an older Shield strips the field, so it never turns a
     * limit into a plain block. Shield applies them after `rules` and `signature_rules`, in this order. Together
     * with `rules` and `signature_rules` at most `POLICY_LIMITS.rulesMax`.
     */
    limit_rules: z.array(BundleLimitRuleSchema).max(POLICY_LIMITS.rulesMax).optional(),
    /**
     * The active Canaries of the App and Environment (those of its most recent `CANARY_LIMITS.buildsInBundle`
     * Builds). Optional: a bundle from before slice 07 has none, and an older Shield strips the field.
     */
    canaries: z.array(CanarySchema).max(CANARY_LIMITS.perBundle).optional(),
    /**
     * The active Containments of the App and Environment. Optional: a bundle from before slice 09 has none,
     * and an older Shield strips the field.
     */
    blocks: z.array(BundleBlockSchema).max(CONTAINMENT_LIMITS.activePerAppEnv).optional(),
    /**
     * The Organization's never-block ranges as canonical CIDRs: a client address inside one is never blocked
     * by a Containment. Optional, as `blocks`.
     */
    allowlist: z.array(CidrSchema).max(CONTAINMENT_LIMITS.allowlistMax).optional(),
    /**
     * The public halves of the API's attestation keys (previous, current, next), each kid once: Shield verifies
     * Attestation Tokens with these and no other key. Optional: a bundle from before slice 03 has none, and an older
     * Shield strips the field.
     */
    attestation_keys: z
      .array(BundleAttestationKeySchema)
      .max(ATTESTATION_LIMITS.keysMax)
      .refine((keys) => new Set(keys.map((key) => key.kid)).size === keys.length, "Must not list a kid twice.")
      .optional(),
    /**
     * The active Virtual patches of the App and Environment (slice 20), each id once, each in the mode the admin
     * chose (monitor until promoted), at most `PATCH_LIMITS.bundleBytesMax` UTF-8 bytes as JSON together (the API
     * ships them by severity, then id, within that budget). Optional: a bundle from before slice 20 has none, and an older Shield strips
     * the field.
     */
    patches: z
      .array(BundlePatchSchema)
      .max(PATCH_LIMITS.perBundle)
      .refine(
        (patches) => new Set(patches.map((patch) => patch.id)).size === patches.length,
        "Must not list a patch twice.",
      )
      .refine(
        (patches) => new TextEncoder().encode(JSON.stringify(patches)).length <= PATCH_LIMITS.bundleBytesMax,
        `Patches hold at most ${PATCH_LIMITS.bundleBytesMax} bytes of JSON together.`,
      )
      .optional(),
  })
  .refine((payload) => payload.rules.length + (payload.signature_rules?.length ?? 0) <= POLICY_LIMITS.rulesMax, {
    message: `rules and signature_rules hold at most ${POLICY_LIMITS.rulesMax} Rules together.`,
    path: ["signature_rules"],
  })
  .refine(
    (payload) =>
      payload.limit_rules === undefined ||
      payload.rules.length + (payload.signature_rules?.length ?? 0) + payload.limit_rules.length <=
        POLICY_LIMITS.rulesMax,
    {
      message: `rules, signature_rules and limit_rules hold at most ${POLICY_LIMITS.rulesMax} Rules together.`,
      path: ["limit_rules"],
    },
  );
export type BundlePayload = z.infer<typeof BundlePayloadSchema>;
export type BundleRule = BundlePayload["rules"][number];
/** An entry of `limit_rules`. */
export type BundleLimitRule = NonNullable<BundlePayload["limit_rules"]>[number];

/** 200 of `GET /v1/policy-bundle`. */
export const SignedBundleSchema = z.object({
  /** The JSON text of a `BundlePayload`. A bundle is ASCII, so its characters are its bytes. */
  bundle: z.string().min(1).max(POLICY_LIMITS.bundleBytesMax),
  /** Ed25519 over the UTF-8 bytes of `bundle`: 64 bytes as 86 base64url characters. */
  signature: z.string().regex(BASE64URL_ED25519_SIGNATURE),
  key_id: KeyIdSchema,
});
export type SignedBundle = z.infer<typeof SignedBundleSchema>;

/** 200 of `GET /v1/signing-key`: the public key Shield is configured with. */
export const SigningKeyResponseSchema = z.object({
  key_id: KeyIdSchema,
  algorithm: z.literal("Ed25519"),
  /** The raw public key: 32 bytes as 43 base64url characters. */
  public_key: z.string().regex(BASE64URL_ED25519_PUBLIC_KEY),
});
export type SigningKeyResponse = z.infer<typeof SigningKeyResponseSchema>;

// Documented examples, reused by the tests of every workspace. They are synthetic and deeply frozen:
// build a variant by spreading, e.g. `{ ...EXAMPLE_POLICY_RULE, mode: "monitor" }`.

/** A valid Rule: every method of everything below `/api/admin` is blocked. */
export const EXAMPLE_POLICY_RULE: PolicyRule = deepFreeze({
  id: "rul_0123456789abcdef01234567",
  name: "Admin area",
  path: "/api/admin/**",
  methods: [],
  action: "block",
  mode: "enforce",
});

/**
 * A valid limit Rule (slice 08), the Console's "Login protection" preset: more than 10 failed responses (401 or
 * 403) per 5 minutes from one address throttle `POST /login`; in Monitor mode until promoted. Not part of
 * `EXAMPLE_POLICY` or `EXAMPLE_BUNDLE_PAYLOAD`; in a bundle it goes in `limit_rules`, without its name.
 */
export const EXAMPLE_LIMIT_RULE = deepFreeze({
  id: "rul_fedcba9876543210fedcba98",
  name: "Login protection",
  path: "/login",
  methods: ["POST"],
  action: "throttle",
  mode: "monitor",
  limit: { requests: 10, window_s: 300, key: "ip", count: "failures" },
}) satisfies PolicyRule;

/** A published Policy of the App of `EXAMPLE_STORED_EVENT`: `EXAMPLE_POLICY_RULE`, then a Rule in Monitor mode. */
export const EXAMPLE_POLICY: Policy = deepFreeze({
  app_id: "app_89abcdef0123456789abcdef",
  environment: "development",
  version: 1,
  rules: [
    EXAMPLE_POLICY_RULE,
    {
      id: "rul_89abcdef0123456789abcdef",
      name: "User export",
      path: "/api/users/*/export",
      methods: ["GET", "POST"],
      action: "block",
      mode: "monitor",
    },
  ],
  published_at: "2026-11-10T08:00:00.000Z",
});

/**
 * `EXAMPLE_POLICY` as the payload of a bundle. `audience` is `bundleAudience` of the synthetic Shield key
 * `ark_dev_` followed by 43 times `A`.
 */
export const EXAMPLE_BUNDLE_PAYLOAD: BundlePayload = deepFreeze({
  format: 1,
  audience: "722d2433364dcb8f1ad3cea20a184a41",
  epoch: "fedcba9876543210fedcba9876543210",
  app_id: EXAMPLE_POLICY.app_id,
  environment: EXAMPLE_POLICY.environment,
  version: EXAMPLE_POLICY.version,
  issued_at: "2026-11-10T08:00:01.000Z",
  not_after: "2026-11-17T08:00:01.000Z",
  // Both Rules of `EXAMPLE_POLICY` are plain block Rules: a Rule with a limit would go in `limit_rules`.
  rules: EXAMPLE_POLICY.rules.map(({ id, path, methods, mode }) => ({ id, path, methods, action: "block", mode })),
});
