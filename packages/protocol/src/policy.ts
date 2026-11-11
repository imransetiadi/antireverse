// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { ATTESTATION_LIMITS, BundleAttestationKeySchema } from "./attestation.ts";
import { CANARY_LIMITS, CanarySchema } from "./canaries.ts";
import { DECISION_MODES, ENVIRONMENTS, ID_PATTERNS } from "./constants.ts";
import { ActorHashSchema, CidrSchema, CONTAINMENT_LIMITS } from "./containment.ts";
import { IP_PREFIX_PATTERN } from "./events.ts";
import { BundlePatchSchema, PATCH_LIMITS } from "./patches.ts";
import { deepFreeze, HttpMethodSchema, RULE_PATH_MAX, RULE_PATH_PATTERN, trimmedText } from "./shared.ts";

// The Policy contract: Rules as the Console sends and the API stores them, and the signed bundle Shield
// applies. Every object schema is a plain `z.object`, which strips unknown keys. Shield validates the
// bundle by hand, without zod: a bound that changes here must change in Shield as well.

/** What a Rule does to a matching request. */
export const RULE_ACTIONS = ["block"] as const;
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

/** One Rule of a Policy, complete: as the API stores and returns it. */
export const PolicyRuleSchema = z.object({
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
});
export type PolicyRule = z.infer<typeof PolicyRuleSchema>;

/**
 * A Rule as a client sends it for publishing. Without `id` the API assigns one; `methods` defaults to
 * every method, `action` to block and `mode` to monitor.
 */
export const PolicyRuleInputSchema = PolicyRuleSchema.extend({
  id: PolicyRuleSchema.shape.id.optional(),
  methods: PolicyRuleSchema.shape.methods.default([]),
  action: PolicyRuleSchema.shape.action.default("block"),
  mode: PolicyRuleSchema.shape.mode.default("monitor"),
});
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
const BundleRuleSchema = PolicyRuleSchema.omit({ name: true, requires: true });

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
    /** The Rules without a requirement, in order, without their names. */
    rules: z.array(BundleRuleSchema).max(POLICY_LIMITS.rulesMax),
    /**
     * The Rules that require a signed request (`requires: "signature"` in the Policy), in Policy order, in the
     * form of `rules` (plan 04 amendment A1). Optional: a bundle from before slice 04 has none, and an older Shield
     * strips the field, so it never turns a requirement into a plain block. Together with `rules` at most
     * `POLICY_LIMITS.rulesMax`.
     */
    signature_rules: z.array(BundleRuleSchema).max(POLICY_LIMITS.rulesMax).optional(),
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
  });
export type BundlePayload = z.infer<typeof BundlePayloadSchema>;
export type BundleRule = BundlePayload["rules"][number];

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
  rules: EXAMPLE_POLICY.rules.map(({ name: _name, ...rule }) => rule),
});
