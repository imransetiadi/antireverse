// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { ATTESTATION_LIMITS, BundleAttestationKeySchema } from "./attestation.ts";
import { CANARY_LIMITS, CanarySchema } from "./canaries.ts";
import { DECISION_MODES, ENVIRONMENTS, ID_PATTERNS, LIMITS } from "./constants.ts";
import { ActorHashSchema, CidrSchema, CONTAINMENT_LIMITS } from "./containment.ts";
import { IP_PREFIX_PATTERN } from "./events.ts";
import { BundlePatchSchema, PATCH_LIMITS } from "./patches.ts";
import { deepFreeze, HttpMethodSchema, RULE_PATH_MAX, RULE_PATH_PATTERN, text, trimmedText } from "./shared.ts";

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

// Policy simulation (slice 11, D-066): the API replays the stored Events of the last 24 hours of one App and
// Environment against draft Rules and reports what the Rules would have done. Nothing is stored or published. The
// result is an estimate: it counts, and never carries a client hash, an address or a concrete path.

export const SIMULATION_LIMITS = deepFreeze({
  /** Hours of stored Events a simulation replays, counted back from the moment it runs. */
  windowHours: 24,
  /** Events replayed at most: the newest ones when the window holds more (then `truncated` is true). */
  eventsMax: 50_000,
  /** Sample routes per Rule in the result. */
  sampleRoutesMax: 5,
  /** Simulations per minute per Organization; one more is refused with 429 and `Retry-After`. */
  perMinute: 6,
  /** Milliseconds a simulation may run; a longer one is cut off with `truncated: true` rather than failing. */
  timeLimitMs: 10_000,
} as const);

/**
 * What a simulation leaves out, as `not_simulated` of a result names it. A later version may name more; a client
 * shows what it knows and must not fail on a value it does not.
 * - `patches`: Virtual patches (slice 20) are not simulated.
 * - `containments`: active blocks of Actors and networks are not applied to the recorded requests.
 * - `decoded_paths`: Shield also matches the decoded and dot-resolved readings of a path; the simulation judges the
 *   recorded route template only.
 * - `device_limits`: an Event stores no device, so a `device` limit is replayed on the address alone and an
 *   attested request past the limit is not judged.
 * - `body_verification`: whether Shield would accept a validly signed request with a body depends on whether its
 *   content type is listed in `bodyVerified` and on the body hook, neither of which an Event records; such a request
 *   is not judged by a signature Rule.
 */
export const SIMULATION_NOT_SIMULATED = deepFreeze([
  "patches",
  "containments",
  "decoded_paths",
  "device_limits",
  "body_verification",
] as const);

/**
 * Body of `POST /v1/apps/:appId/policy/simulate`: the Environment whose Events are replayed and the draft Rules, in
 * Policy order. `rules` is the very schema of a publish (`PublishPolicyRequestSchema`), so a draft that could not
 * be published is refused here as well. The members that only a publish has (`expected_version`, `allow_broad`)
 * are stripped: a simulation publishes nothing.
 */
export const SimulatePolicyRequestSchema = z.object({
  environment: EnvironmentSchema,
  rules: PublishPolicyRequestSchema.shape.rules,
});
/** What a client may send: each Rule as for a publish (only `name` and `path` are required). */
export type SimulatePolicyRequestInput = z.input<typeof SimulatePolicyRequestSchema>;
/** What the API works with after parsing: every Rule complete except, possibly, its `id`. */
export type SimulatePolicyRequest = z.infer<typeof SimulatePolicyRequestSchema>;

/** A count of Events or clients: an integer of 0 or more. */
const CountSchema = z.int().min(0);

/** A route template that Events a Rule would refuse were recorded under, and how many of them. */
const SimulationSampleRouteSchema = z.object({
  /** The route template as the Event stored it (`request.route`). Never the concrete URL. */
  route: text(LIMITS.routeMax).min(1),
  method: HttpMethodSchema,
  /** The Events of this route template and method that the Rule would refuse: at least 1, or the route is no sample. */
  count: z.int().min(1),
});
export type SimulationSampleRoute = z.infer<typeof SimulationSampleRouteSchema>;

/**
 * Refused Events without a client hash are no more than the refused Events, and every client counted has at least
 * one refused Event with a hash.
 */
function checkClients(ctx: z.RefinementCtx, path: string[], refused: number, clients: number, unknown: number): void {
  if (unknown > refused) {
    ctx.addIssue({
      code: "custom",
      path: [...path, "unknown_client_events"],
      message: "Must not be more than the requests that would be refused.",
    });
  } else if (clients > refused - unknown) {
    ctx.addIssue({
      code: "custom",
      path: [...path, "clients_affected"],
      message: "Must not be more than the refused requests that carry a client hash.",
    });
  }
}

/** The members of a Rule's row that can never exceed `matched`. */
const SIMULATION_OUTCOMES = ["would_block", "would_fail_signature", "would_throttle", "already_refused"] as const;

/**
 * What promoting one monitor Rule would do (`if_promoted` of a Rule's row): the outcome of a replay in which the
 * enforced Rules are the draft's Rules in Enforce mode plus this Rule, and every other monitor Rule does nothing —
 * it refuses nothing, and a monitor limit counts nothing that changes another Rule's outcome. Unlike the row's own
 * figures (every Rule enforced, where an earlier Rule takes the requests it covers first), this is what the
 * Console's promote confirmation shows.
 */
const SimulationIfPromotedSchema = z.object({
  /** Events this Rule would refuse once promoted: those no enforced Rule refuses before it. */
  would_refuse: CountSchema,
  /** Distinct clients (actor hashes) among them; Events without a hash are in `unknown_client_events`. */
  clients_affected: CountSchema,
  /** Those of `would_refuse` that carry no client hash. */
  unknown_client_events: CountSchema,
  /** Events this Rule could not be judged for in that replay (route or outcome), as `undecidable` of the row. */
  undecidable: CountSchema,
});
export type SimulationIfPromoted = z.infer<typeof SimulationIfPromotedSchema>;

/**
 * What one draft Rule would have done to the Events replayed. The Rule's mode is ignored: the figures show what
 * Enforce would do. Across Rules the first terminal outcome wins, as in Shield, so an Event is counted as a
 * `would_*` of at most one Rule.
 */
const SimulationRuleResultSchema = z
  .object({
    /** The position of the Rule in the request's `rules`, from 0. Every draft Rule has a row, so it is the row's position too. */
    index: z
      .int()
      .min(0)
      .max(POLICY_LIMITS.rulesMax - 1),
    /** The Rule's id as the request sent it; absent for a draft Rule without one. */
    id: z.string().regex(ID_PATTERNS.rul).optional(),
    /** The Rule's name after trimming, as a publish would store it. */
    name: text(POLICY_LIMITS.nameMax).min(1),
    /**
     * Events whose method and route template matched the Rule. An Event whose route could not be judged is not one;
     * an Event that matched but whose outcome could not be judged is (and is counted in `undecidable` as well).
     */
    matched: CountSchema,
    /** Matched Events a block Rule would refuse with 403. */
    would_block: CountSchema,
    /**
     * Matched Events a `requires: "signature"` Rule would refuse: those whose signature is not valid (missing,
     * invalid, stale, replayed). A valid signature with a body is `undecidable`, never counted here.
     */
    would_fail_signature: CountSchema,
    /**
     * Matched Events a limit Rule would refuse with 429: those over the limit when replayed in time order per
     * client. A lower bound: a request past the limit is counted here only when the claim is certain, and is
     * `undecidable` otherwise (see there).
     */
    would_throttle: CountSchema,
    /**
     * Matched Events that Shield had blocked or throttled when they happened. They never reached the application,
     * so they are not counted again as an outcome of the draft.
     */
    already_refused: CountSchema,
    /**
     * Events the Rule could not be judged for, of two kinds. Never counted as a `would_*`, and not bounded by
     * `matched`.
     *
     * Events whose route could not be judged for this Rule, which are never in `matched`: a route that is not a
     * template of plain segments and parameters (`(unmatched)`, `(mount)/…`, a regular expression, a list of
     * paths, a wildcard or an optional group), and a parameter where the Rule's pattern has a literal.
     *
     * Events that matched but whose outcome could not be judged, which are in `matched` too. For a signature Rule:
     * no recorded signature (an older Shield), a valid signature of a request with a body (checked or not: whether
     * Shield's `bodyVerified` listed its type is not recorded), an OPTIONS request.
     * For a limit Rule: an Event without a client hash; of a network on the never-block list; another Rule may
     * have refused; an OPTIONS request; past a limit above 1,000 (Shield counts those approximately); past the
     * limit only by a request at the very edge of the window; attested and past a `device` limit on its address
     * (an Event stores no device id); or replayed after the simulation held as many request times as it may (then
     * `truncated` is true).
     */
    undecidable: CountSchema,
    /**
     * Distinct clients (actor hashes) among the Events this Rule would refuse. Events without a hash (a Shield
     * without an actor key, or an unknown address) are not clients here: they are counted in
     * `unknown_client_events`. A number only: the hashes never leave the API.
     */
    clients_affected: CountSchema,
    /** The Events this Rule would refuse that carry no client hash: how many clients they are is unknown. */
    unknown_client_events: CountSchema,
    /**
     * The route templates (with their method) of the most Events this Rule would refuse, most first, at most
     * `SIMULATION_LIMITS.sampleRoutesMax`. Empty for a Rule that would refuse nothing.
     */
    sample_routes: z.array(SimulationSampleRouteSchema).max(SIMULATION_LIMITS.sampleRoutesMax),
    /**
     * Present for a Rule whose draft mode is monitor, when it was computed (a simulation that ran out of time
     * leaves it out for the Rules it did not reach); absent for a Rule already in Enforce mode.
     */
    if_promoted: SimulationIfPromotedSchema.optional(),
  })
  .superRefine((rule, ctx) => {
    for (const outcome of SIMULATION_OUTCOMES) {
      if (rule[outcome] > rule.matched) {
        ctx.addIssue({ code: "custom", path: [outcome], message: "Must not be more than matched." });
      }
    }
    const refused = rule.would_block + rule.would_fail_signature + rule.would_throttle;
    checkClients(ctx, [], refused, rule.clients_affected, rule.unknown_client_events);
    if (rule.if_promoted !== undefined) {
      const promoted = rule.if_promoted;
      checkClients(
        ctx,
        ["if_promoted"],
        promoted.would_refuse,
        promoted.clients_affected,
        promoted.unknown_client_events,
      );
    }
  });
export type SimulationRuleResult = z.infer<typeof SimulationRuleResultSchema>;

/**
 * The result of a simulation (`simulation` of `SimulatePolicyResponseSchema`): an estimate from the recorded requests of `period`. The schema
 * checks only the consistency that is certain (no count above what it is a part of, `from` not after `to`, Rule
 * one row per draft Rule in Policy order); it does not check that the rows add up to the totals.
 */
export const SimulationResultSchema = z
  .object({
    /**
     * The time covered: `from` is 24 hours before the simulation ran, or the time of the oldest Event replayed
     * when the Event cap cut the period short. `to` is when it ran (`ran_at`) — or the time of the newest Event
     * replayed when that is later (a Shield's clock up to 5 minutes ahead), or when the time limit cut the replay.
     */
    period: z.object({ from: z.iso.datetime(), to: z.iso.datetime() }),
    /** When the simulation ran: what a figure shown later is dated with. */
    ran_at: z.iso.datetime(),
    /** `request.decision` Events replayed, at most `SIMULATION_LIMITS.eventsMax`. */
    events: CountSchema.max(SIMULATION_LIMITS.eventsMax),
    /**
     * True when the Event cap or the time limit cut the replay short (the figures then cover less than 24 hours),
     * or when the replay stopped judging limits because it held as many request times as it may.
     */
    truncated: z.boolean(),
    /** Events that at least one Rule could not be judged against and that no Rule of the draft would refuse. */
    undecidable_events: CountSchema,
    /**
     * What the simulation leaves out: today `SIMULATION_NOT_SIMULATED`. Any non-empty strings parse, at most 8, so
     * a value added later does not break an older client.
     */
    not_simulated: z.array(z.string().min(1).max(64)).max(8),
    /** One row per draft Rule, in Policy order: the row at position n has `index` n. */
    rules: z.array(SimulationRuleResultSchema).max(POLICY_LIMITS.rulesMax),
    totals: z.object({
      /** Events the draft would refuse: blocked, failed for a signature or throttled, each Event once. */
      would_refuse: CountSchema,
      /** Distinct clients among those Events, counted as in a Rule's row. */
      clients_affected: CountSchema,
      /** Those Events that carry no client hash, counted as in a Rule's row. */
      unknown_client_events: CountSchema,
    }),
  })
  .superRefine((result, ctx) => {
    if (Date.parse(result.period.from) > Date.parse(result.period.to)) {
      ctx.addIssue({ code: "custom", path: ["period", "from"], message: "Must not be after to." });
    }
    if (result.undecidable_events > result.events) {
      ctx.addIssue({ code: "custom", path: ["undecidable_events"], message: "Must not be more than events." });
    }
    if (result.totals.would_refuse > result.events) {
      ctx.addIssue({ code: "custom", path: ["totals", "would_refuse"], message: "Must not be more than events." });
    }
    checkClients(
      ctx,
      ["totals"],
      result.totals.would_refuse,
      result.totals.clients_affected,
      result.totals.unknown_client_events,
    );
    result.rules.forEach((rule, position) => {
      if (rule.if_promoted !== undefined && rule.if_promoted.would_refuse > result.events) {
        ctx.addIssue({
          code: "custom",
          path: ["rules", position, "if_promoted", "would_refuse"],
          message: "Must not be more than events.",
        });
      }
      if (rule.index !== position) {
        ctx.addIssue({
          code: "custom",
          path: ["rules", position, "index"],
          message: "Must be the position of the row: every draft Rule has one row, in Policy order.",
        });
      }
    });
  });
export type SimulationResult = z.infer<typeof SimulationResultSchema>;

/** 200 of `POST /v1/apps/:appId/policy/simulate`. */
export const SimulatePolicyResponseSchema = z.object({ simulation: SimulationResultSchema });
export type SimulatePolicyResponse = z.infer<typeof SimulatePolicyResponseSchema>;

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

/**
 * A valid simulation result (slice 11) over a full 24 hours, not truncated, for three draft Rules:
 * `EXAMPLE_POLICY_RULE` (block), a signature Rule that was never published (no `id`) and `EXAMPLE_LIMIT_RULE`.
 * 310 Events were recorded without a route template (`(unmatched)`), so no Rule could be judged against them; 15
 * more matched the signature Rule but come from a Shield that recorded no signature, so their outcome could not be
 * judged: they count in that Rule's `matched` and in its `undecidable`.
 */
export const EXAMPLE_SIMULATION_RESULT: SimulationResult = deepFreeze({
  period: { from: "2026-11-10T09:00:00.000Z", to: "2026-11-11T09:00:00.000Z" },
  ran_at: "2026-11-11T09:00:00.000Z",
  events: 18_452,
  truncated: false,
  undecidable_events: 325,
  not_simulated: [...SIMULATION_NOT_SIMULATED],
  rules: [
    {
      index: 0,
      id: EXAMPLE_POLICY_RULE.id,
      name: EXAMPLE_POLICY_RULE.name,
      matched: 42,
      would_block: 40,
      would_fail_signature: 0,
      would_throttle: 0,
      already_refused: 2,
      undecidable: 310,
      clients_affected: 3,
      unknown_client_events: 0,
      sample_routes: [
        { route: "/api/admin/users/:id", method: "DELETE", count: 17 },
        { route: "/api/admin/export", method: "GET", count: 13 },
        { route: "/api/admin/users", method: "GET", count: 10 },
      ],
    },
    {
      index: 1,
      name: "Signed checkout",
      matched: 1_260,
      would_block: 0,
      would_fail_signature: 96,
      would_throttle: 0,
      already_refused: 0,
      undecidable: 325,
      clients_affected: 12,
      unknown_client_events: 4,
      sample_routes: [{ route: "/api/checkout", method: "POST", count: 96 }],
      // The draft has it in Monitor mode; the two Rules around it are enforced, so promoting it refuses the same.
      if_promoted: { would_refuse: 96, clients_affected: 12, unknown_client_events: 4, undecidable: 325 },
    },
    {
      index: 2,
      id: EXAMPLE_LIMIT_RULE.id,
      name: EXAMPLE_LIMIT_RULE.name,
      matched: 530,
      would_block: 0,
      would_fail_signature: 0,
      would_throttle: 180,
      already_refused: 25,
      undecidable: 310,
      clients_affected: 4,
      unknown_client_events: 0,
      sample_routes: [{ route: "/login", method: "POST", count: 180 }],
    },
  ],
  totals: { would_refuse: 316, clients_affected: 17, unknown_client_events: 4 },
});
