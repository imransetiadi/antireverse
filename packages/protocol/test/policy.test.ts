import { generateKeyPairSync, sign } from "node:crypto";
import { METHODS } from "node:http";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import {
  ATTESTATION_LIMITS,
  BLOCK_RESPONSE_BODY,
  type BundleBlock,
  type BundlePayload,
  BundlePayloadSchema,
  type BundleRule,
  CANARY_LIMITS,
  CONTAINMENT_LIMITS,
  DECISION_MODES,
  ENVIRONMENTS,
  EXAMPLE_BUNDLE_PATCH,
  EXAMPLE_BUNDLE_PAYLOAD,
  EXAMPLE_CANARIES,
  EXAMPLE_POLICY,
  EXAMPLE_POLICY_RULE,
  EXAMPLE_STORED_EVENT,
  isBroadPattern,
  PATCH_LIMITS,
  PATH_PATTERN,
  type ParsedPolicyRuleInput,
  POLICY_LIMITS,
  type Policy,
  type PolicyResponse,
  PolicyResponseSchema,
  type PolicyRule,
  type PolicyRuleInput,
  PolicyRuleInputSchema,
  PolicyRuleSchema,
  PolicySchema,
  type PolicyVersionsResponse,
  PolicyVersionsResponseSchema,
  type PublishPolicyRequest,
  type PublishPolicyRequestInput,
  PublishPolicyRequestSchema,
  type RollbackPolicyRequest,
  RollbackPolicyRequestSchema,
  RollbackPolicyRequestSchema as RollbackSchemaForBroad,
  RULE_ACTIONS,
  RULE_REQUIREMENTS,
  type RuleAction,
  type RuleRequirement,
  type SignedBundle,
  SignedBundleSchema,
  type SigningKeyResponse,
  SigningKeyResponseSchema,
} from "../src/index.ts";

const rule = (patch: Record<string, unknown> = {}) => ({ ...EXAMPLE_POLICY_RULE, ...patch });
const acceptsRule = (patch: Record<string, unknown>): boolean => PolicyRuleSchema.safeParse(rule(patch)).success;
const acceptsInput = (value: unknown): boolean => PolicyRuleInputSchema.safeParse(value).success;
const policy = (patch: Record<string, unknown> = {}) => ({ ...EXAMPLE_POLICY, ...patch });
const payload = (patch: Record<string, unknown> = {}) => ({ ...EXAMPLE_BUNDLE_PAYLOAD, ...patch });
const rules = (count: number) => Array.from({ length: count }, () => EXAMPLE_POLICY_RULE);

const SIGNATURE = "A".repeat(86);
const KEY_ID = "0123456789abcdef";
const signed = (patch: Record<string, unknown> = {}) => ({
  bundle: JSON.stringify(EXAMPLE_BUNDLE_PAYLOAD),
  signature: SIGNATURE,
  key_id: KEY_ID,
  ...patch,
});
const signingKey = (patch: Record<string, unknown> = {}) => ({
  key_id: KEY_ID,
  algorithm: "Ed25519",
  public_key: "A".repeat(43),
  ...patch,
});

describe("constants", () => {
  it("has the values of contract P1", () => {
    const action: RuleAction = "block";
    expect(RULE_ACTIONS).toEqual([action]);
    expect(POLICY_LIMITS).toEqual({
      rulesMax: 50,
      pathMax: 256,
      methodsMax: 8,
      nameMax: 80,
      bundleBytesMax: 65_536,
      versionsListed: 20,
    });
  });

  it("has the exact body of a block response: nothing but the error", () => {
    expect(BLOCK_RESPONSE_BODY).toBe('{"error":"request_blocked"}');
    expect(JSON.parse(BLOCK_RESPONSE_BODY)).toEqual({ error: "request_blocked" });
  });
});

describe("PATH_PATTERN", () => {
  it.each([
    "/",
    "/login",
    "/api/admin/**",
    "/api/users/*/export",
    "/a.b_c~d-e",
    "/*",
    "/**",
    "/*/*",
    "/*/**",
    "/API/Admin/V2",
    "/0/1.2",
    "/a/b/c/d/e/f/g/h",
  ])("accepts %s", (pattern) => {
    expect(PATH_PATTERN.test(pattern)).toBe(true);
  });

  it.each([
    ["no leading slash", "api"],
    ["no leading slash, pattern segment", "**"],
    ["the empty string", ""],
    ["an empty segment", "/a//b"],
    ["an empty first segment", "//"],
    ["an empty first segment before text", "//a"],
    ["a trailing slash", "/a/"],
    ["a trailing slash after **", "/a/**/"],
    ["** before the last segment", "/a/**/b"],
    ["** twice", "/a/**/**"],
    ["* inside a segment", "/a/*x"],
    ["* at the end of a segment", "/a/x*"],
    ["** inside a segment", "/a/**x"],
    ["three stars", "/a/***"],
    ["a space", "/a b"],
    ["a query string", "/a?x"],
    ["a fragment", "/a#x"],
    ["a percent escape", "/%61"],
    ["a parameter of a route template", "/users/:id"],
    ["a backslash", "/a\\b"],
    ["a plus sign", "/a+b"],
    ["non-ASCII text", "/café"],
    ["NUL", "/a\u0000b"],
    ["a line feed inside", "/a\nb"],
    ["a line feed at the end", "/a\n"],
    ["a line feed at the start", "\n/a"],
    ["a tab", "/a\tb"],
    ["DEL", "/a\u007f"],
    ["a lone surrogate", "/a\ud800"],
  ])("rejects %s", (_reason, pattern) => {
    expect(PATH_PATTERN.test(pattern)).toBe(false);
  });

  it("accepts 256 characters and rejects 257", () => {
    expect(PATH_PATTERN.test("/".padEnd(256, "a"))).toBe(true);
    expect(PATH_PATTERN.test("/".padEnd(257, "a"))).toBe(false);
    expect(PATH_PATTERN.test(`${"/a".repeat(127)}/*`)).toBe(true);
    expect(PATH_PATTERN.test(`${"/a".repeat(127)}/**`)).toBe(false);
  });

  it("keeps no state between tests: neither global nor sticky", () => {
    expect(PATH_PATTERN.flags).toBe("");
    expect(PATH_PATTERN.test("/login")).toBe(true);
    expect(PATH_PATTERN.test("/login")).toBe(true);
  });

  it("answers at once for a long pattern that fails at its last character", () => {
    const started = performance.now();
    expect(PATH_PATTERN.test(`${"/*".repeat(100)}/a/`)).toBe(false);
    expect(PATH_PATTERN.test(`/${"a.".repeat(120)}?`)).toBe(false);
    expect(performance.now() - started).toBeLessThan(50);
  });
});

describe("PolicyRuleSchema", () => {
  it("parses the documented example unchanged", () => {
    const parsed: PolicyRule = PolicyRuleSchema.parse(EXAMPLE_POLICY_RULE);
    expect(parsed).toEqual(EXAMPLE_POLICY_RULE);
    expect(Object.keys(parsed).sort()).toEqual(["action", "id", "methods", "mode", "name", "path"]);
  });

  it("requires every member: a stored Rule has no defaults", () => {
    for (const key of ["id", "name", "path", "methods", "action", "mode"]) {
      const { [key]: _removed, ...rest } = EXAMPLE_POLICY_RULE as Record<string, unknown>;
      expect(PolicyRuleSchema.safeParse(rest).success, key).toBe(false);
    }
  });

  it("requires an id of the form rul_<24 lowercase hex characters>", () => {
    expect(acceptsRule({ id: "rul_0123456789abcdef01234567" })).toBe(true);
    expect(acceptsRule({ id: "rul_0123456789abcdef0123456" })).toBe(false);
    expect(acceptsRule({ id: "rul_0123456789abcdef012345678" })).toBe(false);
    expect(acceptsRule({ id: "rul_0123456789ABCDEF01234567" })).toBe(false);
    expect(acceptsRule({ id: "app_0123456789abcdef01234567" })).toBe(false);
    expect(acceptsRule({ id: "rule_synthetic" })).toBe(false);
    expect(acceptsRule({ id: null })).toBe(false);
  });

  it("trims the name and limits it to 1..80 characters", () => {
    expect(PolicyRuleSchema.parse(rule({ name: "  Admin area \n" })).name).toBe("Admin area");
    expect(PolicyRuleSchema.parse(rule({ name: ` ${"a".repeat(80)} ` })).name).toBe("a".repeat(80));
    expect(acceptsRule({ name: "a".repeat(81) })).toBe(false);
    expect(acceptsRule({ name: "" })).toBe(false);
    expect(acceptsRule({ name: "   " })).toBe(false);
    expect(acceptsRule({ name: 42 })).toBe(false);
  });

  it("accepts a name with ordinary non-ASCII text and rejects control characters and lone surrogates", () => {
    expect(acceptsRule({ name: "Area admin é 日本 😀" })).toBe(true);
    expect(acceptsRule({ name: "Admin\u0000area" })).toBe(false);
    expect(acceptsRule({ name: "Admin\narea" })).toBe(false);
    expect(acceptsRule({ name: "Admin\u007farea" })).toBe(false);
    expect(acceptsRule({ name: "Admin\ud800area" })).toBe(false);
    expect(acceptsRule({ name: "Admin\udc00" })).toBe(false);
  });

  it("requires path to be a path pattern of 1..256 characters", () => {
    for (const path of ["/", "/login", "/api/admin/**", "/api/users/*/export", "/".padEnd(256, "a")]) {
      expect(acceptsRule({ path }), path).toBe(true);
    }
    for (const path of ["", "api", "/a//b", "/a/**/b", "/a/*x", "/a b", "/a?x", "/a#x", "/%61", "/a\u0000"]) {
      expect(acceptsRule({ path }), JSON.stringify(path)).toBe(false);
    }
    expect(acceptsRule({ path: "/".padEnd(257, "a") })).toBe(false);
    expect(acceptsRule({ path: ["/login"] })).toBe(false);
  });

  it("names the field and never the rejected value when the path is malformed", () => {
    const result = PolicyRuleSchema.safeParse(rule({ path: "/secret?token=synthetic" }));
    expect(result.success).toBe(false);
    expect(result.error?.issues.map((issue) => issue.path)).toEqual([["path"]]);
    expect(JSON.stringify(result.error?.issues)).not.toContain("synthetic");
  });

  it("accepts 0 to 8 methods and rejects 9", () => {
    expect(acceptsRule({ methods: [] })).toBe(true);
    expect(acceptsRule({ methods: ["GET"] })).toBe(true);
    expect(acceptsRule({ methods: METHODS.slice(0, 8) })).toBe(true);
    expect(acceptsRule({ methods: METHODS.slice(0, 9) })).toBe(false);
    expect(acceptsRule({ methods: "GET" })).toBe(false);
    expect(acceptsRule({ methods: null })).toBe(false);
  });

  it("applies the method rule of an Event to each method", () => {
    for (const method of METHODS) {
      expect(acceptsRule({ methods: [method] }), method).toBe(true);
    }
    expect(acceptsRule({ methods: ["get"] })).toBe(false);
    expect(acceptsRule({ methods: ["GET", "post"] })).toBe(false);
    expect(acceptsRule({ methods: [""] })).toBe(false);
    expect(acceptsRule({ methods: ["A".repeat(17)] })).toBe(false);
    expect(acceptsRule({ methods: ["GET /x"] })).toBe(false);
    expect(acceptsRule({ methods: ["*"] })).toBe(false);
    expect(acceptsRule({ methods: [42] })).toBe(false);
  });

  it("rejects a method that is listed twice", () => {
    expect(acceptsRule({ methods: ["GET", "POST", "GET"] })).toBe(false);
    const result = PolicyRuleSchema.safeParse(rule({ methods: ["GET", "GET"] }));
    expect(result.error?.issues.map((issue) => issue.path)).toEqual([["methods"]]);
  });

  it("limits action to block and mode to monitor or enforce", () => {
    for (const mode of DECISION_MODES) {
      expect(acceptsRule({ mode }), mode).toBe(true);
    }
    expect(acceptsRule({ action: "block" })).toBe(true);
    expect(acceptsRule({ action: "allow" })).toBe(false);
    expect(acceptsRule({ action: "challenge" })).toBe(false);
    expect(acceptsRule({ mode: "shadow" })).toBe(false);
    expect(acceptsRule({ mode: "Enforce" })).toBe(false);
  });

  it("strips unknown keys", () => {
    const parsed = PolicyRuleSchema.parse(rule({ condition: "synthetic", organization_id: "org_synthetic" }));
    expect(parsed).toEqual(EXAMPLE_POLICY_RULE);
  });
});

describe("PolicyRuleInputSchema", () => {
  it("defaults methods to all, action to block and mode to monitor", () => {
    const input: PolicyRuleInput = { name: "Admin area", path: "/api/admin/**" };
    const parsed: ParsedPolicyRuleInput = PolicyRuleInputSchema.parse(input);
    expect(parsed).toEqual({
      name: "Admin area",
      path: "/api/admin/**",
      methods: [],
      action: "block",
      mode: "monitor",
    });
    expect(parsed).not.toHaveProperty("id");
  });

  it("gives every parsed Rule its own default method list", () => {
    const first = PolicyRuleInputSchema.parse({ name: "a", path: "/a" });
    const second = PolicyRuleInputSchema.parse({ name: "b", path: "/b" });
    first.methods.push("GET");
    expect(second.methods).toEqual([]);
    expect(PolicyRuleInputSchema.parse({ name: "c", path: "/c" }).methods).toEqual([]);
  });

  it("keeps an id, methods, action and mode that are given", () => {
    const input: PolicyRuleInput = { ...EXAMPLE_POLICY_RULE, methods: ["GET", "POST"], mode: "enforce" };
    expect(PolicyRuleInputSchema.parse(input)).toEqual(input);
    expect(PolicyRuleInputSchema.parse(EXAMPLE_POLICY_RULE)).toEqual(EXAMPLE_POLICY_RULE);
  });

  it("rejects an id of the wrong form, also null and the empty string", () => {
    expect(acceptsInput(rule({ id: "rul_1" }))).toBe(false);
    expect(acceptsInput(rule({ id: "" }))).toBe(false);
    expect(acceptsInput(rule({ id: null }))).toBe(false);
  });

  it("requires name and path", () => {
    expect(acceptsInput({ path: "/login" })).toBe(false);
    expect(acceptsInput({ name: "Login" })).toBe(false);
    expect(acceptsInput({})).toBe(false);
    expect(acceptsInput(undefined)).toBe(false);
  });

  it("applies the bounds of a Rule", () => {
    const base = { name: "Login", path: "/login" };
    expect(PolicyRuleInputSchema.parse({ ...base, name: "  Login " }).name).toBe("Login");
    expect(acceptsInput({ ...base, name: "a".repeat(81) })).toBe(false);
    expect(acceptsInput({ ...base, name: "Log\u0000in" })).toBe(false);
    expect(acceptsInput({ ...base, path: "login" })).toBe(false);
    expect(acceptsInput({ ...base, path: "/a/**/b" })).toBe(false);
    expect(acceptsInput({ ...base, methods: METHODS.slice(0, 9) })).toBe(false);
    expect(acceptsInput({ ...base, methods: ["get"] })).toBe(false);
    expect(acceptsInput({ ...base, methods: ["GET", "GET"] })).toBe(false);
    expect(acceptsInput({ ...base, methods: null })).toBe(false);
    expect(acceptsInput({ ...base, action: "allow" })).toBe(false);
    expect(acceptsInput({ ...base, mode: "shadow" })).toBe(false);
  });

  it("strips unknown keys", () => {
    const parsed = PolicyRuleInputSchema.parse({ name: "Login", path: "/login", condition: "synthetic" });
    expect(parsed).toEqual({ name: "Login", path: "/login", methods: [], action: "block", mode: "monitor" });
  });
});

describe("PublishPolicyRequestSchema", () => {
  it("parses Rules in order and applies the defaults to each", () => {
    const input: PublishPolicyRequestInput = {
      rules: [{ name: "Login", path: "/login" }, EXAMPLE_POLICY_RULE, { name: "Root", path: "/", mode: "enforce" }],
    };
    const parsed: PublishPolicyRequest = PublishPolicyRequestSchema.parse(input);
    expect(parsed).toEqual({
      rules: [
        { name: "Login", path: "/login", methods: [], action: "block", mode: "monitor" },
        EXAMPLE_POLICY_RULE,
        { name: "Root", path: "/", methods: [], action: "block", mode: "enforce" },
      ],
    });
  });

  it("accepts 0 to 50 Rules and rejects 51", () => {
    expect(PublishPolicyRequestSchema.parse({ rules: [] })).toEqual({ rules: [] });
  });

  it("carries an optional expected_version, an integer >= 0 (review finding F2)", () => {
    expect(PublishPolicyRequestSchema.parse({ rules: [], expected_version: 3 })).toEqual({
      rules: [],
      expected_version: 3,
    });
    expect(PublishPolicyRequestSchema.parse({ rules: [], expected_version: 0 }).expected_version).toBe(0);
    for (const bad of [-1, 1.5, "3", null]) {
      expect(PublishPolicyRequestSchema.safeParse({ rules: [], expected_version: bad }).success).toBe(false);
    }
    expect(PublishPolicyRequestSchema.safeParse({ rules: rules(50) }).success).toBe(true);
    expect(PublishPolicyRequestSchema.safeParse({ rules: rules(51) }).success).toBe(false);
  });

  it("requires rules to be a list", () => {
    expect(PublishPolicyRequestSchema.safeParse({}).success).toBe(false);
    expect(PublishPolicyRequestSchema.safeParse({ rules: null }).success).toBe(false);
    expect(PublishPolicyRequestSchema.safeParse({ rules: EXAMPLE_POLICY_RULE }).success).toBe(false);
    expect(PublishPolicyRequestSchema.safeParse(undefined).success).toBe(false);
  });

  it("names the Rule and the field of a malformed Rule", () => {
    const result = PublishPolicyRequestSchema.safeParse({
      rules: [EXAMPLE_POLICY_RULE, { name: "Broken", path: "/a//b", methods: ["get"] }],
    });
    expect(result.success).toBe(false);
    expect(result.error?.issues.map((issue) => issue.path.join("."))).toEqual(["rules.1.path", "rules.1.methods.0"]);
  });

  it("strips unknown keys from the request and from each Rule", () => {
    const parsed = PublishPolicyRequestSchema.parse({
      version: 7,
      app_id: "app_ffffffffffffffffffffffff",
      rules: [{ ...EXAMPLE_POLICY_RULE, published_by: "synthetic" }],
    });
    expect(parsed).toEqual({ rules: [EXAMPLE_POLICY_RULE] });
  });
});

describe("PolicySchema", () => {
  it("parses the documented example unchanged", () => {
    const parsed: Policy = PolicySchema.parse(EXAMPLE_POLICY);
    expect(parsed).toEqual(EXAMPLE_POLICY);
    expect(parsed.rules[0]).toEqual(EXAMPLE_POLICY_RULE);
    expect(parsed.app_id).toBe(EXAMPLE_STORED_EVENT.app_id);
  });

  it("parses the built-in Policy: version 0, no Rules, never published", () => {
    const builtIn: Policy = {
      app_id: EXAMPLE_POLICY.app_id,
      environment: "production",
      version: 0,
      rules: [],
      published_at: null,
    };
    expect(PolicySchema.parse(builtIn)).toEqual(builtIn);
  });

  it("limits version to the integers from 0", () => {
    expect(PolicySchema.safeParse(policy({ version: 0 })).success).toBe(true);
    expect(PolicySchema.safeParse(policy({ version: 1_000_000 })).success).toBe(true);
    expect(PolicySchema.safeParse(policy({ version: -1 })).success).toBe(false);
    expect(PolicySchema.safeParse(policy({ version: 1.5 })).success).toBe(false);
    expect(PolicySchema.safeParse(policy({ version: "1" })).success).toBe(false);
  });

  it("requires published_at to be an ISO-8601 UTC datetime or null", () => {
    expect(PolicySchema.safeParse(policy({ published_at: null })).success).toBe(true);
    expect(PolicySchema.safeParse(policy({ published_at: "today" })).success).toBe(false);
    expect(PolicySchema.safeParse(policy({ published_at: "2026-11-10T08:15:30+07:00" })).success).toBe(false);
    expect(PolicySchema.safeParse(policy({ published_at: undefined })).success).toBe(false);
  });

  it("requires an App identifier and a known Environment", () => {
    for (const environment of ENVIRONMENTS) {
      expect(PolicySchema.safeParse(policy({ environment })).success, environment).toBe(true);
    }
    expect(PolicySchema.safeParse(policy({ environment: "qa" })).success).toBe(false);
    expect(PolicySchema.safeParse(policy({ app_id: "org_0123456789abcdef01234567" })).success).toBe(false);
    expect(PolicySchema.safeParse(policy({ app_id: undefined })).success).toBe(false);
  });

  it("holds 0 to 50 complete Rules", () => {
    expect(PolicySchema.safeParse(policy({ rules: rules(50) })).success).toBe(true);
    expect(PolicySchema.safeParse(policy({ rules: rules(51) })).success).toBe(false);
    expect(PolicySchema.safeParse(policy({ rules: [{ name: "Login", path: "/login" }] })).success).toBe(false);
    expect(PolicySchema.safeParse(policy({ rules: undefined })).success).toBe(false);
  });

  it("strips unknown keys from the Policy and from each Rule", () => {
    const parsed = PolicySchema.parse({
      ...EXAMPLE_POLICY,
      organization_id: "org_ffffffffffffffffffffffff",
      published_by: "key_ffffffffffffffffffffffff",
      rules: EXAMPLE_POLICY.rules.map((entry) => ({ ...entry, hits: 3 })),
    });
    expect(parsed).toEqual(EXAMPLE_POLICY);
  });
});

describe("PolicyResponseSchema", () => {
  it("wraps a Policy", () => {
    const body: PolicyResponse = { policy: EXAMPLE_POLICY };
    expect(PolicyResponseSchema.parse({ ...body, internal: true })).toEqual(body);
    expect(PolicyResponseSchema.safeParse({}).success).toBe(false);
    expect(PolicyResponseSchema.safeParse({ policy: policy({ version: -1 }) }).success).toBe(false);
  });
});

describe("PolicyVersionsResponseSchema", () => {
  const entry = { version: 2, published_at: "2026-11-10T09:00:00.000Z", rule_count: 2, enforced_count: 1 };
  const accepts = (patch: Record<string, unknown>): boolean =>
    PolicyVersionsResponseSchema.safeParse({ versions: [{ ...entry, ...patch }] }).success;

  it("parses the published versions and the empty list", () => {
    const body: PolicyVersionsResponse = { versions: [entry, { ...entry, version: 1, enforced_count: 0 }] };
    expect(PolicyVersionsResponseSchema.parse(body)).toEqual(body);
    expect(PolicyVersionsResponseSchema.parse({ versions: [] })).toEqual({ versions: [] });
    expect(PolicyVersionsResponseSchema.safeParse({}).success).toBe(false);
  });

  it("limits version to the integers from 1: version 0 was never published", () => {
    expect(accepts({ version: 1 })).toBe(true);
    expect(accepts({ version: 0 })).toBe(false);
    expect(accepts({ version: 1.5 })).toBe(false);
  });

  it("requires the time of publishing", () => {
    expect(accepts({ published_at: null })).toBe(false);
    expect(accepts({ published_at: "today" })).toBe(false);
    expect(accepts({ published_at: undefined })).toBe(false);
  });

  it("limits both counts to the integers 0..50", () => {
    expect(accepts({ rule_count: 0, enforced_count: 0 })).toBe(true);
    expect(accepts({ rule_count: 50, enforced_count: 50 })).toBe(true);
    expect(accepts({ rule_count: 51 })).toBe(false);
    expect(accepts({ rule_count: -1 })).toBe(false);
    expect(accepts({ enforced_count: 51 })).toBe(false);
    expect(accepts({ enforced_count: 0.5 })).toBe(false);
    expect(accepts({ rule_count: undefined })).toBe(false);
    expect(accepts({ enforced_count: undefined })).toBe(false);
  });

  it("lists at most 20 versions", () => {
    const versions = (count: number) =>
      Array.from({ length: count }, (_, index) => ({ ...entry, version: count - index }));
    expect(PolicyVersionsResponseSchema.safeParse({ versions: versions(20) }).success).toBe(true);
    expect(PolicyVersionsResponseSchema.safeParse({ versions: versions(21) }).success).toBe(false);
  });

  it("strips unknown keys", () => {
    const parsed = PolicyVersionsResponseSchema.parse({
      versions: [{ ...entry, rules: [], published_by: "synthetic" }],
    });
    expect(parsed).toEqual({ versions: [entry] });
  });
});

describe("RollbackPolicyRequestSchema", () => {
  it("names a published version: an integer from 1", () => {
    const body: RollbackPolicyRequest = { version: 3 };
    expect(RollbackPolicyRequestSchema.parse({ ...body, environment: "production" })).toEqual(body);
    expect(RollbackPolicyRequestSchema.safeParse({ version: 1 }).success).toBe(true);
    expect(RollbackPolicyRequestSchema.safeParse({ version: 0 }).success).toBe(false);
    expect(RollbackPolicyRequestSchema.safeParse({ version: -1 }).success).toBe(false);
    expect(RollbackPolicyRequestSchema.safeParse({ version: 1.5 }).success).toBe(false);
    expect(RollbackPolicyRequestSchema.safeParse({ version: "1" }).success).toBe(false);
    expect(RollbackPolicyRequestSchema.safeParse({}).success).toBe(false);
  });
});

describe("BundlePayloadSchema", () => {
  const accepts = (patch: Record<string, unknown>): boolean => BundlePayloadSchema.safeParse(payload(patch)).success;
  const bundleRule = (): BundleRule => EXAMPLE_BUNDLE_PAYLOAD.rules[0] as BundleRule;

  it("parses the documented example unchanged, also after a round trip through JSON", () => {
    const parsed: BundlePayload = BundlePayloadSchema.parse(EXAMPLE_BUNDLE_PAYLOAD);
    expect(parsed).toEqual(EXAMPLE_BUNDLE_PAYLOAD);
    expect(BundlePayloadSchema.parse(JSON.parse(JSON.stringify(EXAMPLE_BUNDLE_PAYLOAD)))).toEqual(
      EXAMPLE_BUNDLE_PAYLOAD,
    );
    expect(Object.keys(parsed).sort()).toEqual([
      "app_id",
      "audience",
      "environment",
      "epoch",
      "format",
      "issued_at",
      "not_after",
      "rules",
      "version",
    ]);
  });

  it("carries the Rules of the documented Policy without their names, valid for 7 days", () => {
    expect(EXAMPLE_BUNDLE_PAYLOAD.rules).toEqual(EXAMPLE_POLICY.rules.map(({ name: _name, ...rest }) => rest));
    expect(EXAMPLE_BUNDLE_PAYLOAD.app_id).toBe(EXAMPLE_POLICY.app_id);
    expect(EXAMPLE_BUNDLE_PAYLOAD.environment).toBe(EXAMPLE_POLICY.environment);
    expect(EXAMPLE_BUNDLE_PAYLOAD.version).toBe(EXAMPLE_POLICY.version);
    const lifetime = Date.parse(EXAMPLE_BUNDLE_PAYLOAD.not_after) - Date.parse(EXAMPLE_BUNDLE_PAYLOAD.issued_at);
    expect(lifetime).toBe(7 * 24 * 60 * 60 * 1000);
  });

  it("accepts format 1 only", () => {
    expect(accepts({ format: 1 })).toBe(true);
    expect(accepts({ format: 2 })).toBe(false);
    expect(accepts({ format: 0 })).toBe(false);
    expect(accepts({ format: "1" })).toBe(false);
    expect(accepts({ format: undefined })).toBe(false);
  });

  it("requires epoch to be 32 lowercase hex characters (review finding F4)", () => {
    expect(accepts({ epoch: "fedcba9876543210fedcba9876543210" })).toBe(true);
    expect(accepts({ epoch: "FEDCBA9876543210FEDCBA9876543210" })).toBe(false);
    expect(accepts({ epoch: "fedcba9876543210" })).toBe(false);
    expect(accepts({ epoch: undefined })).toBe(false);
  });

  it("requires audience to be 32 lowercase hex characters", () => {
    expect(accepts({ audience: "0123456789abcdef0123456789abcdef" })).toBe(true);
    expect(accepts({ audience: "0123456789abcdef0123456789abcde" })).toBe(false);
    expect(accepts({ audience: "0123456789abcdef0123456789abcdef0" })).toBe(false);
    expect(accepts({ audience: "0123456789ABCDEF0123456789ABCDEF" })).toBe(false);
    expect(accepts({ audience: "g".repeat(32) })).toBe(false);
    expect(accepts({ audience: undefined })).toBe(false);
  });

  it("requires an App identifier, a known Environment and a version from 0", () => {
    for (const environment of ENVIRONMENTS) {
      expect(accepts({ environment }), environment).toBe(true);
    }
    expect(accepts({ environment: "qa" })).toBe(false);
    expect(accepts({ app_id: "app_1" })).toBe(false);
    expect(accepts({ version: 0, rules: [] })).toBe(true);
    expect(accepts({ version: -1 })).toBe(false);
    expect(accepts({ version: 1.5 })).toBe(false);
  });

  it("requires issued_at and not_after to be ISO-8601 UTC datetimes", () => {
    expect(accepts({ issued_at: "today" })).toBe(false);
    expect(accepts({ issued_at: null })).toBe(false);
    expect(accepts({ not_after: 1_794_902_401_000 })).toBe(false);
    expect(accepts({ not_after: "2026-11-17T08:00:01+07:00" })).toBe(false);
    expect(accepts({ not_after: undefined })).toBe(false);
  });

  it("carries Rules without a name: a name never reaches Shield", () => {
    const parsed = BundlePayloadSchema.parse(payload({ rules: [EXAMPLE_POLICY_RULE] }));
    expect(parsed.rules).toEqual([bundleRule()]);
    expect(parsed.rules[0]).not.toHaveProperty("name");
    expect(Object.keys(parsed.rules[0] ?? {}).sort()).toEqual(["action", "id", "methods", "mode", "path"]);
  });

  it("applies the bounds of a Rule and gives no defaults", () => {
    const withRule = (patch: Record<string, unknown>) => accepts({ rules: [{ ...bundleRule(), ...patch }] });
    expect(withRule({})).toBe(true);
    expect(withRule({ id: "rul_1" })).toBe(false);
    expect(withRule({ id: undefined })).toBe(false);
    expect(withRule({ path: "/a/**/b" })).toBe(false);
    expect(withRule({ path: "/".padEnd(257, "a") })).toBe(false);
    expect(withRule({ methods: METHODS.slice(0, 9) })).toBe(false);
    expect(withRule({ methods: ["get"] })).toBe(false);
    expect(withRule({ methods: ["GET", "GET"] })).toBe(false);
    expect(withRule({ methods: undefined })).toBe(false);
    expect(withRule({ action: "allow" })).toBe(false);
    expect(withRule({ action: undefined })).toBe(false);
    expect(withRule({ mode: "shadow" })).toBe(false);
    expect(withRule({ mode: undefined })).toBe(false);
  });

  it("accepts 0 to 50 Rules and rejects 51", () => {
    const bundleRules = (count: number) => Array.from({ length: count }, bundleRule);
    expect(accepts({ rules: [] })).toBe(true);
    expect(accepts({ rules: bundleRules(50) })).toBe(true);
    expect(accepts({ rules: bundleRules(51) })).toBe(false);
    expect(accepts({ rules: undefined })).toBe(false);
  });

  it("stays within the size of a bundle with 50 Rules of the longest form", () => {
    const longest: BundleRule = {
      id: "rul_0123456789abcdef01234567",
      path: "/".padEnd(POLICY_LIMITS.pathMax, "a"),
      methods: ["A", "B", "C", "D", "E", "F", "G", "H"].map((letter) => letter.repeat(16)),
      action: "block",
      mode: "enforce",
    };
    const largest = payload({ rules: Array.from({ length: POLICY_LIMITS.rulesMax }, () => longest) });
    expect(BundlePayloadSchema.safeParse(largest).success).toBe(true);
    expect(JSON.stringify(largest).length).toBeLessThanOrEqual(POLICY_LIMITS.bundleBytesMax);
  });

  it("strips unknown keys from the payload and from each Rule", () => {
    const parsed = BundlePayloadSchema.parse({
      ...EXAMPLE_BUNDLE_PAYLOAD,
      organization_id: "org_ffffffffffffffffffffffff",
      published_by: "synthetic",
      rules: EXAMPLE_BUNDLE_PAYLOAD.rules.map((entry) => ({ ...entry, name: "synthetic", hits: 3 })),
    });
    expect(parsed).toEqual(EXAMPLE_BUNDLE_PAYLOAD);
  });
});

describe("BundlePayloadSchema canaries", () => {
  const accepts = (patch: Record<string, unknown>): boolean => BundlePayloadSchema.safeParse(payload(patch)).success;
  const keyCanary = (n: number) => ({
    id: `cny_${n.toString(16).padStart(24, "0")}`,
    kind: "key",
    value: `ak_live_${n.toString(36).padStart(32, "0")}`,
  });
  const many = (count: number) => Array.from({ length: count }, (_, n) => keyCanary(n));

  it("leaves a payload without canaries valid: absent stays absent", () => {
    expect(BundlePayloadSchema.parse(EXAMPLE_BUNDLE_PAYLOAD)).not.toHaveProperty("canaries");
  });

  it("round-trips a payload with Canaries through JSON", () => {
    const withCanaries: BundlePayload = { ...EXAMPLE_BUNDLE_PAYLOAD, canaries: [...EXAMPLE_CANARIES] };
    expect(BundlePayloadSchema.parse(JSON.parse(JSON.stringify(withCanaries)))).toEqual(withCanaries);
  });

  it("accepts 0..100 Canaries and rejects 101 or an invalid Canary", () => {
    expect(accepts({ canaries: [] })).toBe(true);
    expect(accepts({ canaries: many(CANARY_LIMITS.perBundle) })).toBe(true);
    expect(accepts({ canaries: many(CANARY_LIMITS.perBundle + 1) })).toBe(false);
    expect(accepts({ canaries: [{ ...keyCanary(1), kind: "route" }] })).toBe(false);
    expect(accepts({ canaries: null })).toBe(false);
  });

  it("is stripped by an older Shield's schema (a copy without the field)", () => {
    const older = z.object(BundlePayloadSchema.shape).omit({ canaries: true });
    const parsed = older.parse({ ...EXAMPLE_BUNDLE_PAYLOAD, canaries: [...EXAMPLE_CANARIES] });
    expect(parsed).toEqual(EXAMPLE_BUNDLE_PAYLOAD);
    expect(parsed).not.toHaveProperty("canaries");
  });

  it("still fits a bundle string with 50 Rules of the longest form and 100 Canaries of the longest form", () => {
    const longest: BundleRule = {
      id: "rul_0123456789abcdef01234567",
      path: "/".padEnd(POLICY_LIMITS.pathMax, "a"),
      methods: ["A", "B", "C", "D", "E", "F", "G", "H"].map((letter) => letter.repeat(16)),
      action: "block",
      mode: "enforce",
    };
    const longestCanary = { id: "cny_0123456789abcdef01234567", kind: "route", value: "/api/internal/01234567/backup" };
    const largest = payload({
      rules: Array.from({ length: POLICY_LIMITS.rulesMax }, () => longest),
      canaries: Array.from({ length: CANARY_LIMITS.perBundle }, () => longestCanary),
    });
    expect(BundlePayloadSchema.safeParse(largest).success).toBe(true);
    expect(JSON.stringify(largest).length).toBeLessThanOrEqual(POLICY_LIMITS.bundleBytesMax);
  });
});

describe("BundlePayloadSchema blocks and allowlist (slice 09)", () => {
  const accepts = (patch: Record<string, unknown>): boolean => BundlePayloadSchema.safeParse(payload(patch)).success;
  const EXPIRES = "2026-11-10T09:21:00.000Z";
  const actorBlock = (n = 0): BundleBlock => ({
    id: `cnt_${n.toString(16).padStart(24, "0")}`,
    kind: "actor",
    ip_hash: `iph_${n.toString(16).padStart(32, "0")}`,
    expires_at: EXPIRES,
  });
  const prefixBlock = (n = 0): Extract<BundleBlock, { kind: "prefix" }> => ({
    id: `cnt_${n.toString(16).padStart(24, "0")}`,
    kind: "prefix",
    ip_prefix: `203.0.${n % 256}.0/24`,
    expires_at: EXPIRES,
  });
  const blocks = (count: number) =>
    Array.from({ length: count }, (_, n) => (n % 2 === 0 ? actorBlock(n) : prefixBlock(n)));
  const cidrs = (count: number) => Array.from({ length: count }, (_, n) => `10.${n}.0.0/16`);

  it("leaves a payload without blocks and allowlist valid: absent stays absent", () => {
    const parsed = BundlePayloadSchema.parse(EXAMPLE_BUNDLE_PAYLOAD);
    expect(parsed).not.toHaveProperty("blocks");
    expect(parsed).not.toHaveProperty("allowlist");
  });

  it("round-trips a payload with blocks and an allowlist through JSON", () => {
    const full: BundlePayload = {
      ...EXAMPLE_BUNDLE_PAYLOAD,
      canaries: [...EXAMPLE_CANARIES],
      blocks: [actorBlock(1), prefixBlock(2), { ...prefixBlock(3), ip_prefix: "2001:db8:abcd::/48" }],
      allowlist: ["198.51.100.0/24", "2001:db8::/32"],
    };
    expect(BundlePayloadSchema.parse(full)).toEqual(full);
    expect(BundlePayloadSchema.parse(JSON.parse(JSON.stringify(full)))).toEqual(full);
  });

  it("accepts 0..150 blocks and rejects 151", () => {
    expect(CONTAINMENT_LIMITS.activePerAppEnv).toBe(150);
    expect(accepts({ blocks: [] })).toBe(true);
    expect(accepts({ blocks: blocks(150) })).toBe(true);
    expect(accepts({ blocks: blocks(151) })).toBe(false);
    expect(accepts({ blocks: null })).toBe(false);
    expect(accepts({ blocks: {} })).toBe(false);
  });

  it("requires each block to carry a cnt id, the value of its kind and an ISO-8601 UTC expiry", () => {
    const withBlock = (block: Record<string, unknown>) => accepts({ blocks: [block] });
    expect(withBlock({ ...actorBlock() })).toBe(true);
    expect(withBlock({ ...prefixBlock() })).toBe(true);
    expect(withBlock({ ...actorBlock(), id: "cnt_1" })).toBe(false);
    expect(withBlock({ ...actorBlock(), id: "rul_0123456789abcdef01234567" })).toBe(false);
    expect(withBlock({ ...actorBlock(), id: undefined })).toBe(false);
    expect(withBlock({ ...actorBlock(), ip_hash: undefined })).toBe(false);
    expect(withBlock({ ...actorBlock(), ip_hash: "203.0.113.7" })).toBe(false);
    expect(withBlock({ ...actorBlock(), ip_hash: "IPH_0123456789abcdef0123456789abcdef" })).toBe(false);
    expect(withBlock({ ...prefixBlock(), ip_prefix: undefined })).toBe(false);
    expect(withBlock({ ...prefixBlock(), ip_prefix: "203.0.113.7/32" })).toBe(false);
    expect(withBlock({ ...prefixBlock(), ip_prefix: "203.0.113.7" })).toBe(false);
    expect(withBlock({ ...actorBlock(), kind: "prefix" })).toBe(false);
    expect(withBlock({ ...prefixBlock(), kind: "actor" })).toBe(false);
    expect(withBlock({ ...actorBlock(), kind: "device" })).toBe(false);
    expect(withBlock({ ...actorBlock(), kind: undefined })).toBe(false);
    expect(withBlock({ ...actorBlock(), expires_at: undefined })).toBe(false);
    expect(withBlock({ ...actorBlock(), expires_at: null })).toBe(false);
    expect(withBlock({ ...actorBlock(), expires_at: "soon" })).toBe(false);
    expect(withBlock({ ...actorBlock(), expires_at: 1_794_298_530_123 })).toBe(false);
    expect(withBlock({ ...actorBlock(), expires_at: "2026-11-10T09:21:00+07:00" })).toBe(false);
    expect(withBlock({ ...actorBlock(), expires_at: "2026-11-10 09:21:00" })).toBe(false);
  });

  it("strips unknown keys from a block: who created it and for which Incident stay in the API", () => {
    const parsed = BundlePayloadSchema.parse(
      payload({
        blocks: [
          { ...actorBlock(1), ip_prefix: "203.0.113.0/24", created_by: "key_0123456789abcdef01234567" },
          {
            ...prefixBlock(2),
            ip_hash: "iph_0123456789abcdef0123456789abcdef",
            incident_id: "inc_1",
            status: "active",
          },
        ],
      }),
    );
    expect(parsed.blocks).toEqual([actorBlock(1), prefixBlock(2)]);
  });

  it("accepts 0..100 canonical CIDRs as the allowlist and rejects 101", () => {
    expect(CONTAINMENT_LIMITS.allowlistMax).toBe(100);
    expect(accepts({ allowlist: [] })).toBe(true);
    expect(accepts({ allowlist: cidrs(100) })).toBe(true);
    expect(accepts({ allowlist: cidrs(101) })).toBe(false);
    expect(accepts({ allowlist: null })).toBe(false);
    expect(accepts({ allowlist: "10.0.0.0/8" })).toBe(false);
  });

  it("rejects an allowlist entry that is not a canonical CIDR", () => {
    for (const cidr of ["10.0.0.1/8", "10.0.0.0", "10.0.0.0/7", "2001:DB8::/32", "2001:db8:0:0::/32", "::/15", "", 8]) {
      expect(accepts({ allowlist: [cidr] }), String(cidr)).toBe(false);
    }
    expect(accepts({ allowlist: [{ cidr: "10.0.0.0/8" }] })).toBe(false);
  });

  it("is stripped by an older Shield's schema (a copy without the fields)", () => {
    const older = z.object(BundlePayloadSchema.shape).omit({ blocks: true, allowlist: true });
    const parsed = older.parse({ ...EXAMPLE_BUNDLE_PAYLOAD, blocks: blocks(3), allowlist: cidrs(3) });
    expect(parsed).toEqual(EXAMPLE_BUNDLE_PAYLOAD);
    expect(parsed).not.toHaveProperty("blocks");
    expect(parsed).not.toHaveProperty("allowlist");
  });

  describe("bundle size with 50 Rules, 100 Canaries, 150 blocks, 100 allowlist entries and 3 attestation keys of the longest form", () => {
    const longest: BundleRule = {
      id: "rul_0123456789abcdef01234567",
      path: "/".padEnd(POLICY_LIMITS.pathMax, "a"),
      methods: ["A", "B", "C", "D", "E", "F", "G", "H"].map((letter) => letter.repeat(16)),
      action: "block",
      mode: "enforce",
    };
    const longestCanary = { id: "cny_0123456789abcdef01234567", kind: "route", value: "/api/internal/01234567/backup" };
    // The expiry in the form `Date#toISOString` produces, which is what the API issues.
    const longestActor: BundleBlock = actorBlock();
    const longestPrefix: BundleBlock = { ...prefixBlock(), ip_prefix: "ffff:ffff:ffff::/48" };
    const longestCidr = "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128";
    // Slice 03: the attestation key set at its limit. Every key has the same length.
    const attestationKeys = Array.from({ length: ATTESTATION_LIMITS.keysMax }, (_, n) => ({
      kid: `${n}`.repeat(16),
      public_key: "A".repeat(43),
    }));
    const largest = (blockCount: number) =>
      payload({
        rules: Array.from({ length: POLICY_LIMITS.rulesMax }, () => longest),
        canaries: Array.from({ length: CANARY_LIMITS.perBundle }, () => longestCanary),
        blocks: Array.from({ length: blockCount }, () => longestActor),
        allowlist: Array.from({ length: CONTAINMENT_LIMITS.allowlistMax }, () => longestCidr),
        attestation_keys: attestationKeys,
      });
    const size = (blockCount: number) => JSON.stringify(largest(blockCount)).length;

    it("has an actor block as its longest block: 141 characters, a prefix block at most 127", () => {
      expect(JSON.stringify(longestActor).length).toBe(141);
      expect(JSON.stringify(longestPrefix).length).toBe(127);
    });

    it("is a valid payload at every limit and fits the bundle string (plan 09 amendment A1: 150 blocks)", () => {
      expect(BundlePayloadSchema.safeParse(largest(CONTAINMENT_LIMITS.activePerAppEnv)).success).toBe(true);
      // 60,607 before slice 03; the three attestation keys add 279 characters.
      expect(size(CONTAINMENT_LIMITS.activePerAppEnv)).toBe(60_886);
      expect(size(CONTAINMENT_LIMITS.activePerAppEnv)).toBeLessThanOrEqual(POLICY_LIMITS.bundleBytesMax);
    });

    it("keeps headroom: at most 182 blocks of the longest form would fit beside the other limits", () => {
      expect(size(182)).toBeLessThanOrEqual(POLICY_LIMITS.bundleBytesMax);
      expect(size(183)).toBeGreaterThan(POLICY_LIMITS.bundleBytesMax);
    });

    // Slice 04 (amendment A1): the 50 Rules may be split between `rules` and `signature_rules`. The longest split
    // puts every Rule in `signature_rules`, leaving `"rules":[]`: the member name and its brackets add 21 characters.
    const largestSigned = (blockCount: number) => ({
      ...largest(blockCount),
      rules: [],
      signature_rules: Array.from({ length: POLICY_LIMITS.rulesMax }, () => longest),
    });
    const sizeSigned = (blockCount: number) => JSON.stringify(largestSigned(blockCount)).length;

    it("is still valid and fits with every Rule in signature_rules, the longest split (slice 04)", () => {
      expect(BundlePayloadSchema.safeParse(largestSigned(CONTAINMENT_LIMITS.activePerAppEnv)).success).toBe(true);
      expect(sizeSigned(CONTAINMENT_LIMITS.activePerAppEnv)).toBe(60_907);
      for (let split = 0; split <= POLICY_LIMITS.rulesMax; split += 1) {
        const value = {
          ...largest(CONTAINMENT_LIMITS.activePerAppEnv),
          rules: Array.from({ length: split }, () => longest),
          signature_rules: Array.from({ length: POLICY_LIMITS.rulesMax - split }, () => longest),
        };
        expect(JSON.stringify(value).length, String(split)).toBeLessThanOrEqual(60_907);
      }
      expect(sizeSigned(CONTAINMENT_LIMITS.activePerAppEnv)).toBeLessThanOrEqual(POLICY_LIMITS.bundleBytesMax);
    });

    it("keeps the same headroom with signature_rules: 182 blocks fit, 183 do not", () => {
      expect(sizeSigned(182)).toBeLessThanOrEqual(POLICY_LIMITS.bundleBytesMax);
      expect(sizeSigned(183)).toBeGreaterThan(POLICY_LIMITS.bundleBytesMax);
    });
  });
});

describe("BundlePayloadSchema attestation_keys (slice 03)", () => {
  const accepts = (patch: Record<string, unknown>): boolean => BundlePayloadSchema.safeParse(payload(patch)).success;
  const key = (n: number) => ({ kid: n.toString(16).padStart(16, "0"), public_key: "A".repeat(42) + "AEIM"[n % 4] });
  const keys = (count: number) => Array.from({ length: count }, (_, n) => key(n));

  it("leaves a payload without attestation keys valid: absent stays absent", () => {
    expect(BundlePayloadSchema.parse(EXAMPLE_BUNDLE_PAYLOAD)).not.toHaveProperty("attestation_keys");
  });

  it("round-trips a payload with attestation keys through JSON", () => {
    const withKeys: BundlePayload = { ...EXAMPLE_BUNDLE_PAYLOAD, attestation_keys: keys(3) };
    expect(BundlePayloadSchema.parse(JSON.parse(JSON.stringify(withKeys)))).toEqual(withKeys);
  });

  it("accepts 0..3 keys with distinct kids and rejects 4, a repeated kid or a malformed key", () => {
    expect(accepts({ attestation_keys: [] })).toBe(true);
    expect(accepts({ attestation_keys: keys(ATTESTATION_LIMITS.keysMax) })).toBe(true);
    expect(accepts({ attestation_keys: keys(ATTESTATION_LIMITS.keysMax + 1) })).toBe(false);
    expect(accepts({ attestation_keys: [key(1), { ...key(2), kid: key(1).kid }] })).toBe(false);
    expect(accepts({ attestation_keys: [{ ...key(1), kid: "XYZ" }] })).toBe(false);
    expect(accepts({ attestation_keys: [{ ...key(1), public_key: "A".repeat(44) }] })).toBe(false);
    expect(accepts({ attestation_keys: null })).toBe(false);
  });

  it("strips a private member of a key entry", () => {
    const parsed = BundlePayloadSchema.parse({ ...EXAMPLE_BUNDLE_PAYLOAD, attestation_keys: [{ ...key(1), d: "x" }] });
    expect(parsed.attestation_keys).toEqual([key(1)]);
  });

  it("is stripped by an older Shield's schema (a copy without the field)", () => {
    const older = z.object(BundlePayloadSchema.shape).omit({ attestation_keys: true });
    const parsed = older.parse({ ...EXAMPLE_BUNDLE_PAYLOAD, attestation_keys: keys(2) });
    expect(parsed).toEqual(EXAMPLE_BUNDLE_PAYLOAD);
  });
});

describe("SignedBundleSchema", () => {
  const accepts = (patch: Record<string, unknown>): boolean => SignedBundleSchema.safeParse(signed(patch)).success;

  it("parses a bundle string with its signature and key identifier", () => {
    const body = signed() as SignedBundle;
    expect(SignedBundleSchema.parse(body)).toEqual(body);
    expect(BundlePayloadSchema.parse(JSON.parse(body.bundle))).toEqual(EXAMPLE_BUNDLE_PAYLOAD);
  });

  it("keeps the bundle string byte for byte: it is what was signed", () => {
    const bundle = `  ${JSON.stringify({ ...EXAMPLE_BUNDLE_PAYLOAD, extra: "synthetic" })}\n`;
    expect(SignedBundleSchema.parse(signed({ bundle })).bundle).toBe(bundle);
  });

  it("limits the bundle to 1..65536 characters", () => {
    expect(accepts({ bundle: "x" })).toBe(true);
    expect(accepts({ bundle: "x".repeat(65_536) })).toBe(true);
    expect(accepts({ bundle: "x".repeat(65_537) })).toBe(false);
    expect(accepts({ bundle: "" })).toBe(false);
    expect(accepts({ bundle: EXAMPLE_BUNDLE_PAYLOAD })).toBe(false);
    expect(accepts({ bundle: undefined })).toBe(false);
  });

  it("requires a signature of exactly 86 base64url characters", () => {
    expect(accepts({ signature: "A".repeat(86) })).toBe(true);
    expect(accepts({ signature: `${"aZ09_-".repeat(14)}_-` })).toBe(true);
    expect(accepts({ signature: "A".repeat(85) })).toBe(false);
    expect(accepts({ signature: "A".repeat(87) })).toBe(false);
    expect(accepts({ signature: `${"A".repeat(86)}==` })).toBe(false);
    expect(accepts({ signature: `${"A".repeat(85)}+` })).toBe(false);
    expect(accepts({ signature: `${"A".repeat(85)}/` })).toBe(false);
    expect(accepts({ signature: `${"A".repeat(85)}=` })).toBe(false);
    expect(accepts({ signature: `${"A".repeat(86)}\n` })).toBe(false);
    expect(accepts({ signature: "" })).toBe(false);
    expect(accepts({ signature: undefined })).toBe(false);
  });

  it("requires a key identifier of 16 lowercase hex characters", () => {
    expect(accepts({ key_id: "0123456789abcdef" })).toBe(true);
    expect(accepts({ key_id: "0123456789abcde" })).toBe(false);
    expect(accepts({ key_id: "0123456789abcdef0" })).toBe(false);
    expect(accepts({ key_id: "0123456789ABCDEF" })).toBe(false);
    expect(accepts({ key_id: undefined })).toBe(false);
  });

  it("accepts a real Ed25519 signature", () => {
    const { privateKey } = generateKeyPairSync("ed25519");
    const bundle = JSON.stringify(EXAMPLE_BUNDLE_PAYLOAD);
    const signature = sign(null, Buffer.from(bundle, "utf8"), privateKey).toString("base64url");
    expect(accepts({ bundle, signature })).toBe(true);
  });

  it("strips unknown keys", () => {
    expect(SignedBundleSchema.parse(signed({ private_key: "synthetic" }))).toEqual(signed());
  });
});

describe("SigningKeyResponseSchema", () => {
  const accepts = (patch: Record<string, unknown>): boolean =>
    SigningKeyResponseSchema.safeParse(signingKey(patch)).success;

  it("parses the public key with its identifier and algorithm", () => {
    const body = signingKey() as SigningKeyResponse;
    expect(SigningKeyResponseSchema.parse(body)).toEqual(body);
    expect(body.algorithm).toBe("Ed25519");
  });

  it("accepts Ed25519 only", () => {
    expect(accepts({ algorithm: "ed25519" })).toBe(false);
    expect(accepts({ algorithm: "ES256" })).toBe(false);
    expect(accepts({ algorithm: undefined })).toBe(false);
  });

  it("requires a public key of exactly 43 base64url characters", () => {
    expect(accepts({ public_key: `${"aZ09_-".repeat(7)}A` })).toBe(true);
    expect(accepts({ public_key: "A".repeat(42) })).toBe(false);
    expect(accepts({ public_key: "A".repeat(44) })).toBe(false);
    expect(accepts({ public_key: `${"A".repeat(43)}=` })).toBe(false);
    expect(accepts({ public_key: `${"A".repeat(42)}+` })).toBe(false);
    expect(accepts({ public_key: `${"A".repeat(42)}/` })).toBe(false);
    expect(accepts({ public_key: undefined })).toBe(false);
  });

  it("requires a key identifier of 16 lowercase hex characters", () => {
    expect(accepts({ key_id: "f".repeat(16) })).toBe(true);
    expect(accepts({ key_id: "f".repeat(15) })).toBe(false);
    expect(accepts({ key_id: "F".repeat(16) })).toBe(false);
    expect(accepts({ key_id: undefined })).toBe(false);
  });

  it("accepts a real Ed25519 public key in its raw form", () => {
    const { publicKey } = generateKeyPairSync("ed25519");
    expect(accepts({ public_key: publicKey.export({ format: "jwk" }).x })).toBe(true);
  });

  it("strips unknown keys: a private key cannot pass", () => {
    expect(SigningKeyResponseSchema.parse(signingKey({ private_key: "synthetic", d: "synthetic" }))).toEqual(
      signingKey(),
    );
  });
});

describe("documented examples", () => {
  it("are deeply frozen", () => {
    expect(Object.isFrozen(EXAMPLE_POLICY_RULE)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_POLICY_RULE.methods)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_POLICY)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_POLICY.rules)).toBe(true);
    expect(EXAMPLE_POLICY.rules.every((entry) => Object.isFrozen(entry) && Object.isFrozen(entry.methods))).toBe(true);
    expect(Object.isFrozen(EXAMPLE_BUNDLE_PAYLOAD)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_BUNDLE_PAYLOAD.rules)).toBe(true);
    expect(EXAMPLE_BUNDLE_PAYLOAD.rules.every((entry) => Object.isFrozen(entry))).toBe(true);
  });

  it("show one Rule in each mode, the first being the documented Rule", () => {
    expect(EXAMPLE_POLICY.rules[0]).toBe(EXAMPLE_POLICY_RULE);
    expect(EXAMPLE_POLICY.rules.map((entry) => entry.mode).sort()).toEqual(["enforce", "monitor"]);
    expect(EXAMPLE_POLICY_RULE.id).toMatch(/^rul_[0-9a-f]{24}$/);
  });
});

describe("broad Rules (owner decision 2026-11-10: a stronger confirmation)", () => {
  it.each(["/*", "/*/**", "/*/admin", "/**", "/*/*/x"])("%s is broad: its first segment is a wildcard", (path) => {
    expect(isBroadPattern(path)).toBe(true);
  });

  it.each(["/", "/login", "/api/**", "/api/*/export", "/a*", "/files/private/**"])("%s is not broad", (path) => {
    expect(isBroadPattern(path)).toBe(false);
  });

  it("lets a publish and a rollback acknowledge broad Rules, and carries expected_version on a rollback", () => {
    expect(PublishPolicyRequestSchema.parse({ rules: [], allow_broad: true }).allow_broad).toBe(true);
    expect(PublishPolicyRequestSchema.parse({ rules: [] }).allow_broad).toBeUndefined();
    expect(PublishPolicyRequestSchema.safeParse({ rules: [], allow_broad: "yes" }).success).toBe(false);
    expect(RollbackSchemaForBroad.parse({ version: 2, expected_version: 3, allow_broad: true })).toEqual({
      version: 2,
      expected_version: 3,
      allow_broad: true,
    });
    expect(RollbackSchemaForBroad.safeParse({ version: 2, expected_version: -1 }).success).toBe(false);
  });
});

describe("Rule requirement (slice 04)", () => {
  const bundleRule = (): BundleRule => EXAMPLE_BUNDLE_PAYLOAD.rules[0] as BundleRule;
  const signatureRule = { ...EXAMPLE_POLICY_RULE, requires: "signature" } as const;

  it("has the requirements of contract P1", () => {
    const requirement: RuleRequirement = "signature";
    expect(RULE_REQUIREMENTS).toEqual([requirement]);
  });

  it("round-trips a Policy Rule, a Rule input and a Policy with requires through JSON", () => {
    const stored: PolicyRule = signatureRule;
    expect(PolicyRuleSchema.parse(JSON.parse(JSON.stringify(stored)))).toEqual(stored);
    const input: PolicyRuleInput = { name: "Orders", path: "/api/orders", requires: "signature" };
    expect(PolicyRuleInputSchema.parse(input)).toEqual({
      name: "Orders",
      path: "/api/orders",
      methods: [],
      action: "block",
      mode: "monitor",
      requires: "signature",
    });
    const withRequirement: Policy = { ...EXAMPLE_POLICY, rules: [signatureRule] };
    expect(PolicySchema.parse(JSON.parse(JSON.stringify(withRequirement)))).toEqual(withRequirement);
    const request: PublishPolicyRequestInput = { rules: [input] };
    expect(PublishPolicyRequestSchema.parse(request).rules[0]?.requires).toBe("signature");
  });

  it("keeps requires optional: absent stays absent", () => {
    expect(PolicyRuleSchema.parse(EXAMPLE_POLICY_RULE)).not.toHaveProperty("requires");
    expect(PolicyRuleInputSchema.parse({ name: "a", path: "/a" })).not.toHaveProperty("requires");
  });

  it("accepts the known requirement only", () => {
    expect(acceptsRule({ requires: "signature" })).toBe(true);
    expect(acceptsRule({ requires: undefined })).toBe(true);
    for (const requires of ["Signature", "attestation", "", null, true, ["signature"]]) {
      expect(acceptsRule({ requires }), JSON.stringify(requires)).toBe(false);
      expect(acceptsInput({ name: "a", path: "/a", requires }), JSON.stringify(requires)).toBe(false);
    }
  });

  it("never puts requires in a bundle `rules` entry: the schema strips it, so the API must route such a Rule to signature_rules (amendment A1: an older Shield would otherwise enforce it as a plain block)", () => {
    const parsed = BundlePayloadSchema.parse(payload({ rules: [{ ...bundleRule(), requires: "signature" }] }));
    expect(parsed.rules).toEqual([bundleRule()]);
    expect(parsed.rules[0]).not.toHaveProperty("requires");
    expect(Object.keys(parsed.rules[0] ?? {}).sort()).toEqual(["action", "id", "methods", "mode", "path"]);
  });

  describe("BundlePayloadSchema signature_rules", () => {
    const accepts = (patch: Record<string, unknown>): boolean => BundlePayloadSchema.safeParse(payload(patch)).success;
    const many = (count: number) => Array.from({ length: count }, bundleRule);

    it("leaves a payload without signature_rules valid: absent stays absent", () => {
      expect(BundlePayloadSchema.parse(EXAMPLE_BUNDLE_PAYLOAD)).not.toHaveProperty("signature_rules");
    });

    it("round-trips a payload with signature_rules through JSON", () => {
      const withRules: BundlePayload = { ...EXAMPLE_BUNDLE_PAYLOAD, signature_rules: [bundleRule()] };
      expect(BundlePayloadSchema.parse(JSON.parse(JSON.stringify(withRules)))).toEqual(withRules);
    });

    it("has the shape of a bundle Rule, without name and without requires, and with no defaults", () => {
      const parsed = BundlePayloadSchema.parse(
        payload({ signature_rules: [{ ...EXAMPLE_POLICY_RULE, requires: "signature", hits: 3 }] }),
      );
      expect(parsed.signature_rules).toEqual([bundleRule()]);
      const withEntry = (patch: Record<string, unknown>) =>
        accepts({ signature_rules: [{ ...bundleRule(), ...patch }] });
      expect(withEntry({})).toBe(true);
      expect(withEntry({ id: "rul_1" })).toBe(false);
      expect(withEntry({ path: "/a/**/b" })).toBe(false);
      expect(withEntry({ methods: undefined })).toBe(false);
      expect(withEntry({ action: "allow" })).toBe(false);
      expect(withEntry({ mode: undefined })).toBe(false);
      expect(accepts({ signature_rules: null })).toBe(false);
    });

    it("caps rules and signature_rules together at 50", () => {
      expect(accepts({ rules: many(25), signature_rules: many(25) })).toBe(true);
      expect(accepts({ rules: [], signature_rules: many(POLICY_LIMITS.rulesMax) })).toBe(true);
      expect(accepts({ rules: many(POLICY_LIMITS.rulesMax), signature_rules: [] })).toBe(true);
      expect(accepts({ rules: many(26), signature_rules: many(25) })).toBe(false);
      expect(accepts({ rules: many(1), signature_rules: many(POLICY_LIMITS.rulesMax) })).toBe(false);
      expect(accepts({ rules: [], signature_rules: many(POLICY_LIMITS.rulesMax + 1) })).toBe(false);
    });

    it("is stripped by an older Shield's schema (a copy without the field)", () => {
      const older = z.object(BundlePayloadSchema.shape).omit({ signature_rules: true });
      const parsed = older.parse({ ...EXAMPLE_BUNDLE_PAYLOAD, signature_rules: [bundleRule()] });
      expect(parsed).toEqual(EXAMPLE_BUNDLE_PAYLOAD);
      expect(parsed).not.toHaveProperty("signature_rules");
    });
  });
});

describe("BundlePayloadSchema patches (slice 20)", () => {
  const accepts = (patch: Record<string, unknown>): boolean => BundlePayloadSchema.safeParse(payload(patch)).success;
  const entry = (n: number) => ({ ...EXAMPLE_BUNDLE_PATCH, id: `vp_patch_${n}` });
  const entries = (count: number) => Array.from({ length: count }, (_, n) => entry(n));

  it("leaves a payload without patches valid: absent stays absent", () => {
    expect(BundlePayloadSchema.parse(EXAMPLE_BUNDLE_PAYLOAD)).not.toHaveProperty("patches");
  });

  it("round-trips a payload with patches through JSON", () => {
    const full: BundlePayload = { ...EXAMPLE_BUNDLE_PAYLOAD, patches: [EXAMPLE_BUNDLE_PATCH, entry(1)] };
    expect(BundlePayloadSchema.parse(JSON.parse(JSON.stringify(full)))).toEqual(full);
  });

  it("accepts 0..50 patches and rejects 51", () => {
    expect(PATCH_LIMITS.perBundle).toBe(50);
    expect(accepts({ patches: [] })).toBe(true);
    expect(accepts({ patches: entries(50) })).toBe(true);
    expect(accepts({ patches: entries(51) })).toBe(false);
    expect(accepts({ patches: null })).toBe(false);
    expect(accepts({ patches: {} })).toBe(false);
  });

  it("rejects a patch id listed twice", () => {
    expect(accepts({ patches: [entry(1), entry(1)] })).toBe(false);
  });

  it("rejects an invalid patch entry", () => {
    expect(accepts({ patches: [{ ...EXAMPLE_BUNDLE_PATCH, mode: "block" }] })).toBe(false);
    expect(accepts({ patches: [{ ...EXAMPLE_BUNDLE_PATCH, conditions: [] }] })).toBe(false);
  });

  it("holds patches of at most 16,384 bytes of JSON together, exactly at the boundary", () => {
    expect(PATCH_LIMITS.bundleBytesMax).toBe(16_384);
    const condition = (length: number) => ({ target: "body", op: "contains", value: "v".repeat(length) });
    const big = (n: number) => ({ ...entry(n), conditions: Array.from({ length: 8 }, () => condition(256)) });
    const fill = (count: number, last: number) => ({
      ...entry(99),
      // Fixed conditions shorter than the variable one leave no gap in the sizes searched.
      conditions: [...Array.from({ length: count - 1 }, () => condition(200)), condition(last)],
    });
    const sized = (target: number) => {
      for (let count = 1; count <= 8; count++) {
        for (let last = 1; last <= 256; last++) {
          const patches = [big(1), big(2), big(3), big(4), big(5), big(6), fill(count, last)];
          if (new TextEncoder().encode(JSON.stringify(patches)).length === target) return patches;
        }
      }
      throw new Error(`no patch set of ${target} bytes`);
    };
    expect(accepts({ patches: sized(16_384) })).toBe(true);
    expect(accepts({ patches: sized(16_385) })).toBe(false);
    expect(accepts({ patches: [big(1), big(2), big(3), big(4), big(5), big(6), big(7)] })).toBe(false);
  });

  it("is stripped by an older Shield's schema (a copy without the field)", () => {
    const older = z.object(BundlePayloadSchema.shape).omit({ patches: true });
    const parsed = older.parse({ ...EXAMPLE_BUNDLE_PAYLOAD, patches: entries(2) });
    expect(parsed).toEqual(EXAMPLE_BUNDLE_PAYLOAD);
    expect(parsed).not.toHaveProperty("patches");
  });
});
