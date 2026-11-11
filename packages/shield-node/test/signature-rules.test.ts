// Slice 04, Review Focus 4 (Shield side): requirement Rules arrive in the bundle member `signature_rules` (amendment
// A1), are validated by hand as `rules` are (together at most 50), and match a request only when the requirement is
// not met. A Shield from before slice 04 ignores the member, so a requirement never becomes a plain block.
import { BundlePayloadSchema, POLICY_LIMITS } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import { decide } from "../src/decide.ts";
import { compilePattern, type PathPattern } from "../src/policy/match.ts";
import { buildPolicy, routeOfDecision } from "../src/policy/store.ts";
import { audienceOf, importPublicKey, type VerifyContext, verifyBundle } from "../src/policy/verify.ts";
import { createSigner, DAY_MS, NOW, payload, rule, signed } from "./policy-helpers.ts";

const KEY = generateKey("shield", "development").key;
const signer = createSigner();

function context(): VerifyContext {
  return {
    publicKey: importPublicKey(signer.publicKey) as NonNullable<ReturnType<typeof importPublicKey>>,
    audience: audienceOf(KEY),
    appliedVersion: 0,
    appliedEpoch: null,
    appliedIssuedAt: 0,
    now: NOW,
  };
}

const ORDERS = rule(10, { path: "/api/orders/**", methods: ["POST"], mode: "enforce" });
const REPORTS = rule(11, { path: "/api/reports", mode: "monitor" });

describe("verifyBundle: signature_rules", () => {
  it("reads signature_rules into the Policy's requirement Rules, apart from the plain Rules", () => {
    const body = payload(KEY, { rules: [rule(1)], signature_rules: [ORDERS, REPORTS] });
    expect(BundlePayloadSchema.safeParse(body).success).toBe(true);
    const verified = verifyBundle(signed(signer, body), context());
    if (!verified.ok) throw new Error(verified.detail);
    expect(verified.policy.rules.map((r) => r.id)).toEqual([rule(1).id]);
    expect(verified.policy.signatureRules.map((r) => [r.id, r.path, r.methods, r.mode])).toEqual([
      [ORDERS.id, "/api/orders/**", ["POST"], "enforce"],
      [REPORTS.id, "/api/reports", [], "monitor"],
    ]);
  });

  it("a bundle without signature_rules has none", () => {
    const verified = verifyBundle(signed(signer, payload(KEY)), context());
    expect(verified.ok && verified.policy.signatureRules).toEqual([]);
  });

  it.each([
    ["not a list", { signature_rules: "x" }],
    ["a malformed Rule", { signature_rules: [{ ...ORDERS, id: "rul_x" }] }],
    ["a Rule with an unknown mode", { signature_rules: [{ ...ORDERS, mode: "deny" }] }],
    ["a Rule with a bad path", { signature_rules: [{ ...ORDERS, path: "api" }] }],
    [
      "more than 50 Rules together with rules",
      {
        rules: Array.from({ length: 30 }, (_, i) => rule(i + 1)),
        signature_rules: Array.from({ length: 21 }, (_, i) => rule(i + 100)),
      },
    ],
  ])("refuses the whole bundle for %s, as the protocol does", (_name, overrides) => {
    const body = { ...payload(KEY), ...overrides };
    expect(BundlePayloadSchema.safeParse(body).success).toBe(false);
    expect(verifyBundle(signed(signer, body), context())).toMatchObject({ ok: false, reason: "invalid" });
  });

  it("accepts exactly 50 Rules together", () => {
    const body = payload(KEY, {
      rules: Array.from({ length: 30 }, (_, i) => rule(i + 1)),
      signature_rules: Array.from({ length: 20 }, (_, i) => rule(i + 100)),
    });
    expect(POLICY_LIMITS.rulesMax).toBe(50);
    expect(BundlePayloadSchema.safeParse(body).success).toBe(true);
    expect(verifyBundle(signed(signer, body), context()).ok).toBe(true);
  });

  it("a requirement cannot arrive in rules: the bundle schema strips `requires`, and so does Shield", () => {
    const body = payload(KEY, { rules: [{ ...rule(1), requires: "signature" } as never] });
    const parsed = BundlePayloadSchema.parse(body);
    expect(parsed.rules[0]).not.toHaveProperty("requires");
    const verified = verifyBundle(signed(signer, body), context());
    expect(verified.ok && verified.policy.signatureRules).toEqual([]);
  });

  it("a parser from before slice 04 (no signature_rules field) ignores the requirement: nothing is blocked", () => {
    const body = payload(KEY, { rules: [], signature_rules: [ORDERS] });
    const verified = verifyBundle(signed(signer, body), context());
    if (!verified.ok) throw new Error(verified.detail);
    // What an older Shield applied: the same bundle read without the member.
    const older = buildPolicy({
      version: verified.policy.version,
      issuedAt: verified.policy.issuedAt,
      notAfter: verified.policy.notAfter,
      rules: verified.policy.rules,
    });
    expect(decide(older, { method: "POST", path: "/api/orders/1" }).action).toBe("allow");
    // This Shield applies it as a requirement.
    expect(decide(verified.policy, { method: "POST", path: "/api/orders/1" })).toMatchObject({
      action: "block",
      ruleId: ORDERS.id,
    });
  });
});

function compiled(spec: { id: string; path: string; mode: "monitor" | "enforce"; methods?: string[] }) {
  return {
    id: spec.id,
    path: spec.path,
    mode: spec.mode,
    methods: spec.methods ?? [],
    pattern: compilePattern(spec.path) as PathPattern,
  };
}

const PLAIN_ENFORCE = "rul_0000000000000000000000a1";
const PLAIN_MONITOR = "rul_0000000000000000000000a2";
const SIG_ENFORCE = "rul_0000000000000000000000b1";
const SIG_MONITOR = "rul_0000000000000000000000b2";

describe("decide: requirement Rules", () => {
  const policy = buildPolicy({
    version: 4,
    issuedAt: NOW,
    notAfter: NOW + DAY_MS,
    rules: [
      compiled({ id: PLAIN_MONITOR, path: "/api/both", mode: "monitor" }),
      compiled({ id: PLAIN_ENFORCE, path: "/api/admin/**", mode: "enforce" }),
    ],
    signatureRules: [
      compiled({ id: SIG_MONITOR, path: "/api/watch", mode: "monitor" }),
      compiled({ id: SIG_ENFORCE, path: "/api/orders", mode: "enforce", methods: ["POST"] }),
      compiled({ id: "rul_0000000000000000000000b3", path: "/api/both", mode: "enforce" }),
    ],
  });

  it("matches (path + methods) only when the requirement is not met", () => {
    expect(decide(policy, { method: "POST", path: "/api/orders", signed: false })).toEqual({
      action: "block",
      mode: "enforce",
      ruleId: SIG_ENFORCE,
      policyVersion: 4,
    });
    expect(decide(policy, { method: "POST", path: "/api/orders" }).ruleId).toBe(SIG_ENFORCE); // unknown = not met
    expect(decide(policy, { method: "POST", path: "/api/orders", signed: true })).toEqual({
      action: "allow",
      mode: "enforce",
      ruleId: null,
      policyVersion: 4,
    });
    expect(decide(policy, { method: "GET", path: "/api/orders", signed: false }).action).toBe("allow");
    expect(decide(policy, { method: "POST", path: "/api/other", signed: false }).action).toBe("allow");
  });

  it("monitor records the requirement Rule; the route of its Decision is its path", () => {
    const decision = decide(policy, { method: "GET", path: "/api/watch", signed: false });
    expect(decision).toEqual({ action: "block", mode: "monitor", ruleId: SIG_MONITOR, policyVersion: 4 });
    expect(routeOfDecision(decision)).toBe("/api/watch");
  });

  it("matches raw and canonical path forms, as plain Rules do", () => {
    expect(decide(policy, { method: "POST", path: "/api/%6Frders", signed: false }).ruleId).toBe(SIG_ENFORCE);
    expect(decide(policy, { method: "POST", path: "/api/x/../orders", signed: false }).ruleId).toBe(SIG_ENFORCE);
  });

  it("review F2: HEAD meets a requirement Rule for GET; plain Rules for GET apply to HEAD too", () => {
    const getOnly = buildPolicy({
      version: 5,
      issuedAt: NOW,
      notAfter: NOW + DAY_MS,
      rules: [compiled({ id: PLAIN_ENFORCE, path: "/api/admin/**", mode: "enforce", methods: ["GET"] })],
      signatureRules: [compiled({ id: SIG_ENFORCE, path: "/api/data", mode: "enforce", methods: ["GET"] })],
    });
    expect(decide(getOnly, { method: "HEAD", path: "/api/data", signed: false }).ruleId).toBe(SIG_ENFORCE);
    expect(decide(getOnly, { method: "HEAD", path: "/api/data", signed: true }).action).toBe("allow");
    expect(decide(getOnly, { method: "HEAD", path: "/api/admin/x" }).ruleId).toBe(PLAIN_ENFORCE);
    expect(decide(getOnly, { method: "POST", path: "/api/admin/x" }).action).toBe("allow");
  });

  it("review F3: a CORS preflight (OPTIONS, preflight) is exempt from requirement Rules only", () => {
    const all = buildPolicy({
      version: 6,
      issuedAt: NOW,
      notAfter: NOW + DAY_MS,
      rules: [compiled({ id: PLAIN_ENFORCE, path: "/api/admin/**", mode: "enforce" })],
      signatureRules: [compiled({ id: SIG_ENFORCE, path: "/api/**", mode: "enforce" })],
    });
    expect(decide(all, { method: "OPTIONS", path: "/api/data", preflight: true }).action).toBe("allow");
    expect(decide(all, { method: "OPTIONS", path: "/api/data" }).ruleId).toBe(SIG_ENFORCE);
    expect(decide(all, { method: "OPTIONS", path: "/api/data", preflight: false }).ruleId).toBe(SIG_ENFORCE);
    // Plain Rules still apply to a preflight.
    expect(decide(all, { method: "OPTIONS", path: "/api/admin/x", preflight: true }).ruleId).toBe(PLAIN_ENFORCE);
    // Only OPTIONS can be a preflight.
    expect(decide(all, { method: "GET", path: "/api/data", preflight: true }).ruleId).toBe(SIG_ENFORCE);
  });

  it("orders plain Rules before requirement Rules; the first Enforce match wins over any Monitor match", () => {
    // /api/both: a plain Monitor Rule and an Enforce requirement Rule match: Enforce wins.
    expect(decide(policy, { method: "GET", path: "/api/both", signed: false }).ruleId).toBe(
      "rul_0000000000000000000000b3",
    );
    // Signed: only the plain Monitor Rule matches.
    expect(decide(policy, { method: "GET", path: "/api/both", signed: true }).ruleId).toBe(PLAIN_MONITOR);
    // A plain Enforce Rule decides whatever the signature.
    expect(decide(policy, { method: "GET", path: "/api/admin/x", signed: true }).ruleId).toBe(PLAIN_ENFORCE);
  });
});
