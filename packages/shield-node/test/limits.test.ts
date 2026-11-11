// Slice 08: Shield's hand-written limit contract agrees with the protocol's; the bundle member `limit_rules` is read
// with tolerance (an entry Shield cannot read is skipped and counted, the bundle is never refused for it); and the
// limiter — which Rules count a request, under which key, and when a limit refuses.
import {
  type BundleLimitRule,
  type BundlePayload,
  BundlePayloadSchema,
  EXAMPLE_LIMIT_RULE,
  LIMIT_COUNTS as PROTOCOL_COUNTS,
  LIMIT_FAILURE_STATUSES as PROTOCOL_FAILURE_STATUSES,
  LIMIT_KEYS as PROTOCOL_KEYS,
  LIMIT_LIMITS as PROTOCOL_LIMITS,
  RATE_LIMITED_RESPONSE_BODY,
} from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import { parseAddress, parseCidr } from "../src/address.ts";
import type { Client } from "../src/containment.ts";
import { type CounterStore, MemoryCounterStore } from "../src/counters.ts";
import {
  createLimiter,
  LIMIT_COUNTS,
  LIMIT_DEVICE_ADDRESS_FACTOR,
  LIMIT_FAILURE_STATUSES,
  LIMIT_KEYS,
  LIMIT_LIMITS,
  type LimitRuleInput,
  RATE_LIMITED_BODY,
} from "../src/limits.ts";
import { compilePattern } from "../src/policy/match.ts";
import { type AppliedPolicy, buildPolicy } from "../src/policy/store.ts";
import { audienceOf, importPublicKey, verifyBundle } from "../src/policy/verify.ts";
import { createSigner, NOW, payload, rule, signed } from "./policy-helpers.ts";

const KEY = generateKey("shield", "development").key;
const signer = createSigner();

function limitRule(n: number, overrides: Partial<BundleLimitRule> = {}): BundleLimitRule {
  return {
    id: `rul_${(0xa000 + n).toString(16).padStart(24, "0")}`,
    path: "/login",
    methods: ["POST"],
    action: "throttle",
    mode: "enforce",
    limit: { requests: 3, window_s: 60, key: "ip", count: "requests" },
    ...overrides,
  };
}

function verify(overrides: Record<string, unknown>) {
  const publicKey = importPublicKey(signer.publicKey);
  if (publicKey === null) throw new Error("the test key did not import");
  return verifyBundle(signed(signer, { ...payload(KEY), ...overrides }), {
    publicKey,
    audience: audienceOf(KEY),
    appliedVersion: 0,
    appliedEpoch: null,
    appliedIssuedAt: 0,
    now: NOW + 1_000,
  });
}

describe("Shield's limit constants are the protocol's", () => {
  it("keys, counts, bounds, failure statuses and the response body agree", () => {
    expect([...LIMIT_KEYS]).toEqual([...PROTOCOL_KEYS]);
    expect([...LIMIT_COUNTS]).toEqual([...PROTOCOL_COUNTS]);
    expect({ ...LIMIT_LIMITS }).toEqual({ ...PROTOCOL_LIMITS });
    expect([...LIMIT_FAILURE_STATUSES]).toEqual([...PROTOCOL_FAILURE_STATUSES]);
    expect([...LIMIT_FAILURE_STATUSES]).toEqual([401, 403]);
    expect(RATE_LIMITED_BODY).toBe(RATE_LIMITED_RESPONSE_BODY);
  });
});

describe("reading limit_rules of a bundle", () => {
  it("applies the protocol's example limit Rule as the bundle carries it", () => {
    const { name: _name, ...entry } = EXAMPLE_LIMIT_RULE;
    const bundle = { ...payload(KEY, { rules: [rule(1)] }), limit_rules: [entry] } as BundlePayload;
    expect(BundlePayloadSchema.safeParse(bundle).success).toBe(true);
    const result = verify({ rules: [rule(1)], limit_rules: [entry] });
    if (!result.ok) throw new Error(`refused: ${result.detail}`);
    expect(result.policy.rules).toHaveLength(1);
    expect(result.policy.limitRulesSkipped).toBe(0);
    expect(result.policy.limitRules).toHaveLength(1);
    expect(result.policy.limitRules[0]).toMatchObject({
      id: EXAMPLE_LIMIT_RULE.id,
      path: "/login",
      methods: ["POST"],
      mode: "monitor",
      requests: 10,
      windowMs: 300_000,
      key: "ip",
      failures: true,
      decision: { action: "throttle", mode: "monitor", ruleId: EXAMPLE_LIMIT_RULE.id, policyVersion: 1 },
    });
  });

  it("a bundle without the member, as before slice 08, has no limit Rules", () => {
    const result = verify({});
    if (!result.ok) throw new Error(`refused: ${result.detail}`);
    expect(result.policy.limitRules).toEqual([]);
    expect(result.policy.limitRulesSkipped).toBe(0);
  });

  it("keeps the order of the bundle", () => {
    const result = verify({ limit_rules: [limitRule(3), limitRule(1), limitRule(2)] });
    if (!result.ok) throw new Error(`refused: ${result.detail}`);
    expect(result.policy.limitRules.map((entry) => entry.id)).toEqual([
      limitRule(3).id,
      limitRule(1).id,
      limitRule(2).id,
    ]);
  });

  it.each<[string, unknown, number, number]>([
    ["the member is not a list", { not: "a list" }, 0, 1],
    ["the member is a string", "limit", 0, 1],
    ["an entry is not an object", [42, limitRule(1)], 1, 1],
    ["an entry has no limit", [{ ...limitRule(1), limit: undefined }, limitRule(2)], 1, 1],
    ["a limit is not an object", [{ ...limitRule(1), limit: [3, 60] }], 0, 1],
    ["a key is unknown", [{ ...limitRule(1), limit: { ...limitRule(1).limit, key: "account" } }, limitRule(2)], 1, 1],
    ["a count is unknown", [{ ...limitRule(1), limit: { ...limitRule(1).limit, count: "errors" } }], 0, 1],
    ["a count is missing", [{ ...limitRule(1), limit: { requests: 3, window_s: 60, key: "ip" } }], 0, 1],
    ["requests is 0", [{ ...limitRule(1), limit: { ...limitRule(1).limit, requests: 0 } }], 0, 1],
    ["requests is above the bound", [{ ...limitRule(1), limit: { ...limitRule(1).limit, requests: 100_001 } }], 0, 1],
    ["requests is not whole", [{ ...limitRule(1), limit: { ...limitRule(1).limit, requests: 1.5 } }], 0, 1],
    ["requests is text", [{ ...limitRule(1), limit: { ...limitRule(1).limit, requests: "3" } }], 0, 1],
    ["window_s is 0", [{ ...limitRule(1), limit: { ...limitRule(1).limit, window_s: 0 } }], 0, 1],
    ["window_s is above the bound", [{ ...limitRule(1), limit: { ...limitRule(1).limit, window_s: 3_601 } }], 0, 1],
    ["the action is block", [{ ...limitRule(1), action: "block" }, limitRule(2)], 1, 1],
    ["the action is unknown", [{ ...limitRule(1), action: "challenge" }], 0, 1],
    ["the mode is unknown", [{ ...limitRule(1), mode: "shadow" }], 0, 1],
    ["the id is not a Rule identifier", [{ ...limitRule(1), id: "limit-1" }], 0, 1],
    ["the path is not a pattern", [{ ...limitRule(1), path: "login" }, limitRule(2)], 1, 1],
    ["a method is not a method", [{ ...limitRule(1), methods: ["post"] }], 0, 1],
    ["an id is listed twice", [limitRule(1), limitRule(1, { path: "/other" }), limitRule(2)], 2, 1],
    [
      "the bounds are met exactly",
      [
        limitRule(1, { limit: { requests: 100_000, window_s: 3_600, key: "device", count: "failures" } }),
        limitRule(2, { limit: { requests: 1, window_s: 1, key: "ip", count: "requests" } }),
      ],
      2,
      0,
    ],
    ["an entry has a member Shield does not know", [{ ...limitRule(1), burst: 5 }], 1, 0],
  ])(
    "applies the bundle when %s: the Rules stay, the limit Rules it can read apply, the rest are counted",
    (_name, member, applied, skipped) => {
      const result = verify({ rules: [rule(1)], limit_rules: member });
      if (!result.ok) throw new Error(`refused: ${result.detail}`);
      expect(result.policy.rules).toHaveLength(1);
      expect(result.policy.limitRules).toHaveLength(applied);
      expect(result.policy.limitRulesSkipped).toBe(skipped);
    },
  );

  it("rules, signature_rules and limit_rules hold 50 Rules together: what is beyond is skipped and counted", () => {
    const rules = Array.from({ length: 20 }, (_, i) => rule(i + 1));
    const signature_rules = Array.from({ length: 10 }, (_, i) => rule(100 + i, { path: "/signed/**" }));
    const limit_rules = Array.from({ length: 25 }, (_, i) => limitRule(i));
    const result = verify({ rules, signature_rules, limit_rules });
    if (!result.ok) throw new Error(`refused: ${result.detail}`);
    expect(result.policy.rules).toHaveLength(20);
    expect(result.policy.signatureRules).toHaveLength(10);
    expect(result.policy.limitRules).toHaveLength(20);
    expect(result.policy.limitRules.map((entry) => entry.id)).toEqual(
      limit_rules.slice(0, 20).map((entry) => entry.id),
    );
    expect(result.policy.limitRulesSkipped).toBe(5);
  });

  it("a limit Rule in the wrong member is refused, never applied as a block", () => {
    // The protocol refuses both; Shield must not read a throttle Rule, or a Rule with a limit, as a plain block.
    const throttleInRules = verify({ rules: [limitRule(1)] });
    expect(throttleInRules).toMatchObject({ ok: false, reason: "invalid" });
    const limitInRules = verify({ rules: [{ ...rule(1), limit: limitRule(1).limit }] });
    expect(limitInRules).toMatchObject({ ok: false, reason: "invalid" });
    const limitInSignatureRules = verify({ signature_rules: [{ ...rule(2), limit: limitRule(1).limit }] });
    expect(limitInSignatureRules).toMatchObject({ ok: false, reason: "invalid" });
    for (const overrides of [
      { rules: [limitRule(1)] },
      { rules: [{ ...rule(1), limit: limitRule(1).limit }] },
      { signature_rules: [{ ...rule(2), limit: limitRule(1).limit }] },
    ]) {
      expect(BundlePayloadSchema.safeParse({ ...payload(KEY), ...overrides }).success).toBe(false);
    }
  });
});

// --- The limiter ----------------------------------------------------------------------------------------------------

const T0 = NOW + 60_000;

function input(n: number, overrides: Partial<Omit<LimitRuleInput, "pattern">> = {}): LimitRuleInput {
  const path = overrides.path ?? "/login";
  const pattern = compilePattern(path);
  if (pattern === null) throw new Error("not a pattern");
  return {
    id: `rul_${(0xb000 + n).toString(16).padStart(24, "0")}`,
    methods: ["POST"],
    mode: "enforce",
    requests: 3,
    windowS: 60,
    key: "ip",
    count: "requests",
    ...overrides,
    path,
    pattern,
  };
}

function policyOf(limitRules: LimitRuleInput[], allowlist: string[] = []): AppliedPolicy {
  return buildPolicy({
    version: 7,
    issuedAt: NOW,
    notAfter: NOW + 86_400_000,
    rules: [],
    limitRules,
    allowlist: allowlist.map((cidr) => {
      const parsed = parseCidr(cidr);
      if (parsed === null) throw new Error("not a CIDR");
      return parsed;
    }),
  });
}

function clientOf(address: string): Client {
  return { address: parseAddress(address), hash: null };
}

/** A store that records every call, on top of the real one. */
function recordingStore(): CounterStore & { calls: string[]; keys: Set<string> } {
  const inner = new MemoryCounterStore();
  const calls: string[] = [];
  const keys = new Set<string>();
  return {
    calls,
    keys,
    hit(key, windowMs, now, limit) {
      calls.push(`hit ${windowMs}`);
      keys.add(key);
      return inner.hit(key, windowMs, now, limit);
    },
    peek(key, windowMs, now, limit) {
      calls.push(`peek ${windowMs}`);
      keys.add(key);
      return inner.peek(key, windowMs, now, limit);
    },
    retryAfterMs: (key, windowMs, limit, now) => inner.retryAfterMs(key, windowMs, limit, now),
    size: () => inner.size(),
  };
}

const POST = { method: "POST", path: "/login", preflight: false, device: null };

describe("the limiter: requests", () => {
  it("allows `requests` requests per window and refuses the next, with the seconds until one more is allowed", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const policy = policyOf([input(1)]);
    const client = clientOf("203.0.113.9");
    for (let i = 0; i < 3; i++) {
      const outcome = limiter.evaluate(policy, { ...POST, client }, T0 + i);
      expect(outcome?.throttled ?? null).toBeNull();
      expect(outcome?.marked ?? null).toBeNull();
    }
    const refused = limiter.evaluate(policy, { ...POST, client }, T0 + 10_000);
    expect(refused?.throttled?.id).toBe(input(1).id);
    expect(refused?.throttled?.decision).toEqual({
      action: "throttle",
      mode: "enforce",
      ruleId: input(1).id,
      policyVersion: 7,
    });
    // 3 hits in the first sub-window (60 s from the first hit): one is allowed just after it turns, 50 s from now.
    expect(refused?.retryAfterS).toBe(51);
    // Another client is untouched.
    expect(limiter.evaluate(policy, { ...POST, client: clientOf("203.0.113.10") }, T0 + 10_000)?.throttled).toBeNull();
  });

  it("a refused request is not counted: hammering does not extend the refusal", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const policy = policyOf([input(1)]);
    const client = clientOf("203.0.113.9");
    for (let i = 0; i < 3; i++) limiter.evaluate(policy, { ...POST, client }, T0);
    let retry = 0;
    for (let i = 0; i < 500; i++) {
      const outcome = limiter.evaluate(policy, { ...POST, client }, T0 + 1_000 + i);
      expect(outcome?.throttled).not.toBeNull();
      retry = outcome?.retryAfterS ?? 0;
    }
    expect(retry).toBe(59);
    const later = T0 + 1_499 + retry * 1_000;
    expect(limiter.evaluate(policy, { ...POST, client }, later)?.throttled).toBeNull();
  });

  it("Retry-After is at least 1 and never promises too early", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const policy = policyOf([input(1, { requests: 1, windowS: 1 })]);
    const client = clientOf("203.0.113.9");
    limiter.evaluate(policy, { ...POST, client }, T0);
    const refused = limiter.evaluate(policy, { ...POST, client }, T0 + 999);
    expect(refused?.throttled).not.toBeNull();
    expect(refused?.retryAfterS).toBe(1);
    expect(limiter.evaluate(policy, { ...POST, client }, T0 + 999 + 1_000)?.throttled).toBeNull();
  });

  it("a monitor limit counts every request, marks the ones over the limit and refuses none", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const policy = policyOf([input(1, { mode: "monitor" })]);
    const client = clientOf("203.0.113.9");
    const seen = Array.from({ length: 6 }, (_, i) => limiter.evaluate(policy, { ...POST, client }, T0 + i));
    expect(seen.map((outcome) => outcome?.throttled ?? null)).toEqual([null, null, null, null, null, null]);
    expect(seen.map((outcome) => outcome?.marked?.id ?? null)).toEqual([
      null,
      null,
      null,
      input(1).id,
      input(1).id,
      input(1).id,
    ]);
    expect(seen[5]?.marked?.decision).toEqual({
      action: "throttle",
      mode: "monitor",
      ruleId: input(1).id,
      policyVersion: 7,
    });
  });

  it("A7 F3: every matching limit is looked at first; the request counts on all of them only when none refuses", () => {
    const store = recordingStore();
    const limiter = createLimiter(store);
    const policy = policyOf([
      input(1, { mode: "monitor", requests: 1 }),
      input(2, { path: "/other" }),
      input(3, { requests: 2, windowS: 30 }),
      input(4, { requests: 1, windowS: 10 }),
    ]);
    const client = clientOf("203.0.113.9");
    const first = limiter.evaluate(policy, { ...POST, client }, T0);
    expect(first?.throttled).toBeNull();
    // Rule 2 does not match. Rules 1, 3 and 4 are looked at, then counted.
    expect(store.calls).toEqual(["peek 60000", "peek 30000", "peek 10000", "hit 60000", "hit 30000", "hit 10000"]);
    store.calls.length = 0;
    const second = limiter.evaluate(policy, { ...POST, client }, T0 + 1);
    // Rule 4 is over: it refuses, and nothing is counted — not on Rule 3, not on the monitor Rule 1 before it.
    expect(second?.throttled?.id).toBe(input(4).id);
    expect(store.calls).toEqual(["peek 60000", "peek 30000", "peek 10000"]);
    store.calls.length = 0;
    const third = limiter.evaluate(policy, { ...POST, client }, T0 + 2);
    expect(third?.throttled?.id).toBe(input(4).id);
    expect(store.calls).toEqual(["peek 60000", "peek 30000", "peek 10000"]);
    // Once Rule 4's window has passed, Rule 3 still has room for one: it was never charged for the refusals.
    expect(limiter.evaluate(policy, { ...POST, client }, T0 + 10_001)?.throttled).toBeNull();
    expect(limiter.evaluate(policy, { ...POST, client }, T0 + 20_002)?.throttled?.id).toBe(input(3).id);
  });

  it("t3b H: requests a narrow Rule refuses do not use up a broad Rule after it", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const broad = input(1, { path: "/**", methods: [], requests: 20, windowS: 3_600 });
    const narrow = input(2, { requests: 3, windowS: 10 });
    for (const order of [
      [broad, narrow],
      [narrow, broad],
    ]) {
      const policy = policyOf(order);
      const client = clientOf(order[0] === broad ? "203.0.113.9" : "203.0.113.10");
      const statuses: string[] = [];
      for (let i = 0; i < 25; i++) {
        const outcome = limiter.evaluate(policy, { ...POST, client }, T0 + i);
        statuses.push(outcome?.throttled ? `429:${outcome.throttled.id}` : "ok");
      }
      expect(statuses).toEqual([...Array(3).fill("ok"), ...Array(22).fill(`429:${narrow.id}`)]);
      // Later, another route under the broad Rule is served: it counted 3, not 25.
      const other = limiter.evaluate(policy, { ...POST, path: "/api/data", client }, T0 + 22_000);
      expect(other?.throttled).toBeNull();
    }
  });

  it("t7 H'': a monitor Rule neither counts nor marks a request an enforced Rule refused", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const watch = input(1, { path: "/**", methods: [], mode: "monitor", requests: 5, windowS: 3_600 });
    const narrow = input(2, { requests: 3, windowS: 10 });
    const policy = policyOf([watch, narrow]);
    const client = clientOf("203.0.113.9");
    const seen: string[] = [];
    for (let i = 0; i < 8; i++) {
      const outcome = limiter.evaluate(policy, { ...POST, client }, T0 + i);
      seen.push(outcome?.throttled ? "throttle" : outcome?.marked ? "mark" : "ok");
    }
    expect(seen).toEqual(["ok", "ok", "ok", ...Array(5).fill("throttle")]);
    // The monitor Rule counted 3: two more requests elsewhere are within its 5, the third is over.
    const later = (at: number) =>
      limiter.evaluate(policy, { ...POST, method: "GET", path: "/api/data", client }, T0 + at)?.marked?.id ?? null;
    expect([later(22_000), later(22_001), later(22_002)]).toEqual([null, null, watch.id]);
  });

  it("Retry-After is the longest wait of the enforced Rules that are over", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const short = input(1, { requests: 1, windowS: 10 });
    const long = input(2, { requests: 1, windowS: 100 });
    const policy = policyOf([short, long]);
    const client = clientOf("203.0.113.9");
    limiter.evaluate(policy, { ...POST, client }, T0);
    const refused = limiter.evaluate(policy, { ...POST, client }, T0 + 1_000);
    expect(refused?.throttled?.id).toBe(short.id);
    expect(refused?.retryAfterS).toBe(100);
  });
});

describe("the limiter: failures", () => {
  const failures = input(1, { count: "failures", requests: 2, windowS: 300 });

  it("counts a response that closes with 401 or 403 and nothing else", () => {
    const store = recordingStore();
    const limiter = createLimiter(store);
    const policy = policyOf([failures]);
    const client = clientOf("203.0.113.9");
    for (const status of [200, 204, 302, 400, 404, 429, 500]) {
      const outcome = limiter.evaluate(policy, { ...POST, client }, T0);
      if (outcome === null) throw new Error("no outcome");
      limiter.settle(outcome, status, T0);
    }
    expect(store.calls.filter((call) => call.startsWith("hit"))).toEqual([]);
    for (const status of [401, 403]) {
      const outcome = limiter.evaluate(policy, { ...POST, client }, T0);
      if (outcome === null) throw new Error("no outcome");
      expect(outcome.throttled).toBeNull();
      limiter.settle(outcome, status, T0);
    }
    expect(store.calls.filter((call) => call.startsWith("hit"))).toEqual(["hit 300000", "hit 300000"]);
  });

  it("refuses at decision time once the failures in the window reach `requests`, and counts no refused request", () => {
    const store = recordingStore();
    const limiter = createLimiter(store);
    const policy = policyOf([failures]);
    const client = clientOf("203.0.113.9");
    for (let i = 0; i < 2; i++) {
      const outcome = limiter.evaluate(policy, { ...POST, client }, T0 + i);
      if (outcome === null) throw new Error("no outcome");
      limiter.settle(outcome, 401, T0 + i);
    }
    store.calls.length = 0;
    const refused = limiter.evaluate(policy, { ...POST, client }, T0 + 1_000);
    expect(refused?.throttled?.id).toBe(failures.id);
    expect(refused?.retryAfterS).toBe(300);
    if (refused === null) throw new Error("no outcome");
    // The throttled response (429) is settled like any other: it is not a failure, and even a 401 would not count.
    limiter.settle(refused, 429, T0 + 1_000);
    limiter.settle(refused, 401, T0 + 1_000);
    expect(store.calls).toEqual(["peek 300000"]);
    // One more is allowed once the window lets a failure go.
    expect(limiter.evaluate(policy, { ...POST, client }, T0 + 300_001)?.throttled).toBeNull();
    // Another client still logs in.
    expect(limiter.evaluate(policy, { ...POST, client: clientOf("198.51.100.4") }, T0 + 1_000)?.throttled).toBeNull();
  });

  it("in monitor, marks the request once the failures reach `requests` and keeps counting", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const policy = policyOf([{ ...failures, mode: "monitor" }]);
    const client = clientOf("203.0.113.9");
    const marks: (string | null)[] = [];
    for (let i = 0; i < 4; i++) {
      const outcome = limiter.evaluate(policy, { ...POST, client }, T0 + i);
      if (outcome === null) throw new Error("no outcome");
      expect(outcome.throttled).toBeNull();
      marks.push(outcome.marked?.id ?? null);
      limiter.settle(outcome, 403, T0 + i);
    }
    expect(marks).toEqual([null, null, failures.id, failures.id]);
  });

  it("A7 F1: a request in flight holds a slot, so parallel guesses cannot pass the limit", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const policy = policyOf([{ ...failures, requests: 10 }]);
    const client = clientOf("203.0.113.9");
    // 1,000 guesses arrive before any of them is answered.
    const outcomes = Array.from({ length: 1_000 }, () => limiter.evaluate(policy, { ...POST, client }, T0));
    const admitted = outcomes.filter((outcome) => outcome?.throttled === null);
    expect(admitted).toHaveLength(10);
    expect(limiter.inFlight()).toBe(10);
    // Each admitted guess fails: the slots become failures, and the limit stays reached.
    for (const outcome of admitted) limiter.settle(outcome as NonNullable<typeof outcome>, 401, T0 + 1);
    expect(limiter.inFlight()).toBe(0);
    expect(limiter.evaluate(policy, { ...POST, client }, T0 + 2)?.throttled?.id).toBe(failures.id);
  });

  it("A7 F1: a slot is released when the response closes, whatever its status, exactly once", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const policy = policyOf([failures]);
    const client = clientOf("203.0.113.9");
    const a = limiter.evaluate(policy, { ...POST, client }, T0);
    const b = limiter.evaluate(policy, { ...POST, client }, T0);
    expect(limiter.evaluate(policy, { ...POST, client }, T0)?.throttled?.id).toBe(failures.id); // 0 + 2 in flight
    if (a === null || b === null) throw new Error("no outcome");
    limiter.settle(a, 200, T0); // a success: released, nothing counted
    limiter.settle(a, 401, T0); // a second close changes nothing
    expect(limiter.inFlight()).toBe(1);
    const c = limiter.evaluate(policy, { ...POST, client }, T0);
    expect(c?.throttled).toBeNull();
    limiter.release(b); // an aborted request: released without a status
    limiter.settle(b, 401, T0); // and never counted afterwards
    expect(limiter.inFlight()).toBe(1);
    if (c === null) throw new Error("no outcome");
    limiter.settle(c, 403, T0);
    expect(limiter.inFlight()).toBe(0);
    // One failure counted (c): one more is admitted.
    expect(limiter.evaluate(policy, { ...POST, client }, T0)?.throttled).toBeNull();
  });

  it("A7: the outcome names the first failure-counting Rule that matched, whether or not it throttled", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const requestsRule = input(2, { requests: 1 });
    const policy = policyOf([requestsRule, failures, input(3, { count: "failures", requests: 5 })]);
    const client = clientOf("203.0.113.9");
    const first = limiter.evaluate(policy, { ...POST, client }, T0);
    expect(first?.failureRule?.id).toBe(failures.id);
    if (first !== null) limiter.release(first);
    const refused = limiter.evaluate(policy, { ...POST, client }, T0);
    expect(refused?.throttled?.id).toBe(requestsRule.id);
    expect(refused?.failureRule?.id).toBe(failures.id);
    const plain = limiter.evaluate(policyOf([input(4)]), { ...POST, client }, T0);
    expect(plain?.failureRule).toBeNull();
  });

  it("failures of a request that a later enforced limit refused are not counted", () => {
    const store = recordingStore();
    const limiter = createLimiter(store);
    const policy = policyOf([failures, input(2, { requests: 1 })]);
    const client = clientOf("203.0.113.9");
    limiter.evaluate(policy, { ...POST, client }, T0);
    const refused = limiter.evaluate(policy, { ...POST, client }, T0 + 1);
    expect(refused?.throttled?.id).toBe(input(2).id);
    if (refused === null) throw new Error("no outcome");
    store.calls.length = 0;
    limiter.settle(refused, 401, T0 + 1);
    expect(store.calls).toEqual([]);
  });
});

describe("the limiter: keys", () => {
  const SECRET = Buffer.alloc(32, 7);
  const DEVICE_A = "dev_0123456789abcdef01234567";
  const DEVICE_B = "dev_fedcba9876543210fedcba98";

  /** The keys each request touches, under one secret (a limiter of its own per request, so nothing is refused). */
  function keysFor(
    rules: LimitRuleInput[],
    requests: { address: string; device?: string | null }[],
    secret: Buffer | null = SECRET,
  ): string[][] {
    return requests.map(({ address, device }) => {
      const store = recordingStore();
      createLimiter(store, secret === null ? {} : { secret }).evaluate(
        policyOf(rules),
        { ...POST, client: clientOf(address), device: device ?? null },
        T0,
      );
      return [...store.keys];
    });
  }

  it("ip: one key per IPv4 address; an IPv4-mapped IPv6 address is that IPv4 address", () => {
    const [a, b, mapped] = keysFor(
      [input(1)],
      [{ address: "203.0.113.9" }, { address: "203.0.113.10" }, { address: "::ffff:203.0.113.9" }],
    );
    expect(a).toHaveLength(1);
    expect(a).not.toEqual(b);
    expect(mapped).toEqual(a);
  });

  it("ip: IPv6 addresses of one /64 share a key, so rotating inside it escapes nothing", () => {
    const [a, same, zone, other] = keysFor(
      [input(1)],
      [
        { address: "2001:db8:1:2:aaaa:bbbb:cccc:dddd" },
        { address: "2001:db8:1:2::1" },
        { address: "2001:db8:1:2:ffff:ffff:ffff:ffff%eth0" },
        { address: "2001:db8:1:3::1" },
      ],
    );
    expect(same).toEqual(a);
    expect(zone).toEqual(a);
    expect(other).not.toEqual(a);
  });

  it("an ip-keyed limit ignores the device: a token, valid or not, changes nothing", () => {
    const [bare, attested, another] = keysFor(
      [input(1)],
      [
        { address: "203.0.113.9" },
        { address: "203.0.113.9", device: DEVICE_A },
        { address: "203.0.113.9", device: DEVICE_B },
      ],
    );
    expect(attested).toEqual(bare);
    expect(another).toEqual(bare);
  });

  it("device: an attested request counts on its device and on its address; without a valid token on the address alone", () => {
    const device = input(1, { key: "device" });
    const [bare, attested, moved, another] = keysFor(
      [device],
      [
        { address: "203.0.113.9" },
        { address: "203.0.113.9", device: DEVICE_A },
        { address: "198.51.100.4", device: DEVICE_A },
        { address: "203.0.113.9", device: DEVICE_B },
      ],
    );
    expect(bare).toHaveLength(1);
    expect(attested).toHaveLength(2);
    // The address counter is the one a request without a token counts on: dropping the token escapes nothing.
    expect(attested).toContain(bare?.[0]);
    const deviceKey = attested?.find((key) => key !== bare?.[0]);
    // The device counter follows the device to another address; the address counter does not.
    expect(moved).toContain(deviceKey);
    expect(moved).not.toContain(bare?.[0]);
    // Another device behind the same address: its own device counter, the same address counter.
    expect(another).toContain(bare?.[0]);
    expect(another).not.toContain(deviceKey);
    // Without a valid token a device-keyed limit counts the address, as an ip-keyed limit of that Rule would.
    const [ipKeyed] = keysFor([input(1)], [{ address: "203.0.113.9" }]);
    expect(bare).toEqual(ipKeyed);
  });

  it("two Rules never share a counter, and a Rule whose limit changed starts a new one", () => {
    const [both] = keysFor([input(1), input(2)], [{ address: "203.0.113.9" }]);
    expect(both).toHaveLength(2);
    const [before] = keysFor([input(1)], [{ address: "203.0.113.9" }]);
    const [after] = keysFor([input(1, { windowS: 61 })], [{ address: "203.0.113.9" }]);
    const [failures] = keysFor([input(1, { count: "failures" })], [{ address: "203.0.113.9" }]);
    expect(after).not.toEqual(before);
    expect(failures).not.toEqual(before);
  });

  it("a key handed to the store holds no address and no device id: the client part is a keyed hash of 16 bytes", () => {
    const requests = [
      { address: "203.0.113.9", device: DEVICE_A },
      { address: "2001:db8:1:2:aaaa:bbbb:cccc:dddd", device: DEVICE_B },
      { address: "203.0.113.9" },
    ];
    const keys = keysFor([input(1), input(2, { key: "device" }), input(3, { count: "failures" })], requests).flat();
    expect(keys.length).toBeGreaterThanOrEqual(8);
    for (const key of keys) {
      expect(key).toMatch(/^rul_[0-9a-f]{24}\/60\/[rf]\/[0-9a-f]{32}$/);
      for (const secret of ["203.0.113", "203", "113", "2001", "db8", DEVICE_A, DEVICE_A.slice(4), DEVICE_B.slice(4)]) {
        expect(key.slice(key.lastIndexOf("/") + 1)).not.toContain(secret);
      }
    }
    // Numeric forms of the address (as Shield holds it: 16-bit words) are not in a key either.
    expect(keys.join(" ")).not.toContain(`${(203 << 8) | 0}.${(113 << 8) | 9}`);
  });

  it("the hash is keyed with a secret of the process: random by default, so keys mean nothing outside it", () => {
    const request = [{ address: "203.0.113.9", device: DEVICE_A }];
    const rules = [input(1, { key: "device" })];
    const fixed = keysFor(rules, request);
    expect(keysFor(rules, request)).toEqual(fixed); // the same secret: the same keys
    const other = keysFor(rules, request, Buffer.alloc(32, 8));
    expect(other).not.toEqual(fixed);
    const random1 = keysFor(rules, request, null);
    const random2 = keysFor(rules, request, null);
    expect(random1).not.toEqual(fixed);
    expect(random1).not.toEqual(random2);
    // One limiter keeps one secret: the same client counts on the same counters.
    const store = recordingStore();
    const limiter = createLimiter(store);
    for (let i = 0; i < 3; i++) {
      limiter.evaluate(policyOf(rules), { ...POST, client: clientOf("203.0.113.9"), device: DEVICE_A }, T0);
    }
    expect(store.keys.size).toBe(2);
  });
});

describe("the limiter: a device-keyed limit also counts the address, at 5 times the limit", () => {
  const perDevice = input(1, { key: "device", requests: 2 });
  const device = (n: number): string => `dev_${n.toString(16).padStart(24, "0")}`;
  const from = (address: string, id: string | null) => ({ ...POST, client: clientOf(address), device: id });
  const X = "203.0.113.9";

  it("the factor is 5", () => {
    expect(LIMIT_DEVICE_ADDRESS_FACTOR).toBe(5);
  });

  it("a device over its limit is refused, at any address", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const policy = policyOf([perDevice]);
    expect(limiter.evaluate(policy, from(X, device(1)), T0)?.throttled).toBeNull();
    expect(limiter.evaluate(policy, from("198.51.100.4", device(1)), T0)?.throttled).toBeNull();
    const refused = limiter.evaluate(policy, from("192.0.2.1", device(1)), T0);
    expect(refused?.throttled?.id).toBe(perDevice.id);
    expect(refused?.retryAfterS).toBe(61);
  });

  it("dropping the token escapes nothing: the address has counted the attested requests", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const policy = policyOf([perDevice]);
    limiter.evaluate(policy, from(X, device(1)), T0);
    limiter.evaluate(policy, from(X, device(1)), T0);
    expect(limiter.evaluate(policy, from(X, device(1)), T0)?.throttled).not.toBeNull();
    // Without a token the plain limit applies to the address, which stands at 2 already.
    expect(limiter.evaluate(policy, from(X, null), T0)?.throttled?.id).toBe(perDevice.id);
    // Another address without a token has its own plain budget.
    expect(limiter.evaluate(policy, from("198.51.100.4", null), T0)?.throttled).toBeNull();
  });

  it("minting device ids multiplies the budget of one address by 5 at most", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const policy = policyOf([perDevice]);
    let served = 0;
    for (let n = 1; n <= 40; n++) {
      // A new device for every request: no device counter ever reaches 2.
      if (limiter.evaluate(policy, from(X, device(n)), T0)?.throttled === null) served += 1;
    }
    expect(served).toBe(10);
    const refused = limiter.evaluate(policy, from(X, device(99)), T0 + 10_000);
    expect(refused?.throttled?.id).toBe(perDevice.id);
    expect(refused?.retryAfterS).toBe(51); // the address counter's wait
    // A device elsewhere is untouched.
    expect(limiter.evaluate(policy, from("198.51.100.4", device(99)), T0)?.throttled).toBeNull();
  });

  it("requests without a token do not use the 5 times: the address is held to the plain limit", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const policy = policyOf([perDevice]);
    expect(limiter.evaluate(policy, from(X, null), T0)?.throttled).toBeNull();
    expect(limiter.evaluate(policy, from(X, null), T0)?.throttled).toBeNull();
    expect(limiter.evaluate(policy, from(X, null), T0)?.throttled).not.toBeNull();
    // An attested device behind that address is still served: the address is below 5 times the limit.
    expect(limiter.evaluate(policy, from(X, device(1)), T0)?.throttled).toBeNull();
  });

  it("a refused attested request counts on neither counter", () => {
    const store = recordingStore();
    const limiter = createLimiter(store);
    const policy = policyOf([perDevice]);
    limiter.evaluate(policy, from(X, device(1)), T0);
    limiter.evaluate(policy, from(X, device(1)), T0);
    store.calls.length = 0;
    expect(limiter.evaluate(policy, from(X, device(1)), T0)?.throttled).not.toBeNull();
    expect(store.calls).toEqual(["peek 60000", "peek 60000"]);
  });

  it("failures: both counters count the failed response; the device at the limit or the address at 5 times refuses", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const rule = input(1, { key: "device", requests: 2, count: "failures" });
    const policy = policyOf([rule]);
    const fail = (id: string | null): boolean => {
      const outcome = limiter.evaluate(policy, from(X, id), T0);
      if (outcome === null) throw new Error("no outcome");
      if (outcome.throttled !== null) return false;
      limiter.settle(outcome, 401, T0);
      return true;
    };
    expect([fail(device(1)), fail(device(1)), fail(device(1))]).toEqual([true, true, false]);
    // The address stands at 2 failures: without a token it is refused at once.
    expect(fail(null)).toBe(false);
    // New devices: 8 more failures until the address reaches 10.
    let served = 0;
    for (let n = 2; n <= 30; n++) if (fail(device(n))) served += 1;
    expect(served).toBe(8);
  });

  it("monitor: marks when either counter is over and refuses nothing", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const rule = input(1, { key: "device", requests: 2, mode: "monitor" });
    const policy = policyOf([rule]);
    const marks: (string | null)[] = [];
    for (let n = 1; n <= 12; n++) {
      const outcome = limiter.evaluate(policy, from(X, device(n)), T0);
      expect(outcome?.throttled).toBeNull();
      marks.push(outcome?.marked?.id ?? null);
    }
    // Ten devices, one request each: the address reaches 10; the 11th is over 5 times the limit.
    expect(marks).toEqual([...Array(10).fill(null), rule.id, rule.id]);
  });
});

describe("the limiter: what is exempt, and what matches", () => {
  const client = clientOf("203.0.113.9");

  it("an address on the never-block list is never counted and never throttled", () => {
    const store = recordingStore();
    const limiter = createLimiter(store);
    const policy = policyOf([input(1, { requests: 1 })], ["203.0.113.0/28", "2001:db8:9::/48"]);
    for (let i = 0; i < 5; i++) expect(limiter.evaluate(policy, { ...POST, client }, T0 + i)).toBeNull();
    expect(limiter.evaluate(policy, { ...POST, client: clientOf("2001:db8:9:1::5") }, T0)).toBeNull();
    expect(store.calls).toEqual([]);
    // An address outside the ranges is limited.
    limiter.evaluate(policy, { ...POST, client: clientOf("203.0.113.16") }, T0);
    expect(limiter.evaluate(policy, { ...POST, client: clientOf("203.0.113.16") }, T0)?.throttled).not.toBeNull();
  });

  it("t1, A7 F6: a CORS preflight is never counted, but is refused once the client is over a matching limit", () => {
    const store = recordingStore();
    const limiter = createLimiter(store);
    const policy = policyOf([input(1, { methods: [], requests: 2 })]);
    const preflight = { method: "OPTIONS", path: "/login", preflight: true, device: null, client };
    for (let i = 0; i < 3; i++) expect(limiter.evaluate(policy, preflight, T0)?.throttled ?? null).toBeNull();
    expect(store.calls.filter((call) => call.startsWith("hit"))).toEqual([]);
    limiter.evaluate(policy, { ...POST, client }, T0);
    limiter.evaluate(policy, { ...POST, client }, T0);
    expect(limiter.evaluate(policy, { ...POST, client }, T0)?.throttled).not.toBeNull();
    const refused = limiter.evaluate(policy, preflight, T0);
    expect(refused?.throttled?.id).toBe(input(1).id);
    expect(refused?.retryAfterS).toBe(61);
    // A preflight holds no failure slot either.
    const failing = createLimiter(new MemoryCounterStore());
    const fpolicy = policyOf([input(2, { methods: [], requests: 1, count: "failures" })]);
    for (let i = 0; i < 3; i++) failing.evaluate(fpolicy, preflight, T0);
    expect(failing.inFlight()).toBe(0);
  });

  it("a CORS preflight is exempt; a plain OPTIONS is not", () => {
    const store = recordingStore();
    const limiter = createLimiter(store);
    const policy = policyOf([input(1, { methods: [], requests: 1 })]);
    for (let i = 0; i < 3; i++) {
      const outcome = limiter.evaluate(
        policy,
        { method: "OPTIONS", path: "/login", preflight: true, device: null, client },
        T0,
      );
      expect(outcome?.throttled ?? null).toBeNull();
    }
    expect(store.calls.filter((call) => call.startsWith("hit"))).toEqual([]);
    limiter.evaluate(policy, { method: "OPTIONS", path: "/login", preflight: false, device: null, client }, T0);
    expect(
      limiter.evaluate(policy, { method: "OPTIONS", path: "/login", preflight: false, device: null, client }, T0)
        ?.throttled,
    ).not.toBeNull();
    // `preflight` on another method is ignored, as `decide` ignores it.
    expect(
      limiter.evaluate(policy, { method: "POST", path: "/login", preflight: true, device: null, client }, T0)
        ?.throttled,
    ).not.toBeNull();
  });

  it("a client without an address is not limited (fail open)", () => {
    const store = recordingStore();
    const limiter = createLimiter(store);
    const policy = policyOf([input(1, { requests: 1 })]);
    for (const rawAddress of [undefined, "", "   "]) {
      for (let i = 0; i < 3; i++) {
        const unknown = { ...POST, client: { address: null, hash: null }, rawAddress };
        expect(limiter.evaluate(policy, unknown, T0)).toBeNull();
      }
    }
    expect(store.calls).toEqual([]);
    expect(limiter.unparsedAddresses()).toBe(0);
  });

  it("t2 A, A7 F7: an address Shield cannot parse is counted by its trimmed text, hashed like any key", () => {
    const store = recordingStore();
    const limiter = createLimiter(store);
    const policy = policyOf([input(1, { requests: 3 })]);
    const unparsed = (rawAddress: string) => ({ ...POST, client: { address: null, hash: null }, rawAddress });
    for (const raw of ["banana", "203.0.113.9:4444", "[2001:db8::1]", "203.0.113.9, 10.0.0.1", "203.000.113.009"]) {
      const statuses: boolean[] = [];
      for (let i = 0; i < 5; i++) statuses.push(limiter.evaluate(policy, unparsed(raw), T0)?.throttled !== null);
      expect(statuses, raw).toEqual([false, false, false, true, true]);
    }
    // Trimmed: the same counter with or without spaces around it.
    expect(limiter.evaluate(policy, unparsed("  banana \t"), T0)?.throttled).not.toBeNull();
    // Only the first 64 characters count: a longer text cannot mint keys by varying its tail.
    const long = "x".repeat(64);
    for (let i = 0; i < 3; i++) limiter.evaluate(policy, unparsed(`${long}${i}`), T0);
    expect(limiter.evaluate(policy, unparsed(`${long}tail`), T0)?.throttled).not.toBeNull();
    // Never the text itself in a key.
    for (const key of store.keys) {
      expect(key).toMatch(/\/[0-9a-f]{32}$/);
      expect(key).not.toContain("banana");
      expect(key).not.toContain("203.0.113");
    }
    expect(limiter.unparsedAddresses()).toBeGreaterThan(0);
    // A parsed address is never confused with the text of an unparsed one.
    expect(limiter.evaluate(policy, { ...POST, client: clientOf("203.0.113.9") }, T0)?.throttled).toBeNull();
  });

  it("HEAD counts with GET; a method the Rule does not list is not counted", () => {
    const limiter = createLimiter(new MemoryCounterStore());
    const policy = policyOf([input(1, { methods: ["GET"], path: "/api/data", requests: 2 })]);
    const get = { method: "GET", path: "/api/data", preflight: false, device: null, client };
    limiter.evaluate(policy, get, T0);
    limiter.evaluate(policy, { ...get, method: "HEAD" }, T0);
    expect(limiter.evaluate(policy, { ...get, method: "POST" }, T0)).toBeNull();
    expect(limiter.evaluate(policy, { ...get, method: "HEAD" }, T0)?.throttled).not.toBeNull();
    expect(limiter.evaluate(policy, get, T0)?.throttled).not.toBeNull();
  });

  it.each([
    "/login",
    "/LOGIN",
    "/login/",
    "/login?next=%2Fhome",
    "/login#top",
    "/%6cogin",
    "/%256cogin",
    "/x/../login",
    "/./login",
    "//login",
    "/x/..%2flogin",
    "/x\\..\\login",
    "http://host.test/login",
  ])("every reading of the path counts on the same counter: %s", (path) => {
    const limiter = createLimiter(new MemoryCounterStore());
    const policy = policyOf([input(1, { requests: 1 })]);
    limiter.evaluate(policy, { ...POST, client }, T0);
    expect(limiter.evaluate(policy, { ...POST, path, client }, T0)?.throttled?.id).toBe(input(1).id);
  });

  it("a path the Rule does not name is neither counted nor refused", () => {
    const store = recordingStore();
    const limiter = createLimiter(store);
    const policy = policyOf([input(1, { requests: 1 })]);
    for (const path of ["/logins", "/login/reset", "/api/login", "login", ""]) {
      const outcome = limiter.evaluate(policy, { ...POST, path, client }, T0);
      expect(outcome?.throttled ?? null).toBeNull();
    }
    expect(store.calls).toEqual([]);
  });

  it("a Policy without limit Rules costs nothing", () => {
    const store = recordingStore();
    expect(createLimiter(store).evaluate(policyOf([]), { ...POST, client }, T0)).toBeNull();
    expect(store.calls).toEqual([]);
  });
});

describe("the limiter: a store that misbehaves", () => {
  const client = clientOf("203.0.113.9");

  it("a count that is not a number (a promise, NaN) is read as nothing counted: the request proceeds", () => {
    for (const answer of [Promise.resolve(99), Number.NaN, "9", undefined, Number.POSITIVE_INFINITY]) {
      const store = {
        hit: () => answer,
        peek: () => answer,
        size: () => 0,
      } as unknown as CounterStore;
      const limiter = createLimiter(store);
      const policy = policyOf([input(1, { requests: 1 }), input(2, { requests: 1, count: "failures" })]);
      const outcome = limiter.evaluate(policy, { ...POST, client }, T0);
      expect(outcome?.throttled ?? null).toBeNull();
      expect(outcome?.marked ?? null).toBeNull();
    }
  });

  it("without retryAfterMs, Retry-After is the whole window", () => {
    const inner = new MemoryCounterStore();
    const store: CounterStore = {
      hit: (key, windowMs, now) => inner.hit(key, windowMs, now),
      peek: (key, windowMs, now) => inner.peek(key, windowMs, now),
      size: () => inner.size(),
    };
    const limiter = createLimiter(store);
    const policy = policyOf([input(1, { requests: 1, windowS: 45 })]);
    limiter.evaluate(policy, { ...POST, client }, T0);
    expect(limiter.evaluate(policy, { ...POST, client }, T0 + 1)?.retryAfterS).toBe(45);
  });

  it("a store that throws lets the error out to the caller, which fails open", () => {
    const store = {
      hit: () => {
        throw new Error("store down");
      },
      peek: () => {
        throw new Error("store down");
      },
      size: () => 0,
    } as CounterStore;
    const limiter = createLimiter(store);
    expect(() => limiter.evaluate(policyOf([input(1)]), { ...POST, client }, T0)).toThrow("store down");
  });
});
