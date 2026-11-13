import type { ParsedPolicyRuleInput } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
// The real decision code of Shield, read from its source: the parity the simulation promises is with this code.
import { parseAddress } from "../../../packages/shield-node/src/address.ts";
import { MemoryCounterStore } from "../../../packages/shield-node/src/counters.ts";
import { decide } from "../../../packages/shield-node/src/decide.ts";
import { createLimiter } from "../../../packages/shield-node/src/limits.ts";
import { compilePattern, type PathPattern } from "../../../packages/shield-node/src/policy/match.ts";
import { buildPolicy } from "../../../packages/shield-node/src/policy/store.ts";
import { type ReplayEvent, replay } from "../src/simulate/replay.ts";

// Traffic is sent once. It is recorded as a Shield without Rules records it (every request reaches the application:
// the Events a simulation reads), and it is decided by Shield's own `decide` and limiter under the draft Rules in
// Enforce mode, in the order of the middleware: Rules, then limits, the failure counted when the response closes.
// The replay of the recorded Events must count what Shield refused.

const T0 = Date.parse("2026-11-11T08:00:00.000Z");

interface Sent {
  at: number;
  method: string;
  path: string;
  /** The route template Express would report. */
  route: string;
  ip: string;
  /** The status the application answers with. */
  status: number;
  signature: NonNullable<ReplayEvent["signature"]>;
}

const pattern = (path: string): PathPattern => {
  const compiled = compilePattern(path);
  if (compiled === null) throw new Error("not a pattern");
  return compiled;
};

/** What Shield refuses of `traffic` under `rules`, all in Enforce mode: refusals by Rule id. */
function decideWithShield(rules: (ParsedPolicyRuleInput & { id: string })[], traffic: Sent[]) {
  const compiled = rules.map((rule) => ({ ...rule, mode: "enforce" as const, pattern: pattern(rule.path) }));
  const policy = buildPolicy({
    version: 1,
    issuedAt: T0,
    notAfter: Number.POSITIVE_INFINITY,
    rules: compiled.filter((rule) => rule.limit === undefined && rule.requires === undefined),
    signatureRules: compiled.filter((rule) => rule.requires === "signature"),
    limitRules: compiled.flatMap((rule) =>
      rule.limit === undefined
        ? []
        : [
            {
              id: rule.id,
              path: rule.path,
              methods: rule.methods,
              mode: rule.mode,
              pattern: rule.pattern,
              requests: rule.limit.requests,
              windowS: rule.limit.window_s,
              key: rule.limit.key,
              count: rule.limit.count,
            },
          ],
    ),
  });
  const limiter = createLimiter(new MemoryCounterStore());
  const blocked = new Map<string, number>();
  const throttled = new Map<string, number>();
  const refusedClients = new Set<string>();
  const add = (counts: Map<string, number>, id: string) => counts.set(id, (counts.get(id) ?? 0) + 1);
  for (const sent of traffic) {
    const signed =
      sent.signature.status === "valid" && (sent.signature.body === "checked" || sent.signature.body === "none");
    const decision = decide(policy, { method: sent.method, path: sent.path, signed });
    if (decision.action === "block" && decision.mode === "enforce") {
      add(blocked, decision.ruleId ?? "");
      refusedClients.add(sent.ip);
      continue;
    }
    const outcome = limiter.evaluate(
      policy,
      {
        method: sent.method,
        path: sent.path,
        preflight: false,
        client: { address: parseAddress(sent.ip), hash: null },
        device: null,
      },
      sent.at,
    );
    if (outcome === null) continue;
    if (outcome.throttled !== null) {
      add(throttled, outcome.throttled.id);
      refusedClients.add(sent.ip);
      continue;
    }
    limiter.settle(outcome, sent.status, sent.at);
  }
  return { blocked, throttled, refusedClients };
}

/** The Event a Shield without Rules records for a request. */
function recorded(sent: Sent): ReplayEvent {
  const octets = sent.ip.split(".").map((octet) => Number(octet).toString(16).padStart(2, "0"));
  return {
    ts: new Date(sent.at).toISOString(),
    // One Shield process (A9), and the application answers at once.
    instance_id: "0123456789abcdef0123456789abcdef",
    request: { method: sent.method, route: sent.route, status: sent.status, latency_ms: 0 },
    decision: { action: "allow", mode: "monitor" },
    actor: { ip_hash: `iph_${octets.join("").padStart(32, "0")}` },
    signature: sent.signature,
  };
}

/** A fixed sequence of numbers in [0, 1): the traffic is the same on every run. */
function sequence(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1_103_515_245) + 12_345) >>> 0;
    return state / 0x1_0000_0000;
  };
}

const SIGNATURES: Sent["signature"][] = [
  { status: "valid", body: "none" },
  { status: "missing", body: null },
  { status: "invalid", body: "mismatch" },
  { status: "stale", body: "checked" },
];

/** 3,000 requests over 5 minutes from 6 addresses, over the routes the Rules below name and some they do not. */
function traffic(): Sent[] {
  const random = sequence(20_261_111);
  const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)] as T;
  const sent: Sent[] = [];
  const times = new Set<number>();
  // Within 10 ms of a whole window (30, 60 or 120 s) after an earlier request, the replay rightly declines to judge:
  // Shield's clock readings and latency may each lie up to 5 ms off what an Event records (`timing`).
  const nearEdge = (at: number): boolean =>
    [30_000, 60_000, 120_000].some((window) => {
      for (let off = -10; off <= 10; off++) if (times.has(at - window + off)) return true;
      return false;
    });
  let at = T0;
  for (let n = 0; n < 3_000; n++) {
    // Multiples of 37 ms, never the same moment: whether a response closed before the next request arrived could
    // not be told (A9 B2); moved on by 37 ms while near a window's edge.
    at += 37 * (1 + Math.floor(random() * 5));
    while (nearEdge(at)) at += 37;
    times.add(at);
    const ip = `203.0.113.${1 + Math.floor(random() * 6)}`;
    const signature = pick(SIGNATURES);
    const id = 1 + Math.floor(random() * 50);
    const shapes: Omit<Sent, "at" | "ip" | "signature">[] = [
      { method: "POST", path: "/login", route: "/login", status: random() < 0.6 ? 401 : 200 },
      { method: "POST", path: "/login", route: "/login", status: random() < 0.3 ? 403 : 200 },
      { method: "GET", path: `/api/products/${id}`, route: "/api/products/:id", status: 200 },
      { method: "HEAD", path: `/api/products/${id}`, route: "/api/products/:id", status: 200 },
      { method: "GET", path: "/api/admin/users", route: "/api/admin/users", status: 200 },
      { method: "DELETE", path: `/api/admin/users/${id}`, route: "/api/admin/users/:id", status: 204 },
      { method: "POST", path: "/api/checkout", route: "/api/checkout", status: 201 },
      { method: "GET", path: "/api/checkout", route: "/api/checkout", status: 200 },
      { method: "GET", path: "/health", route: "/health", status: 200 },
    ];
    sent.push({ at, ip, signature, ...pick(shapes) });
  }
  return sent;
}

const id = (n: number): string => `rul_${String(n).padStart(24, "0")}`;
const base = { methods: [] as string[], action: "block" as const, mode: "monitor" as const };

const RULES: (ParsedPolicyRuleInput & { id: string })[] = [
  {
    ...base,
    id: id(1),
    name: "Products limit",
    path: "/api/products/*",
    methods: ["GET"],
    action: "throttle",
    limit: { requests: 6, window_s: 30, key: "ip", count: "requests" },
  },
  { ...base, id: id(2), name: "Signed checkout", path: "/api/checkout", methods: ["POST"], requires: "signature" },
  { ...base, id: id(3), name: "Admin", path: "/api/admin/**" },
  {
    ...base,
    id: id(4),
    name: "Login protection",
    path: "/login",
    methods: ["POST"],
    action: "throttle",
    limit: { requests: 4, window_s: 120, key: "ip", count: "failures" },
  },
  {
    ...base,
    id: id(5),
    name: "Api limit",
    path: "/api/**",
    action: "throttle",
    limit: { requests: 25, window_s: 60, key: "device", count: "requests" },
  },
  { ...base, id: id(6), name: "Delete users", path: "/api/admin/users/*", methods: ["DELETE"] },
];

describe("simulation parity with Shield", () => {
  it("counts per Rule what Shield's decide and limiter refuse on the same traffic", () => {
    const sent = traffic();
    const shield = decideWithShield(RULES, sent);
    const simulated = replay(RULES, sent.map(recorded));

    // The traffic exercises every kind of Rule.
    expect(shield.blocked.get(id(3))).toBeGreaterThan(100);
    expect(shield.blocked.get(id(2))).toBeGreaterThan(100);
    expect(shield.throttled.get(id(1))).toBeGreaterThan(20);
    expect(shield.throttled.get(id(4))).toBeGreaterThan(20);
    expect(shield.throttled.get(id(5))).toBeGreaterThan(20);

    for (const row of simulated.rules) {
      const ruleId = row.id as string;
      expect([ruleId, row.would_block + row.would_fail_signature]).toEqual([ruleId, shield.blocked.get(ruleId) ?? 0]);
      expect([ruleId, row.would_throttle]).toEqual([ruleId, shield.throttled.get(ruleId) ?? 0]);
      expect(row.undecidable).toBe(0);
    }
    // A signature Rule's refusals are counted as such, a block Rule's as blocks.
    expect(simulated.rules[1]).toMatchObject({ would_block: 0, would_fail_signature: shield.blocked.get(id(2)) });
    expect(simulated.rules[2]).toMatchObject({ would_fail_signature: 0, would_block: shield.blocked.get(id(3)) });
    // The later block Rule never decides: the earlier one covers its requests.
    expect(simulated.rules[5]).toMatchObject({ would_block: 0 });
    expect(simulated.rules[5]?.matched).toBeGreaterThan(0);

    const refused = [...shield.blocked.values(), ...shield.throttled.values()].reduce((sum, n) => sum + n, 0);
    expect(simulated.totals).toEqual({
      would_refuse: refused,
      clients_affected: shield.refusedClients.size,
      unknown_client_events: 0,
    });
    expect(simulated.undecidable_events).toBe(0);
  });

  it("claims less than Shield does, never more, where a template hides the path", () => {
    // Shield blocks product 7 alone. The Events say `/api/products/:id`: the replay cannot tell which were 7.
    const rules = [{ ...base, id: id(7), name: "Product 7", path: "/api/products/7" }];
    const sent = traffic();
    const shield = decideWithShield(rules, sent);
    const simulated = replay(rules, sent.map(recorded));
    const really = shield.blocked.get(id(7)) ?? 0;
    expect(really).toBeGreaterThan(0);
    expect(simulated.rules[0]).toMatchObject({ matched: 0, would_block: 0 });
    expect(simulated.rules[0]?.undecidable).toBe(
      sent.filter((request) => request.route === "/api/products/:id").length,
    );
    expect(simulated.rules[0]?.undecidable).toBeGreaterThanOrEqual(really);
    expect(simulated.undecidable_events).toBe(simulated.rules[0]?.undecidable);
  });
});
