import type { ParsedPolicyRuleInput } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
// The real decision code of Shield, read from its source.
import { parseAddress } from "../../../packages/shield-node/src/address.ts";
import { MemoryCounterStore } from "../../../packages/shield-node/src/counters.ts";
import { decide } from "../../../packages/shield-node/src/decide.ts";
import { createLimiter } from "../../../packages/shield-node/src/limits.ts";
import { compilePattern, type PathPattern } from "../../../packages/shield-node/src/policy/match.ts";
import { buildPolicy } from "../../../packages/shield-node/src/policy/store.ts";
import { type ReplayEvent, replay } from "../src/simulate/replay.ts";

// The promise of the replay: a request it claims the draft would refuse, an enforcing Shield refuses. It rests on
// one invariant — for every limit counter, the replay's count never exceeds Shield's — which this test checks
// through its consequence over many generated sequences.
//
// Each sequence hides from the replay exactly what an Event hides: the concrete path behind a route template, the
// device behind a valid attestation, the signature of an older Shield, whether an OPTIONS request was a preflight,
// and the few milliseconds between the limiter's reading of the clock and the Event's `ts`. Shield decides with all
// of it; the replay sees the Events a Shield without Rules would record.

const T0 = Date.parse("2026-11-11T08:00:00.000Z");
const id = (n: number): string => `rul_${String(n).padStart(24, "0")}`;

function sequence(seed: number): () => number {
  let state = seed;
  return () => {
    state = (Math.imul(state, 1_103_515_245) + 12_345) >>> 0;
    return state / 0x1_0000_0000;
  };
}

interface Sent {
  at: number;
  /** The limiter's reading of the clock: up to 5 ms before `at`. */
  readAt: number;
  method: string;
  path: string;
  route: string;
  ip: string | null;
  status: number;
  /** What Shield knew; `recorded` is what the Event says (null: an older Shield). */
  signed: boolean;
  recorded: NonNullable<ReplayEvent["signature"]> | null;
  device: string | null;
  preflight: boolean;
}

const pattern = (path: string): PathPattern => {
  const compiled = compilePattern(path);
  if (compiled === null) throw new Error("not a pattern");
  return compiled;
};

/** Per request: whether an enforcing Shield refused it. */
function shieldRefuses(rules: (ParsedPolicyRuleInput & { id: string })[], traffic: Sent[]): boolean[] {
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
  return traffic.map((sent) => {
    const decision = decide(policy, {
      method: sent.method,
      path: sent.path,
      signed: sent.signed,
      preflight: sent.preflight,
    });
    if (decision.action === "block" && decision.mode === "enforce") return true;
    if (sent.ip === null) return false; // no address: not limited
    const outcome = limiter.evaluate(
      policy,
      {
        method: sent.method,
        path: sent.path,
        preflight: sent.preflight,
        client: { address: parseAddress(sent.ip), hash: null },
        device: sent.device,
      },
      sent.readAt,
    );
    if (outcome === null) return false;
    if (outcome.throttled !== null) return true;
    limiter.settle(outcome, sent.status, sent.readAt);
    return false;
  });
}

function recorded(sent: Sent): ReplayEvent {
  return {
    ts: new Date(sent.at).toISOString(),
    request: { method: sent.method, route: sent.route, status: sent.status },
    decision: { action: "allow", mode: "monitor" },
    actor: {
      ip_hash: sent.ip === null ? null : `iph_${sent.ip.split(".").at(-1)?.padStart(32, "0")}`,
      ip_prefix: sent.ip === null ? null : "203.0.113.0/24",
    },
    signature: sent.recorded,
    attestation: { status: sent.device === null ? "missing" : "valid" },
  };
}

const PATHS = [
  { path: "/login", route: "/login", method: "POST" },
  { path: "/api/users/me", route: "/api/users/:id", method: "GET" },
  { path: "/api/users/7", route: "/api/users/:id", method: "GET" },
  { path: "/api/data", route: "/api/data", method: "GET" },
  { path: "/api/data", route: "/api/data", method: "HEAD" },
  { path: "/api/data", route: "/api/data", method: "OPTIONS" },
  { path: "/assets/app.js", route: "(unmatched)", method: "GET" },
  { path: "/api/orders", route: "/api/orders", method: "POST" },
];
const RULE_PATHS = ["/**", "/api/**", "/api/data", "/api/users/me", "/api/users/*", "/login", "/assets/**", "/api/*"];

function draft(random: () => number): (ParsedPolicyRuleInput & { id: string })[] {
  const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)] as T;
  return Array.from({ length: 1 + Math.floor(random() * 4) }, (_, n) => {
    const base = { id: id(n + 1), name: `r${n}`, path: pick(RULE_PATHS), mode: "monitor" as const };
    const methods = pick([[], ["GET"], ["POST"], ["GET", "POST"]]);
    const kind = random();
    if (kind < 0.25) return { ...base, methods, action: "block" as const };
    if (kind < 0.45) return { ...base, methods, action: "block" as const, requires: "signature" as const };
    return {
      ...base,
      methods,
      action: "throttle" as const,
      limit: {
        requests: 1 + Math.floor(random() * 3),
        window_s: 1 + Math.floor(random() * 4),
        key: pick(["ip", "ip", "device"] as const),
        count: pick(["requests", "requests", "failures"] as const),
      },
    };
  });
}

function traffic(random: () => number): Sent[] {
  const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)] as T;
  const sent: Sent[] = [];
  let at = T0;
  for (let n = 0; n < 60; n++) {
    // Mostly a few hundred milliseconds apart, now and then right at a window's edge.
    at += random() < 0.15 ? 1_000 - 6 + Math.floor(random() * 12) : Math.floor(random() * 700);
    const shape = pick(PATHS);
    const signature = random();
    const recordedSignature =
      signature < 0.15
        ? null
        : signature < 0.45
          ? ({ status: "valid", body: "none" } as const)
          : signature < 0.6
            ? ({ status: "valid", body: "checked" } as const)
            : signature < 0.8
              ? ({ status: "missing", body: null } as const)
              : ({ status: "invalid", body: "none" } as const);
    sent.push({
      at,
      readAt: at - Math.floor(random() * 6),
      ...shape,
      ip: pick(["203.0.113.1", "203.0.113.1", "203.0.113.2", null]),
      status: shape.path === "/login" ? pick([200, 401, 401, 403, 500]) : 200,
      // A valid signature with no body is met; one with a body may or may not be (`bodyVerified`); an older
      // Shield's request either way.
      signed:
        recordedSignature === null
          ? random() < 0.5
          : recordedSignature.status === "valid" && (recordedSignature.body === "none" || random() < 0.5),
      recorded: recordedSignature,
      device: random() < 0.4 ? pick(["dev_a", "dev_b", "dev_c"]) : null,
      preflight: shape.method === "OPTIONS" && random() < 0.5,
    });
  }
  return sent;
}

describe("the replay never claims a refusal Shield would not make", () => {
  it("holds over 300 generated drafts and sequences, and still judges a good share of them", () => {
    let claimed = 0;
    let refused = 0;
    const overClaims: string[] = [];
    for (let seed = 1; seed <= 300; seed++) {
      const random = sequence(seed * 7_919);
      const rules = draft(random);
      const sent = traffic(random);
      const truth = shieldRefuses(rules, sent);
      const events = sent.map(recorded);
      refused += truth.filter(Boolean).length;
      // Per Event, whether the replay claims it: the refusals of the prefix that ends with it, less those before.
      let before = 0;
      for (let n = 0; n < events.length; n++) {
        const now = replay(rules, events.slice(0, n + 1)).totals.would_refuse;
        if (now > before) {
          claimed += 1;
          if (!truth[n]) overClaims.push(`seed ${seed}, request ${n}: ${sent[n]?.method} ${sent[n]?.path}`);
        }
        before = now;
      }
    }
    expect(overClaims).toEqual([]);
    // Not vacuous: the replay claims a real share of what Shield refuses.
    expect(claimed).toBeGreaterThan(refused / 4);
  });
});
