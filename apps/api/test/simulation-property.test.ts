import type { ParsedPolicyRuleInput } from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
// The real decision code of Shield, read from its source.
import { parseAddress } from "../../../packages/shield-node/src/address.ts";
import { MemoryCounterStore } from "../../../packages/shield-node/src/counters.ts";
import { decide } from "../../../packages/shield-node/src/decide.ts";
import { createLimiter, type LimitOutcome } from "../../../packages/shield-node/src/limits.ts";
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
// of it; the replay sees the Events a Shield without Rules would record. The second world (plan 11 amendment A9)
// adds what made the review find over-claims: several Shield processes behind a load balancer, each with its own
// counters, restarted now and then (a new instance id), Shields too old to stamp the id, and responses that take
// time — a failure counts when its response closes, and a request holds a failure slot while it is in flight.

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
  /** The Shield process that took it, and whether its Event names it (a Shield from before A9 does not). */
  process: string;
  stamped: boolean;
  /** From the reading of the clock to the close of the response; Shield records it up to 1 ms later. */
  latency: number;
  recordedLatency: number;
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
  // One limiter per process: counters live in one process. Responses close in time order.
  const limiters = new Map<string, ReturnType<typeof createLimiter>>();
  const open: { at: number; outcome: LimitOutcome; status: number; limiter: ReturnType<typeof createLimiter> }[] = [];
  return traffic.map((sent) => {
    open.sort((a, b) => a.at - b.at);
    while (open.length > 0 && (open[0] as (typeof open)[number]).at <= sent.readAt) {
      const closed = open.shift() as (typeof open)[number];
      closed.limiter.settle(closed.outcome, closed.status, closed.at);
    }
    const decision = decide(policy, {
      method: sent.method,
      path: sent.path,
      signed: sent.signed,
      preflight: sent.preflight,
    });
    if (decision.action === "block" && decision.mode === "enforce") return true;
    if (sent.ip === null) return false; // no address: not limited
    let limiter = limiters.get(sent.process);
    if (limiter === undefined) {
      limiter = createLimiter(new MemoryCounterStore());
      limiters.set(sent.process, limiter);
    }
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
    if (sent.latency === 0) limiter.settle(outcome, sent.status, sent.readAt);
    else open.push({ at: sent.readAt + sent.latency, outcome, status: sent.status, limiter });
    return false;
  });
}

function recorded(sent: Sent): ReplayEvent {
  return {
    ts: new Date(sent.at).toISOString(),
    ...(sent.stamped ? { instance_id: sent.process } : {}),
    request: { method: sent.method, route: sent.route, status: sent.status, latency_ms: sent.recordedLatency },
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

/** Instance ids: 32 hex characters. */
const instance = (n: number): string => n.toString(16).padStart(32, "0");

/**
 * The traffic of one sequence. In the world of one process (`many` false) every response closes at once and every
 * Event names the process — the world of amendments A7 and A8, drawn from the same numbers as then. With `many`, 1 to
 * 3 processes share the traffic, one now and then restarts, a sequence's Shield may be too old to name its process,
 * and responses take from nothing to 3 s.
 */
function traffic(random: () => number, many = false): Sent[] {
  const pick = <T>(items: readonly T[]): T => items[Math.floor(random() * items.length)] as T;
  const sent: Sent[] = [];
  let at = T0;
  const processes = many
    ? Array.from({ length: 1 + Math.floor(random() * 3) }, (_, n) => instance(n + 1))
    : [instance(1)];
  let restarts = processes.length;
  const stamped = !many || random() < 0.8;
  for (let n = 0; n < 60; n++) {
    // Mostly a few hundred milliseconds apart, now and then right at a window's edge.
    at += random() < 0.15 ? 1_000 - 6 + Math.floor(random() * 12) : Math.floor(random() * (many ? 300 : 700));
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
      process: processes[0] as string,
      stamped,
      latency: 0,
      recordedLatency: 0,
    });
    if (!many) continue;
    const request = sent.at(-1) as Sent;
    // Shield reads the clock up to 4 ms before `ts` and measures the latency up to 1 ms past the close: within 5 ms.
    request.readAt = at - Math.floor(random() * 5);
    if (random() < 0.03) processes[Math.floor(random() * processes.length)] = instance(++restarts);
    request.process = pick(processes);
    request.latency = random() < 0.6 ? Math.floor(random() * 50) : Math.floor(random() * 3_000);
    request.recordedLatency = request.latency + random();
  }
  return sent;
}

/**
 * Per seed, the refusals claimed and the Events judged (claimed, or passed with certainty) by the replay of plan 11
 * amendment A7 (tainted counters), before the two counts of D-070. The replay may judge more, never claim fewer.
 */
const BEFORE_CLAIMED = [
  "0 3 31 17 0 15 0 5 0 0 0 10 6 0 0 1 34 42 0 17 8 1 52 12 7 22 6 8 22 0",
  "13 10 43 29 30 0 24 34 5 3 44 30 33 0 0 1 0 3 0 0 2 55 0 9 4 0 2 1 2 0",
  "50 0 2 2 14 47 3 25 0 0 26 14 0 3 5 3 16 1 4 22 7 12 27 45 42 2 0 14 14 7",
  "0 34 28 19 3 6 12 0 17 0 1 43 1 0 27 1 1 0 14 0 17 8 0 2 2 12 0 1 13 17",
  "0 13 11 3 0 28 2 0 5 9 16 0 43 3 36 24 19 0 46 16 0 0 17 11 13 0 8 3 0 5",
  "1 5 10 0 0 0 0 0 0 0 7 2 0 10 0 0 26 0 2 33 9 0 0 6 2 0 5 41 14 9",
  "30 16 0 8 0 8 26 12 0 38 32 52 17 24 6 0 0 26 2 0 0 3 0 0 1 0 23 9 32 19",
  "0 49 0 3 26 30 0 31 0 0 3 3 0 14 9 21 6 0 16 0 5 46 49 23 7 0 28 5 29 12",
  "30 28 36 10 0 13 4 0 14 4 0 24 0 0 32 8 16 9 0 1 0 0 1 9 1 13 0 0 0 1",
  "0 5 4 33 3 16 0 14 6 33 0 4 3 8 16 18 0 24 33 8 46 26 51 43 21 12 36 19 0 0",
].join(" ");
const BEFORE_JUDGED = [
  "30 19 44 37 50 41 11 34 8 58 24 28 51 46 27 29 52 45 51 31 27 52 52 33 46 34 30 39 45 40",
  "52 48 49 47 38 60 49 50 60 30 49 52 43 34 44 42 34 32 22 22 24 55 39 15 44 50 26 17 59 48",
  "50 60 31 53 35 54 4 53 56 28 47 52 53 44 46 47 23 57 48 32 51 38 54 56 50 54 28 28 52 49",
  "32 49 52 46 46 41 20 53 52 38 53 48 48 34 38 26 52 37 24 31 37 40 21 33 37 26 31 27 25 36",
  "60 24 48 58 44 41 55 11 32 47 35 50 50 38 51 26 43 33 55 58 53 34 51 29 42 48 19 33 57 8",
  "34 11 19 45 38 9 54 51 17 54 22 15 42 32 3 49 35 41 24 41 39 39 50 52 48 35 45 45 33 51",
  "39 39 60 37 40 60 46 14 60 52 53 57 18 57 20 43 42 51 35 52 24 55 34 11 48 43 35 43 54 31",
  "31 52 43 47 52 57 24 44 46 18 6 35 34 40 50 50 44 60 26 38 51 52 55 52 42 35 48 41 54 21",
  "53 48 52 53 60 20 51 60 44 24 60 43 9 34 56 42 31 48 8 34 40 47 5 53 43 23 24 50 41 30",
  "59 30 52 51 47 26 46 50 51 46 26 53 21 54 53 34 39 50 48 58 52 29 54 48 52 53 52 32 49 24",
].join(" ");
const before = (figures: string): number[] => figures.split(" ").map(Number);

/** Per Event of a sequence: claimed, judged a pass, or could not be judged; with Shield's truth. */
function judge(seed: number, many: boolean) {
  const random = sequence(seed * 7_919);
  const rules = draft(random);
  const sent = traffic(random, many);
  const truth = shieldRefuses(rules, sent);
  const events = sent.map(recorded);
  const outcome = { refused: truth.filter(Boolean).length, claimed: 0, judged: 0, overClaims: [] as string[] };
  const misses: string[] = [];
  // Per Event, whether the replay claims it — the refusals of the prefix that ends with it, less those before —
  // or judges it a certain pass: not claimed, and not counted as could not be judged.
  let refusing = 0;
  let undecidable = 0;
  for (let n = 0; n < events.length; n++) {
    const run = replay(rules, events.slice(0, n + 1));
    const where = `seed ${seed}, request ${n}: ${sent[n]?.method} ${sent[n]?.path}`;
    if (run.totals.would_refuse > refusing) {
      outcome.claimed += 1;
      outcome.judged += 1;
      if (!truth[n]) outcome.overClaims.push(where);
    } else if (run.undecidable_events === undecidable) {
      outcome.judged += 1;
      if (truth[n]) misses.push(where);
    }
    refusing = run.totals.would_refuse;
    undecidable = run.undecidable_events;
  }
  return { ...outcome, misses };
}

describe("the replay never claims a refusal Shield would not make, nor passes one it would make", () => {
  it("holds over 300 generated drafts and sequences of one process, and still judges a good share of them", () => {
    let claimed = 0;
    let judged = 0;
    let refused = 0;
    const overClaims: string[] = [];
    const misses: string[] = [];
    const claimedPerSeed: number[] = [];
    for (let seed = 1; seed <= 300; seed++) {
      const outcome = judge(seed, false);
      claimed += outcome.claimed;
      judged += outcome.judged;
      refused += outcome.refused;
      overClaims.push(...outcome.overClaims);
      misses.push(...outcome.misses);
      claimedPerSeed.push(outcome.claimed);
    }
    expect(overClaims).toEqual([]);
    expect(misses).toEqual([]);
    // Not vacuous: the replay claims a real share of what Shield refuses.
    expect(claimed).toBeGreaterThan(refused / 4);
    // No regression against the replay before the two counts: on every seed, at least the refusals it claimed.
    const claimedBefore = before(BEFORE_CLAIMED);
    const judgedBefore = before(BEFORE_JUDGED);
    expect(claimedPerSeed.flatMap((count, n) => (count < (claimedBefore[n] as number) ? [n + 1] : []))).toEqual([]);
    const sum = (figures: number[]) => figures.reduce((total, figure) => total + figure, 0);
    console.log(
      `simulation property, one process: Shield refused ${refused}; claimed ${sum(claimedBefore)} -> ${claimed}; ` +
        `judged ${sum(judgedBefore)} -> ${judged} of ${300 * 60} Events`,
    );
  });

  it("holds with several processes, restarts, Shields that do not name their process, and slow responses", () => {
    let claimed = 0;
    let judged = 0;
    let refused = 0;
    const overClaims: string[] = [];
    const misses: string[] = [];
    for (let seed = 1; seed <= 300; seed++) {
      const outcome = judge(seed, true);
      claimed += outcome.claimed;
      judged += outcome.judged;
      refused += outcome.refused;
      overClaims.push(...outcome.overClaims);
      misses.push(...outcome.misses);
    }
    expect(overClaims).toEqual([]);
    expect(misses).toEqual([]);
    // Not vacuous.
    expect(claimed).toBeGreaterThan(refused / 10);
    console.log(
      `simulation property, several processes: Shield refused ${refused}; claimed ${claimed}; judged ${judged} ` +
        `of ${300 * 60} Events`,
    );
  });
});
