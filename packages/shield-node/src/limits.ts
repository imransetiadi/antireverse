// Limit Rules (slice 08): a Rule that limits how often one client may call a route, or how often it may fail there.
//
// The constants are hand copies of the protocol's (`LIMIT_KEYS`, `LIMIT_COUNTS`, `LIMIT_LIMITS`,
// `LIMIT_FAILURE_STATUSES`, `RATE_LIMITED_RESPONSE_BODY`), because Shield imports no protocol code at run time;
// test/limits.test.ts pins the agreement. A value that changes there must change here.
//
// The limiter runs after Containments and Rules, for a request neither refused, and before the Virtual patches. A
// limit Rule matches as a plain Rule does (methods and path: every reading of the path, HEAD with GET). For one
// request (amendment A7, F3):
// 1. Every matching Rule is looked at, nothing counted. A Rule is over when its count plus this request passes
//    `requests` — for `count: "failures"`, its failures counted in the window plus the requests of its client in
//    flight (F1: each holds a slot from decision to close, so parallel guesses cannot all pass before the first
//    failure is counted).
// 2. If an enforced Rule is over, the request is refused: the first such Rule in bundle order names the throttle,
//    and `Retry-After` is the longest wait of all the enforced Rules that are over. Nothing is counted, on any Rule
//    (a refused request uses up no budget elsewhere, and does not push its own wait further out), and no monitor Rule
//    marks it.
// 3. Otherwise the request counts on every matching Rule — a hit for `count: "requests"`, a slot for
//    `count: "failures"`, which becomes a failure if the response closes with 401 or 403 (`settle`) and is released
//    whatever the response, or if the client went away (`release`) — and the first monitor Rule over its limit
//    marks it.
// A CORS preflight (F6) is looked at, never counted, and is refused when an enforced Rule is already over.
//
// Keys. `ip` is the client address Shield derived for the request: a whole IPv4 address (an IPv4-mapped IPv6 address
// is that IPv4 address), or the /64 of an IPv6 address. An `ip` limit never looks at the token.
//
// A `device` limit (decided with Jev, device_also_counts_ip_hash_keys) counts a request with a valid Attestation
// Token on two counters of the Rule: the token's device, held to the limit, and the address, held to
// `LIMIT_DEVICE_ADDRESS_FACTOR` (5) times the limit — same window, same count kind. The request is over the limit
// when either counter is. A request without a valid token (missing, forged, expired) counts on the address counter
// alone, held to the plain limit. It is the same address counter in both cases, so a device that drops its token
// finds its own requests already counted there, and an address that mints device ids gets 5 times the limit at
// most, not one limit per id.
//
// A key names its Rule, window and count kind — two Rules never share a counter, and a Rule whose limit was edited
// starts a new one — followed by the client part. The client part handed to the counter store is never the address
// or the device id: it is the first 16 bytes, in hex, of SHA-256(secret + "a/" or "d/" + the address or device),
// the secret being 32 random bytes made when the limiter is created (per process, never stored or sent). It is
// computed once per request for the address and once for the device, not once per Rule, and joined to each Rule's
// prefix: the Rule id is no secret, and 50 matching Rules cost two hashes, not fifty. So a custom store, its logs
// and whatever it writes to see only values that mean nothing outside this process. Nothing here logs, and nothing
// of a key goes into an Event.
//
// An address Shield cannot parse (F7) — a `clientAddress` that returns `ip:port`, a list, a name — is counted by its
// text, trimmed, its first 64 characters, hashed like any other key (`r/` + text); `onUnparsedAddress` is called
// for it (Shield warns once, without the text). A client without any address is not limited: there is nothing to
// count it by (fail open). Exempt: a client on the never-block list (the bundle's allowlist). Nothing here catches:
// the adapter contains whatever the store throws and lets the request proceed.
import { createHash, randomBytes } from "node:crypto";
import { inCidr, type ParsedAddress } from "./address.ts";
import type { Client } from "./containment.ts";
import type { CounterStore } from "./counters.ts";
import { matchForms, matchMethod, normalisePath, type PathPattern, pathForms } from "./policy/match.ts";
import type { AppliedPolicy } from "./policy/store.ts";

/** What a limit counts per. Equal to `LIMIT_KEYS` of the protocol. */
export const LIMIT_KEYS = ["ip", "device"] as const;
export type LimitKey = (typeof LIMIT_KEYS)[number];
/** What a limit counts. Equal to `LIMIT_COUNTS` of the protocol. */
export const LIMIT_COUNTS = ["requests", "failures"] as const;
export type LimitCount = (typeof LIMIT_COUNTS)[number];
/** The bounds of a limit. Equal to `LIMIT_LIMITS` of the protocol. */
export const LIMIT_LIMITS = { requestsMax: 100_000, windowSecondsMax: 3_600 } as const;
/** The response statuses a failure limit counts. Equal to `LIMIT_FAILURE_STATUSES` of the protocol. */
export const LIMIT_FAILURE_STATUSES = [401, 403] as const;
/**
 * A device-keyed limit also counts the address of an attested request, and refuses it when the address is over this
 * many times the limit: what one address can gain by presenting many device ids. Shield's own (no protocol twin).
 */
export const LIMIT_DEVICE_ADDRESS_FACTOR = 5;
/** The whole body of a throttle response. Equal to `RATE_LIMITED_RESPONSE_BODY` of the protocol. */
export const RATE_LIMITED_BODY = '{"error":"rate_limited"}';

/** One limit Rule of a bundle, already checked. */
export interface LimitRuleInput {
  readonly id: string;
  readonly path: string;
  readonly methods: readonly string[];
  readonly mode: "monitor" | "enforce";
  readonly pattern: PathPattern;
  readonly requests: number;
  /** `window_s` of the limit. */
  readonly windowS: number;
  readonly key: LimitKey;
  readonly count: LimitCount;
}

/** What the Event of a request records when a limit Rule decided it. One frozen object per Rule. */
export interface ThrottleDecision {
  readonly action: "throttle";
  readonly mode: "monitor" | "enforce";
  readonly ruleId: string;
  readonly policyVersion: number;
}

/** One limit Rule of the applied Policy, ready to match and count. */
export interface AppliedLimitRule {
  readonly id: string;
  /** The path pattern as published: the `request.route` of the Event of a throttled request. */
  readonly path: string;
  readonly methods: readonly string[];
  readonly mode: "monitor" | "enforce";
  readonly pattern: PathPattern;
  readonly requests: number;
  readonly windowMs: number;
  readonly key: LimitKey;
  /** `count: "failures"`: counted when the response closes with a failure status. */
  readonly failures: boolean;
  /** What every counter key of this Rule starts with: the Rule, its window and what it counts. */
  readonly keyPrefix: string;
  readonly decision: ThrottleDecision;
}

/** Compiles a checked limit Rule for the Policy of `version`. */
export function prepareLimitRule(rule: LimitRuleInput, version: number): AppliedLimitRule {
  return Object.freeze({
    id: rule.id,
    path: rule.path,
    methods: Object.freeze([...rule.methods]),
    mode: rule.mode,
    pattern: rule.pattern,
    requests: rule.requests,
    windowMs: rule.windowS * 1_000,
    key: rule.key,
    failures: rule.count === "failures",
    keyPrefix: `${rule.id}/${rule.windowS}/${rule.count === "failures" ? "f" : "r"}/`,
    decision: Object.freeze({ action: "throttle", mode: rule.mode, ruleId: rule.id, policyVersion: version }),
  });
}

/** What the limiter is given of one request. */
export interface LimitInput {
  /** The method in upper case. */
  readonly method: string;
  /** The path `decide` is given. */
  readonly path: string;
  /** A CORS preflight (`OPTIONS` with `access-control-request-method`): never counted, refused when already over. */
  readonly preflight: boolean;
  readonly client: Client;
  /** The address as given (the socket's, or `clientAddress`'s), used when `client.address` could not be parsed. */
  readonly rawAddress?: unknown;
  /** The device of the request's valid Attestation Token; null without a valid token. Hashed before it is a key. */
  readonly device: string | null;
}

/** What the limits made of one request. */
export interface LimitOutcome {
  /** The enforced limit that refuses the request, or null. */
  readonly throttled: AppliedLimitRule | null;
  /** With `throttled`: whole seconds until one more request is allowed, at least 1. Otherwise 0. */
  readonly retryAfterS: number;
  /** The first limit in monitor the request is over, or null. Recorded when nothing else decided the request. */
  readonly marked: AppliedLimitRule | null;
  /**
   * The first failure-counting limit Rule that matched the request, whether or not it throttled, or null: the Event's
   * `decision.limit_rule_id` (A7, D-064).
   */
  readonly failureRule: AppliedLimitRule | null;
  /** The failure slots the request holds: key, window, limit, key, window, limit, … Empty when none. */
  readonly pending: readonly (string | number)[];
}

export interface Limiter {
  /**
   * Looks at every limit Rule of `policy` that matches the request, refuses it or counts it (see the top of this
   * file). Null when no limit applies. Throws only what the store throws: the caller fails open.
   */
  evaluate(policy: AppliedPolicy, input: LimitInput, now: number): LimitOutcome | null;
  /**
   * When the response of the request closed with `status`: counts a failure (401, 403) on its failure limits, and
   * releases its slots. Once per outcome; later calls, and calls after `release`, do nothing.
   */
  settle(outcome: LimitOutcome, status: number, now: number): void;
  /** Releases the request's slots without counting anything: Shield answered it, or nothing could be counted. */
  release(outcome: LimitOutcome): void;
  /** Failure slots held now, all keys together. */
  inFlight(): number;
  /** Requests counted by the text of an address that could not be parsed. Internal: not part of `ShieldStats`. */
  unparsedAddresses(): number;
}

/** The outcome as the limiter keeps it: whether its slots were released. */
interface Held extends LimitOutcome {
  done: boolean;
}

const NO_SLOTS: readonly (string | number)[] = Object.freeze([]);
/** Characters of an address that could not be parsed that a key is made from, at most. */
const RAW_ADDRESS_MAX = 64;

/** What the address counter is of: an IPv4 address in full, or the /64 of an IPv6 address. Hashed before use. */
function addressSubject(address: ParsedAddress): string {
  const w = address.words;
  return address.version === 4 ? `a/4/${w[0]}.${w[1]}` : `a/6/${w[0]}.${w[1]}.${w[2]}.${w[3]}`;
}

/** Bytes of the keyed hash kept as the client part of a key. */
const CLIENT_HASH_BYTES = 16;

/** A count as the store answered it: anything but a finite number is nothing counted. */
function countOf(value: unknown): number {
  return typeof value === "number" && Number.isFinite(value) ? value : 0;
}

/** Whole seconds until the count of `key` is below `limit`: after them one more request is allowed. At least 1. */
function retryAfter(store: CounterStore, key: string, rule: AppliedLimitRule, limit: number, now: number): number {
  const windowS = rule.windowMs / 1_000;
  if (typeof store.retryAfterMs !== "function") return windowS;
  const wait = store.retryAfterMs(key, rule.windowMs, limit, now);
  if (typeof wait !== "number" || !Number.isFinite(wait) || wait < 0) return windowS;
  // The count is below the limit only after `wait`: the next whole second, never the one it falls in. One
  // millisecond is added first, so that a rounding error in `wait` can never promise a second too early.
  return Math.min(Math.floor((wait + 1) / 1_000) + 1, 2 * windowS + 1);
}

/**
 * `secret`: the key of the client hash; left out, 32 random bytes of this limiter (what Shield uses). Given only by
 * tests that compare keys. `onUnparsedAddress`: called for each request counted by the text of an address that
 * could not be parsed.
 */
export function createLimiter(
  store: CounterStore,
  options: { secret?: Uint8Array; onUnparsedAddress?: () => void } = {},
): Limiter {
  const secret = options.secret ?? randomBytes(32);
  const onUnparsed = options.onUnparsedAddress;
  /** Failure slots held, by key. An entry exists only while a request holds a slot: bounded by the requests in flight. */
  const slots = new Map<string, number>();
  let held = 0;
  let unparsed = 0;
  /** The client part of a key: never the address or the device id itself. */
  const clientHash = (material: string): string =>
    createHash("sha256")
      .update(secret)
      .update(material, "utf8")
      .digest("hex")
      .slice(0, CLIENT_HASH_BYTES * 2);

  function evaluate(policy: AppliedPolicy, input: LimitInput, now: number): LimitOutcome | null {
    const rules = policy.limitRules;
    if (rules.length === 0) return null;
    const method = input.method;
    const preflight = input.preflight && method === "OPTIONS";
    const address = input.client.address;
    // The address part of every key: the parsed address, else the text of the one given (F7), else nothing.
    let subject: string | null = null;
    if (address === null) {
      const raw = typeof input.rawAddress === "string" ? input.rawAddress.trim().slice(0, RAW_ADDRESS_MAX) : "";
      if (raw === "") return null; // nothing to count the client by
      subject = `r/${raw}`;
    }
    const forms = pathForms(normalisePath(input.path));
    if (forms.length === 0) return null; // not a path: no Rule matches
    const device = input.device;
    // Hashed once per request, when the first Rule needs them.
    let addressPart: string | undefined;
    let devicePart: string | undefined;
    // Step 1: look. The matching Rules with their keys, in bundle order: rule, key, wide key (or null).
    let matched: (AppliedLimitRule | string | null)[] | null = null;
    let throttled: AppliedLimitRule | null = null;
    let retryAfterS = 0;
    let marked: AppliedLimitRule | null = null;
    let failureRule: AppliedLimitRule | null = null;
    for (let i = 0; i < rules.length; i++) {
      const rule = rules[i] as AppliedLimitRule;
      if (!matchMethod(rule.methods, method) || !matchForms(rule.pattern, forms)) continue;
      if (matched === null) {
        // The never-block list, read once and only for a request a limit names.
        if (address !== null) {
          const allowlist = policy.allowlist;
          for (let k = 0; k < allowlist.length; k++) {
            if (inCidr(allowlist[k] as (typeof allowlist)[number], address)) return null;
          }
        } else {
          unparsed += 1;
          onUnparsed?.();
        }
        matched = [];
      }
      addressPart ??= clientHash(subject ?? addressSubject(address as ParsedAddress));
      const addressKey = rule.keyPrefix + addressPart;
      // The counter held to the limit: the device of an attested request under a device limit, else the address.
      // `wide` is then the address counter of that attested request, held to 5 times the limit; null otherwise.
      let key = addressKey;
      let wide: string | null = null;
      if (rule.key === "device" && device !== null) {
        devicePart ??= clientHash(`d/${device}`);
        key = rule.keyPrefix + devicePart;
        wide = addressKey;
      }
      const windowMs = rule.windowMs;
      const limit = rule.requests;
      const wideLimit = limit * LIMIT_DEVICE_ADDRESS_FACTOR;
      if (rule.failures) failureRule ??= rule;
      const flying = rule.failures ? (slots.get(key) ?? 0) : 0;
      const over = countOf(store.peek(key, windowMs, now, limit)) + flying + 1 > limit;
      let wideOver = false;
      if (wide !== null) {
        const wideFlying = rule.failures ? (slots.get(wide) ?? 0) : 0;
        wideOver = countOf(store.peek(wide, windowMs, now, wideLimit)) + wideFlying + 1 > wideLimit;
      }
      if (over || wideOver) {
        if (rule.mode === "enforce") {
          throttled ??= rule;
          if (over) retryAfterS = Math.max(retryAfterS, retryAfter(store, key, rule, limit, now));
          if (wideOver && wide !== null) {
            retryAfterS = Math.max(retryAfterS, retryAfter(store, wide, rule, wideLimit, now));
          }
        } else {
          marked ??= rule;
        }
      }
      matched.push(rule, key, wide);
    }
    if (matched === null) return null;
    // Step 2: refused, or a preflight — nothing is counted.
    if (throttled !== null) {
      return { throttled, retryAfterS, marked: null, failureRule, pending: NO_SLOTS, done: true } as Held;
    }
    if (preflight)
      return { throttled: null, retryAfterS: 0, marked: null, failureRule, pending: NO_SLOTS, done: true } as Held;
    // Step 3: count on every matching Rule.
    let pending: (string | number)[] | null = null;
    for (let i = 0; i < matched.length; i += 3) {
      const rule = matched[i] as AppliedLimitRule;
      const key = matched[i + 1] as string;
      const wide = matched[i + 2] as string | null;
      const limit = rule.requests;
      if (rule.failures) {
        pending ??= [];
        pending.push(key, rule.windowMs, limit);
        slots.set(key, (slots.get(key) ?? 0) + 1);
        held += 1;
        if (wide !== null) {
          pending.push(wide, rule.windowMs, limit * LIMIT_DEVICE_ADDRESS_FACTOR);
          slots.set(wide, (slots.get(wide) ?? 0) + 1);
          held += 1;
        }
      } else {
        store.hit(key, rule.windowMs, now, limit);
        if (wide !== null) store.hit(wide, rule.windowMs, now, limit * LIMIT_DEVICE_ADDRESS_FACTOR);
      }
    }
    const outcome: Held = {
      throttled: null,
      retryAfterS: 0,
      marked,
      failureRule,
      pending: pending ?? NO_SLOTS,
      done: pending === null,
    };
    return outcome;
  }

  function release(outcome: LimitOutcome): void {
    const own = outcome as Held;
    if (own.done !== false) return;
    own.done = true;
    const pending = own.pending;
    for (let i = 0; i < pending.length; i += 3) {
      const key = pending[i] as string;
      const left = (slots.get(key) ?? 1) - 1;
      if (left > 0) slots.set(key, left);
      else slots.delete(key);
      held -= 1;
    }
  }

  function settle(outcome: LimitOutcome, status: number, now: number): void {
    const own = outcome as Held;
    if (own.done !== false) return;
    // Released first: whatever the store does, the slots never stay held.
    release(own);
    if (status !== LIMIT_FAILURE_STATUSES[0] && status !== LIMIT_FAILURE_STATUSES[1]) return;
    const pending = own.pending;
    for (let i = 0; i < pending.length; i += 3) {
      store.hit(pending[i] as string, pending[i + 1] as number, now, pending[i + 2] as number);
    }
  }

  return { evaluate, settle, release, inFlight: () => held, unparsedAddresses: () => unparsed };
}
