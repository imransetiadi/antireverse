// Request signatures (slice 04). Guard signs each request with the P-256 session key whose public half its
// Attestation Token carries in `cnf.jwk`; Shield verifies offline, in this order: header parse → content hash form →
// token valid with a jwk → signature → timestamp → nonce. A nonce is remembered only after a valid signature, until
// t + 61 s. The canonical string binds the exact `content-type` value (review F1).
//
// Shield has no runtime dependency, so the protocol's constants, parser and canonical string are repeated here by
// hand, and test/signature.test.ts pins them against the protocol (`verifyRequestSignature` is checked on a corpus
// of valid and mutated requests). A bound that changes there must change here.
//
// Nothing here logs. A signature, a nonce, a content hash, a token or a body never leaves the process: the Event
// records `{ status, body }` only.
import { createHash, createPublicKey, type KeyObject, timingSafeEqual, verify } from "node:crypto";
import type { IncomingMessage } from "node:http";
import { BLOCK_BODY } from "./express.ts";

/** Equal to `SIGNATURE_HEADER` of the protocol. */
export const SIGNATURE_HEADER = "ar-signature";
/** Equal to `CONTENT_HASH_HEADER` of the protocol. */
export const CONTENT_HASH_HEADER = "ar-content-sha256";
/** Equal to `SIGNATURE_LIMITS.windowS`. */
export const WINDOW_S = 60;
/**
 * Equal to `SIGNATURE_LIMITS.nonceKeepS`: a nonce is remembered until `t + NONCE_KEEP_S` seconds, exactly as long as
 * its signature is not stale (review F5).
 */
export const NONCE_KEEP_S = 61;
/** Equal to `SIGNATURE_LIMITS.nonceStoreMax`. A store full of live entries evicts none. */
export const NONCE_STORE_MAX = 100_000;
/** Session keys imported and kept at most, by jkt. */
export const KEY_CACHE_MAX = 10_000;
/** Equal to `EMPTY_CONTENT_SHA256` of the protocol: the SHA-256 of no bytes. */
export const EMPTY_CONTENT_SHA256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";
/** Equal to `CONTENT_SHA256_PATTERN` of the protocol: canonical base64url of 32 bytes. */
export const CONTENT_SHA256_PATTERN = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
/** Equal to the protocol's `ar-signature` form. */
const SIGNATURE_HEADER_FORM = /^v1,t=(0|[1-9][0-9]{0,9}),n=([A-Za-z0-9_-]{21}[AQgw]),s=([A-Za-z0-9_-]{85}[AQgw])$/;
/** Equal to `ATTESTATION_PATTERNS.coordinate`. */
const COORDINATE = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
const P1363_BYTES = 64;

export type SignatureStatus = "valid" | "missing" | "invalid" | "stale" | "replayed";
export type BodyState = "checked" | "unchecked" | "mismatch" | "none";

/** The session public key of a token (`cnf.jwk`), the four public members. */
export interface SessionJwk {
  readonly kty: "EC";
  readonly crv: "P-256";
  readonly x: string;
  readonly y: string;
}

/** What a valid Attestation Token binds a request signature to. */
export interface SessionBinding {
  readonly jti: string;
  readonly jkt: string;
  /** Null for a token without `cnf.jwk`: it cannot back a signature. */
  readonly jwk: SessionJwk | null;
}

/** `parseSignatureHeader` of the protocol. Never throws. */
export function parseSignatureHeader(value: unknown): { t: number; n: string; s: string } | null {
  if (typeof value !== "string") return null;
  const match = SIGNATURE_HEADER_FORM.exec(value);
  if (match === null) return null;
  return { t: Number(match[1]), n: match[2] as string, s: match[3] as string };
}

/**
 * `canonicalSigningString` of the protocol, byte for byte: with the exact `content-type` line (review F1). Throws a
 * TypeError where it does.
 */
export function canonicalSigningString(input: {
  method: string;
  target: string;
  contentType: string;
  contentSha256: string;
  t: number;
  n: string;
  jti: string;
}): string {
  const { method, target, contentType, contentSha256, t, n, jti } = input;
  for (const value of [method, target, contentType, contentSha256, n, jti]) {
    if (typeof value !== "string") throw new TypeError("The signed values are strings.");
    if (value.includes("\n")) throw new TypeError("A signed value must not contain a line feed.");
  }
  if (typeof t !== "number" || !Number.isSafeInteger(t) || t < 0) {
    throw new TypeError("t is a non-negative integer of seconds.");
  }
  return `ar-sig-v1\n${method.toUpperCase()}\n${target}\n${contentType}\n${contentSha256}\n${t}\n${n}\n${jti}`;
}

/** The session key from a jwk, as the protocol's reference imports it: EC P-256, canonical coordinates, on the curve. */
function importSessionKey(jwk: unknown): KeyObject | null {
  if (typeof jwk !== "object" || jwk === null) return null;
  const { kty, crv, x, y } = jwk as Record<string, unknown>;
  if (kty !== "EC" || crv !== "P-256") return null;
  if (typeof x !== "string" || typeof y !== "string" || !COORDINATE.test(x) || !COORDINATE.test(y)) return null;
  try {
    return createPublicKey({ key: { kty, crv, x, y }, format: "jwk" });
  } catch {
    return null;
  }
}

export interface KeyCache {
  /** The imported key of `jwk`, cached under `jkt`. A cached key is returned only for the same coordinates. */
  get(jkt: string, jwk: unknown): KeyObject | null;
  size(): number;
}

/**
 * Imported session keys by jkt, at most `max` (least recently used out first). A hit requires the same coordinates:
 * a token whose jkt names another key's coordinates gets its own key, imported and not cached.
 */
export function createKeyCache(max = KEY_CACHE_MAX): KeyCache {
  const cache = new Map<string, { x: string; y: string; key: KeyObject }>();
  return {
    get(jkt, jwk) {
      const given = jwk as { kty?: unknown; crv?: unknown; x?: unknown; y?: unknown } | null | undefined;
      const entry = cache.get(jkt);
      if (entry !== undefined && typeof given === "object" && given !== null) {
        if (given.kty === "EC" && given.crv === "P-256" && entry.x === given.x && entry.y === given.y) {
          cache.delete(jkt);
          cache.set(jkt, entry);
          return entry.key;
        }
        return importSessionKey(jwk); // another key under a known jkt: never the cached one, never cached
      }
      const key = importSessionKey(jwk);
      if (key === null) return null;
      cache.set(jkt, { x: (given as { x: string }).x, y: (given as { y: string }).y, key });
      if (cache.size > max) {
        const oldest = cache.keys().next().value;
        if (oldest !== undefined) cache.delete(oldest);
      }
      return key;
    },
    size: () => cache.size,
  };
}

/**
 * `verifyRequestSignature` of the protocol, by hand: `valid`, `invalid` or `stale`; nonce and replay are the
 * caller's. With `keys` and `jkt` the session key is taken from the cache. Never throws.
 */
export function verifySignature(
  input: {
    method: string;
    target: string;
    contentType: string;
    contentSha256: string;
    header: unknown;
    jti: string;
    jwk: unknown;
    nowS: number;
    jkt?: string;
  },
  keys?: KeyCache,
): "valid" | "invalid" | "stale" {
  const parsed = parseSignatureHeader(input?.header);
  if (parsed === null) return "invalid";
  return verifyParsed(input, parsed, keys);
}

function verifyParsed(
  input: {
    method: string;
    target: string;
    contentType: string;
    contentSha256: string;
    jti: string;
    jwk: unknown;
    nowS: number;
    jkt?: string;
  },
  parsed: { t: number; n: string; s: string },
  keys: KeyCache | undefined,
): "valid" | "invalid" | "stale" {
  if (typeof input.contentSha256 !== "string" || !CONTENT_SHA256_PATTERN.test(input.contentSha256)) return "invalid";
  const key =
    keys !== undefined && typeof input.jkt === "string" ? keys.get(input.jkt, input.jwk) : importSessionKey(input.jwk);
  if (key === null) return "invalid";
  let canonical: string;
  try {
    canonical = canonicalSigningString({
      method: input.method,
      target: input.target,
      contentType: input.contentType,
      contentSha256: input.contentSha256,
      t: parsed.t,
      n: parsed.n,
      jti: input.jti,
    });
  } catch {
    return "invalid";
  }
  const signature = Buffer.from(parsed.s, "base64url");
  if (signature.byteLength !== P1363_BYTES) return "invalid";
  let genuine = false;
  try {
    genuine = verify("sha256", Buffer.from(canonical, "utf8"), { key, dsaEncoding: "ieee-p1363" }, signature);
  } catch {
    genuine = false;
  }
  if (!genuine) return "invalid";
  const now = input.nowS;
  if (typeof now !== "number" || !Number.isFinite(now)) return "invalid";
  return Math.abs(parsed.t - now) > WINDOW_S ? "stale" : "valid";
}

export interface NonceStore {
  readonly max: number;
  /**
   * `fresh`: not remembered (or its expiry passed), now remembered until `expiresMs` (absolute, milliseconds since
   * the epoch). `seen`: remembered and live (a replay). `full`: not seen, and the store holds `max` live entries:
   * nothing is remembered and nothing is evicted.
   */
  check(key: string, nowMs: number, expiresMs: number): "fresh" | "seen" | "full";
  size(): number;
}

/** Milliseconds between two full sweeps of a full store: a store full of live entries costs one sweep per second. */
const FULL_SWEEP_EVERY_MS = 1_000;

/**
 * The per-instance nonce window: key → absolute expiry in milliseconds, in insertion order. The signature checker
 * gives each nonce the expiry `(t + NONCE_KEEP_S) s`: a nonce is kept exactly as long as its signature is not stale,
 * whenever it was first seen (review F5). Expiries are therefore not in insertion order: expired entries are swept
 * from the oldest end on every check, and — when the store is full — once a second over the whole store, so an
 * expired entry behind a live one is not counted as live. A live entry is never evicted; memory stays bounded by
 * `max` either way.
 */
export function createNonceStore(options: { max?: number } = {}): NonceStore {
  const max =
    Number.isSafeInteger(options.max) && (options.max as number) > 0 ? (options.max as number) : NONCE_STORE_MAX;
  const entries = new Map<string, number>();
  let lastFullSweep = Number.NEGATIVE_INFINITY;
  return {
    max,
    check(key, nowMs, expiresMs) {
      for (const [oldest, expires] of entries) {
        if (expires > nowMs) break;
        entries.delete(oldest);
      }
      const expires = entries.get(key);
      if (expires !== undefined) {
        if (expires > nowMs) return "seen";
        entries.delete(key);
      }
      if (!(expiresMs > nowMs)) return "fresh"; // already past its expiry: nothing to remember
      if (entries.size >= max && Math.abs(nowMs - lastFullSweep) >= FULL_SWEEP_EVERY_MS) {
        lastFullSweep = nowMs;
        for (const [entry, until] of entries) if (until <= nowMs) entries.delete(entry);
      }
      if (entries.size >= max) return "full";
      entries.set(key, expiresMs);
      return "fresh";
    },
    size: () => entries.size,
  };
}

/** The signature state of one request. The middleware reads it when the response closes, after `verifyBody`. */
export interface SignatureState {
  status: SignatureStatus;
  /** Null exactly when the status is `missing`. */
  body: BodyState | null;
  /**
   * The Decision to record if `verifyBody` finds a mismatch, or never runs: set by the middleware when a requirement
   * was deferred to the body hook (`bodyVerified`). Opaque here.
   */
  deferred: unknown;
  /**
   * An enforced requirement Rule applies to this request and was deferred to the body hook: a mismatch is refused
   * (403). Otherwise a mismatch is only recorded and the parser goes on: Monitor never changes a response.
   */
  refuse: boolean;
}

/**
 * The fixed error `verifyBody` throws on a mismatch; body-parser answers 403 with it before the handler, and
 * `shield.errorHandler()` turns it into the standard block response (review F6).
 *
 * `expose`, `body` and `type` are read-only accessors: body-parser passes the error through `http-errors`, which
 * would otherwise set `expose = true` and `body` = the raw request body. Kept as they are, an application that
 * renders `err.body` shows the block body, and the request body never rides on the error.
 */
export class BodyMismatchError extends Error {
  readonly status = 403;
  readonly statusCode = 403;
  declare readonly expose: false;
  declare readonly body: string;
  declare readonly type: string;
  constructor() {
    super("request_blocked");
    this.name = "BodyMismatchError";
    const fixed = (value: unknown) => ({ get: () => value, set: () => {}, enumerable: true, configurable: false });
    Object.defineProperties(this, {
      expose: fixed(false),
      body: fixed(BLOCK_BODY),
      type: fixed("entity.verify.failed"),
    });
  }
}

interface InternalState extends SignatureState {
  /** The signed content hash as bytes, while the body is to be compared; null otherwise. */
  expected: Buffer | null;
}

export interface SignatureChecker {
  /**
   * The signature state of `request`, registered for `verifyBody`. `binding` is that of the request's Attestation
   * Token when it is valid, else null. `nowMs` is Shield's clock.
   */
  check(request: IncomingMessage, binding: SessionBinding | null, nowMs: number): SignatureState;
  /** The state registered for a request, if any. */
  stateOf(request: IncomingMessage): SignatureState | undefined;
  /**
   * The body-parser `verify` hook. For a request with a signature state and a body not yet compared: equal SHA-256 →
   * `checked`; otherwise `mismatch` and status `invalid`, and — only when the state says `refuse` (an enforced
   * requirement applies) — a `BodyMismatchError` is thrown. Otherwise nothing.
   */
  verifyBody(request: IncomingMessage, body: unknown): void;
  stats(): { nonces: number; keys: number };
}

/** A request has a body when `content-length` is above 0 or `transfer-encoding` is present. */
function hasBody(request: IncomingMessage): boolean {
  const headers = request.headers ?? {};
  if (headers["transfer-encoding"] !== undefined) return true;
  const length = headers["content-length"];
  return typeof length === "string" && /^[0-9]+$/.test(length) && !/^0+$/.test(length);
}

/**
 * The exact `content-type` value of the request (review F1), `""` when it has none, or null when it cannot be one
 * value (Node keeps the first of repeated `content-type` headers, so a list only comes from a double).
 */
export function contentTypeOf(request: IncomingMessage): string | null {
  const value = request.headers?.["content-type"];
  if (value === undefined) return "";
  return typeof value === "string" ? value : null;
}

function targetOf(request: IncomingMessage): unknown {
  const original = (request as IncomingMessage & { originalUrl?: unknown }).originalUrl;
  return typeof original === "string" ? original : request.url;
}

const MISSING: InternalState = Object.freeze({
  status: "missing",
  body: null,
  deferred: undefined,
  refuse: false,
  expected: null,
});

export function createSignatureChecker(options: { nonceMax?: number; keyMax?: number } = {}): SignatureChecker {
  const nonces = createNonceStore(options.nonceMax === undefined ? {} : { max: options.nonceMax });
  const keys = createKeyCache(options.keyMax);
  const states = new WeakMap<IncomingMessage, InternalState>();

  function evaluate(request: IncomingMessage, binding: SessionBinding | null, nowMs: number, body: BodyState) {
    const headers = request.headers ?? {};
    const parsed = parseSignatureHeader(headers[SIGNATURE_HEADER]);
    if (parsed === null) return { status: "invalid" as const, expected: null };
    const hash = headers[CONTENT_HASH_HEADER];
    if (typeof hash !== "string" || !CONTENT_SHA256_PATTERN.test(hash))
      return { status: "invalid" as const, expected: null };
    const expected = body === "unchecked" ? Buffer.from(hash, "base64url") : null;
    // Without a body the signed hash must be that of no bytes.
    if (body === "none" && hash !== EMPTY_CONTENT_SHA256) return { status: "invalid" as const, expected };
    if (binding === null || binding.jwk === null) return { status: "invalid" as const, expected };
    const method = typeof request.method === "string" ? request.method : "";
    const target = targetOf(request);
    if (typeof target !== "string") return { status: "invalid" as const, expected };
    const contentType = contentTypeOf(request);
    if (contentType === null) return { status: "invalid" as const, expected };
    const verified = verifyParsed(
      {
        method,
        target,
        contentType,
        contentSha256: hash,
        jti: binding.jti,
        jwk: binding.jwk,
        jkt: binding.jkt,
        nowS: Math.floor(nowMs / 1000),
      },
      parsed,
      keys,
    );
    if (verified !== "valid") return { status: verified, expected };
    // Only now is the nonce consumed, and kept until the signature would be stale (t + 61 s). A full store cannot
    // rule a replay out: invalid.
    const seen = nonces.check(binding.jti + parsed.n, nowMs, (parsed.t + NONCE_KEEP_S) * 1000);
    const status: SignatureStatus = seen === "fresh" ? "valid" : seen === "seen" ? "replayed" : "invalid";
    return { status, expected };
  }

  return {
    check(request, binding, nowMs) {
      if (request.headers?.[SIGNATURE_HEADER] === undefined) {
        states.set(request, MISSING);
        return MISSING;
      }
      const body: BodyState = hasBody(request) ? "unchecked" : "none";
      const { status, expected } = evaluate(request, binding, nowMs, body);
      const state: InternalState = { status, body, deferred: undefined, refuse: false, expected };
      states.set(request, state);
      return state;
    },
    stateOf(request) {
      return states.get(request);
    },
    verifyBody(request, body) {
      if (typeof request !== "object" || request === null) return;
      const state = states.get(request);
      if (state === undefined || state.body !== "unchecked" || state.expected === null) return;
      if (!Buffer.isBuffer(body) && !(body instanceof Uint8Array)) return;
      const digest = createHash("sha256").update(body).digest();
      const expected = state.expected;
      state.expected = null;
      if (digest.length === expected.length && timingSafeEqual(digest, expected)) {
        state.body = "checked";
        return;
      }
      state.body = "mismatch";
      state.status = "invalid";
      if (state.refuse) throw new BodyMismatchError();
    },
    stats: () => ({ nonces: nonces.size(), keys: keys.size() }),
  };
}
