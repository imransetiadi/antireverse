// Attestation Tokens (slice 03, observe only). Shield verifies the token of the `ar-attestation` header offline, with
// the attestation keys of the applied signed bundle, and records `{ status, verdict, risk }` on the Event. Nothing
// here changes the request or the response, and nothing logs: the token, its `sub` and its `jti` never leave the
// process.
//
// Shield has no runtime dependency, so the token is verified by hand. The rules are those of
// `verifyAttestationToken` of the protocol's server entry, and test/attestation.test.ts checks on a corpus of valid
// and malformed tokens that both give the same result. The bounds and patterns are the protocol's
// (`ATTESTATION_LIMITS`, `ATTESTATION_PATTERNS`, `AttestationClaimsSchema`); a bound that changes there must change
// here, and the same test pins the agreement.
//
// A token is `<header>.<payload>.<signature>`, three canonical base64url parts; the header is exactly
// `alg: "EdDSA"`, `typ: "JWT"`, a kid of the applied bundle and no `crit`; the signature is Ed25519 over the ASCII
// bytes of `<header>.<payload>` as received. Nothing of the payload is trusted before the signature verified.
import { createHash, verify } from "node:crypto";
import type { AttestationClaims } from "@antireverse/protocol";
import type { AppliedPolicy } from "./policy/store.ts";
import type { SessionBinding, SessionJwk } from "./signature.ts";

/** The request header. Equal to `ATTESTATION_HEADER` of the protocol. */
export const HEADER_NAME = "ar-attestation";
/** Characters of a token at most. Equal to `ATTESTATION_LIMITS.headerMax`. */
export const TOKEN_MAX = 2048;
/** Seconds a token lives at most (`exp - iat`). Equal to `ATTESTATION_LIMITS.ttlS`. */
export const TTL_S = 300;
/** Seconds of clock skew allowed on `iat` and `exp`. Equal to `ATTESTATION_LIMITS.skewS`. */
export const SKEW_S = 30;
/** Attestation keys of a bundle at most. Equal to `ATTESTATION_LIMITS.keysMax`. */
export const KEYS_MAX = 3;
/** Signal ids of a token at most. Equal to the bound of `AttestationClaimsSchema.sig`. */
export const SIGNALS_MAX = 16;
/** Verified tokens remembered at most. */
export const ATTESTATION_CACHE_MAX = 10_000;
export const ISSUER = "antireverse";
export const VERDICT_SET: ReadonlySet<string> = new Set(["trusted", "suspect", "hostile"]);

/** Equal to `ATTESTATION_PATTERNS.kid`. */
export const KID_PATTERN = /^[0-9a-f]{16}$/;
/** Equal to `ATTESTATION_PATTERNS.publicKey`. */
export const PUBLIC_KEY_PATTERN = /^[A-Za-z0-9_-]{43}$/;
/** Equal to `ATTESTATION_PATTERNS.jti`. */
export const JTI_PATTERN = /^[0-9a-f]{32}$/;
/** Equal to `ATTESTATION_PATTERNS.sub`. */
export const SUB_PATTERN = /^dev_[0-9a-f]{24}$/;
/** Equal to `ATTESTATION_PATTERNS.jkt`. */
export const JKT_PATTERN = /^[A-Za-z0-9_-]{43}$/;
/** Equal to `ATTESTATION_PATTERNS.signal`. */
export const SIGNAL_PATTERN = /^(?=.{1,32}$)[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*$/;
/** Equal to `ATTESTATION_PATTERNS.coordinate`: a P-256 coordinate of `cnf.jwk`. */
export const COORDINATE_PATTERN = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;
/** Equal to `ID_PATTERNS.app`. */
export const APP_ID_PATTERN = /^app_[0-9a-f]{24}$/;

/** A JWS part: base64url without padding. */
const PART = /^[A-Za-z0-9_-]*$/;
/** An Ed25519 signature: 64 bytes as 86 base64url characters. */
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;
const RISK_MAX = 100;

export type AttestationStatus = "valid" | "missing" | "invalid" | "expired";

/** What the Event records. Verdict and risk are set exactly when the status is valid. */
export interface AttestationResult {
  readonly status: AttestationStatus;
  readonly verdict: "trusted" | "suspect" | "hostile" | null;
  readonly risk: number | null;
}

export type AttestationVerification =
  | { status: "valid"; claims: AttestationClaims }
  | { status: "invalid" }
  | { status: "expired" };

/** The keys and audience a token is verified against: the applied Policy. */
export type AttestationContext = Pick<AppliedPolicy, "appId" | "attestationKeys">;

const INVALID: { status: "invalid" } = Object.freeze({ status: "invalid" });
const EXPIRED: { status: "expired" } = Object.freeze({ status: "expired" });

export const MISSING_RESULT: AttestationResult = Object.freeze({ status: "missing", verdict: null, risk: null });
export const INVALID_RESULT: AttestationResult = Object.freeze({ status: "invalid", verdict: null, risk: null });
export const EXPIRED_RESULT: AttestationResult = Object.freeze({ status: "expired", verdict: null, risk: null });
const MISSING_BOUND = Object.freeze({ result: MISSING_RESULT, binding: null, device: null });
const INVALID_BOUND = Object.freeze({ result: INVALID_RESULT, binding: null, device: null });
const EXPIRED_BOUND = Object.freeze({ result: EXPIRED_RESULT, binding: null, device: null });

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** The JSON object a base64url part holds, or null. Canonical base64url only: re-encoding must give the part. */
function decodeObject(part: string): Record<string, unknown> | null {
  if (part.length === 0 || part.length % 4 === 1 || !PART.test(part)) return null;
  const bytes = Buffer.from(part, "base64url");
  if (bytes.toString("base64url") !== part) return null;
  try {
    const value: unknown = JSON.parse(bytes.toString("utf8"));
    return isObject(value) ? value : null;
  } catch {
    return null;
  }
}

/** Seconds since the Unix epoch: a whole number from 0 up to the largest safe integer. */
function isSeconds(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function matches(value: unknown, pattern: RegExp): value is string {
  return typeof value === "string" && pattern.test(value);
}

/** The claims as `AttestationClaimsSchema` parses them (unknown members dropped), or null. */
function readClaims(payload: Record<string, unknown>): AttestationClaims | null {
  const { iss, aud, sub, iat, exp, jti, cnf, verdict, risk, sig, pv } = payload;
  if (iss !== ISSUER || !matches(aud, APP_ID_PATTERN) || !matches(sub, SUB_PATTERN)) return null;
  if (!isSeconds(iat) || !isSeconds(exp) || !matches(jti, JTI_PATTERN)) return null;
  if (!isObject(cnf) || !matches(cnf.jkt, JKT_PATTERN)) return null;
  // Optional (slice 04): the session public key. Present, it must be exactly an EC P-256 key with canonical
  // coordinates (other members are dropped, as the schema drops them).
  let jwk: SessionJwk | undefined;
  if (cnf.jwk !== undefined) {
    const given = cnf.jwk;
    if (!isObject(given) || given.kty !== "EC" || given.crv !== "P-256") return null;
    if (!matches(given.x, COORDINATE_PATTERN) || !matches(given.y, COORDINATE_PATTERN)) return null;
    jwk = { kty: "EC", crv: "P-256", x: given.x, y: given.y };
  }
  if (typeof verdict !== "string" || !VERDICT_SET.has(verdict)) return null;
  if (typeof risk !== "number" || !Number.isSafeInteger(risk) || risk < 0 || risk > RISK_MAX) return null;
  if (!Array.isArray(sig) || sig.length > SIGNALS_MAX) return null;
  for (let i = 0; i < sig.length; i++) {
    if (!matches(sig[i], SIGNAL_PATTERN) || sig.indexOf(sig[i]) !== i) return null;
  }
  if (pv !== 1) return null;
  if (!(exp > iat && exp - iat <= TTL_S)) return null;
  return {
    iss: ISSUER,
    aud,
    sub,
    iat,
    exp,
    jti,
    cnf: jwk === undefined ? { jkt: cnf.jkt } : { jkt: cnf.jkt, jwk },
    verdict: verdict as AttestationClaims["verdict"],
    risk,
    sig: [...(sig as string[])],
    pv: 1,
  };
}

/**
 * Verifies an Attestation Token with the keys and `app_id` of the applied Policy at `nowS` (seconds). Never throws.
 * The same result as `verifyAttestationToken` of the protocol: `invalid` for anything malformed, a key not in the
 * bundle, a signature that does not verify, another audience or an `iat` more than 30 s ahead; `expired` for a token
 * that passed all of that and whose `exp` is 30 s or more in the past; otherwise `valid` with the claims.
 */
export function verifyAttestation(token: unknown, context: AttestationContext, nowS: number): AttestationVerification {
  const verified = verifyToken(token, context, nowS);
  return verified.status === "valid" ? { status: "valid", claims: verified.claims } : verified;
}

/** `verifyAttestation`, and for a valid token also the kid of the key it verified with. */
function verifyToken(
  token: unknown,
  context: AttestationContext,
  nowS: number,
): { status: "valid"; claims: AttestationClaims; kid: string } | { status: "invalid" } | { status: "expired" } {
  if (typeof token !== "string" || token.length > TOKEN_MAX) return INVALID;
  const first = token.indexOf(".");
  const second = first === -1 ? -1 : token.indexOf(".", first + 1);
  if (second === -1 || token.indexOf(".", second + 1) !== -1) return INVALID;
  const headerPart = token.slice(0, first);
  const payloadPart = token.slice(first + 1, second);
  const signaturePart = token.slice(second + 1);

  const header = decodeObject(headerPart);
  if (header === null) return INVALID;
  if (header.alg !== "EdDSA" || header.typ !== "JWT" || "crit" in header) return INVALID;
  const kid = header.kid;
  if (!matches(kid, KID_PATTERN)) return INVALID;
  const entry = context.attestationKeys.get(kid);
  if (entry === undefined) return INVALID;

  // The signature covers the bytes as received; one spelling per signature (unused trailing bits zero).
  if (!SIGNATURE.test(signaturePart)) return INVALID;
  const signature = Buffer.from(signaturePart, "base64url");
  if (signature.toString("base64url") !== signaturePart) return INVALID;
  let genuine = false;
  try {
    genuine = verify(null, Buffer.from(token.slice(0, second), "ascii"), entry.key, signature);
  } catch {
    genuine = false;
  }
  if (!genuine) return INVALID;

  const payload = decodeObject(payloadPart);
  if (payload === null) return INVALID;
  const claims = readClaims(payload);
  if (claims === null) return INVALID;
  if (context.appId === null || claims.aud !== context.appId) return INVALID;
  if (typeof nowS !== "number" || !Number.isFinite(nowS)) return INVALID;
  if (claims.iat > nowS + SKEW_S) return INVALID;
  if (claims.exp <= nowS - SKEW_S) return EXPIRED;
  return { status: "valid", claims, kid };
}

/** One verified token, under the SHA-256 of its exact string. Never the token itself. */
interface CacheEntry {
  readonly kid: string;
  /** The raw key the token verified with: the entry holds only while the applied bundle carries that key. */
  readonly publicKey: string;
  readonly aud: string;
  readonly iat: number;
  readonly exp: number;
  /** The Event's attestation for this token while it is valid. One frozen object per entry. */
  readonly result: AttestationResult;
  /** What a request signature is verified against: jti, jkt and the session key (slice 04). */
  readonly binding: SessionBinding;
  /** The attested device (`sub`): what a device-keyed limit counts by (slice 08). Never recorded. */
  readonly device: string;
}

export interface AttestationStats {
  entries: number;
  max: number;
  /** Full verifications made (cache misses that reached the verifier). */
  verifications: number;
  /** Requests answered from the cache. */
  hits: number;
}

export interface AttestationChecker {
  /**
   * The attestation of one request: `header` is the value of `ar-attestation` as node:http gives it (undefined
   * when absent). Missing → missing; anything but one string of at most 2,048 characters → invalid; otherwise the
   * token's verification under `context` at `nowS`. Valid tokens are cached by the hash of the token string.
   */
  check(context: AttestationContext, header: unknown, nowS: number): AttestationResult;
  /**
   * `check`, and for a valid token also what a request signature binds to and the attested device (`sub`); both
   * null for any other result.
   */
  checkBound(
    context: AttestationContext,
    header: unknown,
    nowS: number,
  ): { result: AttestationResult; binding: SessionBinding | null; device: string | null };
  stats(): AttestationStats;
  /** The cache keys (token hashes), least recently used first. For tests. */
  keys(): string[];
  /** The cache content, for tests: no token in it. */
  inspect(): unknown[];
}

const hashOf = (token: string): string => createHash("sha256").update(token, "utf8").digest("base64url");

/**
 * The per-request attestation check with its cache: SHA-256 of the exact token string → the result of that token,
 * valid tokens only, at most `maxEntries` (least recently used out first). Nothing of a token is parsed before it
 * is looked up: a hit parses nothing, and a miss goes to the verifier, which reads no payload before the signature
 * verified. A hit requires the key and `app_id` the token verified with to be those of the applied bundle still,
 * and re-checks `iat` and `exp` against `nowS`. A token with the same jti but other bytes is a miss.
 */
export function createAttestationChecker(options: { maxEntries?: number } = {}): AttestationChecker {
  const max =
    Number.isSafeInteger(options.maxEntries) && (options.maxEntries as number) > 0
      ? (options.maxEntries as number)
      : ATTESTATION_CACHE_MAX;
  const cache = new Map<string, CacheEntry>();
  let verifications = 0;
  let hits = 0;

  function checkBound(
    context: AttestationContext,
    header: unknown,
    nowS: number,
  ): { result: AttestationResult; binding: SessionBinding | null; device: string | null } {
    if (header === undefined) return MISSING_BOUND;
    if (typeof header !== "string" || header.length === 0 || header.length > TOKEN_MAX) return INVALID_BOUND;
    const hash = hashOf(header);
    const entry = cache.get(hash);
    if (
      entry !== undefined &&
      context.attestationKeys.get(entry.kid)?.publicKey === entry.publicKey &&
      context.appId === entry.aud
    ) {
      hits += 1;
      cache.delete(hash);
      if (!(entry.iat <= nowS + SKEW_S)) return INVALID_BOUND; // a clock set back, or one that returns nonsense
      if (entry.exp <= nowS - SKEW_S) return EXPIRED_BOUND;
      cache.set(hash, entry); // most recently used last
      return entry;
    }
    // The key retired or the App changed (the entry stays for a bundle that carries them again), or never seen.
    verifications += 1;
    const verified = verifyToken(header, context, nowS);
    if (verified.status === "invalid") return INVALID_BOUND;
    if (verified.status === "expired") return EXPIRED_BOUND;
    const { claims, kid } = verified;
    const key = context.attestationKeys.get(kid) as NonNullable<ReturnType<typeof context.attestationKeys.get>>;
    const result: AttestationResult = Object.freeze({ status: "valid", verdict: claims.verdict, risk: claims.risk });
    const binding: SessionBinding = Object.freeze({
      jti: claims.jti,
      jkt: claims.cnf.jkt,
      jwk: claims.cnf.jwk === undefined ? null : Object.freeze({ ...claims.cnf.jwk }),
    });
    const fresh: CacheEntry = Object.freeze({
      kid,
      publicKey: key.publicKey,
      aud: claims.aud,
      iat: claims.iat,
      exp: claims.exp,
      result,
      binding,
      device: claims.sub,
    });
    cache.delete(hash);
    cache.set(hash, fresh);
    if (cache.size > max) {
      const oldest = cache.keys().next().value;
      if (oldest !== undefined) cache.delete(oldest);
    }
    return fresh;
  }

  return {
    check: (context, header, nowS) => checkBound(context, header, nowS).result,
    checkBound,
    stats: () => ({ entries: cache.size, max, verifications, hits }),
    keys: () => [...cache.keys()],
    inspect: () => [...cache.values()].map((entry) => ({ ...entry })),
  };
}
