// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";

// The request-signature contract (slice 04). Guard signs each request with its non-extractable P-256 session key
// (the key whose public half the Attestation Token carries in `cnf.jwk`) over `canonicalSigningString`, and sends
// `ar-signature` and `ar-content-sha256` beside `ar-attestation`. Shield verifies offline, in this order: header
// parse → token valid with a jwk → signature → timestamp → nonce; a nonce is remembered only after a valid
// signature. The server entry has a reference verifier (`verifyRequestSignature`). Never log a signature or a body.

/** The request header that carries the signature: lower case, one value. */
export const SIGNATURE_HEADER = "ar-signature";

/** The request header that carries the SHA-256 of the exact body bytes (of the empty string without a body). */
export const CONTENT_HASH_HEADER = "ar-content-sha256";

export const SIGNATURE_LIMITS = {
  /** Seconds `t` may differ from Shield's clock, either way, before a signed request is stale. */
  windowS: 60,
  /**
   * A nonce (per token id) is remembered on one Shield instance until `t + nonceKeepS` seconds of absolute time:
   * exactly as long as its signature is not stale (review F5). Never a fixed time from first sight.
   */
  nonceKeepS: 61,
  /** Nonces one Shield instance remembers at most. A store full of live entries evicts none. */
  nonceStoreMax: 100_000,
} as const;

/**
 * What Shield records per request: `missing` without `ar-signature`; `invalid` for malformed headers, no valid
 * token, a token without `cnf.jwk`, a bad signature or a body mismatch; `stale` when |t − now| > 60 s after the
 * signature verified; `replayed` when the pair (token jti, n) was seen before on this instance while its signature is
 * not yet stale (it is remembered until t + 61 s); `valid`.
 */
export const SIGNATURE_STATUSES = ["valid", "missing", "invalid", "stale", "replayed"] as const;
export type SignatureStatus = (typeof SIGNATURE_STATUSES)[number];

/**
 * Whether the body was bound: `checked` (the parser hook saw bytes with the signed hash), `unchecked` (a body
 * exists but no hook ran), `mismatch` (the hook saw other bytes and refused the request) or `none` (no body).
 */
export const BODY_STATES = ["checked", "unchecked", "mismatch", "none"] as const;
export type BodyState = (typeof BODY_STATES)[number];

/** `ar-content-sha256` of a request without a body: the SHA-256 of the empty string as base64url. */
export const EMPTY_CONTENT_SHA256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

/**
 * A SHA-256 as canonical base64url: 43 characters, the last one with its 2 unused low bits zero, so that every
 * hash has exactly one spelling.
 */
export const CONTENT_SHA256_PATTERN = /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/;

/**
 * `v1,t=<unix seconds>,n=<nonce>,s=<signature>`, nothing else: `t` 1..10 digits without a leading zero; `n` 128
 * bits as 22 canonical base64url characters; `s` the 64-byte IEEE P1363 `r‖s` as 86 canonical base64url
 * characters (in both, the 4 unused low bits of the last character are zero).
 */
const SIGNATURE_HEADER_FORM = /^v1,t=(0|[1-9][0-9]{0,9}),n=([A-Za-z0-9_-]{21}[AQgw]),s=([A-Za-z0-9_-]{85}[AQgw])$/;

/**
 * The members of an `ar-signature` value, or null for anything but the exact form: the version `v1`, then `t`,
 * `n` and `s` once each in that order, separated by commas, without white space. Never throws.
 */
export function parseSignatureHeader(value: unknown): { t: number; n: string; s: string } | null {
  if (typeof value !== "string") return null;
  const match = SIGNATURE_HEADER_FORM.exec(value);
  if (match === null) return null;
  return { t: Number(match[1]), n: match[2] as string, s: match[3] as string };
}

/**
 * The string Guard signs and Shield verifies, as UTF-8: `ar-sig-v1`, the method in upper case, the request target
 * exactly as sent on the wire (path and query, Express `req.originalUrl`), the exact `content-type` header value
 * sent (the empty string when none was sent; review F1), the content hash, `t`, `n` and the token's `jti`, each on
 * its own line, without a final line feed. Only the method is changed; the other values are taken as given. Throws
 * a TypeError for a value that is not a string (`contentType` included: it is required, never defaulted), a `t`
 * that is not a non-negative integer, or a line feed in any value (it would let one field run into the next).
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

/**
 * The signature of one request as an Event records it. Never the header, the nonce or the hash. `body` is null
 * exactly when the status is `missing` (no signature, nothing to bind the body to); every other status carries a
 * body state, and a `mismatch` comes only with status `invalid`, as the plan makes a refused body an invalid
 * signature.
 */
export const EventSignatureSchema = z
  .object({
    status: z.enum(SIGNATURE_STATUSES),
    body: z.enum(BODY_STATES).nullable(),
  })
  .refine(
    ({ status, body }) => (status === "missing") === (body === null),
    "body is null exactly when status is missing.",
  )
  .refine(
    ({ status, body }) => body !== "mismatch" || status === "invalid",
    "A body mismatch is recorded with status invalid.",
  );
export type EventSignature = z.infer<typeof EventSignatureSchema>;
