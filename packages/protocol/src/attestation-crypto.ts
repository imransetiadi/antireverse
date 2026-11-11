import { createHash, createPublicKey, type KeyObject, sign, verify } from "node:crypto";
import {
  ATTESTATION_LIMITS,
  ATTESTATION_PATTERNS,
  type AttestationClaims,
  AttestationClaimsSchema,
  type BundleAttestationKey,
} from "./attestation.ts";

// Attestation Tokens (slice 03): compact JWS, header `{"alg":"EdDSA","typ":"JWT","kid":<16 hex>}`, the claims as
// JSON, Ed25519 over the ASCII bytes of `<header>.<payload>` exactly as transmitted. Only EdDSA is accepted, and
// only with a key the caller passes (the applied bundle's set). Never log a token.

const ED25519_PUBLIC_KEY_BYTES = 32;
const HEADER_ALG = "EdDSA";
const HEADER_TYP = "JWT";
/** A JWS part: base64url without padding. A part of length 4n+1 is never valid base64url. */
const PART = /^[A-Za-z0-9_-]*$/;
/** An Ed25519 signature: 64 bytes as 86 base64url characters. */
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;

/**
 * The key id of an attestation key: the first 16 hex characters of the SHA-256 of the raw 32-byte Ed25519 public
 * key. An encoded key (SPKI, PEM, base64url text) is refused.
 */
export function attestationKid(publicKeyRaw: Uint8Array): string {
  if (!(publicKeyRaw instanceof Uint8Array) || publicKeyRaw.byteLength !== ED25519_PUBLIC_KEY_BYTES) {
    throw new TypeError("An Ed25519 public key is 32 raw bytes.");
  }
  return createHash("sha256").update(publicKeyRaw).digest("hex").slice(0, 16);
}

/**
 * The RFC 7638 thumbprint of an EC P-256 public key: SHA-256 over `{"crv":"P-256","kty":"EC","x":…,"y":…}` (the
 * required members in lexicographic order, no white space), as 43 base64url characters. Other members are ignored.
 */
export function jwkThumbprint(jwk: { kty: "EC"; crv: "P-256"; x: string; y: string }): string {
  if (typeof jwk !== "object" || jwk === null || jwk.kty !== "EC" || jwk.crv !== "P-256") {
    throw new TypeError("Only EC P-256 public keys have a thumbprint here.");
  }
  if (
    typeof jwk.x !== "string" ||
    typeof jwk.y !== "string" ||
    !ATTESTATION_PATTERNS.coordinate.test(jwk.x) ||
    !ATTESTATION_PATTERNS.coordinate.test(jwk.y)
  ) {
    // The pattern of `cnf.jwk`: canonical base64url only, so that one key has exactly one thumbprint.
    throw new TypeError("A P-256 coordinate is 32 bytes as 43 canonical base64url characters.");
  }
  const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
  return createHash("sha256").update(canonical, "utf8").digest("base64url");
}

/**
 * The pseudonymous subject of a device for one App: `dev_` and the first 24 hex characters of
 * SHA-256(`<app id>:<device id>`). The same device has unrelated subjects in different Apps.
 */
export function deviceSubject(appId: string, deviceId: string): string {
  if (typeof appId !== "string" || appId.length === 0 || typeof deviceId !== "string" || deviceId.length === 0) {
    throw new TypeError("An App id and a device id are non-empty strings.");
  }
  return `dev_${createHash("sha256").update(`${appId}:${deviceId}`, "utf8").digest("hex").slice(0, 24)}`;
}

const encode = (value: unknown): string => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");

/**
 * Signs claims as an Attestation Token with an Ed25519 private key. The claims are validated first (and written
 * in schema order, unknown members dropped). Throws a TypeError for invalid claims, a malformed kid, a key that is
 * not a private Ed25519 key, or a token longer than `ATTESTATION_LIMITS.headerMax`.
 */
export function signAttestationToken(privateKey: KeyObject, kid: string, claims: AttestationClaims): string {
  if (typeof kid !== "string" || !ATTESTATION_PATTERNS.kid.test(kid)) {
    throw new TypeError("A kid is 16 lower-case hex characters.");
  }
  if (privateKey?.type !== "private" || privateKey.asymmetricKeyType !== "ed25519") {
    throw new TypeError("An Attestation Token is signed with a private Ed25519 key.");
  }
  const parsed = AttestationClaimsSchema.safeParse(claims);
  if (!parsed.success) throw new TypeError("The claims are not valid Attestation Token claims.");
  const signingInput = `${encode({ alg: HEADER_ALG, typ: HEADER_TYP, kid })}.${encode(parsed.data)}`;
  const token = `${signingInput}.${sign(null, Buffer.from(signingInput, "ascii"), privateKey).toString("base64url")}`;
  if (token.length > ATTESTATION_LIMITS.headerMax) {
    throw new TypeError(`An Attestation Token is at most ${ATTESTATION_LIMITS.headerMax} characters.`);
  }
  return token;
}

export type AttestationVerification =
  | { status: "valid"; claims: AttestationClaims }
  | { status: "invalid" }
  | { status: "expired" };

const INVALID: AttestationVerification = Object.freeze({ status: "invalid" });
const EXPIRED: AttestationVerification = Object.freeze({ status: "expired" });

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

function importKey(publicKey: unknown): KeyObject | null {
  if (typeof publicKey !== "string" || !ATTESTATION_PATTERNS.publicKey.test(publicKey)) return null;
  try {
    return createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: publicKey }, format: "jwk" });
  } catch {
    return null;
  }
}

/**
 * Verifies an Attestation Token offline with a key set (the applied bundle's `attestation_keys`). Never throws.
 *
 * `invalid`: not a string of at most 2048 characters; not three canonical base64url parts; header not
 * `alg: "EdDSA"`, `typ: "JWT"` and a kid of the set, or with `crit`; signature not Ed25519 over the received
 * `header.payload`; claims breaking `AttestationClaimsSchema` (lifetime 1..300 s included); `iss` not
 * `antireverse`; `aud` not `appId`; `iat` more than 30 s after `nowS`. `expired`: a token that passed all of
 * that whose `exp` is 30 s or more before `nowS`. Claims are returned for a valid token only.
 */
export function verifyAttestationToken(
  token: string,
  keys: readonly BundleAttestationKey[],
  opts: { appId: string; nowS: number },
): AttestationVerification {
  if (typeof token !== "string" || token.length > ATTESTATION_LIMITS.headerMax) return INVALID;
  const parts = token.split(".");
  if (parts.length !== 3) return INVALID;
  const [headerPart, payloadPart, signaturePart] = parts as [string, string, string];

  const header = decodeObject(headerPart);
  if (header === null) return INVALID;
  if (header.alg !== HEADER_ALG || header.typ !== HEADER_TYP || "crit" in header) return INVALID;
  const kid = header.kid;
  if (typeof kid !== "string" || !ATTESTATION_PATTERNS.kid.test(kid)) return INVALID;
  const entry = Array.isArray(keys) ? keys.find((candidate) => candidate?.kid === kid) : undefined;
  const publicKey = importKey(entry?.public_key);
  if (publicKey === null) return INVALID;

  // The signature covers the bytes as received. Nothing of the payload is read before it verified.
  if (!SIGNATURE.test(signaturePart)) return INVALID;
  const signature = Buffer.from(signaturePart, "base64url");
  // One spelling per signature: unused trailing bits must be zero.
  if (signature.toString("base64url") !== signaturePart) return INVALID;
  let genuine = false;
  try {
    genuine = verify(null, Buffer.from(`${headerPart}.${payloadPart}`, "ascii"), publicKey, signature);
  } catch {
    genuine = false;
  }
  if (!genuine) return INVALID;

  const payload = decodeObject(payloadPart);
  if (payload === null) return INVALID;
  const parsed = AttestationClaimsSchema.safeParse(payload);
  if (!parsed.success) return INVALID;
  const claims = parsed.data;
  if (claims.aud !== opts.appId) return INVALID;
  const now = opts.nowS;
  if (typeof now !== "number" || !Number.isFinite(now)) return INVALID;
  if (claims.iat > now + ATTESTATION_LIMITS.skewS) return INVALID;
  if (claims.exp <= now - ATTESTATION_LIMITS.skewS) return EXPIRED;
  return { status: "valid", claims };
}
