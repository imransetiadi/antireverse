import { createPublicKey, type KeyObject, randomBytes, sign, verify } from "node:crypto";
import { ATTESTATION_PATTERNS } from "./attestation.ts";
import { CONTENT_SHA256_PATTERN, canonicalSigningString, parseSignatureHeader, SIGNATURE_LIMITS } from "./signature.ts";

// Request signatures (slice 04): ECDSA P-256 with SHA-256 over the UTF-8 bytes of `canonicalSigningString`, the
// signature in the IEEE P1363 form (64 bytes r‖s, what WebCrypto produces), never DER. These are the reference
// implementations the tests of every workspace check against; Shield has its own verifier with a key cache and a
// nonce store. Never log a signature, a nonce or a body.

const P1363_BYTES = 64;

function importSessionKey(jwk: unknown): KeyObject | null {
  if (typeof jwk !== "object" || jwk === null) return null;
  const { kty, crv, x, y } = jwk as Record<string, unknown>;
  if (kty !== "EC" || crv !== "P-256") return null;
  if (typeof x !== "string" || typeof y !== "string") return null;
  if (!ATTESTATION_PATTERNS.coordinate.test(x) || !ATTESTATION_PATTERNS.coordinate.test(y)) return null;
  try {
    // Only the four public members: a point off the curve makes the import throw.
    return createPublicKey({ key: { kty, crv, x, y }, format: "jwk" });
  } catch {
    return null;
  }
}

/**
 * Verifies the `ar-signature` of one request against the session key of its (already verified) Attestation Token.
 * Never throws. Nonce and replay are the caller's: this answers `valid`, `invalid` or `stale` only.
 *
 * `invalid`: a header that `parseSignatureHeader` refuses; a content hash that is not 43 canonical base64url
 * characters; no key, or not an EC P-256 public key with canonical coordinates on the curve (a token without
 * `cnf.jwk` cannot back a signature); a value the canonical string refuses; a signature that does not verify
 * over the canonical string; a clock that is not a finite number. `stale`: a signature that verified, with
 * |t − nowS| > `SIGNATURE_LIMITS.windowS`. Staleness is decided only after the signature verified.
 */
export function verifyRequestSignature(input: {
  method: string;
  target: string;
  /** The exact `content-type` header value of the request, `""` when it has none. */
  contentType: string;
  contentSha256: string;
  header: unknown;
  jti: string;
  jwk: unknown;
  nowS: number;
}): "valid" | "invalid" | "stale" {
  const parsed = parseSignatureHeader(input?.header);
  if (parsed === null) return "invalid";
  if (typeof input.contentSha256 !== "string" || !CONTENT_SHA256_PATTERN.test(input.contentSha256)) return "invalid";
  const key = importSessionKey(input.jwk);
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
  return Math.abs(parsed.t - now) > SIGNATURE_LIMITS.windowS ? "stale" : "valid";
}

/**
 * TEST AND REFERENCE HELPER — never used by Guard (which signs in the browser with WebCrypto) or Shield. Signs a
 * request as Guard does and returns the `ar-signature` value. `t` defaults to the current second, `n` to 16 fresh
 * random bytes. Throws a TypeError for a key that is not a private EC P-256 key, or for values the canonical string
 * refuses.
 */
export function signRequestForTest(input: {
  privateKey: KeyObject;
  method: string;
  target: string;
  /** The exact `content-type` header value the request will carry, `""` for none. Required. */
  contentType: string;
  contentSha256: string;
  jti: string;
  t?: number;
  n?: string;
}): string {
  const { privateKey } = input;
  if (
    privateKey?.type !== "private" ||
    privateKey.asymmetricKeyType !== "ec" ||
    privateKey.asymmetricKeyDetails?.namedCurve !== "prime256v1"
  ) {
    throw new TypeError("A request is signed with a private EC P-256 key.");
  }
  const t = input.t ?? Math.floor(Date.now() / 1000);
  const n = input.n ?? randomBytes(16).toString("base64url");
  const canonical = canonicalSigningString({
    method: input.method,
    target: input.target,
    contentType: input.contentType,
    contentSha256: input.contentSha256,
    t,
    n,
    jti: input.jti,
  });
  const s = sign("sha256", Buffer.from(canonical, "utf8"), { key: privateKey, dsaEncoding: "ieee-p1363" });
  return `v1,t=${t},n=${n},s=${s.toString("base64url")}`;
}
