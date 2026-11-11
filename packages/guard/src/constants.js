// Mirrors of @antireverse/protocol (attestation.ts, signature.ts), pinned by test/package.test.ts. Guard must not import the
// protocol at runtime: it would pull zod into the page.

/** The request header that carries the token. */
export const ATTESTATION_HEADER = "ar-attestation";

/** The request header that carries the request signature (protocol `SIGNATURE_HEADER`). */
export const SIGNATURE_HEADER = "ar-signature";

/** The request header that carries the SHA-256 of the body bytes (protocol `CONTENT_HASH_HEADER`). */
export const CONTENT_HASH_HEADER = "ar-content-sha256";

/** SHA-256 of the empty string as base64url: the content hash of a request without a body. */
export const EMPTY_CONTENT_SHA256 = "47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU";

/** The signal ids of Guard v1, in their canonical order. */
export const ATTESTATION_SIGNALS =
  /** @type {readonly ["automation.webdriver", "automation.headless", "env.inconsistent"]} */ (
    Object.freeze(["automation.webdriver", "automation.headless", "env.inconsistent"])
  );

export const GUARD_LIMITS = Object.freeze({
  /** Seconds a token lives at most (protocol `ATTESTATION_LIMITS.ttlS`). */
  ttlS: 300,
  /** Characters of a token at most (protocol `ATTESTATION_LIMITS.headerMax`). */
  headerMax: 2048,
  /** Re-attest this long before the token expires. */
  reattestLeadMs: 60_000,
  /** Never re-attest sooner than this after a token arrived (guards against a skewed client clock). */
  reattestMinMs: 30_000,
  /** A request (challenge or attest, body included) that has not answered by then fails. */
  requestTimeoutMs: 10_000,
  /** requestIdleCallback timeout of start(). */
  idleTimeoutMs: 2_000,
});

/** localStorage key of the device id. */
export const DEVICE_STORAGE_KEY = "ar.device";

export const PATTERNS = Object.freeze({
  /** 128 random bits as 22 base64url characters (protocol `ATTESTATION_PATTERNS.device`). */
  device: /^[A-Za-z0-9_-]{22}$/,
  /** Challenge nonce (protocol `ATTESTATION_PATTERNS.nonce`). */
  nonce: /^[0-9a-f]{32}$/,
  /** A compact JWS: three base64url parts. */
  token: /^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/,
  /** A P-256 coordinate: 32 bytes as 43 canonical base64url characters (protocol `ATTESTATION_PATTERNS.coordinate`). */
  coordinate: /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/,
  /** Token id: 128 bits as 32 hex characters (protocol `ATTESTATION_PATTERNS.jti`). */
  jti: /^[0-9a-f]{32}$/,
});
