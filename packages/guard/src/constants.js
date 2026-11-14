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

/**
 * The integrity collector (slice 21b). `markerKey` is Harden's `MARKER_KEY`, `filesMax` the protocol's
 * `INTEGRITY_LIMITS.filesMax`; `storageKey` names the memo in localStorage (what this device reported, by App and
 * Build, and when) and, as a `Symbol.for` key, the page-wide claims of the Builds being collected.
 */
export const INTEGRITY = Object.freeze({
  markerKey: "ar.build",
  storageKey: "ar.integrity",
  filesMax: 32,
  /** A listed path longer than this is ignored (the protocol's artifact paths are at most this long). */
  pathMax: 256,
  /** A page URL longer than this is not a candidate. */
  urlMax: 2048,
  /** At most: registry entries read, Builds planned at once, URLs read per source, memo entries kept. */
  markersMax: 64,
  buildsMax: 4,
  scanMax: 500,
  memoMax: 64,
  /** Resource Timing entries from which its buffer may be full (the default size). */
  timingFull: 250,
  /** A larger file is not hashed. */
  fileMaxBytes: 2 * 1024 * 1024,
  /** Wall time of one collection. */
  budgetMs: 5_000,
  /** From the first token to the collection. */
  delayMs: 30_000,
  /** A device reports a Build once in this time. */
  memoMs: 86_400_000,
  /** How long a collection keeps other tabs from collecting the same Build. */
  claimMs: 60_000,
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
  /** A Build id (protocol `ID_PATTERNS.bld`). */
  build: /^bld_[0-9a-f]{24}$/,
  /** A key of the integrity memo: the App id (protocol `ID_PATTERNS.app`), "/" and the Build id. */
  memoKey: /^app_[0-9a-f]{24}\/bld_[0-9a-f]{24}$/,
  /** Token id: 128 bits as 32 hex characters (protocol `ATTESTATION_PATTERNS.jti`). */
  jti: /^[0-9a-f]{32}$/,
});
