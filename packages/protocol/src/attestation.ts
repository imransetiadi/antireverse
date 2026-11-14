// Isomorphic: this module is safe for browsers. It must not import a Node built-in.
import { z } from "zod";
import { ID_PATTERNS } from "./constants.ts";
import { IntegrityReportSchema } from "./integrity.ts";
import { deepFreeze, isoDateTime } from "./shared.ts";

// The Attestation contract (slice 03). Guard asks `POST /v1/attest/challenge` for a nonce, then sends
// `POST /v1/attest` with its device id, signal ids and session key thumbprint; the API answers an Ed25519 JWT
// (`signAttestationToken` of the server entry) that Shield verifies offline (`verifyAttestationToken`) with the
// public keys of the signed Policy Bundle, and records the result on the Event. Every object schema is a plain
// `z.object`, which strips unknown keys. A verdict is evidence only: a Trusted token shows that a Guard-like
// client completed the handshake recently, not that the client is genuine.

/** The request header that carries the token: lower case, one value. */
export const ATTESTATION_HEADER = "ar-attestation";

/** The signal ids of Guard v1, in their canonical order. Ids only: no value is ever sent. */
export const ATTESTATION_SIGNALS = ["automation.webdriver", "automation.headless", "env.inconsistent"] as const;
export type AttestationSignal = (typeof ATTESTATION_SIGNALS)[number];

export const VERDICTS = ["trusted", "suspect", "hostile"] as const;
export type Verdict = (typeof VERDICTS)[number];

/** What Shield records per request: `missing` without a header, `valid`, `invalid` or `expired` otherwise. */
export const ATTESTATION_STATUSES = ["valid", "missing", "invalid", "expired"] as const;
export type AttestationStatus = (typeof ATTESTATION_STATUSES)[number];

export const ATTESTATION_LIMITS = {
  /** Seconds a token lives: `exp - iat` at most. */
  ttlS: 300,
  /** Seconds a challenge nonce lives. */
  nonceS: 60,
  /** Seconds of clock skew allowed on `iat` and `exp`. */
  skewS: 30,
  /** Characters of the `ar-attestation` header (the token) at most. */
  headerMax: 2048,
  /** Attestation public keys a bundle carries at most: previous, current, next. */
  keysMax: 3,
} as const;

/** Signal ids a request or a token lists at most. */
const SIGNALS_MAX = 16;

/**
 * Patterns of the derived values of an attestation. None is a random `<prefix>_<hex>` identifier, so none is one
 * of `ID_PATTERNS` (like `ACTOR_HASH_PATTERN` and `BEACON_TOKEN_PATTERN`).
 */
export const ATTESTATION_PATTERNS = {
  /** Key id: the first 16 hex characters of the SHA-256 of the raw public key (`attestationKid`). */
  kid: /^[0-9a-f]{16}$/,
  /** RFC 7638 thumbprint of the session key: SHA-256 as 43 base64url characters (`jwkThumbprint`). */
  jkt: /^[A-Za-z0-9_-]{43}$/,
  /** Pseudonymous device subject: `dev_` and 24 hex characters (`deviceSubject`). */
  sub: /^dev_[0-9a-f]{24}$/,
  /** Guard's device id: 128 random bits as 22 base64url characters. */
  device: /^[A-Za-z0-9_-]{22}$/,
  /** Challenge nonce: 128 random bits as 32 hex characters. */
  nonce: /^[0-9a-f]{32}$/,
  /** Token id: 128 random bits as 32 hex characters. */
  jti: /^[0-9a-f]{32}$/,
  /** Raw Ed25519 public key: 32 bytes as 43 base64url characters. */
  publicKey: /^[A-Za-z0-9_-]{43}$/,
  /** A signal id, known or not: 1..32 characters of lower-case dot-separated words. */
  signal: /^(?=.{1,32}$)[a-z][a-z0-9_]*(?:\.[a-z0-9_]+)*$/,
  /** A P-256 coordinate of `cnf.jwk`: 32 bytes as 43 canonical base64url characters (last 2 bits zero). */
  coordinate: /^[A-Za-z0-9_-]{42}[AEIMQUYcgkosw048]$/,
} as const;

const RISK_OF: Readonly<Record<AttestationSignal, number>> = {
  "automation.webdriver": 70,
  "automation.headless": 60,
  "env.inconsistent": 40,
};
const TRUSTED_RISK = 5;
const RISK_MAX = 100;

/**
 * Verdict v1: no signal → trusted, risk 5; one signal → suspect with that signal's risk (webdriver 70, headless
 * 60, inconsistent 40); two or more → hostile, risk = min(100, sum). Unknown ids are ignored; an id listed twice
 * counts once.
 */
export function verdictFor(signals: readonly string[]): { verdict: Verdict; risk: number } {
  const known = ATTESTATION_SIGNALS.filter((id) => signals.includes(id));
  if (known.length === 0) return { verdict: "trusted", risk: TRUSTED_RISK };
  const sum = known.reduce((total, id) => total + RISK_OF[id], 0);
  if (known.length === 1) return { verdict: "suspect", risk: sum };
  return { verdict: "hostile", risk: Math.min(RISK_MAX, sum) };
}

const AppIdSchema = z.string().regex(ID_PATTERNS.app);
const SignalIdSchema = z.string().regex(ATTESTATION_PATTERNS.signal);
const RiskSchema = z.int().min(0).max(RISK_MAX);
const VerdictSchema = z.enum(VERDICTS);
/**
 * The session public key (slice 04): EC P-256, the four public members only (a private `d` is stripped). Its RFC
 * 7638 thumbprint is `cnf.jkt` (`jwkThumbprint` of the server entry), which the API checks on `/v1/attest`.
 */
const SessionJwkSchema = z.object({
  kty: z.literal("EC"),
  crv: z.literal("P-256"),
  x: z.string().regex(ATTESTATION_PATTERNS.coordinate),
  y: z.string().regex(ATTESTATION_PATTERNS.coordinate),
});
/**
 * `jwk` is optional: a Guard or a token from before slice 04 has none. A token without it still verifies, but
 * cannot back a request signature (Shield records the signature `invalid`).
 */
const CnfSchema = z.object({
  jkt: z.string().regex(ATTESTATION_PATTERNS.jkt),
  jwk: SessionJwkSchema.optional(),
});
/** Seconds since the Unix epoch. */
const SecondsSchema = z.int().min(0);

/** Body of `POST /v1/attest/challenge`. */
export const ChallengeRequestSchema = z.object({ app_id: AppIdSchema });
export type ChallengeRequest = z.infer<typeof ChallengeRequestSchema>;

/** 200 of `POST /v1/attest/challenge`: a single-use nonce, valid for `ATTESTATION_LIMITS.nonceS`. */
export const ChallengeResponseSchema = z.object({
  nonce: z.string().regex(ATTESTATION_PATTERNS.nonce),
  expires_at: isoDateTime(),
});
export type ChallengeResponse = z.infer<typeof ChallengeResponseSchema>;

/**
 * Body of `POST /v1/attest`. `signals` accepts up to 16 signal-id-shaped strings, so that an older API takes a
 * newer Guard's request; parsing keeps the known ids only, each once, in the order of `ATTESTATION_SIGNALS`.
 * `integrity` (slice 21a) is the optional integrity report of the page's Build. It never fails the attestation: a
 * report that does not parse is dropped (the request parses without it), an older API strips the unknown key, and an
 * older Guard sends none. It is judged after the response and changes neither the token nor the verdict.
 */
export const AttestRequestSchema = z.object({
  app_id: AppIdSchema,
  nonce: z.string().regex(ATTESTATION_PATTERNS.nonce),
  device: z.string().regex(ATTESTATION_PATTERNS.device),
  signals: z
    .array(SignalIdSchema)
    .max(SIGNALS_MAX)
    .transform((ids): AttestationSignal[] => ATTESTATION_SIGNALS.filter((id) => ids.includes(id))),
  cnf: CnfSchema,
  integrity: IntegrityReportSchema.optional().catch(undefined),
});
export type AttestRequestInput = z.input<typeof AttestRequestSchema>;
export type AttestRequest = z.infer<typeof AttestRequestSchema>;

/** 200 of `POST /v1/attest`. */
export const AttestResponseSchema = z.object({
  token: z.string().min(1).max(ATTESTATION_LIMITS.headerMax),
  expires_at: isoDateTime(),
});
export type AttestResponse = z.infer<typeof AttestResponseSchema>;

/**
 * The claims of an Attestation Token. `sig` may hold ids this version does not know (a newer API may detect
 * more), so that a newer token stays valid at an older Shield; `verdict` and `risk` are the API's and are not
 * recomputed. The lifetime `exp - iat` is 1..`ATTESTATION_LIMITS.ttlS` seconds.
 */
export const AttestationClaimsSchema = z
  .object({
    iss: z.literal("antireverse"),
    aud: AppIdSchema,
    sub: z.string().regex(ATTESTATION_PATTERNS.sub),
    iat: SecondsSchema,
    exp: SecondsSchema,
    jti: z.string().regex(ATTESTATION_PATTERNS.jti),
    cnf: CnfSchema,
    verdict: VerdictSchema,
    risk: RiskSchema,
    sig: z
      .array(SignalIdSchema)
      .max(SIGNALS_MAX)
      .refine((ids) => new Set(ids).size === ids.length, "Must not list a signal twice."),
    pv: z.literal(1),
  })
  .refine(
    (claims) => claims.exp > claims.iat && claims.exp - claims.iat <= ATTESTATION_LIMITS.ttlS,
    `exp must be 1 to ${ATTESTATION_LIMITS.ttlS} seconds after iat.`,
  );
export type AttestationClaims = z.infer<typeof AttestationClaimsSchema>;

/**
 * The attestation of one request as an Event records it: verdict and risk when, and only when, the token was
 * valid. Never the token, never the claims beyond these.
 */
export const EventAttestationSchema = z
  .object({
    status: z.enum(ATTESTATION_STATUSES),
    verdict: VerdictSchema.nullable(),
    risk: RiskSchema.nullable(),
  })
  .refine(
    ({ status, verdict, risk }) =>
      (status === "valid") === (verdict !== null) && (verdict !== null) === (risk !== null),
    "verdict and risk are set exactly when status is valid.",
  );
export type EventAttestation = z.infer<typeof EventAttestationSchema>;

/** One attestation public key as a Policy Bundle carries it. */
export const BundleAttestationKeySchema = z.object({
  kid: z.string().regex(ATTESTATION_PATTERNS.kid),
  /** The raw Ed25519 public key: 32 bytes as 43 base64url characters. */
  public_key: z.string().regex(ATTESTATION_PATTERNS.publicKey),
});
export type BundleAttestationKey = z.infer<typeof BundleAttestationKeySchema>;

// Documented example, reused by the tests of every workspace. Synthetic and deeply frozen.

/**
 * Claims of a Suspect token for the App of `EXAMPLE_STORED_EVENT`, issued 2026-11-10T08:15:30Z. `sub` is
 * `deviceSubject` of that App and the device id `AAECAwQFBgcICQoLDA0ODw` (bytes 0..15); `cnf.jkt` is the RFC 7638
 * thumbprint of the EC key of RFC 7517 appendix A.1.
 */
export const EXAMPLE_ATTESTATION_CLAIMS: AttestationClaims = deepFreeze({
  iss: "antireverse",
  aud: "app_89abcdef0123456789abcdef",
  sub: "dev_06c43c0cbc18cb7048ab26a1",
  iat: 1_794_298_530,
  exp: 1_794_298_830,
  jti: "0123456789abcdef0123456789abcdef",
  cnf: { jkt: "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s" },
  verdict: "suspect",
  risk: 70,
  sig: ["automation.webdriver"],
  pv: 1,
});
