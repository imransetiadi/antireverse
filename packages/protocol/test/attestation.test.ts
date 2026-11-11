import { describe, expect, it } from "vitest";
import {
  ATTESTATION_HEADER,
  ATTESTATION_LIMITS,
  ATTESTATION_PATTERNS,
  ATTESTATION_SIGNALS,
  ATTESTATION_STATUSES,
  type AttestationClaims,
  AttestationClaimsSchema,
  type AttestRequest,
  AttestRequestSchema,
  AttestResponseSchema,
  BundleAttestationKeySchema,
  ChallengeRequestSchema,
  ChallengeResponseSchema,
  type EventAttestation,
  EventAttestationSchema,
  EXAMPLE_ATTESTATION_CLAIMS,
  VERDICTS,
  verdictFor,
} from "../src/index.ts";

const APP = "app_89abcdef0123456789abcdef";
const NONCE = "0123456789abcdef0123456789abcdef";
const DEVICE = "AAECAwQFBgcICQoLDA0ODw";
const JKT = "cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s";
const request = (patch: Record<string, unknown> = {}) => ({
  app_id: APP,
  nonce: NONCE,
  device: DEVICE,
  signals: [],
  cnf: { jkt: JKT },
  ...patch,
});
const claims = (patch: Record<string, unknown> = {}) => ({ ...EXAMPLE_ATTESTATION_CLAIMS, ...patch });
const acceptsClaims = (patch: Record<string, unknown>): boolean =>
  AttestationClaimsSchema.safeParse(claims(patch)).success;

describe("constants (contract P1)", () => {
  it("has the signals, verdicts, statuses and limits of the plan", () => {
    expect(ATTESTATION_SIGNALS).toEqual(["automation.webdriver", "automation.headless", "env.inconsistent"]);
    expect(VERDICTS).toEqual(["trusted", "suspect", "hostile"]);
    expect(ATTESTATION_STATUSES).toEqual(["valid", "missing", "invalid", "expired"]);
    expect(ATTESTATION_LIMITS).toEqual({ ttlS: 300, nonceS: 60, skewS: 30, headerMax: 2048, keysMax: 3 });
    expect(ATTESTATION_HEADER).toBe("ar-attestation");
  });

  it("has the derived-value patterns (not ID_PATTERNS: none of them is a random id with a prefix)", () => {
    const { kid, jkt, sub, device, nonce, jti, publicKey, signal } = ATTESTATION_PATTERNS;
    expect(kid.test("0123456789abcdef")).toBe(true);
    expect(kid.test("0123456789ABCDEF")).toBe(false);
    expect(kid.test("0123456789abcde")).toBe(false);
    expect(jkt.test(JKT)).toBe(true);
    expect(jkt.test(`${JKT}A`)).toBe(false);
    expect(jkt.test(JKT.replace("-", "+"))).toBe(false);
    expect(sub.test("dev_06c43c0cbc18cb7048ab26a1")).toBe(true);
    expect(sub.test("dev_06c43c0cbc18cb7048ab26a")).toBe(false);
    expect(sub.test("dvc_06c43c0cbc18cb7048ab26a1")).toBe(false);
    expect(device.test(DEVICE)).toBe(true);
    expect(device.test(`${DEVICE}A`)).toBe(false);
    expect(device.test(DEVICE.replace("A", "="))).toBe(false);
    expect(nonce.test(NONCE)).toBe(true);
    expect(nonce.test(NONCE.toUpperCase())).toBe(false);
    expect(jti.test(NONCE)).toBe(true);
    expect(jti.test(`${NONCE}0`)).toBe(false);
    expect(publicKey.test("A".repeat(43))).toBe(true);
    expect(publicKey.test("A".repeat(44))).toBe(false);
    for (const id of ATTESTATION_SIGNALS) expect(signal.test(id)).toBe(true);
    expect(signal.test("future.signal_2")).toBe(true);
    expect(signal.test("Automation.webdriver")).toBe(false);
    expect(signal.test("a".repeat(33))).toBe(false);
    expect(signal.test("")).toBe(false);
  });
});

describe("verdictFor (Verdict v1 table)", () => {
  it("is trusted with risk 5 without signals", () => {
    expect(verdictFor([])).toEqual({ verdict: "trusted", risk: 5 });
  });

  it("is suspect for exactly one signal, with that signal's risk", () => {
    expect(verdictFor(["automation.webdriver"])).toEqual({ verdict: "suspect", risk: 70 });
    expect(verdictFor(["automation.headless"])).toEqual({ verdict: "suspect", risk: 60 });
    expect(verdictFor(["env.inconsistent"])).toEqual({ verdict: "suspect", risk: 40 });
  });

  it("is hostile for two or more signals, risk = min(100, sum)", () => {
    expect(verdictFor(["automation.headless", "env.inconsistent"])).toEqual({ verdict: "hostile", risk: 100 });
    expect(verdictFor(["automation.webdriver", "env.inconsistent"])).toEqual({ verdict: "hostile", risk: 100 });
    expect(verdictFor(["automation.webdriver", "automation.headless"])).toEqual({ verdict: "hostile", risk: 100 });
    expect(verdictFor([...ATTESTATION_SIGNALS])).toEqual({ verdict: "hostile", risk: 100 });
  });

  it("ignores unknown ids and counts duplicates once", () => {
    expect(verdictFor(["future.signal", "toString", "__proto__", "constructor"])).toEqual({
      verdict: "trusted",
      risk: 5,
    });
    expect(verdictFor(["automation.headless", "future.signal"])).toEqual({ verdict: "suspect", risk: 60 });
    expect(verdictFor(["env.inconsistent", "env.inconsistent", "env.inconsistent"])).toEqual({
      verdict: "suspect",
      risk: 40,
    });
  });
});

describe("ChallengeRequestSchema and ChallengeResponseSchema", () => {
  it("takes an App id and strips anything else", () => {
    expect(ChallengeRequestSchema.parse({ app_id: APP, extra: 1 })).toEqual({ app_id: APP });
    expect(ChallengeRequestSchema.safeParse({ app_id: "org_89abcdef0123456789abcdef" }).success).toBe(false);
    expect(ChallengeRequestSchema.safeParse({}).success).toBe(false);
  });

  it("answers a 32-hex nonce and its expiry", () => {
    const response = { nonce: NONCE, expires_at: "2026-11-10T08:16:30.000Z" };
    expect(ChallengeResponseSchema.parse(response)).toEqual(response);
    expect(ChallengeResponseSchema.safeParse({ ...response, nonce: NONCE.slice(1) }).success).toBe(false);
    expect(ChallengeResponseSchema.safeParse({ ...response, nonce: NONCE.toUpperCase() }).success).toBe(false);
    expect(ChallengeResponseSchema.safeParse({ ...response, expires_at: 1794298590 }).success).toBe(false);
  });
});

describe("AttestRequestSchema", () => {
  const accepts = (patch: Record<string, unknown>): boolean => AttestRequestSchema.safeParse(request(patch)).success;

  it("parses a well-formed request and strips unknown keys", () => {
    const parsed: AttestRequest = AttestRequestSchema.parse({ ...request(), user_agent: "synthetic" });
    expect(parsed).toEqual(request());
  });

  it("requires the App id, a 32-hex nonce, a 128-bit base64url device id and a 43-char thumbprint", () => {
    expect(accepts({ app_id: "app_x" })).toBe(false);
    expect(accepts({ nonce: "0".repeat(31) })).toBe(false);
    expect(accepts({ device: DEVICE.slice(1) })).toBe(false);
    expect(accepts({ device: `${DEVICE}==` })).toBe(false);
    expect(accepts({ device: DEVICE.replace("A", "/") })).toBe(false);
    expect(accepts({ cnf: { jkt: JKT.slice(1) } })).toBe(false);
    expect(accepts({ cnf: {} })).toBe(false);
    expect(accepts({ cnf: undefined })).toBe(false);
    for (const key of ["app_id", "nonce", "device", "signals"]) expect(accepts({ [key]: undefined }), key).toBe(false);
  });

  it("keeps the known signal ids only, each once, in the order of ATTESTATION_SIGNALS", () => {
    const parsed = AttestRequestSchema.parse(
      request({ signals: ["env.inconsistent", "future.signal", "automation.webdriver", "env.inconsistent"] }),
    );
    expect(parsed.signals).toEqual(["automation.webdriver", "env.inconsistent"]);
    expect(AttestRequestSchema.parse(request({ signals: ["future.signal"] })).signals).toEqual([]);
  });

  it("bounds the list: at most 16 entries, each a signal-id shape of at most 32 characters", () => {
    const many = (count: number) => Array.from({ length: count }, (_, n) => `future.s${n}`);
    expect(accepts({ signals: many(16) })).toBe(true);
    expect(accepts({ signals: many(17) })).toBe(false);
    expect(accepts({ signals: ["a".repeat(33)] })).toBe(false);
    expect(accepts({ signals: ["Has Space"] })).toBe(false);
    expect(accepts({ signals: [7] })).toBe(false);
    expect(accepts({ signals: "automation.webdriver" })).toBe(false);
  });
});

describe("AttestResponseSchema", () => {
  it("carries a token of at most the header limit and its expiry", () => {
    const response = { token: "a.b.c", expires_at: "2026-11-10T08:20:30.000Z" };
    expect(AttestResponseSchema.parse(response)).toEqual(response);
    expect(AttestResponseSchema.safeParse({ ...response, token: "a".repeat(2049) }).success).toBe(false);
    expect(AttestResponseSchema.safeParse({ ...response, token: "" }).success).toBe(false);
  });
});

describe("AttestationClaimsSchema", () => {
  it("parses the documented example unchanged", () => {
    const parsed: AttestationClaims = AttestationClaimsSchema.parse(EXAMPLE_ATTESTATION_CLAIMS);
    expect(parsed).toEqual(EXAMPLE_ATTESTATION_CLAIMS);
    expect(Object.keys(parsed)).toEqual([
      "iss",
      "aud",
      "sub",
      "iat",
      "exp",
      "jti",
      "cnf",
      "verdict",
      "risk",
      "sig",
      "pv",
    ]);
  });

  it("fixes iss, pv and the shapes of aud, sub, jti and cnf", () => {
    expect(acceptsClaims({ iss: "someone" })).toBe(false);
    expect(acceptsClaims({ pv: 2 })).toBe(false);
    expect(acceptsClaims({ aud: "org_89abcdef0123456789abcdef" })).toBe(false);
    expect(acceptsClaims({ aud: [APP] })).toBe(false);
    expect(acceptsClaims({ sub: DEVICE })).toBe(false);
    expect(acceptsClaims({ jti: "x" })).toBe(false);
    expect(acceptsClaims({ cnf: { jkt: "x" } })).toBe(false);
  });

  it("takes integer times with 0 < exp − iat ≤ 300", () => {
    const iat = EXAMPLE_ATTESTATION_CLAIMS.iat;
    expect(acceptsClaims({ exp: iat + 300 })).toBe(true);
    expect(acceptsClaims({ exp: iat + 1 })).toBe(true);
    expect(acceptsClaims({ exp: iat + 301 })).toBe(false);
    expect(acceptsClaims({ exp: iat })).toBe(false);
    expect(acceptsClaims({ exp: iat - 1 })).toBe(false);
    expect(acceptsClaims({ iat: iat + 0.5 })).toBe(false);
    expect(acceptsClaims({ iat: -1, exp: 10 })).toBe(false);
    expect(acceptsClaims({ iat: String(iat) })).toBe(false);
  });

  it("takes a known verdict and an integer risk of 0..100", () => {
    expect(acceptsClaims({ verdict: "hostile", risk: 100 })).toBe(true);
    expect(acceptsClaims({ verdict: "trusted", risk: 0 })).toBe(true);
    expect(acceptsClaims({ verdict: "genuine" })).toBe(false);
    expect(acceptsClaims({ risk: 101 })).toBe(false);
    expect(acceptsClaims({ risk: -1 })).toBe(false);
    expect(acceptsClaims({ risk: 50.5 })).toBe(false);
  });

  it("takes up to 16 unique signal ids, unknown ones included (a newer API may know more)", () => {
    expect(acceptsClaims({ sig: [] })).toBe(true);
    expect(acceptsClaims({ sig: ["future.signal"] })).toBe(true);
    expect(acceptsClaims({ sig: Array.from({ length: 16 }, (_, n) => `s${n}`) })).toBe(true);
    expect(acceptsClaims({ sig: Array.from({ length: 17 }, (_, n) => `s${n}`) })).toBe(false);
    expect(acceptsClaims({ sig: ["env.inconsistent", "env.inconsistent"] })).toBe(false);
    expect(acceptsClaims({ sig: ["NOT AN ID"] })).toBe(false);
  });

  it("strips unknown claims", () => {
    expect(AttestationClaimsSchema.parse(claims({ nbf: 1, email: "synthetic" }))).toEqual(EXAMPLE_ATTESTATION_CLAIMS);
  });

  it("is deeply frozen as an example", () => {
    expect(Object.isFrozen(EXAMPLE_ATTESTATION_CLAIMS)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_ATTESTATION_CLAIMS.cnf)).toBe(true);
    expect(Object.isFrozen(EXAMPLE_ATTESTATION_CLAIMS.sig)).toBe(true);
  });
});

describe("EventAttestationSchema", () => {
  const accepts = (value: unknown): boolean => EventAttestationSchema.safeParse(value).success;

  it("carries verdict and risk exactly when the status is valid", () => {
    const valid: EventAttestation = { status: "valid", verdict: "suspect", risk: 70 };
    expect(EventAttestationSchema.parse(valid)).toEqual(valid);
    for (const status of ["missing", "invalid", "expired"]) {
      expect(accepts({ status, verdict: null, risk: null }), status).toBe(true);
      expect(accepts({ status, verdict: "trusted", risk: 5 }), status).toBe(false);
      expect(accepts({ status, verdict: "trusted", risk: null }), status).toBe(false);
      expect(accepts({ status, verdict: null, risk: 5 }), status).toBe(false);
    }
    expect(accepts({ status: "valid", verdict: null, risk: null })).toBe(false);
    expect(accepts({ status: "valid", verdict: "trusted", risk: null })).toBe(false);
    expect(accepts({ status: "valid", verdict: null, risk: 5 })).toBe(false);
  });

  it("rejects unknown statuses and verdicts, and out-of-range risks", () => {
    expect(accepts({ status: "forged", verdict: null, risk: null })).toBe(false);
    expect(accepts({ status: "valid", verdict: "genuine", risk: 5 })).toBe(false);
    expect(accepts({ status: "valid", verdict: "trusted", risk: 101 })).toBe(false);
    expect(accepts({ status: "valid", verdict: "trusted", risk: 1.5 })).toBe(false);
  });

  it("strips unknown keys (privacy allowlist: never the token)", () => {
    expect(EventAttestationSchema.parse({ status: "missing", verdict: null, risk: null, token: "a.b.c" })).toEqual({
      status: "missing",
      verdict: null,
      risk: null,
    });
  });
});

describe("BundleAttestationKeySchema", () => {
  const key = { kid: "21fe31dfa154a261", public_key: "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo" };
  it("takes a 16-hex kid and a 43-char base64url raw Ed25519 public key", () => {
    expect(BundleAttestationKeySchema.parse({ ...key, private_key: "x" })).toEqual(key);
    expect(BundleAttestationKeySchema.safeParse({ ...key, kid: "21FE31DFA154A261" }).success).toBe(false);
    expect(BundleAttestationKeySchema.safeParse({ ...key, kid: key.kid.slice(1) }).success).toBe(false);
    expect(BundleAttestationKeySchema.safeParse({ ...key, public_key: `${key.public_key}=` }).success).toBe(false);
    expect(BundleAttestationKeySchema.safeParse({ ...key, public_key: undefined }).success).toBe(false);
  });
});

describe("cnf.jwk: the session public key (slice 04)", () => {
  // The EC P-256 key of RFC 7517 appendix A.1: its RFC 7638 thumbprint is JKT.
  const JWK = {
    kty: "EC",
    crv: "P-256",
    x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
  } as const;
  const acceptsRequest = (cnf: unknown): boolean => AttestRequestSchema.safeParse(request({ cnf })).success;
  const acceptsCnf = (cnf: unknown): boolean => acceptsClaims({ cnf });

  it("round-trips a request and claims with cnf.jwk through JSON", () => {
    const withKey: AttestRequest = { ...request(), cnf: { jkt: JKT, jwk: JWK } } as AttestRequest;
    expect(AttestRequestSchema.parse(JSON.parse(JSON.stringify(withKey)))).toEqual(withKey);
    const claimsWithKey: AttestationClaims = { ...EXAMPLE_ATTESTATION_CLAIMS, cnf: { jkt: JKT, jwk: JWK } };
    expect(AttestationClaimsSchema.parse(JSON.parse(JSON.stringify(claimsWithKey)))).toEqual(claimsWithKey);
  });

  it("keeps cnf.jwk optional: absent stays absent (older Guards and tokens)", () => {
    expect(AttestRequestSchema.parse(request()).cnf).toEqual({ jkt: JKT });
    expect(AttestRequestSchema.parse(request()).cnf).not.toHaveProperty("jwk");
    expect(AttestationClaimsSchema.parse(EXAMPLE_ATTESTATION_CLAIMS).cnf).not.toHaveProperty("jwk");
  });

  it("takes an EC P-256 public key only: kty, crv and two 43-character canonical base64url coordinates", () => {
    for (const accepts of [acceptsRequest, acceptsCnf]) {
      expect(accepts({ jkt: JKT, jwk: JWK })).toBe(true);
      expect(accepts({ jkt: JKT, jwk: { ...JWK, kty: "OKP" } })).toBe(false);
      expect(accepts({ jkt: JKT, jwk: { ...JWK, crv: "P-384" } })).toBe(false);
      expect(accepts({ jkt: JKT, jwk: { ...JWK, x: JWK.x.slice(1) } })).toBe(false);
      expect(accepts({ jkt: JKT, jwk: { ...JWK, y: `${JWK.y}A` } })).toBe(false);
      expect(accepts({ jkt: JKT, jwk: { ...JWK, x: `/${JWK.x.slice(1)}` } })).toBe(false);
      expect(accepts({ jkt: JKT, jwk: { ...JWK, y: `${JWK.y.slice(0, 42)}N` } })).toBe(false);
      expect(accepts({ jkt: JKT, jwk: { ...JWK, x: undefined } })).toBe(false);
      expect(accepts({ jkt: JKT, jwk: null })).toBe(false);
      expect(accepts({ jkt: JKT, jwk: "key" })).toBe(false);
      expect(accepts({ jwk: JWK })).toBe(false);
    }
  });

  it("strips every other member of the key: a private `d` never passes", () => {
    const leaky = { ...JWK, d: "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE", kid: "1", use: "sig" };
    expect(AttestRequestSchema.parse(request({ cnf: { jkt: JKT, jwk: leaky } })).cnf).toEqual({ jkt: JKT, jwk: JWK });
    expect(AttestationClaimsSchema.parse(claims({ cnf: { jkt: JKT, jwk: leaky } })).cnf).toEqual({
      jkt: JKT,
      jwk: JWK,
    });
  });

  it("has a coordinate pattern: 43 base64url characters whose last 2 bits are zero", () => {
    const { coordinate } = ATTESTATION_PATTERNS;
    expect(coordinate.test(JWK.x)).toBe(true);
    expect(coordinate.test(JWK.y)).toBe(true);
    expect(coordinate.test(`${"A".repeat(42)}B`)).toBe(false);
    expect(coordinate.test("A".repeat(44))).toBe(false);
  });
});
