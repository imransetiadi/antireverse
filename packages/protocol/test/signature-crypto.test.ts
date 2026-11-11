import { createHash, createPrivateKey, createPublicKey, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
import { canonicalSigningString, EMPTY_CONTENT_SHA256, parseSignatureHeader, SIGNATURE_LIMITS } from "../src/index.ts";
import { signRequestForTest, verifyRequestSignature } from "../src/server.ts";

// Known answer computed independently of this package (2026-11-11): the EC P-256 key of RFC 7517 appendix A.1/A.2
// (its thumbprint is EXAMPLE_ATTESTATION_CLAIMS.cnf.jkt); the canonical string of signature.test.ts written with
// `printf` (with its content-type line, review F1; recomputed 2026-11-11 with OpenSSL 4.0.3, the key assembled from
// the RFC's d, x and y with `openssl asn1parse -genconf`); `openssl dgst -sha256 -sign key.pem` gave a DER signature
// (verified with `openssl dgst -verify`), whose r and s (`openssl asn1parse`) concatenated are the P1363 signature.
const JWK = {
  kty: "EC",
  crv: "P-256",
  x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
  y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
} as const;
const RFC_KEY = createPrivateKey({
  key: { ...JWK, d: "870MB6gfuTJ4HtUnUvYMyJpr5eUZNP4Bk43bVdj3eAE" },
  format: "jwk",
});
const T = 1_794_298_530;
const NONCE = "AAECAwQFBgcICQoLDA0ODw";
const JTI = "0123456789abcdef0123456789abcdef";
const BODY_SHA256 = "AVq9f1zFei3ZS3WQ8ErYCEJzkF7jPsXOvq5iJ2qX-GI";
const KNOWN_P1363 = "IDA53HBew54o0q6SKAPT5l6ZVL2YPS6o93IQphlf0Xg_66t7A3OaaxKIS-JMZByG7hHRXcJOEqEsENiLA3O0YQ";
const KNOWN_DER = "MEQCICAwOdxwXsOeKNKukigD0-ZemVS9mD0uqPdyEKYZX9F4AiA_66t7A3OaaxKIS-JMZByG7hHRXcJOEqEsENiLA3O0YQ";

const REQUEST = {
  method: "post",
  target: "/api/orders?id=7&q=a%20b",
  contentType: "application/json",
  contentSha256: BODY_SHA256,
  jti: JTI,
};
const known = (patch: Record<string, unknown> = {}) => ({
  ...REQUEST,
  header: `v1,t=${T},n=${NONCE},s=${KNOWN_P1363}`,
  jwk: JWK,
  nowS: T,
  ...patch,
});

function freshKey(): { privateKey: KeyObject; jwk: { kty: "EC"; crv: "P-256"; x: string; y: string } } {
  const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const { x, y } = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  return { privateKey, jwk: { kty: "EC", crv: "P-256", x, y } };
}

describe("verifyRequestSignature: known answer", () => {
  it("accepts the signature made with openssl over the pinned canonical string", () => {
    expect(verifyRequestSignature(known())).toBe("valid");
    expect(verifyRequestSignature(known({ method: "POST" }))).toBe("valid");
  });

  it("signs with the private half of the same key so that the known public key verifies", () => {
    expect(createPublicKey(RFC_KEY).export({ format: "jwk" })).toEqual(JWK);
    const header = signRequestForTest({ privateKey: RFC_KEY, ...REQUEST, t: T, n: NONCE });
    expect(verifyRequestSignature(known({ header }))).toBe("valid");
  });

  it("refuses the same signature in DER encoding (P1363 only)", () => {
    expect(verifyRequestSignature(known({ header: `v1,t=${T},n=${NONCE},s=${KNOWN_DER}` }))).toBe("invalid");
  });
});

describe("signRequestForTest and verifyRequestSignature: round trip", () => {
  const { privateKey, jwk } = freshKey();
  const header = signRequestForTest({ privateKey, ...REQUEST, t: T, n: NONCE });
  const verify = (patch: Record<string, unknown> = {}) =>
    verifyRequestSignature({ ...REQUEST, header, jwk, nowS: T, ...patch });

  it("produces the documented header form and a valid signature", () => {
    expect(header).toMatch(/^v1,t=1794298530,n=AAECAwQFBgcICQoLDA0ODw,s=[A-Za-z0-9_-]{86}$/);
    expect(parseSignatureHeader(header)).not.toBeNull();
    expect(verify()).toBe("valid");
  });

  it("picks a fresh random nonce when none is given, and the current time when t is omitted", () => {
    const a = parseSignatureHeader(signRequestForTest({ privateKey, ...REQUEST, t: T }));
    const b = parseSignatureHeader(signRequestForTest({ privateKey, ...REQUEST, t: T }));
    expect(a?.n).not.toBe(b?.n);
    const now = Math.floor(Date.now() / 1000);
    const c = parseSignatureHeader(signRequestForTest({ privateKey, ...REQUEST }));
    expect(Math.abs((c?.t ?? 0) - now)).toBeLessThanOrEqual(2);
  });

  it("binds the content type exactly (review F1): another type, another spelling or none is invalid", () => {
    expect(verify({ contentType: "text/plain" })).toBe("invalid");
    expect(verify({ contentType: "application/json; charset=utf-8" })).toBe("invalid");
    expect(verify({ contentType: "Application/JSON" })).toBe("invalid");
    expect(verify({ contentType: "" })).toBe("invalid");
    const untyped = signRequestForTest({ privateKey, ...REQUEST, contentType: "", t: T, n: NONCE });
    expect(verify({ header: untyped, contentType: "" })).toBe("valid");
    expect(verify({ header: untyped })).toBe("invalid");
  });

  it("refuses to sign without a content type, or with a line feed in it", () => {
    const { contentType: _left, ...without } = REQUEST;
    expect(() => signRequestForTest({ privateKey, ...without, t: T } as never)).toThrow(TypeError);
    expect(() => signRequestForTest({ privateKey, ...REQUEST, contentType: "a\nb", t: T })).toThrow(TypeError);
  });

  it("binds every field: a change of method, target, hash, t, n or jti is invalid", () => {
    const parsed = parseSignatureHeader(header);
    if (parsed === null) throw new Error("unreachable");
    const other = (patch: { t?: number; n?: string }) =>
      `v1,t=${patch.t ?? parsed.t},n=${patch.n ?? parsed.n},s=${parsed.s}`;
    expect(verify({ method: "PUT" })).toBe("invalid");
    expect(verify({ target: "/api/orders?id=8&q=a%20b" })).toBe("invalid");
    expect(verify({ target: "/api/orders?id=7&q=a b" })).toBe("invalid");
    expect(verify({ target: "/API/orders?id=7&q=a%20b" })).toBe("invalid");
    expect(verify({ contentSha256: EMPTY_CONTENT_SHA256 })).toBe("invalid");
    expect(verify({ header: other({ t: T + 1 }), nowS: T + 1 })).toBe("invalid");
    expect(verify({ header: other({ n: "AAECAwQFBgcICQoLDA0OEA" }) })).toBe("invalid");
    expect(verify({ jti: "fedcba9876543210fedcba9876543210" })).toBe("invalid");
  });

  it("refuses a signature by another key and a JWK of another key", () => {
    expect(verify({ jwk: freshKey().jwk })).toBe("invalid");
    expect(verify({ jwk: JWK })).toBe("invalid");
  });

  it("signs with the P1363 encoding: 64 bytes r‖s", () => {
    const s = parseSignatureHeader(header)?.s ?? "";
    expect(Buffer.from(s, "base64url").byteLength).toBe(64);
  });
});

describe("verifyRequestSignature: time window", () => {
  const { privateKey, jwk } = freshKey();
  const header = signRequestForTest({ privateKey, ...REQUEST, t: T, n: NONCE });
  const verify = (nowS: number, patch: Record<string, unknown> = {}) =>
    verifyRequestSignature({ ...REQUEST, header, jwk, nowS, ...patch });

  it("is valid within 60 s either way and stale beyond", () => {
    expect(verify(T + SIGNATURE_LIMITS.windowS)).toBe("valid");
    expect(verify(T - SIGNATURE_LIMITS.windowS)).toBe("valid");
    expect(verify(T + SIGNATURE_LIMITS.windowS + 1)).toBe("stale");
    expect(verify(T - SIGNATURE_LIMITS.windowS - 1)).toBe("stale");
    expect(verify(T + 0.5)).toBe("valid");
  });

  it("reports stale only after the signature verified: a bad signature with a stale t is invalid", () => {
    expect(verify(T + 3600, { method: "DELETE" })).toBe("invalid");
    expect(verify(T + 3600, { jwk: freshKey().jwk })).toBe("invalid");
  });

  it("is invalid for a non-finite or non-numeric clock", () => {
    for (const nowS of [Number.NaN, Number.POSITIVE_INFINITY, "1794298530"]) {
      expect(verify(nowS as number), String(nowS)).toBe("invalid");
    }
  });
});

describe("verifyRequestSignature: never throws, invalid on malformed input", () => {
  const { privateKey, jwk } = freshKey();
  const header = signRequestForTest({ privateKey, ...REQUEST, t: T, n: NONCE });
  const verify = (patch: Record<string, unknown>) =>
    verifyRequestSignature({ ...REQUEST, header, jwk, nowS: T, ...patch } as never);

  it.each([
    ["no header", { header: undefined }],
    ["a malformed header", { header: "v1,t=1" }],
    ["a header array", { header: [header] }],
    ["no key (a token without cnf.jwk)", { jwk: undefined }],
    ["a null key", { jwk: null }],
    ["a key of another curve", { jwk: { ...jwk, crv: "P-384" } }],
    ["a key of another type", { jwk: { kty: "OKP", crv: "Ed25519", x: jwk.x } }],
    ["a point not on the curve", { jwk: { ...jwk, y: jwk.x } }],
    ["a private key member is ignored, but a malformed coordinate is not", { jwk: { ...jwk, x: "A" } }],
    ["a malformed content hash", { contentSha256: "not-a-hash" }],
    ["a content hash in hex", { contentSha256: createHash("sha256").update("").digest("hex") }],
    ["a line feed in the target", { target: "/api/orders\n" }],
    ["a line feed in the content type", { contentType: "application/json\n" }],
    ["no content type", { contentType: undefined }],
    ["a content type that is not a string (as an array)", { contentType: ["application/json"] }],
    ["a method that is not a string", { method: 7 }],
    ["a jti that is not a string", { jti: null }],
  ])("is invalid for %s", (_reason, patch) => {
    expect(verify(patch)).toBe("invalid");
  });

  it("accepts a JWK that also carries other members (only kty, crv, x, y are read)", () => {
    expect(verify({ jwk: { ...jwk, kid: "synthetic", use: "sig" } })).toBe("valid");
  });

  it("refuses an all-zero signature and a signature of a different message", () => {
    const zero = `v1,t=${T},n=${NONCE},s=${"A".repeat(86)}`;
    expect(verify({ header: zero })).toBe("invalid");
    const other = sign("sha256", Buffer.from("something else"), { key: privateKey, dsaEncoding: "ieee-p1363" });
    expect(verify({ header: `v1,t=${T},n=${NONCE},s=${other.toString("base64url")}` })).toBe("invalid");
  });

  it("verifies exactly the canonical string of the protocol", () => {
    const canonical = canonicalSigningString({ ...REQUEST, t: T, n: NONCE });
    const s = sign("sha256", Buffer.from(canonical, "utf8"), { key: privateKey, dsaEncoding: "ieee-p1363" });
    expect(verify({ header: `v1,t=${T},n=${NONCE},s=${s.toString("base64url")}` })).toBe("valid");
  });
});

describe("signRequestForTest: input checks", () => {
  it("throws a TypeError for a key that is not a private P-256 key", () => {
    const ed = generateKeyPairSync("ed25519").privateKey;
    const pub = generateKeyPairSync("ec", { namedCurve: "P-256" }).publicKey;
    const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" }).privateKey;
    for (const privateKey of [ed, pub, p384, null]) {
      expect(() => signRequestForTest({ privateKey: privateKey as KeyObject, ...REQUEST, t: T })).toThrow(TypeError);
    }
  });
});
