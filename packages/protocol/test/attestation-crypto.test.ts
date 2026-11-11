import {
  createHash,
  createHmac,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  type KeyObject,
  sign,
} from "node:crypto";
import { describe, expect, it } from "vitest";
import { type AttestationClaims, EXAMPLE_ATTESTATION_CLAIMS } from "../src/index.ts";
import {
  attestationKid,
  deviceSubject,
  jwkThumbprint,
  signAttestationToken,
  verifyAttestationToken,
} from "../src/server.ts";

// Known answers computed independently of this package (2026-11-11):
// - RFC 8032 section 7.1 TEST 1 key pair; kid = `printf <public hex> | xxd -r -p | shasum -a 256`, first 16 hex.
// - thumbprint of the EC P-256 key of RFC 7517 appendix A.1:
//   `printf '{"crv":"P-256","kty":"EC","x":...,"y":...}' | openssl dgst -sha256 -binary | base64url`.
// - sub: `printf 'app_89abcdef0123456789abcdef:AAECAwQFBgcICQoLDA0ODw' | shasum -a 256`, first 24 hex.
// - the token: `node -e` with node:crypto `sign(null, ...)` directly over the JSON of the header and of
//   EXAMPLE_ATTESTATION_CLAIMS as written below, without this package.
const RFC8032_SEED = "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60";
const RFC8032_PUBLIC = "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a";
const RFC8032_PUBLIC_B64U = "11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo";
const RFC8032_KID = "21fe31dfa154a261";
const KNOWN_TOKEN =
  "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCIsImtpZCI6IjIxZmUzMWRmYTE1NGEyNjEifQ" +
  ".eyJpc3MiOiJhbnRpcmV2ZXJzZSIsImF1ZCI6ImFwcF84OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYiLCJzdWIiOiJkZXZfMDZjNDNjMGNiYzE4Y2I3MDQ4YWIyNmExIiwiaWF0IjoxNzk0Mjk4NTMwLCJleHAiOjE3OTQyOTg4MzAsImp0aSI6IjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmIiwiY25mIjp7ImprdCI6ImNuLUlfV05NQ2xlaGlWcDUxaV8wVnBPRU5XMXVwRWVyQThzRWFtNWhuLXMifSwidmVyZGljdCI6InN1c3BlY3QiLCJyaXNrIjo3MCwic2lnIjpbImF1dG9tYXRpb24ud2ViZHJpdmVyIl0sInB2IjoxfQ" +
  ".EzLfkjkxw-3a5wxbbeaJnMkq-Anyt712YNJoFgBRhxSbWhEbLlqARuE8hU6biVUDaWm6w4PjRzWO_WxIObJGCg";

const RFC_KEY = createPrivateKey({
  key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), Buffer.from(RFC8032_SEED, "hex")]),
  format: "der",
  type: "pkcs8",
});
const KEYS = [{ kid: RFC8032_KID, public_key: RFC8032_PUBLIC_B64U }];
const APP = EXAMPLE_ATTESTATION_CLAIMS.aud;
const IAT = EXAMPLE_ATTESTATION_CLAIMS.iat;
const OPTS = { appId: APP, nowS: IAT + 10 };

const b64u = (value: unknown): string =>
  Buffer.from(typeof value === "string" ? value : JSON.stringify(value), "utf8").toString("base64url");
const HEADER = { alg: "EdDSA", typ: "JWT", kid: RFC8032_KID };

/** A token built without this package: base64url of the given JSON (or raw text), Ed25519 over "h.p". */
function craft(
  header: unknown = HEADER,
  claims: unknown = EXAMPLE_ATTESTATION_CLAIMS,
  key: KeyObject = RFC_KEY,
): string {
  const signingInput = `${b64u(header)}.${b64u(claims)}`;
  return `${signingInput}.${sign(null, Buffer.from(signingInput, "ascii"), key).toString("base64url")}`;
}
const withClaims = (patch: Record<string, unknown>) => craft(HEADER, { ...EXAMPLE_ATTESTATION_CLAIMS, ...patch });
const verify = (token: unknown, opts: Partial<typeof OPTS> = {}, keys = KEYS) =>
  verifyAttestationToken(token as string, keys, { ...OPTS, ...opts });
const statusOf = (token: unknown, opts: Partial<typeof OPTS> = {}, keys = KEYS) => verify(token, opts, keys).status;

describe("attestationKid", () => {
  it("is the first 16 hex of the SHA-256 of the raw public key (RFC 8032 TEST 1 known answer)", () => {
    expect(attestationKid(Buffer.from(RFC8032_PUBLIC, "hex"))).toBe(RFC8032_KID);
    expect(attestationKid(new Uint8Array(Buffer.from(RFC8032_PUBLIC, "hex")))).toBe(RFC8032_KID);
  });

  it("refuses anything that is not 32 raw bytes", () => {
    expect(() => attestationKid(Buffer.alloc(31))).toThrow(TypeError);
    expect(() => attestationKid(Buffer.from(RFC8032_PUBLIC_B64U))).toThrow(TypeError);
    expect(() => attestationKid(RFC8032_PUBLIC_B64U as unknown as Uint8Array)).toThrow(TypeError);
  });
});

describe("jwkThumbprint (RFC 7638)", () => {
  const RFC7517_EC = {
    kty: "EC" as const,
    crv: "P-256" as const,
    x: "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
    y: "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
  };

  it("hashes the required members in the canonical order crv, kty, x, y (known answer)", () => {
    expect(jwkThumbprint(RFC7517_EC)).toBe("cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s");
  });

  it("ignores member order and other members of the input", () => {
    const reordered = { y: RFC7517_EC.y, x: RFC7517_EC.x, kty: "EC", crv: "P-256", kid: "k", use: "sig", d: "x" };
    expect(jwkThumbprint(reordered as typeof RFC7517_EC)).toBe("cn-I_WNMClehiVp51i_0VpOENW1upEerA8sEam5hn-s");
  });

  it("equals the thumbprint of a WebCrypto-exported P-256 public key computed by hand", () => {
    const { publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
    const jwk = publicKey.export({ format: "jwk" }) as { kty: "EC"; crv: "P-256"; x: string; y: string };
    const canonical = `{"crv":"P-256","kty":"EC","x":"${jwk.x}","y":"${jwk.y}"}`;
    expect(jwkThumbprint(jwk)).toBe(createHash("sha256").update(canonical, "utf8").digest("base64url"));
  });

  it("refuses keys that are not EC P-256 with 43-character coordinates", () => {
    expect(() => jwkThumbprint({ ...RFC7517_EC, kty: "RSA" } as never)).toThrow(TypeError);
    expect(() => jwkThumbprint({ ...RFC7517_EC, crv: "P-384" } as never)).toThrow(TypeError);
    expect(() => jwkThumbprint({ ...RFC7517_EC, x: RFC7517_EC.x.slice(1) })).toThrow(TypeError);
    expect(() => jwkThumbprint({ ...RFC7517_EC, y: `${RFC7517_EC.y}=` })).toThrow(TypeError);
    expect(() => jwkThumbprint(null as never)).toThrow(TypeError);
  });

  it("refuses non-canonical base64url coordinates (unused low bits set), like cnf.jwk (slice 04)", () => {
    // 43 characters carry 258 bits: the last 2 must be zero, so the last character is one of AEIMQUYcgkosw048.
    for (const last of "BFJNRVZdhlptx159-_") {
      expect(() => jwkThumbprint({ ...RFC7517_EC, x: `${RFC7517_EC.x.slice(0, 42)}${last}` }), last).toThrow(TypeError);
      expect(() => jwkThumbprint({ ...RFC7517_EC, y: `${RFC7517_EC.y.slice(0, 42)}${last}` }), last).toThrow(TypeError);
    }
    for (const last of "AEIMQUYcgkosw048") {
      expect(() => jwkThumbprint({ ...RFC7517_EC, x: `${RFC7517_EC.x.slice(0, 42)}${last}` }), last).not.toThrow();
    }
  });
});

describe("deviceSubject", () => {
  it('is "dev_" and the first 24 hex of SHA-256(app_id + ":" + device id) (known answer)', () => {
    expect(deviceSubject(APP, "AAECAwQFBgcICQoLDA0ODw")).toBe("dev_06c43c0cbc18cb7048ab26a1");
  });

  it("differs per App for the same device id", () => {
    expect(deviceSubject("app_ffffffffffffffffffffffff", "AAECAwQFBgcICQoLDA0ODw")).not.toBe(
      "dev_06c43c0cbc18cb7048ab26a1",
    );
  });

  it("refuses empty or non-string input", () => {
    expect(() => deviceSubject("", "AAECAwQFBgcICQoLDA0ODw")).toThrow(TypeError);
    expect(() => deviceSubject(APP, "")).toThrow(TypeError);
    expect(() => deviceSubject(APP, 7 as unknown as string)).toThrow(TypeError);
  });
});

describe("signAttestationToken", () => {
  it("produces exactly the independently computed token (Ed25519 is deterministic)", () => {
    expect(signAttestationToken(RFC_KEY, RFC8032_KID, EXAMPLE_ATTESTATION_CLAIMS)).toBe(KNOWN_TOKEN);
  });

  it("writes the header alg EdDSA, typ JWT and the kid", () => {
    const [header] = signAttestationToken(RFC_KEY, RFC8032_KID, EXAMPLE_ATTESTATION_CLAIMS).split(".");
    expect(JSON.parse(Buffer.from(header as string, "base64url").toString("utf8"))).toEqual(HEADER);
  });

  it("refuses claims that break the schema, a malformed kid and a key that is not a private Ed25519 key", () => {
    expect(() => signAttestationToken(RFC_KEY, RFC8032_KID, { ...EXAMPLE_ATTESTATION_CLAIMS, exp: IAT + 301 })).toThrow(
      TypeError,
    );
    expect(() =>
      signAttestationToken(RFC_KEY, RFC8032_KID, { ...EXAMPLE_ATTESTATION_CLAIMS, iss: "x" } as never),
    ).toThrow(TypeError);
    expect(() => signAttestationToken(RFC_KEY, "XYZ", EXAMPLE_ATTESTATION_CLAIMS)).toThrow(TypeError);
    expect(() => signAttestationToken(createPublicKey(RFC_KEY), RFC8032_KID, EXAMPLE_ATTESTATION_CLAIMS)).toThrow(
      TypeError,
    );
    const ec = generateKeyPairSync("ec", { namedCurve: "P-256" }).privateKey;
    expect(() => signAttestationToken(ec, RFC8032_KID, EXAMPLE_ATTESTATION_CLAIMS)).toThrow(TypeError);
  });

  it("keeps the largest claims within the header limit", () => {
    const largest: AttestationClaims = {
      ...EXAMPLE_ATTESTATION_CLAIMS,
      iat: 4_102_444_800,
      exp: 4_102_445_100,
      risk: 100,
      verdict: "suspect",
      sig: Array.from({ length: 16 }, (_, n) => `${String.fromCharCode(97 + n)}`.repeat(32)),
    };
    const token = signAttestationToken(RFC_KEY, RFC8032_KID, largest);
    expect(token.length).toBeLessThanOrEqual(2048);
  });
});

describe("verifyAttestationToken", () => {
  it("accepts the known token and returns the claims", () => {
    expect(verify(KNOWN_TOKEN)).toEqual({ status: "valid", claims: EXAMPLE_ATTESTATION_CLAIMS });
  });

  it("round-trips a token of a fresh key among several", () => {
    const { privateKey, publicKey } = generateKeyPairSync("ed25519");
    const raw = Buffer.from(publicKey.export({ format: "jwk" }).x as string, "base64url");
    const kid = attestationKid(raw);
    const keys = [...KEYS, { kid, public_key: raw.toString("base64url") }];
    const claims = { ...EXAMPLE_ATTESTATION_CLAIMS, verdict: "hostile" as const, risk: 100, sig: [] };
    expect(verify(signAttestationToken(privateKey, kid, claims), {}, keys)).toEqual({ status: "valid", claims });
  });

  describe("structure", () => {
    it("is invalid unless there are exactly three parts", () => {
      const [h, p, s] = KNOWN_TOKEN.split(".");
      expect(statusOf(`${h}.${p}`)).toBe("invalid");
      expect(statusOf(`${h}.${p}.${s}.`)).toBe("invalid");
      expect(statusOf(`${h}.${p}.${s}.${s}`)).toBe("invalid");
      expect(statusOf("")).toBe("invalid");
      expect(statusOf("..")).toBe("invalid");
    });

    it("is invalid for anything but a string", () => {
      for (const value of [undefined, null, 7, {}, [KNOWN_TOKEN], Buffer.from(KNOWN_TOKEN)]) {
        expect(statusOf(value)).toBe("invalid");
      }
    });

    it("is invalid when longer than 2048 characters, even if otherwise valid", () => {
      const padded = withClaims({ padding: "x".repeat(1600) });
      expect(padded.length).toBeGreaterThan(2048);
      expect(statusOf(padded)).toBe("invalid");
      expect(statusOf(KNOWN_TOKEN + "A".repeat(2048 - KNOWN_TOKEN.length + 1))).toBe("invalid");
    });

    it("is invalid for padding, standard base64 or other characters in any part", () => {
      const [h, p, s] = KNOWN_TOKEN.split(".") as [string, string, string];
      expect(statusOf(`${h}=.${p}.${s}`)).toBe("invalid");
      expect(statusOf(`${h}.${p}==.${s}`)).toBe("invalid");
      expect(statusOf(`${h}.${p}.${s}==`)).toBe("invalid");
      expect(statusOf(`${h}.${p}.${s.replace(/-/g, "+").replace(/_/g, "/")}`)).toBe("invalid");
      expect(statusOf(`${h} .${p}.${s}`)).toBe("invalid");
      expect(statusOf(`${h}.${p}.${s.slice(0, -1)}`)).toBe("invalid");
    });

    it("is invalid when the header or payload is not JSON, or not an object", () => {
      expect(statusOf(craft("not json"))).toBe("invalid");
      expect(statusOf(craft(HEADER, "not json"))).toBe("invalid");
      expect(statusOf(craft([HEADER]))).toBe("invalid");
      expect(statusOf(craft(HEADER, [EXAMPLE_ATTESTATION_CLAIMS]))).toBe("invalid");
      expect(statusOf(craft("null"))).toBe("invalid");
    });
  });

  describe("header (Review Focus 1: only EdDSA)", () => {
    it.each(["none", "None", "NONE", "HS256", "HS512", "ES256", "RS256", "PS256", "eddsa", "EDDSA", "Ed25519", ""])(
      "is invalid for alg %j even with a genuine Ed25519 signature",
      (alg) => {
        expect(statusOf(craft({ ...HEADER, alg }))).toBe("invalid");
      },
    );

    it("is invalid for alg none with an empty signature", () => {
      const [, p] = KNOWN_TOKEN.split(".");
      expect(statusOf(`${b64u({ ...HEADER, alg: "none" })}.${p}.`)).toBe("invalid");
    });

    it("is invalid for an HS256 token keyed with the public key (algorithm confusion)", () => {
      const signingInput = `${b64u({ ...HEADER, alg: "HS256" })}.${b64u(EXAMPLE_ATTESTATION_CLAIMS)}`;
      const mac = createHmac("sha256", RFC8032_PUBLIC_B64U).update(signingInput).digest("base64url");
      expect(statusOf(`${signingInput}.${mac}`)).toBe("invalid");
    });

    it("is invalid without alg, with a non-string alg, or with typ other than JWT", () => {
      const { alg: _alg, ...noAlg } = HEADER;
      expect(statusOf(craft(noAlg))).toBe("invalid");
      expect(statusOf(craft({ ...HEADER, alg: ["EdDSA"] }))).toBe("invalid");
      const { typ: _typ, ...noTyp } = HEADER;
      expect(statusOf(craft(noTyp))).toBe("invalid");
      expect(statusOf(craft({ ...HEADER, typ: "jwt" }))).toBe("invalid");
      expect(statusOf(craft({ ...HEADER, typ: "at+jwt" }))).toBe("invalid");
    });

    it("is invalid with critical extensions", () => {
      expect(statusOf(craft({ ...HEADER, crit: ["b64"], b64: false }))).toBe("invalid");
    });

    it("is invalid for a missing, malformed or unknown kid (no key outside the bundle is accepted)", () => {
      const { kid: _kid, ...noKid } = HEADER;
      expect(statusOf(craft(noKid))).toBe("invalid");
      expect(statusOf(craft({ ...HEADER, kid: 7 }))).toBe("invalid");
      expect(statusOf(craft({ ...HEADER, kid: RFC8032_KID.toUpperCase() }))).toBe("invalid");
      expect(statusOf(craft({ ...HEADER, kid: "0123456789abcdef" }))).toBe("invalid");
      expect(statusOf(KNOWN_TOKEN, {}, [])).toBe("invalid");
    });

    it("is invalid for a token signed by a key outside the bundle that claims a bundle kid", () => {
      const stranger = generateKeyPairSync("ed25519").privateKey;
      expect(statusOf(craft(HEADER, EXAMPLE_ATTESTATION_CLAIMS, stranger))).toBe("invalid");
    });

    it("uses the key the kid names, not any key of the set", () => {
      const other = generateKeyPairSync("ed25519");
      const raw = Buffer.from(other.publicKey.export({ format: "jwk" }).x as string, "base64url");
      const otherKid = attestationKid(raw);
      const keys = [...KEYS, { kid: otherKid, public_key: raw.toString("base64url") }];
      // Signed by the RFC key but naming the other kid.
      expect(statusOf(craft({ ...HEADER, kid: otherKid }), {}, keys)).toBe("invalid");
    });

    it("is invalid when the key set entry holds no usable public key", () => {
      expect(statusOf(KNOWN_TOKEN, {}, [{ kid: RFC8032_KID, public_key: "!".repeat(43) }])).toBe("invalid");
      expect(statusOf(KNOWN_TOKEN, {}, [{ kid: RFC8032_KID, public_key: "" }])).toBe("invalid");
    });
  });

  describe("signature over exactly the received bytes", () => {
    it("is invalid when a payload byte or a signature byte changes", () => {
      const [h, p, s] = KNOWN_TOKEN.split(".") as [string, string, string];
      const tamperedClaims = b64u({ ...EXAMPLE_ATTESTATION_CLAIMS, verdict: "trusted", risk: 5, sig: [] });
      expect(statusOf(`${h}.${tamperedClaims}.${s}`)).toBe("invalid");
      const flipped = s.slice(0, 10) + (s[10] === "A" ? "B" : "A") + s.slice(11);
      expect(statusOf(`${h}.${p}.${flipped}`)).toBe("invalid");
    });

    it("is invalid when the same JSON is re-encoded differently (spacing, member order)", () => {
      const [h, , s] = KNOWN_TOKEN.split(".") as [string, string, string];
      const spaced = b64u(JSON.stringify(EXAMPLE_ATTESTATION_CLAIMS, null, 1));
      const reordered = b64u(Object.fromEntries(Object.entries(EXAMPLE_ATTESTATION_CLAIMS).reverse()));
      expect(statusOf(`${h}.${spaced}.${s}`)).toBe("invalid");
      expect(statusOf(`${h}.${reordered}.${s}`)).toBe("invalid");
      const [, p] = KNOWN_TOKEN.split(".") as [string, string];
      const respacedHeader = b64u(JSON.stringify(HEADER, null, 1));
      expect(statusOf(`${respacedHeader}.${p}.${s}`)).toBe("invalid");
    });

    it("accepts a differently encoded JSON when it was signed as such", () => {
      expect(statusOf(craft(HEADER, JSON.stringify(EXAMPLE_ATTESTATION_CLAIMS, null, 1)))).toBe("valid");
    });

    it("is invalid for a non-canonical spelling of the genuine signature (unused bits set)", () => {
      const [h, p, s] = KNOWN_TOKEN.split(".") as [string, string, string];
      const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
      const last = alphabet.indexOf(s.at(-1) as string);
      const respelled = s.slice(0, -1) + alphabet[last ^ 1];
      expect(Buffer.from(respelled, "base64url").equals(Buffer.from(s, "base64url"))).toBe(true);
      expect(statusOf(`${h}.${p}.${respelled}`)).toBe("invalid");
    });

    it("is invalid for a signature from another token", () => {
      const other = signAttestationToken(RFC_KEY, RFC8032_KID, { ...EXAMPLE_ATTESTATION_CLAIMS, risk: 71 });
      const [h, p] = KNOWN_TOKEN.split(".") as [string, string];
      expect(statusOf(`${h}.${p}.${other.split(".")[2]}`)).toBe("invalid");
    });
  });

  describe("claims", () => {
    it("is invalid for claims that break the schema", () => {
      expect(statusOf(withClaims({ pv: 2 }))).toBe("invalid");
      expect(statusOf(withClaims({ verdict: "genuine" }))).toBe("invalid");
      expect(statusOf(withClaims({ risk: 101 }))).toBe("invalid");
      expect(statusOf(withClaims({ sub: "someone@example.com" }))).toBe("invalid");
      expect(statusOf(withClaims({ cnf: undefined }))).toBe("invalid");
      expect(statusOf(withClaims({ jti: undefined }))).toBe("invalid");
    });

    it("is invalid for another issuer", () => {
      expect(statusOf(withClaims({ iss: "attacker" }))).toBe("invalid");
    });

    it("is invalid for another App's audience", () => {
      expect(statusOf(withClaims({ aud: "app_ffffffffffffffffffffffff" }))).toBe("invalid");
      expect(statusOf(KNOWN_TOKEN, { appId: "app_ffffffffffffffffffffffff" })).toBe("invalid");
      expect(statusOf(withClaims({ aud: [APP] }))).toBe("invalid");
    });

    it("is invalid for an iat more than 30 s ahead of now (inclusive bound at +30)", () => {
      expect(statusOf(KNOWN_TOKEN, { nowS: IAT - 30 })).toBe("valid");
      expect(statusOf(KNOWN_TOKEN, { nowS: IAT - 31 })).toBe("invalid");
    });

    it("is invalid for a lifetime over 300 s or not positive", () => {
      expect(statusOf(withClaims({ exp: IAT + 301 }))).toBe("invalid");
      expect(statusOf(withClaims({ exp: IAT }))).toBe("invalid");
      expect(statusOf(withClaims({ exp: IAT - 5 }))).toBe("invalid");
      expect(statusOf(withClaims({ exp: IAT + 300 }))).toBe("valid");
    });
  });

  describe("expiry", () => {
    const EXP = EXAMPLE_ATTESTATION_CLAIMS.exp;

    it("is valid until exp + 30 s and expired from then on", () => {
      expect(statusOf(KNOWN_TOKEN, { nowS: EXP })).toBe("valid");
      expect(statusOf(KNOWN_TOKEN, { nowS: EXP + 29 })).toBe("valid");
      expect(statusOf(KNOWN_TOKEN, { nowS: EXP + 30 })).toBe("expired");
      expect(statusOf(KNOWN_TOKEN, { nowS: EXP + 86_400 })).toBe("expired");
      expect(verify(KNOWN_TOKEN, { nowS: EXP + 30 })).toEqual({ status: "expired" });
    });

    it("is expired only for a genuine token: forged and expired is invalid", () => {
      const stranger = generateKeyPairSync("ed25519").privateKey;
      const forged = craft(HEADER, EXAMPLE_ATTESTATION_CLAIMS, stranger);
      expect(statusOf(forged, { nowS: EXP + 3600 })).toBe("invalid");
      const [h, , s] = KNOWN_TOKEN.split(".") as [string, string, string];
      const extended = b64u({ ...EXAMPLE_ATTESTATION_CLAIMS, exp: EXP + 3600 });
      expect(statusOf(`${h}.${extended}.${s}`, { nowS: EXP + 60 })).toBe("invalid");
    });

    it("is invalid, not expired, when an expired token also breaks the audience or the schema", () => {
      expect(statusOf(KNOWN_TOKEN, { nowS: EXP + 3600, appId: "app_ffffffffffffffffffffffff" })).toBe("invalid");
      expect(statusOf(withClaims({ pv: 2 }), { nowS: EXP + 3600 })).toBe("invalid");
      expect(statusOf(withClaims({ exp: IAT + 301 }), { nowS: EXP + 3600 })).toBe("invalid");
    });

    it("never returns claims for a status other than valid", () => {
      expect(verify(KNOWN_TOKEN, { nowS: EXP + 3600 })).not.toHaveProperty("claims");
      expect(verify(withClaims({ iss: "x" }))).toEqual({ status: "invalid" });
    });
  });

  it("does not throw for hostile input", () => {
    const hostile = [
      `${b64u({ ...HEADER, kid: "__proto__" })}.${b64u({})}.AA`,
      `${b64u({ ...HEADER, kid: "constructor" })}.${b64u({})}.AA`,
      `${b64u('{"alg":"EdDSA","typ":"JWT","kid":"21fe31dfa154a261","alg":"none"}')}.${b64u({})}.${"A".repeat(86)}`,
      "\u0000.\u0000.\u0000",
    ];
    for (const token of hostile) expect(statusOf(token)).toBe("invalid");
  });
});
