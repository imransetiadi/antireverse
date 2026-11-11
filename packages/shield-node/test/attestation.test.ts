// Slice 03, contract P4: Shield verifies the Attestation Token of the `ar-attestation` header offline, with the keys
// of the applied signed bundle, and records the result on the Event. Review focus 1: only EdDSA, only a key of the
// bundle, the signature over exactly the received bytes, audience and expiry enforced. Shield's verifier must give
// the protocol reference's result on every token (differential test).
import { createHash, sign } from "node:crypto";
import {
  ATTESTATION_HEADER,
  ATTESTATION_LIMITS,
  ATTESTATION_PATTERNS,
  AttestationClaimsSchema,
  BundlePayloadSchema,
  EventAttestationSchema,
  ID_PATTERNS,
  VERDICTS,
} from "@antireverse/protocol";
import { verifyAttestationToken } from "@antireverse/protocol/server";
import { afterEach, describe, expect, it, vi } from "vitest";
import {
  APP_ID_PATTERN,
  ATTESTATION_CACHE_MAX,
  createAttestationChecker,
  HEADER_NAME,
  ISSUER,
  JKT_PATTERN,
  JTI_PATTERN,
  KEYS_MAX,
  KID_PATTERN,
  PUBLIC_KEY_PATTERN,
  SIGNAL_PATTERN,
  SIGNALS_MAX,
  SKEW_S,
  SUB_PATTERN,
  TOKEN_MAX,
  TTL_S,
  VERDICT_SET,
  verifyAttestation,
} from "../src/attestation.ts";
import type { AppliedPolicy } from "../src/policy/store.ts";
import { audienceOf, importPublicKey, verifyBundle } from "../src/policy/verify.ts";
import {
  APP_ID,
  type AttestationKeyPair,
  claims,
  craft,
  createAttestationKey,
  header,
  OTHER_APP_ID,
  token,
} from "./attestation-helpers.ts";
import { KEY } from "./helpers.ts";
import { createSigner, NOW, payload, signed } from "./policy-helpers.ts";

const signer = createSigner();
const previous = createAttestationKey();
const current = createAttestationKey();
const next = createAttestationKey();
const stranger = createAttestationKey();
/** The Shield clock of these tests, in seconds. */
const NOW_S = Math.floor(NOW / 1000);

function verifyWith(overrides: Record<string, unknown>) {
  const publicKey = importPublicKey(signer.publicKey);
  if (publicKey === null) throw new Error("the test key could not be imported");
  return verifyBundle(signed(signer, { ...payload(KEY), ...overrides }), {
    publicKey,
    audience: audienceOf(KEY),
    appliedVersion: 0,
    appliedEpoch: null,
    appliedIssuedAt: 0,
    now: NOW,
  });
}

function policyWith(keys: AttestationKeyPair[], appId = APP_ID): AppliedPolicy {
  const verified = verifyWith({ app_id: appId, attestation_keys: keys.map((key) => key.entry) });
  if (!verified.ok) throw new Error(verified.detail);
  return verified.policy;
}

const POLICY = policyWith([previous, current, next]);
const KEYS = [previous.entry, current.entry, next.entry];

describe("Shield's attestation bounds are the protocol's", () => {
  it("header, limits, patterns, issuer and verdicts agree", () => {
    expect(HEADER_NAME).toBe(ATTESTATION_HEADER);
    expect(TOKEN_MAX).toBe(ATTESTATION_LIMITS.headerMax);
    expect(TTL_S).toBe(ATTESTATION_LIMITS.ttlS);
    expect(SKEW_S).toBe(ATTESTATION_LIMITS.skewS);
    expect(KEYS_MAX).toBe(ATTESTATION_LIMITS.keysMax);
    expect(KID_PATTERN.source).toBe(ATTESTATION_PATTERNS.kid.source);
    expect(PUBLIC_KEY_PATTERN.source).toBe(ATTESTATION_PATTERNS.publicKey.source);
    expect(JTI_PATTERN.source).toBe(ATTESTATION_PATTERNS.jti.source);
    expect(SUB_PATTERN.source).toBe(ATTESTATION_PATTERNS.sub.source);
    expect(JKT_PATTERN.source).toBe(ATTESTATION_PATTERNS.jkt.source);
    expect(SIGNAL_PATTERN.source).toBe(ATTESTATION_PATTERNS.signal.source);
    expect(APP_ID_PATTERN.source).toBe(ID_PATTERNS.app.source);
    expect([...VERDICT_SET].sort()).toEqual([...VERDICTS].sort());
    expect(ISSUER).toBe("antireverse");
    expect(ATTESTATION_CACHE_MAX).toBe(10_000);
  });

  it("a token lists at most SIGNALS_MAX signals, as the protocol's claims schema", () => {
    const sig = (count: number) => Array.from({ length: count }, (_, i) => `s${i}`);
    expect(AttestationClaimsSchema.safeParse(claims(NOW_S, { sig: sig(SIGNALS_MAX) })).success).toBe(true);
    expect(AttestationClaimsSchema.safeParse(claims(NOW_S, { sig: sig(SIGNALS_MAX + 1) })).success).toBe(false);
  });

  it("a bundle with three attestation keys is valid protocol content", () => {
    expect(BundlePayloadSchema.safeParse(payload(KEY, { attestation_keys: KEYS })).success).toBe(true);
  });
});

describe("reading attestation_keys of a bundle", () => {
  it("imports each key once, by kid, and keeps the bundle's app_id", () => {
    expect(POLICY.appId).toBe(APP_ID);
    expect([...POLICY.attestationKeys.keys()]).toEqual([previous.kid, current.kid, next.kid]);
    for (const key of [previous, current, next]) {
      const entry = POLICY.attestationKeys.get(key.kid);
      expect(entry?.publicKey).toBe(key.publicKey);
      expect(entry?.key.type).toBe("public");
      expect(entry?.key.asymmetricKeyType).toBe("ed25519");
    }
  });

  it("a bundle without attestation_keys has none: every token is invalid", () => {
    const verified = verifyWith({});
    if (!verified.ok) throw new Error(verified.detail);
    expect(verified.policy.attestationKeys.size).toBe(0);
    expect(verifyAttestation(token(current, claims(NOW_S)), verified.policy, NOW_S)).toEqual({ status: "invalid" });
  });

  const bad: [string, unknown][] = [
    ["not a list", { kid: current.kid, public_key: current.publicKey }],
    ["four keys", [previous.entry, current.entry, next.entry, stranger.entry]],
    ["a kid twice", [current.entry, current.entry]],
    ["an entry that is not an object", [current.entry, "key"]],
    ["a kid of upper-case hex", [{ ...current.entry, kid: current.kid.toUpperCase() }]],
    ["a kid of 15 hex", [{ ...current.entry, kid: current.kid.slice(1) }]],
    ["a public key of 42 characters", [{ ...current.entry, public_key: current.publicKey.slice(1) }]],
    ["a public key with padding", [{ ...current.entry, public_key: `${current.publicKey.slice(1)}=` }]],
    ["a kid that is not the hash of its key", [{ kid: current.kid, public_key: next.publicKey }]],
    [
      "kids swapped between two keys",
      [
        { kid: next.kid, public_key: current.publicKey },
        { kid: current.kid, public_key: next.publicKey },
      ],
    ],
  ];
  it.each(bad)("refuses the whole bundle for %s, without repeating a key or a kid", (_name, attestation_keys) => {
    const verified = verifyWith({ attestation_keys });
    expect(verified.ok).toBe(false);
    if (verified.ok) return;
    expect(verified.reason).toBe("invalid");
    for (const key of [previous, current, next, stranger]) {
      expect(verified.detail).not.toContain(key.kid);
      expect(verified.detail).not.toContain(key.publicKey);
    }
  });

  it("refuses a bundle whose app_id is not an App identifier: no audience could be checked", () => {
    for (const app_id of [null, "", "app_XYZ", 7, `${APP_ID}0`]) {
      const verified = verifyWith({ app_id, attestation_keys: KEYS });
      expect(verified.ok).toBe(false);
      if (!verified.ok) expect(verified.reason).toBe("invalid");
    }
  });

  it("applies a bundle without app_id (as before slice 03), under which no token is valid", () => {
    const { app_id: _app, ...rest } = payload(KEY, { attestation_keys: KEYS });
    const publicKey = importPublicKey(signer.publicKey);
    if (publicKey === null) throw new Error("the test key could not be imported");
    const verified = verifyBundle(signed(signer, rest), {
      publicKey,
      audience: audienceOf(KEY),
      appliedVersion: 0,
      appliedEpoch: null,
      appliedIssuedAt: 0,
      now: NOW,
    });
    if (!verified.ok) throw new Error(verified.detail);
    expect(verified.policy.appId).toBeNull();
    expect(verifyAttestation(token(current, claims(NOW_S)), verified.policy, NOW_S)).toEqual({ status: "invalid" });
  });

  it("kid derivation matches the protocol: the first 16 hex of SHA-256 of the raw key", () => {
    const raw = Buffer.from(current.publicKey, "base64url");
    expect(current.kid).toBe(createHash("sha256").update(raw).digest("hex").slice(0, 16));
  });
});

describe("verifyAttestation: Review focus 1, every rejection", () => {
  const good = claims(NOW_S);
  const valid = token(current, good);

  it("accepts a token of the API and returns its claims", () => {
    const result = verifyAttestation(valid, POLICY, NOW_S);
    expect(result).toEqual({ status: "valid", claims: good });
  });

  it("key rotation: a bundle of previous, current and next accepts tokens of each", () => {
    for (const key of [previous, current, next]) {
      expect(verifyAttestation(token(key, good), POLICY, NOW_S).status).toBe("valid");
    }
    // After rotation the previous key retires: its tokens no longer verify.
    const rotated = policyWith([current, next, stranger]);
    expect(verifyAttestation(token(previous, good), rotated, NOW_S).status).toBe("invalid");
    expect(verifyAttestation(token(stranger, good), rotated, NOW_S).status).toBe("valid");
  });

  const [h, p, s] = valid.split(".") as [string, string, string];
  const cases: [string, () => string][] = [
    [
      "alg none, no signature",
      () =>
        `${craft(current, header(current, { alg: "none" }), good)
          .split(".")
          .slice(0, 2)
          .join(".")}.`,
    ],
    ["alg none with a signature", () => craft(current, header(current, { alg: "none" }), good)],
    ["alg HS256", () => craft(current, header(current, { alg: "HS256" }), good)],
    ["alg ES256", () => craft(current, header(current, { alg: "ES256" }), good)],
    ["alg eddsa (case)", () => craft(current, header(current, { alg: "eddsa" }), good)],
    ["alg Ed25519", () => craft(current, header(current, { alg: "Ed25519" }), good)],
    ["no alg", () => craft(current, { typ: "JWT", kid: current.kid }, good)],
    ["no kid", () => craft(current, { alg: "EdDSA", typ: "JWT" }, good)],
    ["a kid of no bundle key", () => token(stranger, good)],
    ["a kid of the bundle, signed by another key", () => craft(stranger, header(current), good)],
    ["a kid that is not 16 hex", () => craft(current, header(current, { kid: current.kid.toUpperCase() }), good)],
    ["typ jwt", () => craft(current, header(current, { typ: "jwt" }), good)],
    ["no typ", () => craft(current, { alg: "EdDSA", kid: current.kid }, good)],
    ["crit present", () => craft(current, header(current, { crit: ["exp"] }), good)],
    ["crit empty", () => craft(current, header(current, { crit: [] }), good)],
    ["a header that is not JSON", () => craft(current, "{alg:EdDSA}", good)],
    ["a header that is a JSON list", () => craft(current, [header(current)], good)],
    ["a payload that is not JSON", () => craft(current, header(current), "not json")],
    ["a payload that is a JSON list", () => craft(current, header(current), [good])],
    ["two parts", () => `${h}.${p}`],
    ["four parts", () => `${valid}.${s}`],
    ["an empty token", () => ""],
    ["padding in a part", () => `${h}=.${p}.${s}`],
    ["standard base64 characters", () => `${h.replace(/_/g, "/").replace(/-/g, "+")}+.${p}.${s}`],
    ["a space", () => ` ${valid}`],
    ["a non-canonical header part (trailing bits)", () => nonCanonical(current, header(current), good, "header")],
    ["a non-canonical payload part (trailing bits)", () => nonCanonical(current, header(current), good, "payload")],
    ["a non-canonical signature (trailing bits)", () => `${h}.${p}.${s.slice(0, 85)}${bump(s[85] as string)}`],
    ["a signature of 85 characters", () => `${h}.${p}.${s.slice(1)}`],
    ["a signature of 87 characters", () => `${h}.${p}.${s}A`],
    [
      "a tampered payload",
      () => `${h}.${Buffer.from(JSON.stringify({ ...good, verdict: "trusted", risk: 5 })).toString("base64url")}.${s}`,
    ],
    ["a tampered signature", () => `${h}.${p}.${flipChar(s, 10)}`],
    [
      "a payload re-encoded with white space",
      () => `${h}.${Buffer.from(JSON.stringify(good, null, 1)).toString("base64url")}.${s}`,
    ],
    ["wrong aud", () => token(current, claims(NOW_S, { aud: OTHER_APP_ID }))],
    ["wrong iss", () => craft(current, header(current), { ...good, iss: "someone" })],
    ["no iss", () => craft(current, header(current), { ...good, iss: undefined })],
    ["iat more than 30 s in the future", () => token(current, claims(NOW_S + 31))],
    ["lifetime over 300 s", () => craft(current, header(current), { ...good, exp: good.iat + 301 })],
    ["lifetime 0", () => craft(current, header(current), { ...good, exp: good.iat })],
    ["exp before iat", () => craft(current, header(current), { ...good, exp: good.iat - 1 })],
    ["iat not a whole number", () => craft(current, header(current), { ...good, iat: good.iat + 0.5 })],
    ["iat a string", () => craft(current, header(current), { ...good, iat: String(good.iat) })],
    ["a negative iat", () => craft(current, header(current), { ...good, iat: -10, exp: 100 })],
    ["sub malformed", () => craft(current, header(current), { ...good, sub: "dev_XYZ" })],
    ["jti malformed", () => craft(current, header(current), { ...good, jti: "abc" })],
    ["jkt malformed", () => craft(current, header(current), { ...good, cnf: { jkt: "short" } })],
    ["cnf a list", () => craft(current, header(current), { ...good, cnf: [good.cnf.jkt] })],
    ["verdict unknown", () => craft(current, header(current), { ...good, verdict: "genuine" })],
    ["risk 101", () => craft(current, header(current), { ...good, risk: 101 })],
    ["risk fractional", () => craft(current, header(current), { ...good, risk: 5.5 })],
    ["sig with a malformed id", () => craft(current, header(current), { ...good, sig: ["Automation"] })],
    ["sig listing one id twice", () => craft(current, header(current), { ...good, sig: ["a.b", "a.b"] })],
    [
      "sig with 17 ids",
      () => craft(current, header(current), { ...good, sig: Array.from({ length: 17 }, (_, i) => `s${i}`) }),
    ],
    ["sig not a list", () => craft(current, header(current), { ...good, sig: "automation.webdriver" })],
    ["pv 2", () => craft(current, header(current), { ...good, pv: 2 })],
    ["no pv", () => craft(current, header(current), { ...good, pv: undefined })],
    ["longer than 2048 characters", () => craft(current, header(current), { ...good, pad: "x".repeat(2048) })],
    [
      "expired and forged",
      () =>
        `${token(current, claims(NOW_S - 1000))
          .split(".")
          .slice(0, 2)
          .join(".")}.${s}`,
    ],
    ["expired and of an unknown key", () => token(stranger, claims(NOW_S - 1000))],
    ["expired and for another App", () => token(current, claims(NOW_S - 1000, { aud: OTHER_APP_ID }))],
  ];

  it.each(cases)("%s → invalid, as the reference says", (_name, make) => {
    const given = make();
    expect(verifyAttestation(given, POLICY, NOW_S)).toEqual({ status: "invalid" });
    expect(verifyAttestationToken(given, KEYS, { appId: APP_ID, nowS: NOW_S })).toEqual({ status: "invalid" });
  });

  it("non-strings are invalid", () => {
    for (const given of [undefined, null, 7, ["a.b.c"], { token: valid }]) {
      expect(verifyAttestation(given, POLICY, NOW_S)).toEqual({ status: "invalid" });
    }
  });

  it("expiry by Shield's clock: valid until exp - 30 s has passed, expired from exp + 30 s", () => {
    const issued = claims(NOW_S - 300);
    const given = token(current, issued);
    expect(verifyAttestation(given, POLICY, issued.exp + 29).status).toBe("valid");
    expect(verifyAttestation(given, POLICY, issued.exp + 30)).toEqual({ status: "expired" });
    expect(verifyAttestation(given, POLICY, issued.exp + 10_000)).toEqual({ status: "expired" });
  });

  it("iat skew: up to 30 s ahead of Shield's clock is accepted", () => {
    expect(verifyAttestation(token(current, claims(NOW_S + 30)), POLICY, NOW_S).status).toBe("valid");
    expect(verifyAttestation(token(current, claims(NOW_S + 31)), POLICY, NOW_S).status).toBe("invalid");
  });

  it("a Shield clock that returns nonsense accepts nothing", () => {
    expect(verifyAttestation(valid, POLICY, Number.NaN).status).toBe("invalid");
  });

  it("the built-in Policy has no keys and no App: every token is invalid", async () => {
    const { BUILT_IN_POLICY } = await import("../src/policy/store.ts");
    expect(BUILT_IN_POLICY.attestationKeys.size).toBe(0);
    expect(BUILT_IN_POLICY.appId).toBeNull();
    expect(verifyAttestation(valid, BUILT_IN_POLICY, NOW_S).status).toBe("invalid");
  });

  it("unknown claims are dropped from the result, as the reference's schema strips them", () => {
    const given = craft(current, header(current), { ...good, extra: "x", cnf: { ...good.cnf, more: 1 } });
    expect(verifyAttestation(given, POLICY, NOW_S)).toEqual({ status: "valid", claims: good });
  });
});

describe("differential: Shield's verifier gives the protocol reference's result on every token", () => {
  const good = claims(NOW_S);
  const corpus: string[] = [];
  for (const key of [previous, current, next, stranger]) {
    corpus.push(token(key, good));
    corpus.push(token(key, claims(NOW_S - 400)));
    corpus.push(token(key, claims(NOW_S + 20, { verdict: "hostile", risk: 100, sig: ["a.b", "c"] })));
    corpus.push(token(key, claims(NOW_S, { aud: OTHER_APP_ID })));
  }
  const valid = token(current, good);
  const variants: unknown[] = [
    { ...good, iat: 0, exp: 1 },
    { ...good, iat: Number.MAX_SAFE_INTEGER - 1, exp: Number.MAX_SAFE_INTEGER },
    { ...good, iat: 1e300, exp: 1e300 + 1 },
    { ...good, risk: 0 },
    { ...good, risk: -0 },
    { ...good, risk: 1.0 },
    { ...good, sig: [] },
    { ...good, sig: Array.from({ length: 16 }, (_, i) => `s${i}`) },
    { ...good, sig: ["x".repeat(32)] },
    { ...good, sig: ["x".repeat(33)] },
    { ...good, sig: ["a..b"] },
    { ...good, sig: ["a_b.c_1"] },
    { ...good, sig: [1] },
    { ...good, cnf: null },
    { ...good, cnf: { jkt: good.cnf.jkt, x: 1 } },
    { ...good, aud: APP_ID.toUpperCase() },
    { ...good, iss: "antireverse " },
    { ...good, pv: "1" },
    { ...good, pv: true },
    { ...good, verdict: "Trusted" },
    { ...good, sub: "dev_0123456789abcdef0123456" },
    { ...good, jti: good.jti.toUpperCase() },
    { ...good, exp: good.iat + 300 },
    { ...good, exp: good.iat + 1 },
    { ...good, __proto__: { iss: "antireverse" } },
    JSON.parse(`{"__proto__":{"x":1},${JSON.stringify(good).slice(1)}`),
    "null",
    "1",
    '"text"',
    "{}",
  ];
  for (const variant of variants) corpus.push(craft(current, header(current), variant));
  const headers: unknown[] = [
    header(current, { extra: true }),
    { kid: current.kid, typ: "JWT", alg: "EdDSA" },
    header(current, { kid: 7 }),
    header(current, { typ: null }),
    header(current, { crit: undefined }),
    header(current, { alg: ["EdDSA"] }),
    "null",
    "[]",
  ];
  for (const variant of headers) corpus.push(craft(current, variant, good));
  // Mutations of a valid token: every character of each part, replaced, removed and doubled at a few places.
  for (let at = 0; at < valid.length; at += 7) {
    corpus.push(flipChar(valid, at));
    corpus.push(valid.slice(0, at) + valid.slice(at + 1));
    corpus.push(valid.slice(0, at) + (valid[at] ?? "") + valid.slice(at));
  }

  it(`agrees on ${corpus.length} tokens at four instants`, () => {
    let valids = 0;
    let expireds = 0;
    for (const nowS of [NOW_S, NOW_S - 31, NOW_S + 330, NOW_S + 10_000]) {
      for (const given of corpus) {
        const reference = verifyAttestationToken(given, KEYS, { appId: APP_ID, nowS });
        const shield = verifyAttestation(given, POLICY, nowS);
        expect(shield, given).toEqual(reference);
        if (shield.status === "valid") valids += 1;
        if (shield.status === "expired") expireds += 1;
      }
    }
    // The corpus exercises every outcome.
    expect(valids).toBeGreaterThan(10);
    expect(expireds).toBeGreaterThan(5);
  });
});

describe("createAttestationChecker: the per-request result and its cache", () => {
  const VALID_OF = (verdict: string, risk: number) => ({ status: "valid", verdict, risk });

  it("missing header → missing; anything but one string → invalid; oversize → invalid", () => {
    const checker = createAttestationChecker();
    expect(checker.check(POLICY, undefined, NOW_S)).toEqual({ status: "missing", verdict: null, risk: null });
    const valid = token(current, claims(NOW_S));
    expect(checker.check(POLICY, [valid, valid], NOW_S)).toEqual({ status: "invalid", verdict: null, risk: null });
    expect(checker.check(POLICY, "", NOW_S).status).toBe("invalid");
    expect(checker.check(POLICY, "x".repeat(TOKEN_MAX + 1), NOW_S).status).toBe("invalid");
    expect(checker.stats().verifications).toBe(0); // nothing above was even parsed
    expect(checker.check(POLICY, `${valid}, ${valid}`, NOW_S).status).toBe("invalid"); // node joins repeated headers
  });

  it("every result passes the protocol's EventAttestationSchema; verdict and risk only when valid", () => {
    const checker = createAttestationChecker();
    const results = [
      checker.check(POLICY, undefined, NOW_S),
      checker.check(POLICY, "a.b.c", NOW_S),
      checker.check(POLICY, token(current, claims(NOW_S - 1000)), NOW_S),
      checker.check(POLICY, token(current, claims(NOW_S)), NOW_S),
    ];
    expect(results.map((result) => result.status)).toEqual(["missing", "invalid", "expired", "valid"]);
    for (const result of results) expect(EventAttestationSchema.safeParse(result).success).toBe(true);
    expect(results[3]).toEqual(VALID_OF("suspect", 70));
  });

  it("verifies a token once and answers it from the cache afterwards", () => {
    const checker = createAttestationChecker();
    const valid = token(current, claims(NOW_S));
    for (let i = 0; i < 5; i++) expect(checker.check(POLICY, valid, NOW_S + i)).toEqual(VALID_OF("suspect", 70));
    expect(checker.stats()).toMatchObject({ verifications: 1, hits: 4, entries: 1 });
  });

  it("keys the cache by the SHA-256 of the exact token string", () => {
    const checker = createAttestationChecker();
    const valid = token(current, claims(NOW_S));
    checker.check(POLICY, valid, NOW_S);
    const hash = createHash("sha256").update(valid, "utf8").digest("base64url");
    expect(checker.keys()).toEqual([hash]);
    expect(checker.check(POLICY, valid, NOW_S).status).toBe("valid");
    expect(checker.stats()).toMatchObject({ verifications: 1, hits: 1, entries: 1 });
  });

  describe("nothing of an unverified payload is parsed", () => {
    afterEach(() => vi.restoreAllMocks());

    it("a miss parses the header only until the signature verified (forged signature, unknown kid)", () => {
      const checker = createAttestationChecker();
      const valid = token(current, claims(NOW_S));
      const forged = `${valid.slice(0, valid.lastIndexOf("."))}.${token(stranger, claims(NOW_S)).split(".")[2]}`;
      for (const given of [forged, token(stranger, claims(NOW_S))]) {
        const parse = vi.spyOn(JSON, "parse");
        expect(checker.check(POLICY, given, NOW_S).status).toBe("invalid");
        expect(parse).toHaveBeenCalledTimes(1); // the header
        parse.mockRestore();
      }
    });

    it("a hit parses nothing at all", () => {
      const checker = createAttestationChecker();
      const valid = token(current, claims(NOW_S));
      checker.check(POLICY, valid, NOW_S);
      const parse = vi.spyOn(JSON, "parse");
      expect(checker.check(POLICY, valid, NOW_S).status).toBe("valid");
      expect(parse).not.toHaveBeenCalled();
    });
  });

  it("the cache holds no token: only its hash", () => {
    const checker = createAttestationChecker();
    const valid = token(current, claims(NOW_S));
    checker.check(POLICY, valid, NOW_S);
    const inside = JSON.stringify(checker.inspect());
    expect(inside).not.toContain(valid);
    expect(inside).not.toContain(valid.split(".")[2]);
  });

  it("the same jti in another token string is verified again (a forged twin is invalid)", () => {
    const checker = createAttestationChecker();
    const good = claims(NOW_S);
    const valid = token(current, good);
    expect(checker.check(POLICY, valid, NOW_S).status).toBe("valid");
    // A twin with the same jti and a better verdict, signed by a key of no bundle: never served from the cache.
    const twin = craft(stranger, header(current), { ...good, verdict: "trusted", risk: 5, sig: [] });
    expect(checker.check(POLICY, twin, NOW_S).status).toBe("invalid");
    expect(checker.stats().verifications).toBe(2);
    // A genuine twin (same jti, other bytes: another key of the bundle) is verified from scratch and cached under
    // its own hash; the first token stays cached under its own.
    const other = token(next, { ...good, verdict: "trusted", risk: 5, sig: [] });
    expect(checker.check(POLICY, other, NOW_S)).toEqual(VALID_OF("trusted", 5));
    expect(checker.stats().verifications).toBe(3);
    expect(checker.check(POLICY, valid, NOW_S)).toEqual(VALID_OF("suspect", 70));
    expect(checker.check(POLICY, other, NOW_S)).toEqual(VALID_OF("trusted", 5));
    expect(checker.stats()).toMatchObject({ verifications: 3, hits: 2, entries: 2 });
  });

  it("re-checks expiry against the Shield clock on every hit", () => {
    const checker = createAttestationChecker();
    const issued = claims(NOW_S);
    const valid = token(current, issued);
    expect(checker.check(POLICY, valid, NOW_S).status).toBe("valid");
    expect(checker.check(POLICY, valid, issued.exp + 29).status).toBe("valid");
    expect(checker.check(POLICY, valid, issued.exp + 30)).toEqual({ status: "expired", verdict: null, risk: null });
    expect(checker.stats().verifications).toBe(1);
  });

  it("re-checks iat against the Shield clock on every hit (a clock set back)", () => {
    const checker = createAttestationChecker();
    const valid = token(current, claims(NOW_S));
    expect(checker.check(POLICY, valid, NOW_S).status).toBe("valid");
    expect(checker.check(POLICY, valid, NOW_S - 31).status).toBe("invalid");
  });

  it("a cached token whose key left the bundle, or a bundle of another App, is invalid", () => {
    const checker = createAttestationChecker();
    const valid = token(previous, claims(NOW_S));
    expect(checker.check(POLICY, valid, NOW_S).status).toBe("valid");
    expect(checker.check(policyWith([current, next]), valid, NOW_S).status).toBe("invalid");
    expect(checker.check(policyWith([previous, current, next], OTHER_APP_ID), valid, NOW_S).status).toBe("invalid");
    // The same keys in a newly applied bundle: still valid.
    expect(checker.check(policyWith([previous, current]), valid, NOW_S).status).toBe("valid");
  });

  it("caches only valid tokens", () => {
    const checker = createAttestationChecker();
    const expired = token(current, claims(NOW_S - 1000));
    checker.check(POLICY, expired, NOW_S);
    checker.check(POLICY, expired, NOW_S);
    checker.check(POLICY, token(stranger, claims(NOW_S)), NOW_S);
    expect(checker.stats()).toMatchObject({ entries: 0, verifications: 3, hits: 0 });
  });

  it(`holds at most ${ATTESTATION_CACHE_MAX} entries by default, least recently used out first`, () => {
    const checker = createAttestationChecker({ maxEntries: 3 });
    const tokens = [1, 2, 3, 4].map((n) => token(current, claims(NOW_S, {}, n)));
    const [t1, t2, t3, t4] = tokens as [string, string, string, string];
    checker.check(POLICY, t1, NOW_S);
    checker.check(POLICY, t2, NOW_S);
    checker.check(POLICY, t3, NOW_S);
    checker.check(POLICY, t1, NOW_S); // t1 used again: t2 is now the least recently used
    checker.check(POLICY, t4, NOW_S);
    expect(checker.stats()).toMatchObject({ entries: 3, verifications: 4, hits: 1 });
    checker.check(POLICY, t1, NOW_S);
    checker.check(POLICY, t3, NOW_S);
    expect(checker.stats().verifications).toBe(4);
    checker.check(POLICY, t2, NOW_S);
    expect(checker.stats().verifications).toBe(5);
    expect(createAttestationChecker().stats().max).toBe(ATTESTATION_CACHE_MAX);
  });
});

/** Replaces one character by a different one of the base64url alphabet. */
function flipChar(text: string, at: number): string {
  const replacement = text[at] === "A" ? "B" : text[at] === "." ? "A" : "A";
  return text.slice(0, at) + replacement + text.slice(at + 1);
}

/** The base64url character one above (same high bits, a low bit set). */
function bump(char: string): string {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
  return alphabet[alphabet.indexOf(char) + 1] ?? "A";
}

/** A signed token whose header or payload part decodes to the same bytes but is not the canonical spelling. */
function nonCanonical(key: AttestationKeyPair, head: unknown, body: unknown, which: "header" | "payload"): string {
  const enc = (value: unknown) => Buffer.from(JSON.stringify(value), "utf8").toString("base64url");
  let h = enc(head);
  let p = enc(body);
  const twist = (part: string): string => {
    // Only a part whose length is not a multiple of 4 has unused trailing bits.
    if (part.length % 4 === 0) return part;
    return part.slice(0, -1) + bump(part.at(-1) as string);
  };
  if (which === "header") {
    let pad = 0;
    while (h.length % 4 === 0) h = enc({ ...(head as object), [`p${pad++}`]: 1 });
    h = twist(h);
  } else {
    let pad = "";
    while (p.length % 4 === 0) {
      pad += "x";
      p = enc({ ...(body as object), pad });
    }
    p = twist(p);
  }
  const input = `${h}.${p}`;
  return `${input}.${sign(null, Buffer.from(input, "ascii"), key.privateKey).toString("base64url")}`;
}
