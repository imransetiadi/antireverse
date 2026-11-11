// Slice 04, contract P4, Review Focus 1 and 2: Shield's own request-signature verifier (no runtime dependency)
// gives the protocol reference's result on valid and mutated requests; the nonce store consumes a nonce only after a
// valid signature, keeps it until t + 61 s (review F5: every replay up to staleness is caught), is bounded and never
// evicts a live entry; keys are cached by jkt; the content type is bound (review F1).
import { createHash, generateKeyPairSync, type KeyObject, sign } from "node:crypto";
import {
  CONTENT_HASH_HEADER as PROTOCOL_CONTENT_HASH_HEADER,
  CONTENT_SHA256_PATTERN as PROTOCOL_CONTENT_SHA256_PATTERN,
  EMPTY_CONTENT_SHA256 as PROTOCOL_EMPTY,
  SIGNATURE_HEADER as PROTOCOL_SIGNATURE_HEADER,
  canonicalSigningString as protocolCanonical,
  parseSignatureHeader as protocolParse,
  SIGNATURE_LIMITS,
} from "@antireverse/protocol";
import { jwkThumbprint, signRequestForTest, verifyRequestSignature } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import {
  CONTENT_HASH_HEADER,
  CONTENT_SHA256_PATTERN,
  canonicalSigningString,
  createKeyCache,
  createNonceStore,
  createSignatureChecker,
  EMPTY_CONTENT_SHA256,
  KEY_CACHE_MAX,
  NONCE_KEEP_S,
  NONCE_STORE_MAX,
  parseSignatureHeader,
  type SessionBinding,
  SIGNATURE_HEADER,
  verifySignature,
  WINDOW_S,
} from "../src/signature.ts";

const NOW_S = 1_794_300_000;
const NOW_MS = NOW_S * 1000;
const JTI = "0123456789abcdef0123456789abcdef";
const NONCE = "AAAAAAAAAAAAAAAAAAAAAA";

interface SessionKey {
  privateKey: KeyObject;
  jwk: { kty: "EC"; crv: "P-256"; x: string; y: string };
  jkt: string;
}

function sessionKey(): SessionKey {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });
  const exported = publicKey.export({ format: "jwk" });
  const jwk = { kty: "EC" as const, crv: "P-256" as const, x: exported.x as string, y: exported.y as string };
  return { privateKey, jwk, jkt: jwkThumbprint(jwk) };
}

const session = sessionKey();
const other = sessionKey();
const sha = (text: string): string => createHash("sha256").update(text, "utf8").digest("base64url");

describe("Shield's signature constants are the protocol's", () => {
  it("headers, limits, the empty hash and the hash pattern", () => {
    expect(SIGNATURE_HEADER).toBe(PROTOCOL_SIGNATURE_HEADER);
    expect(CONTENT_HASH_HEADER).toBe(PROTOCOL_CONTENT_HASH_HEADER);
    expect(WINDOW_S).toBe(SIGNATURE_LIMITS.windowS);
    expect(NONCE_KEEP_S).toBe(SIGNATURE_LIMITS.nonceKeepS);
    expect(NONCE_STORE_MAX).toBe(SIGNATURE_LIMITS.nonceStoreMax);
    expect(KEY_CACHE_MAX).toBe(10_000);
    expect(EMPTY_CONTENT_SHA256).toBe(PROTOCOL_EMPTY);
    expect(EMPTY_CONTENT_SHA256).toBe(sha(""));
    expect(CONTENT_SHA256_PATTERN.source).toBe(PROTOCOL_CONTENT_SHA256_PATTERN.source);
    expect(CONTENT_SHA256_PATTERN.flags).toBe(PROTOCOL_CONTENT_SHA256_PATTERN.flags);
  });

  it("parseSignatureHeader agrees with the protocol on valid and malformed values", () => {
    const valid = signRequestForTest({
      privateKey: session.privateKey,
      method: "GET",
      target: "/",
      contentType: "",
      contentSha256: EMPTY_CONTENT_SHA256,
      jti: JTI,
      t: NOW_S,
      n: NONCE,
    });
    const values: unknown[] = [
      valid,
      `${valid} `,
      ` ${valid}`,
      valid.replace("v1,", "v2,"),
      valid.replace(",n=", ", n="),
      valid.replace(`t=${NOW_S}`, `t=0${NOW_S}`),
      valid.replace(`t=${NOW_S}`, "t=0"),
      valid.replace(`t=${NOW_S}`, "t=12345678901"),
      valid.replace(`n=${NONCE}`, "n=AAAAAAAAAAAAAAAAAAAAAB"),
      valid.replace(`n=${NONCE}`, `n=${NONCE}A`),
      valid.slice(0, -1),
      `${valid.slice(0, -1)}B`,
      `v1,n=${NONCE},t=${NOW_S},s=${valid.split("s=")[1]}`,
      `${valid},t=1`,
      "",
      undefined,
      null,
      7,
      [valid],
    ];
    for (const value of values) expect(parseSignatureHeader(value), String(value)).toEqual(protocolParse(value));
  });

  it("canonicalSigningString is the protocol's, byte for byte, and refuses what it refuses", () => {
    const inputs = [
      {
        method: "get",
        target: "/api/x?a=1&b=%20",
        contentType: "",
        contentSha256: EMPTY_CONTENT_SHA256,
        t: 5,
        n: NONCE,
        jti: JTI,
      },
      {
        method: "PoSt",
        target: "/ü/€",
        contentType: "application/json; charset=utf-8",
        contentSha256: sha("x"),
        t: 0,
        n: NONCE,
        jti: JTI,
      },
      { method: "GET", target: "", contentType: "", contentSha256: "", t: NOW_S, n: "", jti: "" },
    ];
    for (const input of inputs) expect(canonicalSigningString(input)).toBe(protocolCanonical(input));
    const bad: unknown[] = [
      { ...inputs[0], target: "/a\nb" },
      { ...inputs[0], t: -1 },
      { ...inputs[0], t: 1.5 },
      { ...inputs[0], method: 7 },
      { ...inputs[0], jti: null },
      { ...inputs[0], contentType: "text/plain\n" },
      { ...inputs[0], contentType: undefined },
      { ...inputs[0], contentType: ["text/plain"] },
    ];
    for (const input of bad) {
      expect(() => protocolCanonical(input as never)).toThrow(TypeError);
      expect(() => canonicalSigningString(input as never)).toThrow(TypeError);
    }
  });
});

describe("differential: verifySignature gives verifyRequestSignature's result on valid and mutated requests", () => {
  const base = {
    method: "POST",
    target: "/api/orders?id=42",
    contentType: "application/json",
    contentSha256: sha('{"a":1}'),
    jti: JTI,
  };
  const header = signRequestForTest({ privateKey: session.privateKey, ...base, t: NOW_S, n: NONCE });
  const der = (() => {
    const canonical = protocolCanonical({ ...base, t: NOW_S, n: NONCE });
    const signature = sign("sha256", Buffer.from(canonical, "utf8"), session.privateKey).toString("base64url");
    return `v1,t=${NOW_S},n=${NONCE},s=${signature}`;
  })();
  const s = header.split("s=")[1] as string;
  const flipChar = (text: string, at: number): string =>
    text.slice(0, at) + (text[at] === "A" ? "B" : "A") + text.slice(at + 1);

  type Input = Parameters<typeof verifyRequestSignature>[0];
  const corpus: Input[] = [];
  const good: Input = { ...base, header, jwk: session.jwk, nowS: NOW_S };
  corpus.push(good);
  for (const nowS of [NOW_S - 60, NOW_S + 60, NOW_S - 61, NOW_S + 61, NOW_S + 1e6, Number.NaN, Infinity]) {
    corpus.push({ ...good, nowS });
  }
  corpus.push({ ...good, method: "post" }); // the method is upper-cased on both sides
  corpus.push({ ...good, method: "PUT" });
  corpus.push({ ...good, target: "/api/orders?id=43" });
  corpus.push({ ...good, target: "/api/Orders?id=42" });
  corpus.push({ ...good, target: "/api/orders?id=42&" });
  corpus.push({ ...good, target: "/api/%6Frders?id=42" });
  corpus.push({ ...good, target: "/api/orders\n?id=42" });
  corpus.push({ ...good, contentSha256: sha('{"a":2}') });
  corpus.push({ ...good, contentType: "" });
  corpus.push({ ...good, contentType: "text/plain" });
  corpus.push({ ...good, contentType: "application/json; charset=utf-8" });
  corpus.push({ ...good, contentType: "APPLICATION/JSON" });
  corpus.push({ ...good, contentType: "application/json\n" });
  corpus.push({ ...good, contentType: undefined as unknown as string });
  corpus.push({ ...good, contentSha256: `${base.contentSha256.slice(0, 42)}B` });
  corpus.push({ ...good, contentSha256: base.contentSha256.slice(1) });
  corpus.push({ ...good, contentSha256: "" });
  corpus.push({ ...good, contentSha256: 7 as unknown as string });
  corpus.push({ ...good, jti: "fedcba9876543210fedcba9876543210" });
  corpus.push({ ...good, jti: 7 as unknown as string });
  corpus.push({ ...good, jwk: other.jwk });
  corpus.push({ ...good, jwk: undefined });
  corpus.push({ ...good, jwk: null });
  corpus.push({ ...good, jwk: { ...session.jwk, crv: "P-384" } });
  corpus.push({ ...good, jwk: { ...session.jwk, kty: "OKP" } });
  corpus.push({ ...good, jwk: { ...session.jwk, extra: 1, d: "x" } });
  corpus.push({ ...good, jwk: { ...session.jwk, x: session.jwk.y } }); // off the curve, almost surely
  corpus.push({ ...good, jwk: { ...session.jwk, x: `${session.jwk.x.slice(0, 42)}B` } });
  corpus.push({ ...good, jwk: { ...session.jwk, x: `${session.jwk.x}=` } });
  corpus.push({ ...good, header: der });
  corpus.push({ ...good, header: header.replace(`n=${NONCE}`, "n=AAAAAAAAAAAAAAAAAAAAAQ") });
  corpus.push({ ...good, header: header.replace(`t=${NOW_S}`, `t=${NOW_S + 1}`) });
  corpus.push({ ...good, header: `${header} ` });
  corpus.push({ ...good, header: undefined });
  corpus.push({ ...good, header: [header] });
  for (let at = 0; at < s.length; at += 5) corpus.push({ ...good, header: header.replace(s, flipChar(s, at)) });
  // A stale signature that verified, and a stale one that did not: only the first is "stale".
  const old = signRequestForTest({ privateKey: session.privateKey, ...base, t: NOW_S - 200, n: NONCE });
  corpus.push({ ...good, header: old });
  corpus.push({ ...good, header: old, jwk: other.jwk });

  it(`agrees on ${corpus.length} requests, with and without the key cache`, () => {
    const keys = createKeyCache();
    const seen = { valid: 0, invalid: 0, stale: 0 };
    for (const input of corpus) {
      const reference = verifyRequestSignature(input);
      expect(verifySignature(input), JSON.stringify(input)).toBe(reference);
      const jwk = input.jwk as { x?: unknown } | null | undefined;
      const jkt = jwk === session.jwk ? session.jkt : jwk === other.jwk ? other.jkt : session.jkt;
      expect(verifySignature({ ...input, jkt }, keys), JSON.stringify(input)).toBe(reference);
      seen[reference] += 1;
    }
    expect(seen.valid).toBeGreaterThanOrEqual(4);
    expect(seen.stale).toBeGreaterThanOrEqual(3);
    expect(seen.invalid).toBeGreaterThan(20);
  });

  it("a DER signature is invalid, P1363 of the same request is valid", () => {
    expect(verifySignature({ ...good, header: der })).toBe("invalid");
    expect(verifySignature(good)).toBe("valid");
  });
});

describe("createKeyCache: one import per jkt, bounded", () => {
  it("returns one KeyObject per jkt, and re-imports when the coordinates differ from the cached ones", () => {
    const keys = createKeyCache();
    const first = keys.get(session.jkt, session.jwk);
    expect(first?.asymmetricKeyType).toBe("ec");
    expect(keys.get(session.jkt, { ...session.jwk })).toBe(first);
    expect(keys.size()).toBe(1);
    // The same jkt with other coordinates never gets the cached key.
    const swapped = keys.get(session.jkt, other.jwk);
    expect(swapped).not.toBe(first);
    expect(swapped?.export({ format: "jwk" }).x).toBe(other.jwk.x);
    expect(keys.get(session.jkt, session.jwk)?.export({ format: "jwk" }).x).toBe(session.jwk.x);
    expect(keys.get(session.jkt, { ...session.jwk, crv: "P-384" })).toBeNull();
  });

  it("holds at most its maximum", () => {
    const keys = createKeyCache(2);
    const three = [sessionKey(), sessionKey(), sessionKey()];
    for (const key of three) keys.get(key.jkt, key.jwk);
    expect(keys.size()).toBe(2);
  });
});

describe("createNonceStore: bounded, kept until its expiry, never evicts a live entry", () => {
  const KEEP_MS = NONCE_KEEP_S * 1000;

  it("remembers a nonce until the absolute expiry it was given: seen before, fresh again from it", () => {
    const store = createNonceStore();
    const until = NOW_MS + KEEP_MS;
    expect(store.check("a", NOW_MS, until)).toBe("fresh");
    expect(store.check("a", NOW_MS, until)).toBe("seen");
    expect(store.check("a", until - 1, until)).toBe("seen");
    expect(store.check("a", until, until + KEEP_MS)).toBe("fresh");
    expect(store.check("b", NOW_MS, until)).toBe("fresh");
  });

  it("the expiry is the one given, not a fixed time from first sight", () => {
    const store = createNonceStore();
    expect(store.check("short", NOW_MS, NOW_MS + 1_000)).toBe("fresh");
    expect(store.check("long", NOW_MS, NOW_MS + 121_000)).toBe("fresh");
    expect(store.check("short", NOW_MS + 1_000, NOW_MS + 2_000)).toBe("fresh");
    expect(store.check("long", NOW_MS + 120_999, NOW_MS + 121_000)).toBe("seen");
  });

  it("when full of live entries refuses a new nonce ('full'), still recognises a seen one, and evicts none", () => {
    const store = createNonceStore({ max: 3 });
    const until = NOW_MS + KEEP_MS;
    for (const key of ["a", "b", "c"]) expect(store.check(key, NOW_MS, until)).toBe("fresh");
    expect(store.check("d", NOW_MS + 1, until)).toBe("full");
    expect(store.check("d", NOW_MS + 2, until)).toBe("full");
    expect(store.size()).toBe(3);
    for (const key of ["a", "b", "c"]) expect(store.check(key, NOW_MS + 3, until)).toBe("seen");
    // Once the oldest expired, it is swept and the new nonce fits.
    expect(store.check("d", until, until + KEEP_MS)).toBe("fresh");
    expect(store.size()).toBeLessThanOrEqual(3);
  });

  it("when full, an expired entry behind a live one (expiries out of insertion order) is swept, not a live one", () => {
    const store = createNonceStore({ max: 3 });
    expect(store.check("long", NOW_MS, NOW_MS + 121_000)).toBe("fresh");
    expect(store.check("short1", NOW_MS, NOW_MS + 1_000)).toBe("fresh");
    expect(store.check("short2", NOW_MS, NOW_MS + 1_000)).toBe("fresh");
    expect(store.check("new", NOW_MS + 5_000, NOW_MS + 66_000)).toBe("fresh");
    expect(store.size()).toBe(2);
    expect(store.check("long", NOW_MS + 6_000, NOW_MS + 67_000)).toBe("seen");
  });

  it("sweeps expired entries so that memory stays bounded by live entries", () => {
    const store = createNonceStore({ max: 1000 });
    for (let i = 0; i < 1000; i++) store.check(`k${i}`, NOW_MS, NOW_MS + KEEP_MS);
    expect(store.check("late", NOW_MS + KEEP_MS, NOW_MS + 2 * KEEP_MS)).toBe("fresh");
    expect(store.size()).toBe(1);
  });

  it("defaults to 100,000 entries", () => {
    const store = createNonceStore();
    expect(store.max).toBe(NONCE_STORE_MAX);
  });
});

/** A request double as node:http and Express give it. */
function request(
  headers: Record<string, string | string[]>,
  overrides: { method?: string; originalUrl?: string; url?: string } = {},
): import("node:http").IncomingMessage {
  return {
    method: overrides.method ?? "GET",
    url: overrides.url ?? "/api/data?x=1",
    originalUrl: overrides.originalUrl ?? overrides.url ?? "/api/data?x=1",
    headers,
  } as unknown as import("node:http").IncomingMessage;
}

const BINDING: SessionBinding = { jti: JTI, jkt: session.jkt, jwk: session.jwk };

function signedHeaders(
  options: {
    method?: string;
    target?: string;
    hash?: string;
    t?: number;
    n?: string;
    key?: SessionKey;
    /** Signed and sent as `content-type`; signed as "" and not sent when left out. */
    contentType?: string;
  } = {},
): Record<string, string> {
  const hash = options.hash ?? EMPTY_CONTENT_SHA256;
  return {
    ...(options.contentType === undefined ? {} : { "content-type": options.contentType }),
    "ar-signature": signRequestForTest({
      privateKey: (options.key ?? session).privateKey,
      method: options.method ?? "GET",
      target: options.target ?? "/api/data?x=1",
      contentType: options.contentType ?? "",
      contentSha256: hash,
      jti: JTI,
      t: options.t ?? NOW_S,
      n: options.n ?? NONCE,
    }),
    "ar-content-sha256": hash,
  };
}

describe("createSignatureChecker: the status of one request", () => {
  it("missing without ar-signature: body null", () => {
    const checker = createSignatureChecker();
    expect(checker.check(request({}), BINDING, NOW_MS)).toMatchObject({ status: "missing", body: null });
    expect(checker.check(request({ "ar-content-sha256": EMPTY_CONTENT_SHA256 }), BINDING, NOW_MS)).toMatchObject({
      status: "missing",
      body: null,
    });
  });

  it("valid, with body none, for a request without a body signed over the raw originalUrl", () => {
    const checker = createSignatureChecker();
    expect(checker.check(request(signedHeaders()), BINDING, NOW_MS)).toMatchObject({ status: "valid", body: "none" });
    // Express strips a mount point from req.url; the signed target is originalUrl.
    const mounted = request(signedHeaders({ target: "/api/data?x=1", n: "AAAAAAAAAAAAAAAAAAAABA" }), {
      url: "/data?x=1",
      originalUrl: "/api/data?x=1",
    });
    expect(checker.check(mounted, BINDING, NOW_MS).status).toBe("valid");
  });

  it.each([
    ["no valid token (no binding)", signedHeaders(), null],
    ["a token without cnf.jwk", signedHeaders(), { jti: JTI, jkt: session.jkt, jwk: null }],
    ["a signature by another key", signedHeaders({ key: other }), BINDING],
    ["a malformed header", { ...signedHeaders(), "ar-signature": "v1,t=1" }, BINDING],
    ["no content hash header", { "ar-signature": signedHeaders()["ar-signature"] as string }, BINDING],
    ["a malformed content hash", { ...signedHeaders(), "ar-content-sha256": "abc" }, BINDING],
    ["another method", signedHeaders({ method: "DELETE" }), BINDING],
    ["another target", signedHeaders({ target: "/api/data?x=2" }), BINDING],
    ["a request without a body whose hash is not the empty hash", signedHeaders({ hash: sha("x") }), BINDING],
    [
      "a content type other than the signed one",
      { ...signedHeaders({ contentType: "application/json" }), "content-type": "text/plain" },
      BINDING,
    ],
    ["a content type sent but none signed", { ...signedHeaders(), "content-type": "application/json" }, BINDING],
    [
      "a content type signed but none sent",
      (() => {
        const { "content-type": _sent, ...rest } = signedHeaders({ contentType: "application/json" });
        return rest;
      })(),
      BINDING,
    ],
    [
      "a content type Node gives as a list",
      { ...signedHeaders({ contentType: "application/json" }), "content-type": ["application/json"] },
      BINDING,
    ],
  ])("invalid for %s", (_name, headers, binding) => {
    const checker = createSignatureChecker();
    expect(
      checker.check(request(headers as Record<string, string>), binding as SessionBinding | null, NOW_MS),
    ).toMatchObject({
      status: "invalid",
      body: "none",
    });
  });

  it("stale beyond 60 s either way, valid at exactly 60 s", () => {
    const checker = createSignatureChecker();
    const at = (t: number, n: string) => checker.check(request(signedHeaders({ t, n })), BINDING, NOW_MS).status;
    expect(at(NOW_S - 61, "AAAAAAAAAAAAAAAAAAAAAA")).toBe("stale");
    expect(at(NOW_S + 61, "AAAAAAAAAAAAAAAAAAAABA")).toBe("stale");
    expect(at(NOW_S - 60, "AAAAAAAAAAAAAAAAAAAACA")).toBe("valid");
    expect(at(NOW_S + 60, "AAAAAAAAAAAAAAAAAAAADA")).toBe("valid");
  });

  it("valid with the exact content type sent and signed (review F1)", () => {
    const checker = createSignatureChecker();
    const headers = signedHeaders({ contentType: "application/json; charset=utf-8" });
    expect(checker.check(request(headers), BINDING, NOW_MS)).toMatchObject({ status: "valid", body: "none" });
  });

  it("F5 boundary: first seen at a whole second with t = now + 60, every replay until stale is replayed", () => {
    const checker = createSignatureChecker();
    const t = NOW_S + 60;
    const n = "AAAAAAAAAAAAAAAAAAAAOA";
    const at = (nowMs: number) => checker.check(request(signedHeaders({ t, n })), BINDING, nowMs).status;
    expect(at(NOW_MS)).toBe("valid");
    // Stale only once now − t > 60 s, i.e. from (t + 61) s: until then a replay is caught, not accepted again.
    for (const offset of [1_000, 60_000, 119_999, 120_000, 120_500, 120_999]) {
      expect(at(NOW_MS + offset), String(offset)).toBe("replayed");
    }
    expect(at(NOW_MS + 121_000)).toBe("stale");
    expect(at(NOW_MS + 121_000 + 3_600_000)).toBe("stale");
  });

  it("F5: a nonce of a request signed with t = now − 60 is forgotten once it would be stale anyway", () => {
    const checker = createSignatureChecker();
    const n = "AAAAAAAAAAAAAAAAAAAAPA";
    expect(checker.check(request(signedHeaders({ t: NOW_S - 60, n })), BINDING, NOW_MS).status).toBe("valid");
    expect(checker.stats().nonces).toBe(1);
    expect(checker.check(request(signedHeaders({ t: NOW_S - 60, n })), BINDING, NOW_MS + 999).status).toBe("replayed");
    // At now + 1 s it is stale (and its nonce no longer needed): a fresh request sweeps it.
    expect(checker.check(request(signedHeaders({ t: NOW_S - 60, n })), BINDING, NOW_MS + 1_000).status).toBe("stale");
    expect(
      checker.check(request(signedHeaders({ t: NOW_S + 1, n: "AAAAAAAAAAAAAAAAAAAAQA" })), BINDING, NOW_MS + 1_000)
        .status,
    ).toBe("valid");
    expect(checker.stats().nonces).toBe(1);
  });

  it("replayed: the same (jti, n) a second time while not stale; another jti with the same n is fresh", () => {
    const checker = createSignatureChecker();
    expect(checker.check(request(signedHeaders()), BINDING, NOW_MS).status).toBe("valid");
    expect(checker.check(request(signedHeaders()), BINDING, NOW_MS + 1000).status).toBe("replayed");
    const otherJti = "fedcba9876543210fedcba9876543210";
    const headers = {
      "ar-signature": signRequestForTest({
        privateKey: session.privateKey,
        method: "GET",
        target: "/api/data?x=1",
        contentType: "",
        contentSha256: EMPTY_CONTENT_SHA256,
        jti: otherJti,
        t: NOW_S,
        n: NONCE,
      }),
      "ar-content-sha256": EMPTY_CONTENT_SHA256,
    };
    expect(checker.check(request(headers), { ...BINDING, jti: otherJti }, NOW_MS).status).toBe("valid");
  });

  it("a nonce is consumed only after a valid signature: invalid and stale requests do not burn it", () => {
    const checker = createSignatureChecker();
    const n = "AAAAAAAAAAAAAAAAAAAAEA";
    expect(checker.check(request(signedHeaders({ n, key: other })), BINDING, NOW_MS).status).toBe("invalid");
    expect(checker.check(request(signedHeaders({ n, t: NOW_S - 100 })), BINDING, NOW_MS).status).toBe("stale");
    expect(checker.check(request(signedHeaders({ n })), null, NOW_MS).status).toBe("invalid");
    expect(checker.check(request(signedHeaders({ n })), BINDING, NOW_MS).status).toBe("valid");
    expect(checker.check(request(signedHeaders({ n })), BINDING, NOW_MS).status).toBe("replayed");
  });

  it("a full nonce store makes a new signed request invalid and evicts no live entry", () => {
    const checker = createSignatureChecker({ nonceMax: 2 });
    const nonces = ["AAAAAAAAAAAAAAAAAAAAFA", "AAAAAAAAAAAAAAAAAAAAGA", "AAAAAAAAAAAAAAAAAAAAHA"];
    const check = (n: string, nowMs = NOW_MS) => checker.check(request(signedHeaders({ n })), BINDING, nowMs).status;
    expect(check(nonces[0] as string)).toBe("valid");
    expect(check(nonces[1] as string)).toBe("valid");
    expect(check(nonces[2] as string)).toBe("invalid");
    expect(checker.stats().nonces).toBe(2);
    // Both live entries are still there: a replay of either is caught.
    expect(check(nonces[0] as string)).toBe("replayed");
    expect(check(nonces[1] as string)).toBe("replayed");
    // The refused nonce was not remembered either.
    expect(checker.stats().nonces).toBe(2);
  });

  it("a request with a body is unchecked until the body hook runs; no body means content-length 0 or absent", () => {
    const checker = createSignatureChecker();
    const hash = sha('{"a":1}');
    const withBody = request(
      { ...signedHeaders({ method: "POST", hash, n: "AAAAAAAAAAAAAAAAAAAAIA" }), "content-length": "7" },
      { method: "POST" },
    );
    expect(checker.check(withBody, BINDING, NOW_MS)).toMatchObject({ status: "valid", body: "unchecked" });
    const chunked = request(
      { ...signedHeaders({ method: "POST", hash, n: "AAAAAAAAAAAAAAAAAAAAJA" }), "transfer-encoding": "chunked" },
      { method: "POST" },
    );
    expect(checker.check(chunked, BINDING, NOW_MS)).toMatchObject({ status: "valid", body: "unchecked" });
    const empty = request(
      { ...signedHeaders({ method: "POST", n: "AAAAAAAAAAAAAAAAAAAAKA" }), "content-length": "0" },
      { method: "POST" },
    );
    expect(checker.check(empty, BINDING, NOW_MS)).toMatchObject({ status: "valid", body: "none" });
  });

  it("verifyBody: equal bytes → checked; other bytes → mismatch and invalid, no throw unless the state refuses", () => {
    const checker = createSignatureChecker();
    const hash = sha('{"a":1}');
    const make = (n: string) =>
      request({ ...signedHeaders({ method: "POST", hash, n }), "content-length": "7" }, { method: "POST" });
    const good = make("AAAAAAAAAAAAAAAAAAAALA");
    checker.check(good, BINDING, NOW_MS);
    checker.verifyBody(good, Buffer.from('{"a":1}'));
    expect(checker.stateOf(good)).toMatchObject({ status: "valid", body: "checked" });

    // No enforced requirement: the mismatch is recorded and the parser goes on.
    const recorded = make("AAAAAAAAAAAAAAAAAAAANA");
    checker.check(recorded, BINDING, NOW_MS);
    expect(() => checker.verifyBody(recorded, Buffer.from('{"a":2}'))).not.toThrow();
    expect(checker.stateOf(recorded)).toMatchObject({ status: "invalid", body: "mismatch" });
  });

  it("verifyBody under an enforced requirement (refuse): a mismatch throws the fixed 403 error", () => {
    const checker = createSignatureChecker();
    const hash = sha('{"a":1}');
    const bad = request(
      { ...signedHeaders({ method: "POST", hash, n: "AAAAAAAAAAAAAAAAAAAAMA" }), "content-length": "7" },
      { method: "POST" },
    );
    const state = checker.check(bad, BINDING, NOW_MS);
    expect(state.refuse).toBe(false);
    state.refuse = true;
    let thrown: unknown;
    try {
      checker.verifyBody(bad, Buffer.from('{"a":2}'));
    } catch (error) {
      thrown = error;
    }
    expect(thrown).toBeInstanceOf(Error);
    expect(thrown).toMatchObject({ message: "request_blocked", status: 403, statusCode: 403, expose: false });
    expect(String((thrown as Error).message)).not.toContain(hash);
    expect(checker.stateOf(bad)).toMatchObject({ status: "invalid", body: "mismatch" });
  });

  it("verifyBody does nothing for a request it holds no state for, or without a signature", () => {
    const checker = createSignatureChecker();
    expect(() => checker.verifyBody(request({}), Buffer.from("x"))).not.toThrow();
    const unsigned = request({ "content-length": "1" }, { method: "POST" });
    checker.check(unsigned, BINDING, NOW_MS);
    expect(() => checker.verifyBody(unsigned, Buffer.from("x"))).not.toThrow();
    expect(checker.stateOf(unsigned)).toMatchObject({ status: "missing", body: null });
  });
});

describe("tokens with cnf.jwk: Shield's token verifier keeps the session key and agrees with the protocol", () => {
  it("valid with the jwk, invalid for a malformed jwk, extra members dropped; the cached binding carries it", async () => {
    const { verifyAttestationToken } = await import("@antireverse/protocol/server");
    const { verifyAttestation, createAttestationChecker } = await import("../src/attestation.ts");
    const { buildPolicy } = await import("../src/policy/store.ts");
    const { importPublicKey } = await import("../src/policy/verify.ts");
    const helpers = await import("./attestation-helpers.ts");
    const key = helpers.createAttestationKey();
    const policy = buildPolicy({
      version: 1,
      issuedAt: 0,
      notAfter: Number.POSITIVE_INFINITY,
      rules: [],
      appId: helpers.APP_ID,
      attestationKeys: [
        {
          kid: key.kid,
          publicKey: key.publicKey,
          key: importPublicKey(key.publicKey) as NonNullable<ReturnType<typeof importPublicKey>>,
        },
      ],
    });
    const good = helpers.claims(NOW_S, { cnf: { jkt: session.jkt, jwk: session.jwk } });
    const variants: unknown[] = [
      good,
      { ...good, cnf: { jkt: session.jkt } },
      { ...good, cnf: { jkt: session.jkt, jwk: { ...session.jwk, d: "secret", extra: 1 } } },
      { ...good, cnf: { jkt: session.jkt, jwk: null } },
      { ...good, cnf: { jkt: session.jkt, jwk: { ...session.jwk, crv: "P-384" } } },
      { ...good, cnf: { jkt: session.jkt, jwk: { ...session.jwk, kty: "RSA" } } },
      { ...good, cnf: { jkt: session.jkt, jwk: { ...session.jwk, x: `${session.jwk.x.slice(0, 42)}B` } } },
      { ...good, cnf: { jkt: session.jkt, jwk: { kty: "EC", crv: "P-256", x: session.jwk.x } } },
      { ...good, cnf: { jkt: session.jkt, jwk: "text" } },
    ];
    let valids = 0;
    for (const variant of variants) {
      const given = helpers.craft(key, helpers.header(key), variant);
      const reference = verifyAttestationToken(given, [key.entry], { appId: helpers.APP_ID, nowS: NOW_S });
      expect(verifyAttestation(given, policy, NOW_S), JSON.stringify(variant)).toEqual(reference);
      if (reference.status === "valid") valids += 1;
    }
    expect(valids).toBe(3);
    const checker = createAttestationChecker();
    const given = helpers.token(key, good);
    const first = checker.checkBound(policy, given, NOW_S);
    expect(first.binding).toEqual({ jti: good.jti, jkt: session.jkt, jwk: session.jwk });
    expect(checker.checkBound(policy, given, NOW_S).binding).toBe(first.binding); // from the cache
    const without = checker.checkBound(policy, helpers.token(key, { ...good, cnf: { jkt: session.jkt } }), NOW_S);
    expect(without).toMatchObject({ result: { status: "valid" }, binding: { jwk: null } });
    // Slice 08: a valid token also names its device (`sub`), for device-keyed limits; any other result names none.
    expect(first.device).toBe(good.sub);
    expect(checker.checkBound(policy, "x.y.z", NOW_S)).toEqual({
      result: { status: "invalid", verdict: null, risk: null },
      binding: null,
      device: null,
    });
  });
});
