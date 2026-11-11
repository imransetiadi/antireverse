import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import {
  BODY_STATES,
  type BodyState,
  CONTENT_HASH_HEADER,
  CONTENT_SHA256_PATTERN,
  canonicalSigningString,
  EMPTY_CONTENT_SHA256,
  type EventSignature,
  EventSignatureSchema,
  parseSignatureHeader,
  SIGNATURE_HEADER,
  SIGNATURE_LIMITS,
  SIGNATURE_STATUSES,
  type SignatureStatus,
} from "../src/index.ts";

// Known answers computed independently of this package (2026-11-11):
// - EMPTY_CONTENT_SHA256: `printf '' | openssl dgst -sha256 -binary | base64 | tr '+/' '-_' | tr -d '='`.
// - BODY_SHA256: the same over `{"a":1}`.
// - the canonical string (with its content-type line, review F1): written with `printf` to a file; `wc -c` gives
//   167 bytes and `shasum -a 256` the hash.
const BODY_SHA256 = "AVq9f1zFei3ZS3WQ8ErYCEJzkF7jPsXOvq5iJ2qX-GI";
const NONCE = "AAECAwQFBgcICQoLDA0ODw";
const SIG = "IDA53HBew54o0q6SKAPT5l6ZVL2YPS6o93IQphlf0Xg_66t7A3OaaxKIS-JMZByG7hHRXcJOEqEsENiLA3O0YQ";
const JTI = "0123456789abcdef0123456789abcdef";
const T = 1_794_298_530;
const HEADER = `v1,t=${T},n=${NONCE},s=${SIG}`;
const EXAMPLE_INPUT = {
  method: "post",
  target: "/api/orders?id=7&q=a%20b",
  contentType: "application/json",
  contentSha256: BODY_SHA256,
  t: T,
  n: NONCE,
  jti: JTI,
};
const EXAMPLE_CANONICAL =
  "ar-sig-v1\nPOST\n/api/orders?id=7&q=a%20b\napplication/json\nAVq9f1zFei3ZS3WQ8ErYCEJzkF7jPsXOvq5iJ2qX-GI\n1794298530\nAAECAwQFBgcICQoLDA0ODw\n0123456789abcdef0123456789abcdef";
const EXAMPLE_CANONICAL_SHA256_HEX = "37d40ba4f05b5235de89f5106cac4c5c7c18f9d3e1ba31b8da11f0b2af7102f6";

describe("constants (contract P1)", () => {
  it("has the headers, limits, statuses and body states of the plan", () => {
    const status: SignatureStatus = "valid";
    const body: BodyState = "checked";
    expect(SIGNATURE_HEADER).toBe("ar-signature");
    expect(CONTENT_HASH_HEADER).toBe("ar-content-sha256");
    expect(SIGNATURE_LIMITS).toEqual({ windowS: 60, nonceKeepS: 61, nonceStoreMax: 100_000 });
    // F5: a nonce is kept until t + nonceKeepS, exactly as long as its signature is not stale.
    expect(SIGNATURE_LIMITS.nonceKeepS).toBe(SIGNATURE_LIMITS.windowS + 1);
    expect(SIGNATURE_STATUSES).toEqual([status, "missing", "invalid", "stale", "replayed"]);
    expect(BODY_STATES).toEqual([body, "unchecked", "mismatch", "none"]);
  });

  it("has the SHA-256 of the empty string as base64url (known answer)", () => {
    expect(EMPTY_CONTENT_SHA256).toBe("47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU");
    expect(createHash("sha256").update("").digest("base64url")).toBe(EMPTY_CONTENT_SHA256);
    expect(createHash("sha256").update('{"a":1}').digest("base64url")).toBe(BODY_SHA256);
  });
});

describe("CONTENT_SHA256_PATTERN", () => {
  it("accepts 43 canonical base64url characters", () => {
    expect(CONTENT_SHA256_PATTERN.test(EMPTY_CONTENT_SHA256)).toBe(true);
    expect(CONTENT_SHA256_PATTERN.test(BODY_SHA256)).toBe(true);
    for (const last of "AEIMQUYcgkosw048") expect(CONTENT_SHA256_PATTERN.test(`${"A".repeat(42)}${last}`)).toBe(true);
  });

  it("rejects other lengths, other alphabets, padding and non-canonical last characters", () => {
    expect(CONTENT_SHA256_PATTERN.test("A".repeat(42))).toBe(false);
    expect(CONTENT_SHA256_PATTERN.test("A".repeat(44))).toBe(false);
    expect(CONTENT_SHA256_PATTERN.test(`${EMPTY_CONTENT_SHA256}=`)).toBe(false);
    expect(CONTENT_SHA256_PATTERN.test(EMPTY_CONTENT_SHA256.replace("-", "+"))).toBe(false);
    expect(CONTENT_SHA256_PATTERN.test(EMPTY_CONTENT_SHA256.replace("_", "/"))).toBe(false);
    // 43 characters carry 258 bits: the last two must be zero.
    for (const last of "BFJNRVZdhlptx159-_")
      expect(CONTENT_SHA256_PATTERN.test(`${"A".repeat(42)}${last}`)).toBe(false);
    expect(CONTENT_SHA256_PATTERN.test(`${EMPTY_CONTENT_SHA256}\n`)).toBe(false);
  });
});

describe("parseSignatureHeader", () => {
  it("parses the documented form", () => {
    expect(parseSignatureHeader(HEADER)).toEqual({ t: T, n: NONCE, s: SIG });
    expect(parseSignatureHeader(`v1,t=0,n=${NONCE},s=${SIG}`)).toEqual({ t: 0, n: NONCE, s: SIG });
    expect(parseSignatureHeader(`v1,t=9999999999,n=${NONCE},s=${SIG}`)).toEqual({ t: 9_999_999_999, n: NONCE, s: SIG });
  });

  it.each([
    ["not a string (number)", 1],
    ["not a string (array, as Node gives repeated headers)", [HEADER]],
    ["null", null],
    ["undefined", undefined],
    ["the empty string", ""],
    ["another version", HEADER.replace("v1,", "v2,")],
    ["no version", HEADER.replace("v1,", "")],
    ["upper-case version", HEADER.replace("v1,", "V1,")],
    ["order n,t,s", `v1,n=${NONCE},t=${T},s=${SIG}`],
    ["order t,s,n", `v1,t=${T},s=${SIG},n=${NONCE}`],
    ["order s,n,t", `v1,s=${SIG},n=${NONCE},t=${T}`],
    ["t twice", `v1,t=${T},t=${T},n=${NONCE},s=${SIG}`],
    ["n twice", `v1,t=${T},n=${NONCE},n=${NONCE},s=${SIG}`],
    ["s twice", `${HEADER},s=${SIG}`],
    ["the header twice (joined by Node)", `${HEADER}, ${HEADER}`],
    ["t missing", `v1,n=${NONCE},s=${SIG}`],
    ["n missing", `v1,t=${T},s=${SIG}`],
    ["s missing", `v1,t=${T},n=${NONCE}`],
    ["an extra member", `${HEADER},x=1`],
    ["a space after a comma", `v1, t=${T},n=${NONCE},s=${SIG}`],
    ["a space around =", `v1,t = ${T},n=${NONCE},s=${SIG}`],
    ["a leading space", ` ${HEADER}`],
    ["a trailing space", `${HEADER} `],
    ["a trailing line feed", `${HEADER}\n`],
    ["a trailing comma", `${HEADER},`],
    ["upper-case keys", `v1,T=${T},N=${NONCE},S=${SIG}`],
    ["t with a leading zero", `v1,t=0${T},n=${NONCE},s=${SIG}`],
    ["t as 00", `v1,t=00,n=${NONCE},s=${SIG}`],
    ["t of 11 digits", `v1,t=10000000000,n=${NONCE},s=${SIG}`],
    ["t negative", `v1,t=-1,n=${NONCE},s=${SIG}`],
    ["t with a sign", `v1,t=+${T},n=${NONCE},s=${SIG}`],
    ["t with a fraction", `v1,t=${T}.5,n=${NONCE},s=${SIG}`],
    ["t in exponent form", `v1,t=1e9,n=${NONCE},s=${SIG}`],
    ["t empty", `v1,t=,n=${NONCE},s=${SIG}`],
    ["t with non-ASCII digits", `v1,t=١٢٣,n=${NONCE},s=${SIG}`],
    ["n of 21 characters", `v1,t=${T},n=${NONCE.slice(1)},s=${SIG}`],
    ["n of 23 characters", `v1,t=${T},n=${NONCE}A,s=${SIG}`],
    ["n with padding", `v1,t=${T},n=${NONCE}==,s=${SIG}`],
    ["n in base64 (+)", `v1,t=${T},n=${NONCE.replace("A", "+")},s=${SIG}`],
    ["n in base64 (/)", `v1,t=${T},n=${NONCE.replace("A", "/")},s=${SIG}`],
    ["n not canonical (last character B)", `v1,t=${T},n=${NONCE.slice(0, 21)}B,s=${SIG}`],
    ["n not canonical (last character x)", `v1,t=${T},n=${NONCE.slice(0, 21)}x,s=${SIG}`],
    ["s of 85 characters", `v1,t=${T},n=${NONCE},s=${SIG.slice(1)}`],
    ["s of 87 characters", `${HEADER}A`],
    ["s with padding", `${HEADER}==`],
    ["s in base64 (+)", `v1,t=${T},n=${NONCE},s=${SIG.replace("-", "+")}`],
    ["s not canonical (last character B)", `v1,t=${T},n=${NONCE},s=${SIG.slice(0, 85)}B`],
    ["s not canonical (last character _)", `v1,t=${T},n=${NONCE},s=${SIG.slice(0, 85)}_`],
    [
      "s as DER (70 bytes, 94 characters)",
      `v1,t=${T},n=${NONCE},s=MEQCICAwOdxwXsOeKNKukigD0-ZemVS9mD0uqPdyEKYZX9F4AiA_66t7A3OaaxKIS-JMZByG7hHRXcJOEqEsENiLA3O0YQ`,
    ],
  ])("returns null for %s", (_reason, value) => {
    expect(parseSignatureHeader(value)).toBeNull();
  });

  it("accepts every canonical last character of n and s (4 unused bits must be zero)", () => {
    for (const last of "AQgw") {
      const n = `${NONCE.slice(0, 21)}${last}`;
      const s = `${SIG.slice(0, 85)}${last}`;
      expect(parseSignatureHeader(`v1,t=${T},n=${n},s=${s}`)).toEqual({ t: T, n, s });
    }
  });
});

describe("canonicalSigningString", () => {
  it("builds the exact bytes of the documented example (pinned)", () => {
    const canonical = canonicalSigningString(EXAMPLE_INPUT);
    expect(canonical).toBe(EXAMPLE_CANONICAL);
    expect(Buffer.byteLength(canonical, "utf8")).toBe(167);
    expect(createHash("sha256").update(canonical, "utf8").digest("hex")).toBe(EXAMPLE_CANONICAL_SHA256_HEX);
    expect(canonical.endsWith("\n")).toBe(false);
  });

  it("upper-cases the method and keeps the target exactly as given", () => {
    for (const method of ["post", "Post", "POST"]) {
      expect(canonicalSigningString({ ...EXAMPLE_INPUT, method })).toBe(EXAMPLE_CANONICAL);
    }
    const target = "/API/Orders/%2F?b=2&a=1&a=1#frag";
    expect(canonicalSigningString({ ...EXAMPLE_INPUT, target }).split("\n")[2]).toBe(target);
  });

  it("keeps the content type exactly as sent, and an empty line when none was sent (review F1)", () => {
    const contentType = "Application/JSON; Charset=UTF-8";
    expect(canonicalSigningString({ ...EXAMPLE_INPUT, contentType }).split("\n")[3]).toBe(contentType);
    expect(canonicalSigningString({ ...EXAMPLE_INPUT, contentType: "" }).split("\n")).toEqual([
      "ar-sig-v1",
      "POST",
      "/api/orders?id=7&q=a%20b",
      "",
      BODY_SHA256,
      String(T),
      NONCE,
      JTI,
    ]);
    // Another content type is another string: the type is bound.
    expect(canonicalSigningString({ ...EXAMPLE_INPUT, contentType: "text/plain" })).not.toBe(EXAMPLE_CANONICAL);
  });

  it("requires the content type: leaving it out is a TypeError, not an empty line", () => {
    const { contentType: _left, ...without } = EXAMPLE_INPUT;
    expect(() => canonicalSigningString(without as never)).toThrow(TypeError);
  });

  it("puts every field in its own line, in order", () => {
    expect(canonicalSigningString({ ...EXAMPLE_INPUT, contentSha256: EMPTY_CONTENT_SHA256, t: 0 }).split("\n")).toEqual(
      ["ar-sig-v1", "POST", "/api/orders?id=7&q=a%20b", "application/json", EMPTY_CONTENT_SHA256, "0", NONCE, JTI],
    );
  });

  it.each(["method", "target", "contentType", "contentSha256", "n", "jti"] as const)(
    "throws a TypeError for a line feed in %s",
    (field) => {
      for (const value of [`${EXAMPLE_INPUT[field]}\n`, `\n${EXAMPLE_INPUT[field]}`, "a\nb"]) {
        expect(() => canonicalSigningString({ ...EXAMPLE_INPUT, [field]: value })).toThrow(TypeError);
      }
    },
  );

  it("throws a TypeError for a field that is not a string, or a t that is not a non-negative integer", () => {
    for (const field of ["method", "target", "contentType", "contentSha256", "n", "jti"] as const) {
      expect(() => canonicalSigningString({ ...EXAMPLE_INPUT, [field]: 7 } as never), field).toThrow(TypeError);
    }
    for (const t of [-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, "1794298530"]) {
      expect(() => canonicalSigningString({ ...EXAMPLE_INPUT, t } as never), String(t)).toThrow(TypeError);
    }
  });
});

describe("EventSignatureSchema", () => {
  const accepts = (value: unknown): boolean => EventSignatureSchema.safeParse(value).success;

  it("round-trips every allowed pair through JSON", () => {
    const pairs: EventSignature[] = [{ status: "missing", body: null }];
    for (const status of SIGNATURE_STATUSES.filter((s) => s !== "missing")) {
      for (const body of BODY_STATES) {
        if (body === "mismatch" && status !== "invalid") continue;
        pairs.push({ status, body });
      }
    }
    expect(pairs).toHaveLength(1 + 4 * 3 + 1);
    for (const value of pairs) {
      expect(EventSignatureSchema.parse(JSON.parse(JSON.stringify(value)))).toEqual(value);
    }
  });

  it("has a null body exactly when the status is missing (Jev: tighten_body_require_jwk, 0.74)", () => {
    expect(accepts({ status: "missing", body: null })).toBe(true);
    for (const body of BODY_STATES) expect(accepts({ status: "missing", body }), body).toBe(false);
    for (const status of SIGNATURE_STATUSES.filter((s) => s !== "missing")) {
      expect(accepts({ status, body: null }), status).toBe(false);
    }
  });

  it("records a body mismatch only with status invalid (plan: a mismatch makes the signature invalid)", () => {
    expect(accepts({ status: "invalid", body: "mismatch" })).toBe(true);
    for (const status of SIGNATURE_STATUSES.filter((s) => s !== "invalid")) {
      expect(accepts({ status, body: "mismatch" }), status).toBe(false);
    }
  });

  it("rejects unknown statuses and body states, and requires both members", () => {
    expect(accepts({ status: "forged", body: null })).toBe(false);
    expect(accepts({ status: "missing" })).toBe(false);
    expect(accepts({ status: "valid", body: "partial" })).toBe(false);
    expect(accepts({ status: "valid" })).toBe(false);
    expect(accepts({ body: "checked" })).toBe(false);
    expect(accepts("valid")).toBe(false);
  });

  it("never carries the signature, the nonce or the hash (privacy allowlist)", () => {
    expect(
      EventSignatureSchema.parse({ status: "valid", body: "checked", s: SIG, n: NONCE, content_sha256: BODY_SHA256 }),
    ).toEqual({ status: "valid", body: "checked" });
  });
});
