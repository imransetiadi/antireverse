// Review focus 2: a bundle that should not be trusted is refused, each cause with its own reason.
import {
  BundlePayloadSchema,
  EXAMPLE_BUNDLE_PAYLOAD,
  POLICY_LIMITS,
  SignedBundleSchema,
  SigningKeyResponseSchema,
} from "@antireverse/protocol";
import { bundleAudience, generateKey, keyIdOf } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import { matchPath, normalisePath } from "../src/policy/match.ts";
import { BUILT_IN_POLICY, createPolicyStore } from "../src/policy/store.ts";
import {
  audienceOf,
  BUNDLE_BYTES_MAX,
  importPublicKey,
  RESPONSE_BYTES_MAX,
  type VerifyContext,
  verifyBody,
  verifyBundle,
} from "../src/policy/verify.ts";
import { createSigner, DAY_MS, EPOCH, flip, NEW_EPOCH, NOW, payload, rule, signed } from "./policy-helpers.ts";

const KEY = generateKey("shield", "development").key;
const OTHER_KEY = generateKey("shield", "development").key;
const signer = createSigner();
const stranger = createSigner();

function context(overrides: Partial<VerifyContext> = {}): VerifyContext {
  const publicKey = importPublicKey(signer.publicKey);
  if (publicKey === null) throw new Error("the test key could not be imported");
  return {
    publicKey,
    audience: audienceOf(KEY),
    appliedVersion: 0,
    appliedEpoch: null,
    appliedIssuedAt: 0,
    now: NOW,
    ...overrides,
  };
}

describe("the test bundles are what the protocol describes", () => {
  it("a helper bundle passes the protocol's schemas, and the signer's key is a signing key of the API", () => {
    const envelope = signed(signer, payload(KEY));
    expect(SignedBundleSchema.safeParse(envelope).success).toBe(true);
    expect(BundlePayloadSchema.safeParse(JSON.parse(envelope.bundle)).success).toBe(true);
    expect(
      SigningKeyResponseSchema.safeParse({ key_id: signer.keyId, algorithm: "Ed25519", public_key: signer.publicKey })
        .success,
    ).toBe(true);
    expect(signer.keyId).toBe(keyIdOf(Buffer.from(signer.publicKey, "base64url")));
  });

  it("Shield's bounds are the protocol's", () => {
    expect(BUNDLE_BYTES_MAX).toBe(POLICY_LIMITS.bundleBytesMax);
    expect(RESPONSE_BYTES_MAX).toBe(131_072);
  });
});

describe("audienceOf", () => {
  it("is the protocol's bundleAudience, computed without the protocol: 32 hex characters that differ per key", () => {
    expect(audienceOf(KEY)).toBe(bundleAudience(KEY));
    expect(audienceOf(KEY)).toMatch(/^[0-9a-f]{32}$/);
    expect(audienceOf(OTHER_KEY)).not.toBe(audienceOf(KEY));
    expect(audienceOf(`ark_dev_${"A".repeat(43)}`)).toBe(EXAMPLE_BUNDLE_PAYLOAD.audience);
  });
});

describe("importPublicKey", () => {
  it("imports a raw Ed25519 public key given as 43 base64url characters", () => {
    const key = importPublicKey(signer.publicKey);
    expect(key?.type).toBe("public");
    expect(key?.asymmetricKeyType).toBe("ed25519");
  });

  it.each([
    ["nothing", undefined],
    ["null", null],
    ["an empty string", ""],
    ["42 characters", signer.publicKey.slice(1)],
    ["44 characters", `${signer.publicKey}A`],
    ["standard base64 with padding", `${signer.publicKey}=`],
    ["a character outside base64url", `${signer.publicKey.slice(0, 42)}+`],
    ["surrounding whitespace", ` ${signer.publicKey}`],
    ["a number", 42],
    ["an object", { x: signer.publicKey }],
    ["a PEM", "-----BEGIN PUBLIC KEY-----\nMCowBQYDK2VwAyEA\n-----END PUBLIC KEY-----"],
  ])("gives null for %s, without throwing", (_name, value) => {
    expect(importPublicKey(value)).toBeNull();
  });
});

describe("verifyBundle: a bundle Shield applies", () => {
  it("verifies the signature and compiles the Rules, in order", () => {
    const bundle = payload(KEY, {
      version: 3,
      rules: [
        rule(1, { path: "/api/products/**", mode: "monitor" }),
        rule(2, { path: "/api/admin/**", mode: "enforce" }),
        rule(3, { path: "/api/users/*/export", methods: ["GET", "POST"] }),
      ],
    });
    const result = verifyBundle(signed(signer, bundle), context());
    if (!result.ok) throw new Error(`refused: ${result.reason}`);
    expect(result.policy.version).toBe(3);
    expect(result.policy.issuedAt).toBe(NOW);
    expect(result.policy.notAfter).toBe(NOW + 7 * DAY_MS);
    expect(result.policy.rules.map((r) => [r.id, r.path, r.mode, r.methods])).toEqual([
      [rule(1).id, "/api/products/**", "monitor", []],
      [rule(2).id, "/api/admin/**", "enforce", []],
      [rule(3).id, "/api/users/*/export", "enforce", ["GET", "POST"]],
    ]);
    const admin = result.policy.rules[1];
    expect(admin && matchPath(admin.pattern, normalisePath("/API/admin/x?y"))).toBe(true);
  });

  it("applies the documented example of the protocol", () => {
    const result = verifyBundle(
      signed(signer, EXAMPLE_BUNDLE_PAYLOAD),
      context({ audience: audienceOf(`ark_dev_${"A".repeat(43)}`), now: Date.parse("2026-11-10T09:00:00.000Z") }),
    );
    expect(result.ok && result.policy.rules.map((r) => r.path)).toEqual(["/api/admin/**", "/api/users/*/export"]);
  });

  it("accepts version 0 without Rules, the bundle of an App nothing was published for", () => {
    const result = verifyBundle(signed(signer, payload(KEY, { version: 0, rules: [] })), context());
    expect(result.ok && [result.policy.version, result.policy.rules.length]).toEqual([0, 0]);
  });

  it("accepts the applied version again: a bundle issued anew carries a later not_after", () => {
    const later = new Date(NOW + DAY_MS).toISOString();
    const result = verifyBundle(
      signed(signer, payload(KEY, { version: 5, issued_at: later })),
      context({ appliedVersion: 5, appliedEpoch: EPOCH, now: NOW + DAY_MS }),
    );
    expect(result.ok && result.policy.notAfter).toBe(NOW + 8 * DAY_MS);
  });

  it("carries the epoch of the bundle into the applied Policy", () => {
    const result = verifyBundle(signed(signer, payload(KEY, { version: 3 })), context());
    expect(result.ok && result.policy.epoch).toBe(EPOCH);
  });

  it("accepts any version of a new epoch: the API's database was reset and its versions restarted", () => {
    for (const version of [0, 1, 4]) {
      const result = verifyBundle(
        signed(signer, payload(KEY, { version, epoch: NEW_EPOCH })),
        context({ appliedVersion: 5, appliedEpoch: EPOCH }),
      );
      if (!result.ok) throw new Error(`version ${version} of a new epoch refused: ${result.reason}`);
      expect([result.policy.version, result.policy.epoch]).toEqual([version, NEW_EPOCH]);
    }
  });

  it("refuses a bundle of another epoch that was issued before the applied one: a replay across a reset (decided with Jev)", () => {
    const applied = { appliedVersion: 5, appliedEpoch: EPOCH, appliedIssuedAt: NOW };
    const earlier = signed(
      signer,
      payload(KEY, { version: 9, epoch: NEW_EPOCH, issued_at: new Date(NOW - DAY_MS).toISOString() }),
    );
    expect(verifyBundle(earlier, context(applied))).toMatchObject({ ok: false, reason: "version" });
    const same = signed(signer, payload(KEY, { version: 1, epoch: NEW_EPOCH, issued_at: new Date(NOW).toISOString() }));
    expect(verifyBundle(same, context(applied))).toMatchObject({ ok: false, reason: "version" });
    const later = signed(
      signer,
      payload(KEY, { version: 1, epoch: NEW_EPOCH, issued_at: new Date(NOW + 1_000).toISOString() }),
    );
    const result = verifyBundle(later, context({ ...applied, now: NOW + 2_000 }));
    expect(result.ok && result.policy.epoch).toBe(NEW_EPOCH);
  });

  it("within one epoch still refuses an older version: a replay of an earlier bundle of the current epoch", () => {
    const old = signed(signer, payload(KEY, { version: 2, epoch: NEW_EPOCH }));
    expect(verifyBundle(old, context({ appliedVersion: 2, appliedEpoch: NEW_EPOCH })).ok).toBe(true);
    expect(verifyBundle(old, context({ appliedVersion: 3, appliedEpoch: NEW_EPOCH }))).toMatchObject({
      ok: false,
      reason: "version",
    });
  });

  it("accepts exactly 50 Rules and a bundle of exactly the maximum size", () => {
    const fifty = Array.from({ length: 50 }, (_, i) => rule(i, { path: `/r/${i}` }));
    expect(verifyBundle(signed(signer, payload(KEY, { rules: fifty })), context()).ok).toBe(true);

    const text = JSON.stringify(payload(KEY));
    const padded = `${text.slice(0, -1)}${" ".repeat(BUNDLE_BYTES_MAX - text.length)}}`;
    expect(Buffer.byteLength(padded)).toBe(BUNDLE_BYTES_MAX);
    expect(verifyBundle(signed(signer, padded), context()).ok).toBe(true);
  });

  it("ignores keys it does not know, at the top and inside a Rule", () => {
    const bundle = {
      ...payload(KEY, { version: 2 }),
      future_field: { nested: true },
      rules: [{ ...rule(1), name: "Admin area", conditions: [{ ip: "203.0.113.7" }] }],
    };
    const result = verifyBundle(signed(signer, bundle), context());
    if (!result.ok) throw new Error(`refused: ${result.reason}`);
    expect(Object.keys(result.policy.rules[0] ?? {}).sort()).toEqual(
      ["decision", "id", "methods", "mode", "path", "pattern"].sort(),
    );
    expect(JSON.stringify(result.policy)).not.toContain("203.0.113.7");
  });

  it("does not need app_id or environment: they name the App for people, the audience binds the bundle", () => {
    const { app_id: _app, environment: _environment, ...rest } = payload(KEY);
    expect(verifyBundle(signed(signer, rest), context()).ok).toBe(true);
  });
});

describe("verifyBundle: a bundle Shield refuses", () => {
  const valid = signed(signer, payload(KEY, { version: 2 }));
  const fiftyOne = Array.from({ length: 51 }, (_, i) => rule(i, { path: `/r/${i}` }));
  const withRule = (broken: unknown) => signed(signer, { ...payload(KEY), rules: [rule(1), broken] });

  const cases: [name: string, envelope: unknown, reason: string, ctx?: Partial<VerifyContext>][] = [
    [
      "one byte of the bundle changed",
      { ...valid, bundle: valid.bundle.replace('"version":2', '"version":3') },
      "signature",
    ],
    ["one character of the bundle flipped", { ...valid, bundle: flip(valid.bundle) }, "signature"],
    ["one character of the signature flipped", { ...valid, signature: flip(valid.signature) }, "signature"],
    ["a space appended to the bundle", { ...valid, bundle: `${valid.bundle} ` }, "signature"],
    ["a valid signature made with another key", signed(stranger, payload(KEY, { version: 2 })), "signature"],
    ["the signature of a different bundle", { ...valid, signature: signer.sign("{}") }, "signature"],
    ["a signature that is too short", { ...valid, signature: valid.signature.slice(1) }, "signature"],
    ["a signature in standard base64", { ...valid, signature: `${valid.signature.slice(0, 85)}+` }, "signature"],
    ["an empty signature", { ...valid, signature: "" }, "signature"],
    ["no signature", { bundle: valid.bundle }, "signature"],
    ["a signature that is not text", { ...valid, signature: 7 }, "signature"],
    ["another format", signed(signer, { ...payload(KEY), format: 2 }), "format"],
    ["no format", signed(signer, { ...payload(KEY), format: undefined }), "format"],
    ["the format as text", signed(signer, { ...payload(KEY), format: "1" }), "format"],
    ["the bundle of another Shield key", signed(signer, payload(OTHER_KEY)), "audience"],
    ["no audience", signed(signer, { ...payload(KEY), audience: undefined }), "audience"],
    [
      "an audience that is a prefix of the own",
      signed(signer, payload(KEY, { audience: audienceOf(KEY).slice(0, 16) })),
      "audience",
    ],
    [
      "an older version",
      signed(signer, payload(KEY, { version: 4 })),
      "version",
      { appliedVersion: 5, appliedEpoch: EPOCH },
    ],
    [
      "version 0 after a published Policy",
      signed(signer, payload(KEY, { version: 0, rules: [] })),
      "version",
      { appliedVersion: 1, appliedEpoch: EPOCH },
    ],
    [
      "a bundle of a new epoch with a bad signature",
      { ...signed(signer, payload(KEY, { version: 1, epoch: NEW_EPOCH })), signature: valid.signature },
      "signature",
      { appliedVersion: 5, appliedEpoch: EPOCH },
    ],
    [
      "a bundle of a new epoch for another Shield key",
      signed(signer, payload(OTHER_KEY, { version: 1, epoch: NEW_EPOCH })),
      "audience",
      { appliedVersion: 5, appliedEpoch: EPOCH },
    ],
    [
      "a bundle of a new epoch that expired",
      signed(signer, payload(KEY, { version: 1, epoch: NEW_EPOCH })),
      "expired",
      { appliedVersion: 5, appliedEpoch: EPOCH, now: NOW + 7 * DAY_MS },
    ],
    [
      "a bundle of a new epoch with 51 Rules",
      signed(signer, payload(KEY, { version: 1, epoch: NEW_EPOCH, rules: fiftyOne })),
      "invalid",
      { appliedVersion: 5, appliedEpoch: EPOCH },
    ],
    ["no epoch", signed(signer, { ...payload(KEY), epoch: undefined }), "invalid"],
    ["an epoch in upper case", signed(signer, payload(KEY, { epoch: EPOCH.toUpperCase() })), "invalid"],
    ["an epoch of 31 characters", signed(signer, payload(KEY, { epoch: EPOCH.slice(1) })), "invalid"],
    ["an epoch of 33 characters", signed(signer, payload(KEY, { epoch: `${EPOCH}0` })), "invalid"],
    ["an epoch that is not text", signed(signer, { ...payload(KEY), epoch: 12 }), "invalid"],
    ["a bundle that expired", valid, "expired", { now: NOW + 7 * DAY_MS + 1 }],
    ["a bundle that expires this instant", valid, "expired", { now: NOW + 7 * DAY_MS }],
    [
      "a not_after before issued_at, long ago",
      signed(signer, payload(KEY, { not_after: "2020-01-01T00:00:00.000Z" })),
      "expired",
    ],
    ["51 Rules", signed(signer, payload(KEY, { rules: fiftyOne })), "invalid"],
    ["200 Rules", signed(signer, payload(KEY, { rules: Array.from({ length: 200 }, (_, i) => rule(i)) })), "invalid"],
    ["Rules that are not a list", signed(signer, { ...payload(KEY), rules: { 0: rule(1) } }), "invalid"],
    ["no Rules member", signed(signer, { ...payload(KEY), rules: undefined }), "invalid"],
    ["a Rule that is null", withRule(null), "invalid"],
    ["a Rule that is text", withRule("/api/admin/**"), "invalid"],
    ["a pattern without a leading slash", withRule(rule(2, { path: "api/admin" })), "invalid"],
    ["a pattern with ** in the middle", withRule(rule(2, { path: "/a/**/b" })), "invalid"],
    ["a pattern with an empty segment", withRule(rule(2, { path: "/a//b" })), "invalid"],
    ["a pattern with a query string", withRule(rule(2, { path: "/a?x" })), "invalid"],
    ["a pattern with an encoded character", withRule(rule(2, { path: "/%61" })), "invalid"],
    ["a pattern with a regular-expression character", withRule(rule(2, { path: "/a(b|c)+" })), "invalid"],
    ["a pattern of 257 characters", withRule(rule(2, { path: `/${"a".repeat(256)}` })), "invalid"],
    ["a pattern that is not text", withRule({ ...rule(2), path: ["/a"] }), "invalid"],
    ["a Rule identifier of the wrong form", withRule(rule(2, { id: "rul_short" })), "invalid"],
    ["a Rule identifier in upper case", withRule(rule(2, { id: `rul_${"A".repeat(24)}` })), "invalid"],
    [
      "nine methods",
      withRule(rule(2, { methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "PURGE"] })),
      "invalid",
    ],
    ["a method in lower case", withRule(rule(2, { methods: ["get"] })), "invalid"],
    ["a method listed twice", withRule(rule(2, { methods: ["GET", "GET"] })), "invalid"],
    ["methods that are not a list", withRule({ ...rule(2), methods: "GET" }), "invalid"],
    ["an action Shield does not know", withRule({ ...rule(2), action: "allow" }), "invalid"],
    ["a mode Shield does not know", withRule({ ...rule(2), mode: "off" }), "invalid"],
    ["a negative version", signed(signer, payload(KEY, { version: -1 })), "invalid"],
    ["a fractional version", signed(signer, payload(KEY, { version: 1.5 })), "invalid"],
    ["a version as text", signed(signer, { ...payload(KEY), version: "3" }), "invalid"],
    ["a version beyond safe integers", signed(signer, payload(KEY, { version: 2 ** 60 })), "invalid"],
    ["a not_after that is not a time", signed(signer, payload(KEY, { not_after: "next week" })), "invalid"],
    ["a not_after without a time zone", signed(signer, payload(KEY, { not_after: "2026-11-17T08:00:00" })), "invalid"],
    ["no not_after", signed(signer, { ...payload(KEY), not_after: undefined }), "invalid"],
    ["an issued_at that is not a time", signed(signer, { ...payload(KEY), issued_at: 12 }), "invalid"],
    ["a signed bundle that is not JSON", signed(signer, "{not json"), "invalid"],
    ["a signed bundle that is a JSON list", signed(signer, "[]"), "invalid"],
    ["a signed bundle that is JSON null", signed(signer, "null"), "invalid"],
    ["a signed empty bundle", signed(signer, ""), "invalid"],
    ["a bundle that is not text", { bundle: payload(KEY), signature: valid.signature }, "invalid"],
    [
      "a signed bundle of 65,537 bytes",
      signed(signer, `${JSON.stringify(payload(KEY)).slice(0, -1)}${" ".repeat(BUNDLE_BYTES_MAX)}}`),
      "invalid",
    ],
    [
      "a signed bundle of 65,536 characters but more bytes",
      signed(signer, JSON.stringify({ ...payload(KEY), pad: "é".repeat(BUNDLE_BYTES_MAX) }).slice(0, BUNDLE_BYTES_MAX)),
      "invalid",
    ],
    ["an envelope that is null", null, "invalid"],
    ["an envelope that is text", "bundle", "invalid"],
  ];

  it.each(cases)("%s: refused as %s", (_name, envelope, reason, ctx) => {
    const result = verifyBundle(envelope, context(ctx));
    expect(result.ok).toBe(false);
    if (result.ok) return;
    expect(result.reason).toBe(reason);
    expect(result.detail).toEqual(expect.any(String));
    expect(result.detail.length).toBeGreaterThan(0);
    expect(result.detail.length).toBeLessThan(160);
  });

  it("names the Rule and the member that is wrong, never the value", () => {
    const result = verifyBundle(withRule(rule(2, { path: "/zq-secret-segment/a b" })), context());
    expect(result).toMatchObject({ ok: false, reason: "invalid" });
    if (result.ok) return;
    expect(result.detail).toMatch(/Rule 2/);
    expect(result.detail).toMatch(/path/);
    expect(result.detail).not.toContain("zq-secret-segment");
  });

  it("gives each cause its own description", () => {
    const details = new Set<string>();
    const pick = [
      "one character of the bundle flipped",
      "another format",
      "the bundle of another Shield key",
      "an older version",
      "a bundle that expired",
      "51 Rules",
      "a pattern with ** in the middle",
      "a signed bundle that is not JSON",
      "a signed bundle of 65,537 bytes",
    ];
    for (const name of pick) {
      const found = cases.find((entry) => entry[0] === name);
      if (found === undefined) throw new Error(`no case named ${name}`);
      const result = verifyBundle(found[1], context(found[3]));
      if (result.ok) throw new Error(`${name} was accepted`);
      details.add(`${result.reason}: ${result.detail}`);
    }
    expect(details.size).toBe(pick.length);
  });

  it("checks the signature before it reads the bundle: a forged bundle is never parsed", () => {
    // Not JSON and not signed by the configured key: the answer is "signature", not "invalid".
    expect(verifyBundle(signed(stranger, "{not json"), context())).toMatchObject({ ok: false, reason: "signature" });
    expect(verifyBundle(signed(stranger, payload(OTHER_KEY)), context())).toMatchObject({ reason: "signature" });
  });
});

describe("verifyBody: the response of GET /v1/policy-bundle", () => {
  it("applies a signed bundle from the response text", () => {
    const result = verifyBody(JSON.stringify(signed(signer, payload(KEY, { version: 9 }))), context());
    expect(result.ok && result.policy.version).toBe(9);
  });

  it("ignores unknown members of the response", () => {
    const body = JSON.stringify({ ...signed(signer, payload(KEY)), extra: [1, 2, 3] });
    expect(verifyBody(body, context()).ok).toBe(true);
  });

  it.each([
    ["no body", undefined, /no body/i],
    ["an empty body", "", /not JSON/i],
    ["a body that is not JSON", "<html>502 Bad Gateway</html>", /not JSON/i],
    ["a JSON list", "[]", /signed bundle/i],
    ["JSON null", "null", /signed bundle/i],
    ["a body without a bundle", JSON.stringify({ signature: "x" }), /signed bundle/i],
    ["a body of 1 MB", JSON.stringify({ bundle: "x".repeat(1_048_576), signature: "y" }), /larger than 131072 bytes/],
    ["a body one byte over the limit", " ".repeat(RESPONSE_BYTES_MAX + 1), /larger than 131072 bytes/],
    [
      "a body within the limit in characters but not in bytes",
      `"${"é".repeat(RESPONSE_BYTES_MAX / 2)}"`,
      /larger than 131072 bytes/,
    ],
  ])("refuses %s as invalid", (_name, body, detail) => {
    const result = verifyBody(body, context());
    expect(result).toMatchObject({ ok: false, reason: "invalid" });
    if (!result.ok) expect(result.detail).toMatch(detail);
  });

  it("does not parse a body over the limit", () => {
    const parse = JSON.parse;
    let parsed = 0;
    JSON.parse = ((text: string) => {
      parsed += 1;
      return parse(text);
    }) as typeof JSON.parse;
    try {
      verifyBody(`[${"0,".repeat(RESPONSE_BYTES_MAX)}0]`, context());
    } finally {
      JSON.parse = parse;
    }
    expect(parsed).toBe(0);
  });
});

describe("the Policy store", () => {
  const applied = (() => {
    const result = verifyBundle(signed(signer, payload(KEY, { version: 2 })), context());
    if (!result.ok) throw new Error("refused");
    return result.policy;
  })();

  it("starts with the built-in Policy: version 0, no Rules, never stale", () => {
    const store = createPolicyStore();
    expect(store.current()).toBe(BUILT_IN_POLICY);
    expect(store.current().version).toBe(0);
    expect(store.current().rules).toEqual([]);
    expect(store.isStale(NOW)).toBe(false);
    expect(store.isStale(NOW + 10_000 * DAY_MS)).toBe(false);
  });

  it("holds the applied Policy and reports it stale once not_after has passed, while it stays applied", () => {
    const store = createPolicyStore();
    store.apply(applied);
    expect(store.current()).toBe(applied);
    expect(store.isStale(NOW)).toBe(false);
    expect(store.isStale(applied.notAfter)).toBe(false);
    expect(store.isStale(applied.notAfter + 1)).toBe(true);
    expect(store.current()).toBe(applied);
    expect(store.current().rules).toHaveLength(1);
  });

  it("does not call a clock that returns nonsense stale", () => {
    const store = createPolicyStore();
    store.apply(applied);
    expect(store.isStale(Number.NaN)).toBe(false);
  });
});
