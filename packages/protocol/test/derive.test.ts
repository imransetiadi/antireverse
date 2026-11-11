import { createHash, createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";
import { BeaconTokenSchema, CANARY_PLAN, CanarySchema, EXAMPLE_CANARIES, LEAK_RULES } from "../src/index.ts";
import { deriveBeaconToken, deriveCanaries, leakFingerprint } from "../src/server.ts";

const hmac = (seed: number, message: string): Buffer =>
  createHmac("sha256", `antireverse/canary/v1/${seed}`).update(message, "utf8").digest();

// The leak-scan rule patterns of the plan's table that a decoy key or route could conceivably resemble.
const LEAK_PATTERNS: [string, RegExp][] = [
  ["aws-access-key", /(?:AKIA|ASIA)[0-9A-Z]{16}/],
  ["github-token", /gh[pousr]_[0-9A-Za-z]{36}/],
  ["stripe-secret", /(?:sk|rk)_live_[0-9A-Za-z]{24,}/],
  ["slack-token", /xox[abprs]-/],
  ["google-api-key", /AIza[0-9A-Za-z_-]{35}/],
  ["internal-url", /https?:\/\//],
  ["source-map", /sourceMappingURL=/],
  ["private-key", /-----BEGIN [A-Z ]*PRIVATE KEY-----/],
];

describe("deriveCanaries", () => {
  it("matches the known-answer vector for seed 1 (EXAMPLE_CANARIES)", () => {
    expect(deriveCanaries(1)).toEqual([
      { id: "cny_33d265fca16c848eb2f23f43", kind: "key", value: "ak_live_083n1BMwZhfu13secInfCOzZrq2cfyQE" },
      { id: "cny_4cb3bd4c9b67d9590fb16b6b", kind: "route", value: "/api/internal/un539n4s/backup" },
      { id: "cny_555fa5c968f7ce38bbcd6c3d", kind: "route", value: "/api/internal/60nekyby/backup" },
    ]);
    expect(deriveCanaries(1)).toEqual(EXAMPLE_CANARIES);
  });

  it("returns CANARY_PLAN Canaries, keys then routes, each valid", () => {
    for (const seed of [0, 1, 42, 4_294_967_295, Number.MAX_SAFE_INTEGER]) {
      const canaries = deriveCanaries(seed);
      expect(canaries.map((canary) => canary.kind)).toEqual([
        ...Array<string>(CANARY_PLAN.key).fill("key"),
        ...Array<string>(CANARY_PLAN.route).fill("route"),
      ]);
      for (const canary of canaries) expect(CanarySchema.parse(canary)).toEqual(canary);
    }
  });

  it("derives each id as cny_ + the first 24 hex of HMAC(seed, id/<kind>/<index>)", () => {
    const [key, route0, route1] = deriveCanaries(7);
    expect(key?.id).toBe(`cny_${hmac(7, "id/key/0").toString("hex").slice(0, 24)}`);
    expect(route0?.id).toBe(`cny_${hmac(7, "id/route/0").toString("hex").slice(0, 24)}`);
    expect(route1?.id).toBe(`cny_${hmac(7, "id/route/1").toString("hex").slice(0, 24)}`);
  });

  it("encodes a key as the HMAC(seed, key/<index>) integer mod 62^32 in 32 base62 digits (0-9A-Za-z)", () => {
    const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let n = BigInt(`0x${hmac(7, "key/0").toString("hex")}`);
    let digits = "";
    for (let i = 0; i < 32; i++) {
      digits = alphabet[Number(n % 62n)] + digits;
      n /= 62n;
    }
    expect(deriveCanaries(7)[0]?.value).toBe(`ak_live_${digits}`);
  });

  it("encodes a route as 8 base36 digits of HMAC bytes 0..15 and a word chosen by byte 31 modulo 5", () => {
    const words = ["export", "debug", "config", "backup", "sync"];
    for (const index of [0, 1]) {
      const digest = hmac(7, `route/${index}`);
      const id = (BigInt(`0x${digest.subarray(0, 16).toString("hex")}`) % 36n ** 8n).toString(36).padStart(8, "0");
      const word = words[(digest[31] as number) % 5];
      expect(deriveCanaries(7)[1 + index]?.value).toBe(`/api/internal/${id}/${word}`);
    }
  });

  it("is deterministic: the same seed reproduces the output exactly", () => {
    expect(JSON.stringify(deriveCanaries(123456))).toBe(JSON.stringify(deriveCanaries(123456)));
  });

  it("differs between seeds, with unique ids and values across seeds 0..999", () => {
    const ids = new Set<string>();
    const values = new Set<string>();
    for (let seed = 0; seed < 1000; seed++) {
      for (const canary of deriveCanaries(seed)) {
        ids.add(canary.id);
        values.add(canary.value);
      }
    }
    expect(ids.size).toBe(3000);
    expect(values.size).toBe(3000);
  });

  it("never produces a value that a leak-scan rule would report (seeds 0..999)", () => {
    for (let seed = 0; seed < 1000; seed++) {
      for (const canary of deriveCanaries(seed)) {
        for (const [, pattern] of LEAK_PATTERNS) expect(pattern.test(canary.value)).toBe(false);
      }
    }
  });

  it("returns a fresh array each time: callers cannot corrupt a later result", () => {
    const first = deriveCanaries(1);
    first.pop();
    expect(deriveCanaries(1)).toHaveLength(3);
  });

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, "1", null, undefined])(
    "throws a TypeError for the seed %j",
    (seed) => {
      expect(() => deriveCanaries(seed as number)).toThrow(TypeError);
    },
  );
});

const APP_A = "app_0123456789abcdef01234567";
const APP_B = "app_89abcdef0123456789abcdef";
// Computed independently from the derivation rule (HMAC key v2, messages prefixed "<appId>\n<version>\n").
const V2_KNOWN_ANSWER = [
  { id: "cny_9c4fa89de6bcfd26da1b4a37", kind: "key", value: "ak_live_f9gncpCrUwJ6nBMCcldmYAqIaM4vN8FP" },
  { id: "cny_ab9541521bd2792669939b12", kind: "route", value: "/api/internal/rapzzak1/config" },
  { id: "cny_c37f9c61da84e274a19a8aa7", kind: "route", value: "/api/internal/xckz3k79/debug" },
];
const hmacV2 = (seed: number, appId: string, version: string, message: string): Buffer =>
  createHmac("sha256", `antireverse/canary/v2/${seed}`).update(`${appId}\n${version}\n${message}`, "utf8").digest();

describe("deriveCanaries with a scope (v2: App and version)", () => {
  it("without a scope is unchanged (v1 known answers)", () => {
    expect(deriveCanaries(1, undefined)).toEqual(EXAMPLE_CANARIES);
  });

  it("derives ids and values with the v2 key and messages prefixed by appId and version", () => {
    const [key, route0, route1] = deriveCanaries(7, { appId: APP_A, version: "1.0.0" });
    expect(key?.id).toBe(`cny_${hmacV2(7, APP_A, "1.0.0", "id/key/0").toString("hex").slice(0, 24)}`);
    expect(route0?.id).toBe(`cny_${hmacV2(7, APP_A, "1.0.0", "id/route/0").toString("hex").slice(0, 24)}`);
    expect(route1?.id).toBe(`cny_${hmacV2(7, APP_A, "1.0.0", "id/route/1").toString("hex").slice(0, 24)}`);
    const alphabet = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    let n = BigInt(`0x${hmacV2(7, APP_A, "1.0.0", "key/0").toString("hex")}`);
    let digits = "";
    for (let i = 0; i < 32; i++) {
      digits = alphabet[Number(n % 62n)] + digits;
      n /= 62n;
    }
    expect(key?.value).toBe(`ak_live_${digits}`);
    const words = ["export", "debug", "config", "backup", "sync"];
    const digest = hmacV2(7, APP_A, "1.0.0", "route/1");
    const segment = (BigInt(`0x${digest.subarray(0, 16).toString("hex")}`) % 36n ** 8n).toString(36).padStart(8, "0");
    expect(route1?.value).toBe(`/api/internal/${segment}/${words[(digest[31] as number) % 5]}`);
  });

  it("matches the v2 known-answer vector (seed 1, app_0123456789abcdef01234567, 1.0.0)", () => {
    expect(deriveCanaries(1, { appId: APP_A, version: "1.0.0" })).toEqual(V2_KNOWN_ANSWER);
  });

  it("gives disjoint ids and values for two versions, two Apps, and the unscoped form", () => {
    const sets = [
      deriveCanaries(1),
      deriveCanaries(1, { appId: APP_A, version: "1.0.0" }),
      deriveCanaries(1, { appId: APP_A, version: "1.0.1" }),
      deriveCanaries(1, { appId: APP_B, version: "1.0.0" }),
    ];
    const ids = new Set(sets.flat().map((c) => c.id));
    const values = new Set(sets.flat().map((c) => c.value));
    expect(ids.size).toBe(12);
    expect(values.size).toBe(12);
    for (const set of sets) for (const canary of set) expect(CanarySchema.parse(canary)).toEqual(canary);
  });

  it("is deterministic for the same seed and scope", () => {
    const scope = { appId: APP_B, version: "2.3.4" };
    expect(JSON.stringify(deriveCanaries(99, scope))).toBe(JSON.stringify(deriveCanaries(99, { ...scope })));
  });

  it("never produces a value that a leak-scan rule would report (scoped, seeds 0..299)", () => {
    for (let seed = 0; seed < 300; seed++) {
      for (const canary of deriveCanaries(seed, { appId: APP_A, version: `1.0.${seed}` })) {
        for (const [, pattern] of LEAK_PATTERNS) expect(pattern.test(canary.value)).toBe(false);
      }
    }
  });

  it.each([
    { appId: "app_short", version: "1.0.0" },
    { appId: "bld_0123456789abcdef01234567", version: "1.0.0" },
    { appId: APP_A, version: "" },
    { appId: APP_A, version: "1.0\n0" },
    { appId: APP_A, version: 1 },
    null,
  ])("throws a TypeError for the scope %j", (scope) => {
    expect(() => deriveCanaries(1, scope as unknown as { appId: string; version: string })).toThrow(TypeError);
  });
});

describe("leakFingerprint", () => {
  it("is the first 32 hex of SHA-256(rule NUL path NUL value)", () => {
    const expected = createHash("sha256")
      .update("aws-access-key\u0000dist/app.js\u0000AKIAIOSFODNN7EXAMPLE", "utf8")
      .digest("hex")
      .slice(0, 32);
    expect(leakFingerprint("aws-access-key", "dist/app.js", "AKIAIOSFODNN7EXAMPLE")).toBe(expected);
  });

  it("matches the known-answer vector", () => {
    expect(leakFingerprint("aws-access-key", "dist/app.js", "AKIAIOSFODNN7EXAMPLE")).toBe(
      "529ddea549dbb04bf5ef251e8dda0090",
    );
  });

  it("changes with the rule, the path and the value", () => {
    const base = leakFingerprint("stripe-secret", "a.js", "v");
    expect(leakFingerprint("slack-token", "a.js", "v")).not.toBe(base);
    expect(leakFingerprint("stripe-secret", "b.js", "v")).not.toBe(base);
    expect(leakFingerprint("stripe-secret", "a.js", "w")).not.toBe(base);
    expect(base).toMatch(/^[0-9a-f]{32}$/);
  });

  it("accepts every leak rule and refuses an unknown one", () => {
    for (const rule of LEAK_RULES) expect(leakFingerprint(rule.id, "a.js", "v")).toMatch(/^[0-9a-f]{32}$/);
    expect(() => leakFingerprint("aws" as "aws-access-key", "a.js", "v")).toThrow(TypeError);
  });

  it("refuses a non-string path or value", () => {
    expect(() => leakFingerprint("private-key", 1 as unknown as string, "v")).toThrow(TypeError);
    expect(() => leakFingerprint("private-key", "a.js", null as unknown as string)).toThrow(TypeError);
  });
});

describe("deriveBeaconToken", () => {
  // Computed independently with node:crypto:
  //   "bcn_" + HMAC-SHA256("antireverse/beacon/v1/<seed>", "<appId>\n<version>\nbeacon").hex.slice(0, 24)
  it.each([
    [1, APP_A, "1.0.0", "bcn_a5dd35b17f47a81a0532f99e"],
    [1, APP_B, "1.4.0", "bcn_284b75545aa061d92bbcfa25"],
    [0, APP_A, "1.0.0", "bcn_a23916c02d8830e9c674c01a"],
  ])("matches the known answer for seed %j, %s, %s", (seed, appId, version, token) => {
    expect(deriveBeaconToken(seed, { appId, version })).toBe(token);
  });

  it("is bcn_ + the first 24 hex of HMAC-SHA256(v1 key, appId, version, beacon) and a valid token", () => {
    const expected = createHmac("sha256", "antireverse/beacon/v1/7")
      .update(`${APP_A}\n2.0.0\nbeacon`, "utf8")
      .digest("hex")
      .slice(0, 24);
    const token = deriveBeaconToken(7, { appId: APP_A, version: "2.0.0" });
    expect(token).toBe(`bcn_${expected}`);
    expect(BeaconTokenSchema.parse(token)).toBe(token);
  });

  it("is deterministic and distinct per seed, App and version", () => {
    const scope = { appId: APP_A, version: "1.0.0" };
    expect(deriveBeaconToken(42, scope)).toBe(deriveBeaconToken(42, { ...scope }));
    const tokens = new Set([
      deriveBeaconToken(1, scope),
      deriveBeaconToken(2, scope),
      deriveBeaconToken(1, { appId: APP_B, version: "1.0.0" }),
      deriveBeaconToken(1, { appId: APP_A, version: "1.0.1" }),
    ]);
    expect(tokens.size).toBe(4);
  });

  it.each([-1, 1.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53, "1", null, undefined])(
    "throws a TypeError for the seed %j",
    (seed) => {
      expect(() => deriveBeaconToken(seed as number, { appId: APP_A, version: "1.0.0" })).toThrow(TypeError);
    },
  );

  it.each([
    undefined,
    null,
    {},
    { appId: "org_0123456789abcdef01234567", version: "1.0.0" },
    { appId: APP_A },
    { appId: APP_A, version: "" },
    { appId: APP_A, version: "1.0\n0" },
    { appId: APP_A, version: "1.0\r0" },
    { appId: APP_A, version: 1 },
  ])("throws a TypeError for the scope %j", (scope) => {
    expect(() => deriveBeaconToken(1, scope as never)).toThrow(TypeError);
  });
});
