// Slice 20: Shield's hand-written patch contract agrees with the protocol's — the bounds, the bundle member and,
// on many generated requests, the matcher itself (differential test against the protocol's `matchPatch`).
import type { IncomingMessage } from "node:http";
import { createRequire } from "node:module";
import {
  AdvisoryIdSchema,
  type BundlePatch,
  BundlePatchSchema,
  BundlePayloadSchema,
  type Condition,
  EXAMPLE_BUNDLE_PATCH,
  EXAMPLE_VIRTUAL_PATCH,
  PATCH_ID_PATTERN,
  LATIN1_CHARSETS as PROTOCOL_LATIN1,
  PATCH_LIMITS as PROTOCOL_LIMITS,
  PATCH_OPS as PROTOCOL_OPS,
  PATCH_TARGETS as PROTOCOL_TARGETS,
  type PatchRequest as ProtocolRequest,
  charsetOfContentType as protocolCharset,
  matchPatch as protocolMatch,
  patchRequestOf as protocolRequestOf,
} from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { describe, expect, it } from "vitest";
import {
  ADVISORY_ID,
  charsetOfContentType,
  LATIN1_CHARSETS,
  matchBody,
  matchPatch,
  PATCH_ID,
  PATCH_LIMITS,
  PATCH_OPS,
  PATCH_TARGETS,
  type PatchRequest,
  patchRequestOf,
  preparePatch,
  RequestView,
  readPatch,
  readPatches,
} from "../src/patches.ts";
import { audienceOf, importPublicKey, verifyBundle } from "../src/policy/verify.ts";
import { createSigner, NOW, payload, rule, signed } from "./policy-helpers.ts";

const KEY = generateKey("shield", "development").key;
const signer = createSigner();

describe("Shield's patch bounds are the protocol's", () => {
  it("targets, operators, limits and the id pattern agree", () => {
    expect([...PATCH_TARGETS]).toEqual([...PROTOCOL_TARGETS]);
    expect([...PATCH_OPS]).toEqual([...PROTOCOL_OPS]);
    for (const [name, value] of Object.entries(PATCH_LIMITS)) {
      expect([name, value]).toEqual([name, PROTOCOL_LIMITS[name as keyof typeof PROTOCOL_LIMITS]]);
    }
    expect(PATCH_ID.source).toBe(PATCH_ID_PATTERN.source);
    expect([...LATIN1_CHARSETS]).toEqual([...PROTOCOL_LATIN1]);
  });

  it.each([
    "CVE-2022-24999",
    "GHSA-hrpp-h998-j3pp",
    "GHSA-2c3m-4p5q-6r7v",
    "OSV-2020-1",
    "C-1",
    "CV-1",
    "cve-2022-1",
    "CVE2022",
    "CVE-",
    `CVE-${"1".repeat(100)}`,
    `CVE-${"1".repeat(101)}`,
    "CVE-2022:1.2_3",
    "CVE-_1",
    "ABCDEFGHIJKLMNOPQ-1",
    "ABCDEFGHIJKLMNOP-1",
  ])("an advisory id %j is accepted exactly when the protocol accepts it", (id) => {
    expect(ADVISORY_ID.test(id)).toBe(AdvisoryIdSchema.safeParse(id).success);
  });
});

const BASE: BundlePatch = {
  id: "vp_qs_proto",
  mode: "monitor",
  conditions: [{ target: "query_key", op: "contains", value: "__proto__" }],
  advisory: "CVE-2022-24999",
};

describe("readPatch: a bundle patch is accepted exactly when the protocol accepts it", () => {
  const variants: [string, unknown][] = [
    ["the documented example", EXAMPLE_BUNDLE_PATCH],
    ["a minimal patch", BASE],
    ["enforce", { ...BASE, mode: "enforce" }],
    ["with methods and a path", { ...BASE, methods: ["GET", "POST"], path: "/api/*/x/**" }],
    ["an empty method list", { ...BASE, methods: [] }],
    ["eight methods", { ...BASE, methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "M-SEARCH"] }],
    [
      "nine methods",
      { ...BASE, methods: ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "M-SEARCH", "X"] },
    ],
    ["a method twice", { ...BASE, methods: ["GET", "GET"] }],
    ["a lower-case method", { ...BASE, methods: ["get"] }],
    ["a path with a trailing slash", { ...BASE, path: "/api/" }],
    ["a path with ** inside", { ...BASE, path: "/api/**/x" }],
    ["the root path", { ...BASE, path: "/" }],
    ["a path with a query", { ...BASE, path: "/api?x" }],
    ["unknown keys", { ...BASE, title: "t", reference: {}, extra: 1 }],
    ["an unknown mode", { ...BASE, mode: "block" }],
    ["no advisory", { ...BASE, advisory: undefined }],
    ["a lower-case advisory", { ...BASE, advisory: "cve-2022-24999" }],
    ["a bad id", { ...BASE, id: "vp_AB" }],
    ["a short id", { ...BASE, id: "vp_ab" }],
    ["no conditions", { ...BASE, conditions: [] }],
    ["eight conditions", { ...BASE, conditions: Array(8).fill(BASE.conditions[0]) }],
    ["nine conditions", { ...BASE, conditions: Array(9).fill(BASE.conditions[0]) }],
    ["conditions not a list", { ...BASE, conditions: BASE.conditions[0] }],
    ["a condition with an unknown key", { ...BASE, conditions: [{ ...BASE.conditions[0], x: 1 }] }],
    ["an unknown target", { ...BASE, conditions: [{ target: "cookie", op: "present" }] }],
    ["an unknown op", { ...BASE, conditions: [{ target: "path", op: "matches", value: "x" }] }],
    ["present with a value", { ...BASE, conditions: [{ target: "path", op: "present", value: "x" }] }],
    ["equals without a value", { ...BASE, conditions: [{ target: "path", op: "equals" }] }],
    ["an empty value", { ...BASE, conditions: [{ target: "path", op: "equals", value: "" }] }],
    ["a 256-character value", { ...BASE, conditions: [{ target: "path", op: "contains", value: "a".repeat(256) }] }],
    ["a 257-character value", { ...BASE, conditions: [{ target: "path", op: "contains", value: "a".repeat(257) }] }],
    ["a value with a tab", { ...BASE, conditions: [{ target: "path", op: "contains", value: "a\tb" }] }],
    ["a value with non-ASCII", { ...BASE, conditions: [{ target: "path", op: "contains", value: "café" }] }],
    ["a header condition", { ...BASE, conditions: [{ target: "header", name: "x-a", op: "contains", value: "1" }] }],
    ["a header without name", { ...BASE, conditions: [{ target: "header", op: "present" }] }],
    ["an upper-case header", { ...BASE, conditions: [{ target: "header", name: "X-A", op: "present" }] }],
    [
      "a 128-character header name",
      { ...BASE, conditions: [{ target: "header", name: "a".repeat(128), op: "present" }] },
    ],
    [
      "a 129-character header name",
      { ...BASE, conditions: [{ target: "header", name: "a".repeat(129), op: "present" }] },
    ],
    ["a named query value", { ...BASE, conditions: [{ target: "query_value", name: "Q[x]", op: "present" }] }],
    ["a name on path", { ...BASE, conditions: [{ target: "path", name: "x", op: "present" }] }],
    ["length_over 1", { ...BASE, conditions: [{ target: "body", op: "length_over", value: "1" }] }],
    ["length_over 1000000", { ...BASE, conditions: [{ target: "body", op: "length_over", value: "1000000" }] }],
    ["length_over 1000001", { ...BASE, conditions: [{ target: "body", op: "length_over", value: "1000001" }] }],
    ["length_over 0", { ...BASE, conditions: [{ target: "body", op: "length_over", value: "0" }] }],
    ["length_over 01", { ...BASE, conditions: [{ target: "body", op: "length_over", value: "01" }] }],
    ["length_over x", { ...BASE, conditions: [{ target: "body", op: "length_over", value: "x" }] }],
    ["json_key on the body", { ...BASE, conditions: [{ target: "body", op: "json_key", value: "constructor" }] }],
    [
      "json_key on a query key",
      { ...BASE, conditions: [{ target: "query_key", op: "json_key", value: "constructor" }] },
    ],
    ["json_key without a value", { ...BASE, conditions: [{ target: "body", op: "json_key" }] }],
    ["a number as value", { ...BASE, conditions: [{ target: "path", op: "equals", value: 1 }] }],
    ["not an object", "vp_qs_proto"],
    ["null", null],
  ];
  /** Shield is stricter than the protocol here on purpose: a field it does not know may change what a patch means. */
  const UNKNOWN_FIELDS = new Set(["unknown keys", "a condition with an unknown key"]);
  it.each(variants)("%s", (name, value) => {
    const expected = BundlePatchSchema.safeParse(value);
    const read = readPatch(value);
    if (UNKNOWN_FIELDS.has(name)) {
      expect(expected.success).toBe(true);
      expect(read).toMatch(/unknown field/);
      return;
    }
    expect(typeof read !== "string").toBe(expected.success);
    if (expected.success && typeof read !== "string") expect(read).toEqual(expected.data);
    // A refusal says what is wrong without repeating a value.
    if (typeof read === "string")
      for (const value of ["__proto__", "cookie", "matches", "café"]) expect(read).not.toContain(value);
  });
});

/** `count` distinct patches, each with conditions of `valueLength` characters. */
function many(count: number, valueLength = 9): BundlePatch[] {
  return Array.from({ length: count }, (_, i) => ({
    ...BASE,
    id: `vp_patch_${String(i).padStart(3, "0")}`,
    conditions: [{ target: "query_key", op: "contains", value: "x".repeat(valueLength) }],
  }));
}

describe("readPatches: tolerant of what this Shield cannot read (forward compatibility)", () => {
  const shape = BundlePayloadSchema.safeParse;
  /** A list the protocol accepts is read whole: nothing skipped, nothing ignored. */
  const whole = (patches: BundlePatch[] | Record<string, unknown>[]): void => {
    expect(shape(payload(KEY, { patches } as never)).success).toBe(true);
    const read = readPatches(patches);
    expect([read.patches.length, read.skipped, read.ignored]).toEqual([patches.length, 0, null]);
  };
  const ids = (value: unknown): string[] => readPatches(value).patches.map((patch) => patch.id);

  it("reads 0 and 50 patches whole; of 51 it keeps the first 50 and counts the rest as skipped", () => {
    whole([]);
    whole(many(50));
    const read = readPatches(many(51));
    expect([read.patches.length, read.skipped, read.ignored]).toEqual([50, 1, null]);
    expect(read.patches.at(-1)?.id).toBe("vp_patch_049");
  });

  it("skips and counts each patch it cannot read, and keeps the others in order", () => {
    const newer = [
      { ...BASE, id: "vp_first" },
      { ...BASE, id: "vp_cookie", conditions: [{ target: "cookie", name: "sid", op: "present" }] },
      { ...BASE, id: "vp_regex", conditions: [{ target: "path", op: "matches", value: "x" }] },
      { ...BASE, id: "vp_mode", mode: "challenge" },
      { ...BASE, id: "vp_field", conditions: [{ target: "path", op: "equals", value: "/x", negate: true }] },
      "not a patch",
      null,
      { ...BASE, id: "vp_last", future_field: { any: "shape" } },
    ];
    const read = readPatches(newer);
    // An unknown field may change what a patch means (a newer Shield's `negate`): such a patch is skipped too.
    expect(read.patches.map((patch) => patch.id)).toEqual(["vp_first"]);
    expect([read.skipped, read.ignored]).toEqual([7, null]);
  });

  it("a Shield from before json_key (A5's operators) skips a json_key patch and keeps the others", () => {
    const A5_OPS = ["equals", "contains", "starts_with", "ends_with", "length_over", "present"] as const;
    const jsonKey = {
      ...BASE,
      id: "vp_json_key",
      conditions: [{ target: "body", op: "json_key", value: "constructor" }],
    };
    const read = readPatches([jsonKey, { ...BASE, id: "vp_plain" }], A5_OPS);
    expect([read.patches.map((patch) => patch.id), read.skipped, read.ignored]).toEqual([["vp_plain"], 1, null]);
    // This Shield reads it.
    expect(readPatches([jsonKey]).patches.map((patch) => patch.id)).toEqual(["vp_json_key"]);
  });

  it("keeps the first of an id listed twice and skips the second", () => {
    const read = readPatches([BASE, { ...BASE, mode: "enforce" }]);
    expect(read.patches.map((patch) => patch.mode)).toEqual(["monitor"]);
    expect(read.skipped).toBe(1);
  });

  it("ignores a member that is not a list, as a member", () => {
    for (const value of [{ 0: BASE }, "x", 7, null]) {
      expect(readPatches(value)).toEqual({ patches: [], skipped: 0, ignored: "patches is not a list" });
    }
  });

  it("never repeats a value of the bundle in what it reports", () => {
    expect(ids([{ ...BASE, conditions: [{ target: "path", op: "contains", value: "__proto__".repeat(30) }] }])).toEqual(
      [],
    );
    expect(JSON.stringify(readPatches([{ ...BASE, conditions: [{ target: "cookie", op: "present" }] }]))).not.toContain(
      "cookie",
    );
  });

  it("ignores the member over the byte budget, exactly at the protocol's boundary", () => {
    // `full` patches with a 256-character value, then one with `count` conditions of `last` characters: find a case
    // where one more character crosses 16,384 bytes, and check both sides.
    const tail = (index: number, count: number, length: number): BundlePatch => ({
      ...BASE,
      id: `vp_patch_${String(index).padStart(3, "0")}`,
      conditions: Array.from({ length: count }, () => ({
        target: "path" as const,
        op: "contains" as const,
        value: "y".repeat(length),
      })),
    });
    const size = (patches: BundlePatch[]): number => JSON.stringify(patches).length;
    let found: [number, number, number] | null = null;
    for (let full = 49; full >= 30 && found === null; full--) {
      for (let count = 1; count <= 8 && found === null; count++) {
        // The size grows by `count` bytes per character of `length`: compute the crossing instead of searching it.
        const first = size([...many(full, 256), tail(full, count, 1)]);
        const length = Math.floor((PATCH_LIMITS.bundleBytesMax - first) / count) + 1;
        if (length >= 1 && length < 256) found = [full, count, length];
      }
    }
    if (found === null) throw new Error("no boundary case");
    const [full, count, last] = found;
    const sized = (length: number): BundlePatch[] => [...many(full, 256), tail(full, count, length)];
    expect(size(sized(last))).toBeLessThanOrEqual(PATCH_LIMITS.bundleBytesMax);
    expect(size(sized(last + 1))).toBeGreaterThan(PATCH_LIMITS.bundleBytesMax);
    const fits = sized(last);
    const over = sized(last + 1);
    expect(shape(payload(KEY, { patches: fits } as never)).success).toBe(true);
    expect(shape(payload(KEY, { patches: over } as never)).success).toBe(false);
    expect([readPatches(fits).patches.length, readPatches(fits).ignored]).toEqual([fits.length, null]);
    // Over the budget the member is ignored as a whole: no patch of it applies.
    expect(readPatches(over)).toEqual({
      patches: [],
      skipped: 0,
      ignored: "patches hold more than 16384 bytes of JSON together",
    });
  });
});

describe("verifyBundle: the optional patches member", () => {
  const publicKey = importPublicKey(signer.publicKey);
  if (publicKey === null) throw new Error("test key");
  const context = {
    publicKey,
    audience: audienceOf(KEY),
    appliedVersion: 0,
    appliedEpoch: null,
    appliedIssuedAt: 0,
    now: NOW + 1,
  };
  const verify = (overrides: Record<string, unknown>) =>
    verifyBundle(signed(signer, { ...payload(KEY), ...overrides }), context);

  it("a bundle without the member, as before slice 20, has no patches", () => {
    const result = verify({});
    expect(result.ok && result.policy.patches).toEqual([]);
  });

  it("applies the patches in order, each with its mode, advisory and a frozen block Decision of the version", () => {
    const enforce = { ...BASE, id: "vp_second", mode: "enforce" as const };
    const result = verify({ version: 4, patches: [EXAMPLE_BUNDLE_PATCH, enforce] });
    if (!result.ok) throw new Error(result.detail);
    expect(result.policy.patches.map((patch) => [patch.id, patch.mode, patch.advisory])).toEqual([
      [EXAMPLE_BUNDLE_PATCH.id, "monitor", EXAMPLE_BUNDLE_PATCH.advisory],
      ["vp_second", "enforce", BASE.advisory],
    ]);
    expect(result.policy.patches[1]?.decision).toEqual({
      action: "block",
      mode: "enforce",
      ruleId: null,
      policyVersion: 4,
    });
    expect(Object.isFrozen(result.policy.patches[1]?.decision)).toBe(true);
  });

  it.each([
    ["the member is not a list (counted once)", { patches: BASE }, 0, 1],
    [
      "a patch has an unknown target",
      {
        patches: [
          { ...BASE, conditions: [{ target: "cookie", op: "present" }] },
          { ...BASE, id: "vp_kept" },
        ],
      },
      1,
      1,
    ],
    [
      "a value is too long",
      { patches: [{ ...BASE, conditions: [{ target: "path", op: "contains", value: "__proto__".repeat(30) }] }] },
      0,
      1,
    ],
    ["51 patches", { patches: many(51) }, 50, 1],
  ])(
    "applies the bundle when %s: the Rules stay, the patches it can read apply, the rest are counted as skipped",
    (_name, overrides, applied, skipped) => {
      const result = verify({ ...overrides, rules: [rule(1)] });
      if (!result.ok) throw new Error(`refused: ${result.detail}`);
      expect(result.policy.rules).toHaveLength(1);
      expect(result.policy.patches).toHaveLength(applied);
      expect(result.policy.patchesSkipped).toBe(skipped);
    },
  );
});

describe("A11: the charset of a content-type, as content-type 2.x and the protocol read it", () => {
  const contentType = createRequire(import.meta.url)("content-type") as {
    parse(header: string): { parameters: Record<string, string> };
  };
  it("agrees on 20,000 generated headers", () => {
    const next = random(11);
    const PIECES = ["charset", "CharSet", "x", "=", "=", ";", ";", ";", " ", "\t", '"', '"', "\\", "utf-8", "UTF-16LE"];
    PIECES.push("latin1", "a;charset=utf-7", ",", "é", "/");
    for (let i = 0; i < 20_000; i++) {
      let header = next() < 0.8 ? "text/plain" : "";
      for (let n = Math.floor(next() * 14); n > 0; n--) header += PIECES[Math.floor(next() * PIECES.length)];
      const theirs = contentType.parse(header).parameters.charset?.toLowerCase();
      expect([header, charsetOfContentType(header)]).toEqual([header, theirs]);
      expect([header, charsetOfContentType(header)]).toEqual([header, protocolCharset(header)]);
    }
  });
});

// --- Differential test against the protocol's matcher -----------------------------------------------------------

/** A small deterministic PRNG (mulberry32). */
function random(seed: number): () => number {
  let state = seed >>> 0;
  return () => {
    state = (state + 0x6d2b79f5) >>> 0;
    let t = state;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4_294_967_296;
  };
}

const rand = random(20_261_111);
const pick = <T>(items: readonly T[]): T => items[Math.floor(rand() * items.length)] as T;
const chance = (p: number): boolean => rand() < p;

const SEGMENTS = [
  "api",
  "admin",
  "Admin",
  "%61dmin",
  "%41DMIN",
  "..",
  ".",
  "",
  "%2e%2e",
  "%2E",
  "x%2fy",
  "__proto__",
  "%5f%5fproto%5f%5f",
  "%255f%255fproto",
  "caf%C3%A9",
  "%zz",
  "%",
  "%4",
  "a+b",
  "users",
  "42",
  "search",
];
const KEYS = [
  "q",
  "Q",
  "a[]",
  "a[__proto__]",
  "__proto__",
  "%5F%5Fproto__",
  "__PROTO__",
  "constructor",
  "q%5b__proto__%5d",
  "q[constructor][prototype]",
  "",
  "x+y",
  "%2B",
  "%255f%255fproto%255f%255f",
  "sort",
  "a[b=c][__proto__]",
  "x[y=1]",
  "a=b]",
];
const VALUES = ["1", "", "__proto__", "a+b", "%2B", "proto", "%00", "admin", "x%20y", "%E2%82%AC", "constructor", "+"];
const HEADER_NAMES = ["x-a", "x-b", "user-agent", "x-forwarded-for", "x-proto", "accept"];
const HEADER_VALUES = [
  "1",
  "  padded\t",
  "__proto__",
  "%5f%5fproto%5f%5f",
  "Mozilla/5.0",
  "a, b",
  "\t",
  "admin",
  "$" + "{jndi:ldap://x}",
  "%24%7Bjndi",
];
const BODIES = [
  '{"__proto__":{"polluted":1}}',
  '{"constructor" :{"prototype"\r\n\t:{"isAdmin":true}}}',
  '{"role":"constructor","stage":"prototype"}',
  '["constructor" ,"prototype"]',
  "%7B%22constructor%22%3A1%7D",
  '{"\\u005f\\u005fproto\\u005f\\u005f":1}',
  '{"\\u005F_proto__":1}',
  '{"constructor":{"prototype":{"x":1}}}',
  '{"name":"constructor"}',
  "a=1&__proto__[x]=1",
  "a=1&%5f%5fproto__=1",
  '{"emoji":"\\ud83d\\ude00"}',
  '{"bad":"\\u12"}',
  '{"tail":"\\u00',
  "<xml><__proto__/></xml>",
  "",
  "plain text",
];
const TOKENS = [
  "__proto__",
  "constructor",
  "prototype",
  "%5f",
  "_",
  "admin",
  "..",
  "/",
  "a",
  "A",
  "+",
  " ",
  "%",
  "%25",
  "x",
  "api",
  "\\u005f",
  "proto",
  "1",
  "jndi",
  "${",
  "polluted",
  "GET",
  "POST",
  "users/42",
  "/api",
  "a[",
  "]",
  "caf",
  "%c3",
  "mozilla",
];
const METHODS = ["GET", "POST", "PUT", "HEAD", "DELETE", "OPTIONS"];
const GLOBS = ["/api/**", "/api/*", "/", "/**", "/api/admin", "/*/admin/**", "/search", "/api/users/*", "/API/**"];
const LENGTHS = ["1", "2", "5", "20", "100", "16383", "16384", "16385", "70000"];

function generatedTarget(): string {
  const segments = Array.from({ length: 1 + Math.floor(rand() * 4) }, () => pick(SEGMENTS));
  let path = `/${segments.join("/")}`;
  if (chance(0.05)) path += `/${"p".repeat(16_380 - path.length + Math.floor(rand() * 10))}/__proto__`;
  if (chance(0.1)) path += "/";
  let target = path;
  if (chance(0.8)) {
    const pairs = Array.from({ length: Math.floor(rand() * 5) }, () => {
      const key = pick(KEYS);
      if (chance(0.15)) return key;
      return `${key}=${pick(VALUES)}`;
    });
    if (chance(0.3)) pairs.push(pairs[0] ?? "q=1"); // a duplicated key
    let query = pairs.join(chance(0.2) ? "&&" : "&");
    if (chance(0.05)) query = `${"k=v&".repeat(4_095)}__proto__=1`;
    target += `?${query}`;
  }
  if (chance(0.1)) target += "#frag?x=__proto__";
  return target;
}

function generatedHeaders(): Record<string, string> {
  const headers: Record<string, string> = {};
  for (let i = Math.floor(rand() * 4); i > 0; i--) {
    let value = pick(HEADER_VALUES);
    if (chance(0.05)) value = `${"h".repeat(16_383 + Math.floor(rand() * 3) - 1)}${value}`;
    headers[pick(HEADER_NAMES)] = value;
  }
  return headers;
}

function utf16(text: string, big: boolean): Uint8Array {
  const out = new Uint8Array(text.length * 2);
  for (let i = 0; i < text.length; i++) {
    const unit = text.charCodeAt(i);
    out[2 * i + (big ? 1 : 0)] = unit & 0xff;
    out[2 * i + (big ? 0 : 1)] = unit >> 8;
  }
  return out;
}

function utf32(text: string, big: boolean): Uint8Array {
  const points = [...text].map((char) => char.codePointAt(0) as number);
  const out = new Uint8Array(points.length * 4);
  points.forEach((point, i) => {
    for (let b = 0; b < 4; b++) out[4 * i + (big ? 3 - b : b)] = (point >>> (8 * b)) & 0xff;
  });
  return out;
}

const join = (...parts: (number[] | Uint8Array)[]): Uint8Array => new Uint8Array(parts.flatMap((part) => [...part]));

/** A body in one of the encodings Shield reads, or not, with the content type that names it (A6, F1). */
function generatedBody(): { body: Uint8Array; contentType?: string } {
  if (chance(0.1))
    return { body: new Uint8Array([0x7b, 0xff, 0xc3, 0x5f, 0x5f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x5f, 0x5f]) };
  let text = pick(BODIES);
  if (chance(0.1)) text = `${" ".repeat(70_000)}${text}`;
  const utf8 = new TextEncoder().encode(text);
  const type = pick(["application/json", "text/plain", "application/x-www-form-urlencoded"]);
  switch (Math.floor(rand() * 12)) {
    case 0:
      return { body: utf16(text, false), contentType: `${type}; charset=utf-16le` };
    case 1:
      return { body: utf16(text, true), contentType: `${type};charset="UTF-16BE"` };
    case 2:
      return { body: join([0xfe, 0xff], utf16(text, true)), contentType: `${type}; charset=utf-16` };
    case 3:
      return { body: join([0xff, 0xfe], utf16(text, false)) };
    case 4:
      return { body: utf32(text, false), contentType: `${type}; Charset=utf-32le` };
    case 5:
      return { body: join([0, 0, 0xfe, 0xff], utf32(text, true)) };
    case 6:
      return {
        body: chance(0.5) ? utf8 : join([0xe9, 0xff], utf8),
        contentType: `${type}; charset=${pick(["iso-8859-1", "Windows-1252", "", "utf-7", "shift_jis", "us-ascii"])}`,
      };
    case 7:
      return { body: join([0xff, 0xfe], utf8) }; // a mark in front of UTF-8
    case 8:
      return { body: join([0xef, 0xbb, 0xbf], utf8), contentType: `${type}; charset=utf-8` };
    case 9:
      // No byte order mark and no order named: both orders are read (A11, H1).
      return {
        body: chance(0.5) ? utf16(text, chance(0.5)) : utf32(text, chance(0.5)),
        contentType: `${type}; charset=${pick(["utf-16", "UTF_16", "utf-32", "ucs-4", "ucs2"])}`,
      };
    case 10:
      // Parameters as content-type 2.x reads them (H2), and iconv-lite's aliases (L1).
      return {
        body: chance(0.5) ? utf16(text, false) : utf8,
        contentType: pick([
          `${type}; x="a;charset=utf-8;"; charset=utf-16le`,
          `${type}; charset=utf-8; charset=utf-16le`,
          `${type}; charset="utf-\\16le"`,
          `${type}; charset="utf-16le`,
          `${type}; charset=ISO_8859-1:1987`,
          `${type}; charset=windows-874`,
          `${type}; charset=hex`,
        ]),
      };
    default:
      return chance(0.5) ? { body: utf8, contentType: type } : { body: utf8 };
  }
}

function generatedCondition(): Condition {
  const op = pick(PROTOCOL_OPS);
  const target = op === "json_key" ? "body" : pick(PROTOCOL_TARGETS);
  const condition: { target: Condition["target"]; name?: string; op: Condition["op"]; value?: string } = {
    target,
    op,
  };
  if (target === "header") condition.name = pick(HEADER_NAMES);
  if (target === "query_value" && chance(0.5)) condition.name = pick(KEYS.filter((key) => key !== ""));
  if (op === "length_over") condition.value = pick(LENGTHS);
  else if (op !== "present") condition.value = chance(0.2) ? `${pick(TOKENS)}${pick(TOKENS)}` : pick(TOKENS);
  if (target === "method" && op === "equals") condition.value = pick(METHODS);
  return condition;
}

function generatedPatch(): BundlePatch {
  const conditions = Array.from({ length: 1 + Math.floor(rand() * (chance(0.7) ? 2 : 8)) }, generatedCondition);
  const patch: BundlePatch = {
    id: "vp_generated",
    mode: chance(0.5) ? "monitor" : "enforce",
    conditions,
    advisory: "CVE-2026-10001",
  };
  if (chance(0.3))
    patch.methods = [pick(METHODS), ...(chance(0.3) ? [pick(METHODS)] : [])].filter(
      (m, i, all) => all.indexOf(m) === i,
    );
  if (chance(0.3)) patch.path = pick(GLOBS);
  return BundlePatchSchema.parse(patch);
}

/** The request as Node and Express give it to Shield: `url`, `originalUrl`, lower-case headers. */
function incoming(method: string, target: string, headers: Record<string, string>): IncomingMessage {
  return { method, url: target, originalUrl: target, headers } as unknown as IncomingMessage;
}

describe("the request Shield reads is the protocol's patchRequestOf", () => {
  it("for 3,000 generated targets: path decoded and dot-resolved, raw path, query", () => {
    for (let i = 0; i < 3_000; i++) {
      const target = generatedTarget();
      const ours = patchRequestOf(incoming("GET", target, {}), "GET");
      const reference = protocolRequestOf({ method: "GET", target });
      expect({ path: ours.path, rawPath: ours.rawPath, query: ours.query }).toEqual({
        path: reference.path,
        rawPath: reference.rawPath,
        query: reference.query,
      });
    }
  });

  it("drops the scheme and authority of a target in absolute form", () => {
    const ours = patchRequestOf(incoming("GET", "http://example.test/api/%61dmin?x=1", {}), "GET");
    expect([ours.path, ours.rawPath, ours.query]).toEqual(["/api/admin", "/api/%61dmin", "x=1"]);
  });
});

describe("matchPatch equals the protocol's matchPatch (differential)", () => {
  const ROUNDS = 4_000;
  const PATCHES_PER_REQUEST = 12;

  it(`over ${ROUNDS} generated requests × ${PATCHES_PER_REQUEST} generated patches, with and without a body`, () => {
    let matched = 0;
    let pending = 0;
    let missed = 0;
    for (let round = 0; round < ROUNDS; round++) {
      const method = pick(METHODS);
      const target = generatedTarget();
      const headers = generatedHeaders();
      const { body, contentType } = generatedBody();
      if (contentType !== undefined) headers["content-type"] = contentType;
      const reference = protocolRequestOf({ method, target, headers: { ...headers } });
      const ours = patchRequestOf(incoming(method, target, headers), method);
      const view = new RequestView(ours);
      for (let k = 0; k < PATCHES_PER_REQUEST; k++) {
        const patch = generatedPatch();
        const read = readPatch(patch);
        if (typeof read === "string") throw new Error(`a valid patch was refused: ${read}`);
        const prepared = preparePatch(read);
        const withBody: ProtocolRequest = { ...reference, body };
        const withoutBody: ProtocolRequest = { ...reference, body: null };
        const expectedFull = protocolMatch(patch, withBody);
        const expectedPending = protocolMatch(patch, withoutBody);
        const context = { round, k, patch, method, target: target.slice(0, 200), headers: Object.keys(headers) };
        // One phase, the body given.
        expect({ ...matchPatch(prepared, view, body), context }).toEqual({ ...expectedFull, context });
        // Two phases, as Shield runs them: at decision time without the body, then the body in verifyBody.
        const first = matchPatch(prepared, view);
        expect({ ...first, context }).toEqual({ ...expectedPending, context });
        const twoPhase = first.matched || (first.bodyPending && matchBody(prepared, view, body));
        expect({ twoPhase, context }).toEqual({ twoPhase: expectedFull.matched, context });
        if (expectedFull.matched) matched++;
        else if (expectedPending.bodyPending) pending++;
        else missed++;
      }
    }
    // The corpus exercises every outcome, not only misses.
    expect(matched).toBeGreaterThan(2_000);
    expect(pending).toBeGreaterThan(500);
    expect(missed).toBeGreaterThan(10_000);
  }, 120_000); // large inputs (16 KB fields, 70 KB bodies): slow on a loaded machine

  it("the documented catalog entry: its exploit matches and its benign request does not", () => {
    const read = readPatch(
      BundlePatchSchema.parse({ ...EXAMPLE_VIRTUAL_PATCH, mode: "monitor", advisory: "CVE-2026-10001" }),
    );
    if (typeof read === "string") throw new Error(read);
    const prepared = preparePatch(read);
    for (const [name, expected] of [
      ["exploit", true],
      ["benign", false],
    ] as const) {
      const reference = EXAMPLE_VIRTUAL_PATCH.reference[name];
      const ours: PatchRequest = patchRequestOf(incoming(reference.method, reference.target, {}), reference.method);
      expect(matchPatch(prepared, new RequestView(ours), new Uint8Array()).matched).toBe(expected);
    }
  });

  it("is linear: a 16 KB query of near misses against 50 patches × 8 contains conditions stays fast", () => {
    const patches = Array.from({ length: 50 }, () =>
      preparePatch({
        conditions: Array.from({ length: 8 }, () => ({
          target: "query_key" as const,
          op: "contains" as const,
          value: `${"a".repeat(255)}b`,
        })),
      }),
    );
    const query = `${"a".repeat(16_000)}=1`;
    const view = new RequestView({ method: "GET", path: "/", rawPath: "/", query, headers: {} });
    const started = performance.now();
    for (const patch of patches) expect(matchPatch(patch, view).matched).toBe(false);
    // Quadratic matching would compare about 16,000 × 256 characters per condition: seconds, not milliseconds.
    expect(performance.now() - started).toBeLessThan(500);
  });
});
