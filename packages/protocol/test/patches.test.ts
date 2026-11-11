import { createRequire } from "node:module";
import { describe, expect, it } from "vitest";
import {
  type BundlePatch,
  BundlePatchSchema,
  type Condition,
  ConditionSchema,
  EXAMPLE_BUNDLE_PATCH,
  EXAMPLE_VIRTUAL_PATCH,
  matchPatch,
  PATCH_ID_PATTERN,
  PATCH_LIMITS,
  PATCH_OPS,
  PATCH_TARGETS,
  PatchIdSchema,
  type PatchRequest,
  patchRequestOf,
  type VirtualPatch,
  VirtualPatchSchema,
} from "../src/index.ts";
import { charsetOfContentType, LATIN1_CHARSETS, PATCH_BODY_STATES } from "../src/patches.ts";

// Dev-only: the libraries Express's body parsers use, to check that this module reads a header and a charset name
// as they do. Never imported by the source.
const requireDev = createRequire(import.meta.url);
const contentType = requireDev("content-type") as { parse(header: string): { parameters: Record<string, string> } };
const iconv = requireDev("iconv-lite") as {
  encodingExists(name: string): boolean;
  decode(bytes: Uint8Array, name: string): string;
};

const ok = (schema: { safeParse: (value: unknown) => { success: boolean } }, value: unknown): boolean =>
  schema.safeParse(value).success;

/** A request with nothing in it but what `patch` sets. */
const request = (patch: Partial<PatchRequest> = {}): PatchRequest => ({
  method: "GET",
  path: "/",
  rawPath: "/",
  query: "",
  headers: {},
  ...patch,
});

/** A patch with these conditions and nothing else. */
const only = (...conditions: Condition[]) => ({ conditions });
const matches = (conditions: Condition[], req: Partial<PatchRequest>): boolean =>
  matchPatch(only(...conditions), request(req)).matched;

const PROTO_KEY: Condition = { target: "query_key", op: "contains", value: "__proto__" };

describe("constants", () => {
  it("has the targets, operators and limits of the plan's Global Constraints", () => {
    expect(PATCH_TARGETS).toEqual(["method", "path", "query_key", "query_value", "header_name", "header", "body"]);
    expect(PATCH_OPS).toEqual(["equals", "contains", "starts_with", "ends_with", "length_over", "present", "json_key"]);
    expect(PATCH_LIMITS).toEqual({
      conditionsMax: 8,
      perBundle: 50,
      valueMin: 1,
      valueMax: 256,
      lengthOverMax: 1_000_000,
      titleMax: 120,
      advisoriesMax: 10,
      methodsMax: 8,
      headerNameMax: 128,
      pathMax: 16_384,
      queryMax: 16_384,
      headerValueMax: 16_384,
      referenceTargetMax: 16_384,
      referenceHeadersMax: 32,
      referenceBodyMax: 65_536,
      bundleBytesMax: 16_384,
    });
  });

  it("freezes the limits and the lists", () => {
    expect(Object.isFrozen(PATCH_LIMITS)).toBe(true);
    expect(Object.isFrozen(PATCH_TARGETS)).toBe(true);
    expect(Object.isFrozen(PATCH_OPS)).toBe(true);
  });
});

describe("PatchIdSchema", () => {
  it.each(["vp_qs_proto", "vp_abc", `vp_${"a".repeat(48)}`, "vp_lodash_2019_10744"])("accepts %j", (id) => {
    expect(ok(PatchIdSchema, id)).toBe(true);
    expect(PATCH_ID_PATTERN.test(id)).toBe(true);
  });

  it.each([
    "vp_ab",
    `vp_${"a".repeat(49)}`,
    "vp_QS",
    "vp_qs-proto",
    "qs_proto",
    "vp_qs proto",
    "VP_abc",
    "vp_abc\n",
    "",
  ])("rejects %j", (id) => {
    expect(ok(PatchIdSchema, id)).toBe(false);
  });
});

describe("ConditionSchema", () => {
  it("accepts every target with a value operator", () => {
    for (const target of PATCH_TARGETS) {
      const name = target === "header" ? { name: "x-test" } : {};
      for (const op of ["equals", "contains", "starts_with", "ends_with"] as const) {
        expect(ok(ConditionSchema, { target, op, value: "abc", ...name }), `${target} ${op}`).toBe(true);
      }
      expect(ok(ConditionSchema, { target, op: "length_over", value: "10", ...name })).toBe(true);
      expect(ok(ConditionSchema, { target, op: "present", ...name })).toBe(true);
    }
  });

  it("requires a value except for present, and refuses one for present", () => {
    expect(ok(ConditionSchema, { target: "path", op: "contains" })).toBe(false);
    expect(ok(ConditionSchema, { target: "path", op: "present", value: "x" })).toBe(false);
  });

  it("accepts values of 1..256 printable ASCII characters only", () => {
    const withValue = (value: unknown) => ok(ConditionSchema, { target: "path", op: "contains", value });
    expect(withValue("a")).toBe(true);
    expect(withValue("a".repeat(256))).toBe(true);
    expect(withValue(" ~")).toBe(true);
    expect(withValue("")).toBe(false);
    expect(withValue("a".repeat(257))).toBe(false);
    expect(withValue("café")).toBe(false);
    expect(withValue("a\tb")).toBe(false);
    expect(withValue("a\u0000")).toBe(false);
    expect(withValue("a\u007f")).toBe(false);
    expect(withValue(7)).toBe(false);
  });

  it("takes length_over as a decimal of 1..1,000,000", () => {
    const over = (value: unknown) => ok(ConditionSchema, { target: "path", op: "length_over", value });
    expect(over("1")).toBe(true);
    expect(over("1000000")).toBe(true);
    expect(over("0")).toBe(false);
    expect(over("1000001")).toBe(false);
    expect(over("01")).toBe(false);
    expect(over("1.5")).toBe(false);
    expect(over("-1")).toBe(false);
    expect(over("1e3")).toBe(false);
    expect(over(" 1")).toBe(false);
    expect(over(10)).toBe(false);
  });

  it("requires a lower-case name for header, allows one for query_value and refuses one elsewhere", () => {
    expect(ok(ConditionSchema, { target: "header", op: "present" })).toBe(false);
    expect(ok(ConditionSchema, { target: "header", op: "present", name: "content-type" })).toBe(true);
    expect(ok(ConditionSchema, { target: "header", op: "present", name: "Content-Type" })).toBe(false);
    expect(ok(ConditionSchema, { target: "header", op: "present", name: "x y" })).toBe(false);
    expect(ok(ConditionSchema, { target: "header", op: "present", name: "a".repeat(128) })).toBe(true);
    expect(ok(ConditionSchema, { target: "header", op: "present", name: "a".repeat(129) })).toBe(false);
    expect(ok(ConditionSchema, { target: "query_value", op: "present" })).toBe(true);
    expect(ok(ConditionSchema, { target: "query_value", op: "present", name: "a[b]" })).toBe(true);
    expect(ok(ConditionSchema, { target: "query_value", op: "present", name: "" })).toBe(false);
    for (const target of ["method", "path", "query_key", "header_name", "body"]) {
      expect(ok(ConditionSchema, { target, op: "present", name: "x" }), target).toBe(false);
    }
  });

  it("takes json_key on the body only, with a value (amendment A6, F6)", () => {
    expect(ok(ConditionSchema, { target: "body", op: "json_key", value: "constructor" })).toBe(true);
    expect(ok(ConditionSchema, { target: "body", op: "json_key" })).toBe(false);
    for (const target of PATCH_TARGETS.filter((target) => target !== "body")) {
      const name = target === "header" ? { name: "x-a" } : {};
      expect(ok(ConditionSchema, { target, op: "json_key", value: "constructor", ...name }), target).toBe(false);
    }
  });

  it("rejects an unknown target or operator, and strips unknown keys", () => {
    expect(ok(ConditionSchema, { target: "cookie", op: "present" })).toBe(false);
    expect(ok(ConditionSchema, { target: "path", op: "matches", value: "x" })).toBe(false);
    expect(ok(ConditionSchema, { target: "path", op: "regex", value: ".*" })).toBe(false);
    expect(ConditionSchema.parse({ target: "path", op: "contains", value: "x", note: "y" })).toEqual({
      target: "path",
      op: "contains",
      value: "x",
    });
  });
});

describe("VirtualPatchSchema", () => {
  const patch = (extra: Record<string, unknown>) => ({ ...EXAMPLE_VIRTUAL_PATCH, ...extra });

  it("parses the documented catalog entry unchanged", () => {
    const parsed: VirtualPatch = VirtualPatchSchema.parse(EXAMPLE_VIRTUAL_PATCH);
    expect(parsed).toEqual(EXAMPLE_VIRTUAL_PATCH);
    expect(VirtualPatchSchema.parse(JSON.parse(JSON.stringify(EXAMPLE_VIRTUAL_PATCH)))).toEqual(EXAMPLE_VIRTUAL_PATCH);
    expect(Object.isFrozen(EXAMPLE_VIRTUAL_PATCH)).toBe(true);
  });

  it("documents a reference exploit that matches and a benign request that does not", () => {
    const { exploit, benign } = EXAMPLE_VIRTUAL_PATCH.reference;
    expect(matchPatch(EXAMPLE_VIRTUAL_PATCH, patchRequestOf(exploit)).matched).toBe(true);
    expect(matchPatch(EXAMPLE_VIRTUAL_PATCH, patchRequestOf(benign)).matched).toBe(false);
  });

  it("takes 1..8 conditions", () => {
    const conditions = (count: number) => Array.from({ length: count }, () => PROTO_KEY);
    expect(ok(VirtualPatchSchema, patch({ conditions: conditions(1) }))).toBe(true);
    expect(ok(VirtualPatchSchema, patch({ conditions: conditions(8) }))).toBe(true);
    expect(ok(VirtualPatchSchema, patch({ conditions: [] }))).toBe(false);
    expect(ok(VirtualPatchSchema, patch({ conditions: conditions(9) }))).toBe(false);
  });

  it("takes 1..10 distinct advisory ids", () => {
    const ids = (count: number) => Array.from({ length: count }, (_, n) => `CVE-2026-${10000 + n}`);
    expect(ok(VirtualPatchSchema, patch({ advisories: ids(1) }))).toBe(true);
    expect(ok(VirtualPatchSchema, patch({ advisories: ids(10) }))).toBe(true);
    expect(ok(VirtualPatchSchema, patch({ advisories: [] }))).toBe(false);
    expect(ok(VirtualPatchSchema, patch({ advisories: ids(11) }))).toBe(false);
    expect(ok(VirtualPatchSchema, patch({ advisories: ["CVE-2026-10000", "CVE-2026-10000"] }))).toBe(false);
    expect(ok(VirtualPatchSchema, patch({ advisories: ["not an advisory"] }))).toBe(false);
  });

  it("takes a title of 1..120 characters, an npm package, optional distinct methods and an optional rule glob", () => {
    expect(ok(VirtualPatchSchema, patch({ title: "t".repeat(120) }))).toBe(true);
    expect(ok(VirtualPatchSchema, patch({ title: "t".repeat(121) }))).toBe(false);
    expect(ok(VirtualPatchSchema, patch({ title: "  " }))).toBe(false);
    expect(ok(VirtualPatchSchema, patch({ package: "@scope/name" }))).toBe(true);
    expect(ok(VirtualPatchSchema, patch({ package: "not a package" }))).toBe(false);
    expect(ok(VirtualPatchSchema, patch({ methods: ["GET", "POST"] }))).toBe(true);
    expect(ok(VirtualPatchSchema, patch({ methods: ["GET", "GET"] }))).toBe(false);
    expect(ok(VirtualPatchSchema, patch({ methods: ["get"] }))).toBe(false);
    expect(ok(VirtualPatchSchema, patch({ path: "/api/**" }))).toBe(true);
    expect(ok(VirtualPatchSchema, patch({ path: "/api/*/x" }))).toBe(true);
    expect(ok(VirtualPatchSchema, patch({ path: "api" }))).toBe(false);
    expect(ok(VirtualPatchSchema, patch({ path: "/api/**/x" }))).toBe(false);
  });

  it("requires a reference exploit and benign request with a method and an origin-form target", () => {
    const withExploit = (exploit: Record<string, unknown>) =>
      ok(VirtualPatchSchema, patch({ reference: { ...EXAMPLE_VIRTUAL_PATCH.reference, exploit } }));
    expect(withExploit({ method: "POST", target: "/x", body: "{}", content_type: "application/json" })).toBe(true);
    expect(withExploit({ method: "GET", target: "/x", headers: { "x-a": "1" } })).toBe(true);
    expect(withExploit({ method: "GET", target: "x" })).toBe(false);
    expect(withExploit({ method: "GET", target: "/x\n" })).toBe(false);
    expect(withExploit({ method: "GET", target: `/${"a".repeat(16_384)}` })).toBe(false);
    expect(withExploit({ method: "GET", target: "/x", headers: { "X-A": "1" } })).toBe(false);
    expect(withExploit({ target: "/x" })).toBe(false);
    expect(ok(VirtualPatchSchema, patch({ reference: { exploit: EXAMPLE_VIRTUAL_PATCH.reference.exploit } }))).toBe(
      false,
    );
  });
});

describe("BundlePatchSchema", () => {
  it("parses the documented bundle entry unchanged and strips catalog-only fields", () => {
    const parsed: BundlePatch = BundlePatchSchema.parse(EXAMPLE_BUNDLE_PATCH);
    expect(parsed).toEqual(EXAMPLE_BUNDLE_PATCH);
    const stripped = BundlePatchSchema.parse({
      ...EXAMPLE_BUNDLE_PATCH,
      title: "x",
      package: "qs",
      reference: EXAMPLE_VIRTUAL_PATCH.reference,
    });
    expect(stripped).toEqual(EXAMPLE_BUNDLE_PATCH);
  });

  it("requires a mode, an advisory and 1..8 conditions", () => {
    const entry = (extra: Record<string, unknown>) => ({ ...EXAMPLE_BUNDLE_PATCH, ...extra });
    expect(ok(BundlePatchSchema, entry({ mode: "enforce" }))).toBe(true);
    expect(ok(BundlePatchSchema, entry({ mode: "block" }))).toBe(false);
    expect(ok(BundlePatchSchema, entry({ mode: undefined }))).toBe(false);
    expect(ok(BundlePatchSchema, entry({ advisory: undefined }))).toBe(false);
    expect(ok(BundlePatchSchema, entry({ advisory: "x" }))).toBe(false);
    expect(ok(BundlePatchSchema, entry({ conditions: [] }))).toBe(false);
    expect(ok(BundlePatchSchema, entry({ conditions: Array.from({ length: 9 }, () => PROTO_KEY) }))).toBe(false);
    expect(ok(BundlePatchSchema, entry({ id: "vp_X" }))).toBe(false);
  });
});

describe("matchPatch: operators", () => {
  const path = (op: Condition["op"], value: string) => ({ target: "path", op, value }) as Condition;

  it("equals, contains, starts_with and ends_with compare ASCII letters without regard to case", () => {
    expect(matches([path("equals", "/API/Admin")], { path: "/api/admin", rawPath: "/api/admin" })).toBe(true);
    expect(matches([path("equals", "/api")], { path: "/api/admin", rawPath: "/api/admin" })).toBe(false);
    expect(matches([path("contains", "ADM")], { path: "/api/admin", rawPath: "/api/admin" })).toBe(true);
    expect(matches([path("contains", "adx")], { path: "/api/admin", rawPath: "/api/admin" })).toBe(false);
    expect(matches([path("starts_with", "/API")], { path: "/api/admin", rawPath: "/api/admin" })).toBe(true);
    expect(matches([path("starts_with", "/admin")], { path: "/api/admin", rawPath: "/api/admin" })).toBe(false);
    expect(matches([path("ends_with", "MIN")], { path: "/api/admin", rawPath: "/api/admin" })).toBe(true);
    expect(matches([path("ends_with", "/api")], { path: "/api/admin", rawPath: "/api/admin" })).toBe(false);
  });

  it("folds only ASCII letters: no Unicode case folding", () => {
    // U+212A KELVIN SIGN lower-cases to "k" under Unicode rules; it must not match "k".
    expect(matches([path("contains", "k")], { path: "/K", rawPath: "/K" })).toBe(false);
    // "İ" (U+0130) is not "i".
    expect(matches([path("contains", "i")], { path: "/İ", rawPath: "/İ" })).toBe(false);
  });

  it("contains finds overlapping and repeated prefixes (no naive skipping)", () => {
    expect(matches([path("contains", "aab")], { path: "/aaab", rawPath: "/aaab" })).toBe(true);
    expect(matches([path("contains", "abab")], { path: "/abaabab", rawPath: "/abaabab" })).toBe(true);
    expect(matches([path("contains", "abac")], { path: "/abababab", rawPath: "/abababab" })).toBe(false);
    expect(matches([path("contains", "/")], { path: "/", rawPath: "/" })).toBe(true);
  });

  it("length_over is strictly greater: boundaries", () => {
    const of = (length: number) => {
      const p = `/${"a".repeat(length - 1)}`;
      return { path: p, rawPath: p };
    };
    expect(matches([path("length_over", "10")], of(10))).toBe(false);
    expect(matches([path("length_over", "10")], of(11))).toBe(true);
    expect(matches([path("length_over", "1")], of(1))).toBe(false);
    expect(matches([path("length_over", "1")], of(2))).toBe(true);
  });

  it("present holds when the target has a value at all", () => {
    expect(matches([{ target: "path", op: "present" }], {})).toBe(true);
    expect(matches([{ target: "method", op: "present" }], {})).toBe(true);
  });

  it("requires every condition to hold", () => {
    const both = [path("contains", "admin"), { target: "method", op: "equals", value: "post" } as Condition];
    expect(matches(both, { method: "POST", path: "/admin", rawPath: "/admin" })).toBe(true);
    expect(matches(both, { method: "GET", path: "/admin", rawPath: "/admin" })).toBe(false);
    expect(matches(both, { method: "POST", path: "/user", rawPath: "/user" })).toBe(false);
  });
});

describe("matchPatch: methods and path of the patch", () => {
  const base = only({ target: "path", op: "present" });

  it("applies only to the listed methods; HEAD counts as GET; an empty or absent list is every method", () => {
    expect(matchPatch({ ...base, methods: ["POST"] }, request({ method: "POST" })).matched).toBe(true);
    expect(matchPatch({ ...base, methods: ["POST"] }, request({ method: "GET" })).matched).toBe(false);
    expect(matchPatch({ ...base, methods: ["GET"] }, request({ method: "HEAD" })).matched).toBe(true);
    expect(matchPatch({ ...base, methods: [] }, request({ method: "DELETE" })).matched).toBe(true);
    expect(matchPatch(base, request({ method: "DELETE" })).matched).toBe(true);
  });

  it("applies only below the glob, on the decoded path or the raw path", () => {
    const scoped = { ...base, path: "/api/*/import" };
    expect(matchPatch(scoped, request({ path: "/api/v1/import", rawPath: "/api/v1/import" })).matched).toBe(true);
    expect(matchPatch(scoped, request({ path: "/API/v1/Import/", rawPath: "/API/v1/Import/" })).matched).toBe(true);
    expect(matchPatch(scoped, request({ path: "/api/import", rawPath: "/api/import" })).matched).toBe(false);
    expect(matchPatch(scoped, request({ path: "/api/v1/import", rawPath: "/api/v1/%69mport" })).matched).toBe(true);
    expect(matchPatch(scoped, request({ path: "/other", rawPath: "/api/v1/import" })).matched).toBe(true);
    const rest = { ...base, path: "/api/**" };
    expect(matchPatch(rest, request({ path: "/api", rawPath: "/api" })).matched).toBe(true);
    expect(matchPatch(rest, request({ path: "/api/a/b/c", rawPath: "/api/a/b/c" })).matched).toBe(true);
    expect(matchPatch(rest, request({ path: "/apix", rawPath: "/apix" })).matched).toBe(false);
    const root = { ...base, path: "/" };
    expect(matchPatch(root, request({ path: "/", rawPath: "/" })).matched).toBe(true);
    expect(matchPatch(root, request({ path: "/a", rawPath: "/a" })).matched).toBe(false);
  });
});

describe("matchPatch: query (evasion)", () => {
  it("matches a prototype key in bracket notation, raw or percent-encoded", () => {
    expect(matches([PROTO_KEY], { query: "a[__proto__][x]=1" })).toBe(true);
    expect(matches([PROTO_KEY], { query: "a%5B__proto__%5D%5Bx%5D=1" })).toBe(true);
    expect(matches([PROTO_KEY], { query: "__proto__[x]=1" })).toBe(true);
    expect(matches([PROTO_KEY], { query: "%5f%5fproto%5f%5f=1" })).toBe(true);
    expect(matches([PROTO_KEY], { query: "%5F%5Fproto%5F%5F=1" })).toBe(true);
  });

  it("matches mixed case", () => {
    expect(matches([PROTO_KEY], { query: "a[__PROTO__]=1" })).toBe(true);
    expect(matches([PROTO_KEY], { query: "a[__Proto__]=1" })).toBe(true);
  });

  it("decodes exactly one pass: a double-encoded key matches only if the once-decoded form does", () => {
    // %255f decodes once to %5f, which is neither the raw form nor `_`: one pass is the documented bound.
    expect(matches([PROTO_KEY], { query: "%255f%255fproto%255f%255f=1" })).toBe(false);
    // A condition written for the once-decoded form of a double encoding still matches it.
    expect(
      matches([{ target: "query_key", op: "contains", value: "%5f%5fproto" }], { query: "%255f%255fproto=1" }),
    ).toBe(true);
  });

  it("reads + as a space in the query only after decoding, and a literal %2B as +", () => {
    const space: Condition = { target: "query_value", name: "q", op: "equals", value: "a b" };
    expect(matches([space], { query: "q=a+b" })).toBe(true);
    expect(matches([space], { query: "q=a%20b" })).toBe(true);
    const plus: Condition = { target: "query_value", name: "q", op: "equals", value: "a+b" };
    expect(matches([plus], { query: "q=a%2Bb" })).toBe(true);
    // The raw form is compared as well, so a + written as + also matches a condition naming +.
    expect(matches([plus], { query: "q=a+b" })).toBe(true);
  });

  it("sees every value of a duplicated key", () => {
    const value: Condition = { target: "query_value", name: "id", op: "contains", value: "constructor" };
    expect(matches([value], { query: "id=1&id=constructor" })).toBe(true);
    expect(matches([value], { query: "id=constructor&id=1" })).toBe(true);
    expect(matches([value], { query: "id=1&id=2" })).toBe(false);
  });

  it("matches a named value through the decoded or raw key, case-insensitively", () => {
    const value: Condition = { target: "query_value", name: "a[b]", op: "equals", value: "x" };
    expect(matches([value], { query: "a[b]=x" })).toBe(true);
    expect(matches([value], { query: "a%5Bb%5D=x" })).toBe(true);
    expect(matches([value], { query: "A[B]=X" })).toBe(true);
    expect(matches([value], { query: "a[c]=x" })).toBe(false);
  });

  it("matches any value when no name is given", () => {
    const value: Condition = { target: "query_value", op: "contains", value: "<script" };
    expect(matches([value], { query: "a=1&b=%3Cscript%3E" })).toBe(true);
    expect(matches([value], { query: "a=1&b=2" })).toBe(false);
  });

  it("splits on & only, at the first =, and skips empty segments", () => {
    const key = (value: string): Condition => ({ target: "query_key", op: "equals", value });
    expect(matches([key("a")], { query: "a=b=c" })).toBe(true);
    expect(matches([{ target: "query_value", name: "a", op: "equals", value: "b=c" }], { query: "a=b=c" })).toBe(true);
    expect(matches([key("flag")], { query: "&&flag&&" })).toBe(true);
    expect(matches([key("a;b")], { query: "a;b=1" })).toBe(true);
  });

  it("present on a named query value means the key is there, with or without a value", () => {
    const present: Condition = { target: "query_value", name: "debug", op: "present" };
    expect(matches([present], { query: "debug" })).toBe(true);
    expect(matches([present], { query: "debug=" })).toBe(true);
    expect(matches([present], { query: "x=debug" })).toBe(false);
    expect(matches([present], { query: "" })).toBe(false);
    expect(matches([{ target: "query_key", op: "present" }], { query: "" })).toBe(false);
    expect(matches([{ target: "query_value", op: "present" }], { query: "" })).toBe(false);
    expect(matches([{ target: "query_key", op: "present" }], { query: "a" })).toBe(true);
  });

  it("leaves a malformed percent sequence as it is", () => {
    expect(matches([{ target: "query_key", op: "equals", value: "%zz" }], { query: "%zz=1" })).toBe(true);
    expect(matches([{ target: "query_key", op: "equals", value: "a%" }], { query: "a%=1" })).toBe(true);
    expect(matches([{ target: "query_key", op: "equals", value: "a%4" }], { query: "a%4=1" })).toBe(true);
  });
});

describe("matchPatch: false positives", () => {
  it("does not match ordinary keys and values that merely resemble a prototype key", () => {
    expect(matches([PROTO_KEY], { query: "proto=1&a[b][c]=2" })).toBe(false);
    expect(matches([PROTO_KEY], { query: "q=__proto__" })).toBe(false);
    const ctorKey: Condition = { target: "query_key", op: "equals", value: "constructor" };
    expect(matches([ctorKey], { query: "constructor_name=x" })).toBe(false);
  });

  it("does not match an encoded path segment that only resembles the condition after two decodings", () => {
    const cond: Condition = { target: "path", op: "contains", value: "/admin" };
    expect(matches([cond], { path: "/%61dmin", rawPath: "/%2561dmin" })).toBe(false);
  });

  it("does not see a header that is not there", () => {
    expect(matches([{ target: "header", name: "x-a", op: "contains", value: "1" }], { headers: { "x-b": "1" } })).toBe(
      false,
    );
  });
});

describe("matchPatch: path", () => {
  it("compares the decoded, dot-resolved path and the raw path", () => {
    const cond: Condition = { target: "path", op: "contains", value: "/admin" };
    expect(matches([cond], { path: "/admin", rawPath: "/%61dmin" })).toBe(true);
    expect(matches([cond], { path: "/x", rawPath: "/admin" })).toBe(true);
    expect(matches([cond], { path: "/x", rawPath: "/x" })).toBe(false);
  });
});

describe("matchPatch: headers", () => {
  it("present on a missing header name does not hold", () => {
    expect(matches([{ target: "header", name: "x-evil", op: "present" }], { headers: {} })).toBe(false);
    expect(matches([{ target: "header", name: "x-evil", op: "present" }], { headers: { "x-evil": "" } })).toBe(true);
    expect(matches([{ target: "header_name", op: "present" }], { headers: {} })).toBe(false);
    expect(matches([{ target: "header_name", op: "present" }], { headers: { a: "1" } })).toBe(true);
  });

  it("never reads a header through the prototype chain", () => {
    for (const name of ["constructor", "__proto__", "tostring", "hasownproperty"]) {
      expect(matches([{ target: "header", name, op: "present" }], { headers: {} }), name).toBe(false);
    }
    const headers: Record<string, string> = Object.assign(Object.create(null), { constructor: "x" });
    expect(matches([{ target: "header", name: "constructor", op: "equals", value: "x" }], { headers })).toBe(true);
  });

  it("ignores spaces and tabs around a header value", () => {
    const cond: Condition = { target: "header", name: "x-mode", op: "equals", value: "debug" };
    expect(matches([cond], { headers: { "x-mode": "  debug\t" } })).toBe(true);
    expect(matches([{ ...cond, op: "starts_with" }], { headers: { "x-mode": " debug" } })).toBe(true);
    expect(matches([{ ...cond, op: "ends_with" }], { headers: { "x-mode": "debug " } })).toBe(true);
  });

  it("compares a header value raw and percent-decoded once (no + as space)", () => {
    const cond: Condition = { target: "header", name: "cookie", op: "contains", value: "__proto__" };
    expect(matches([cond], { headers: { cookie: "a=%5F%5Fproto%5F%5F" } })).toBe(true);
    const space: Condition = { target: "header", name: "x-a", op: "equals", value: "a b" };
    expect(matches([space], { headers: { "x-a": "a+b" } })).toBe(false);
  });

  it("matches header names, which arrive in lower case", () => {
    expect(
      matches([{ target: "header_name", op: "starts_with", value: "X-Debug" }], { headers: { "x-debug-a": "1" } }),
    ).toBe(true);
  });
});

describe("matchPatch: method", () => {
  it("compares the method case-insensitively", () => {
    expect(matches([{ target: "method", op: "equals", value: "post" }], { method: "POST" })).toBe(true);
    expect(matches([{ target: "method", op: "equals", value: "PUT" }], { method: "POST" })).toBe(false);
  });
});

describe("matchPatch: body", () => {
  const enc = (text: string) => new TextEncoder().encode(text);
  const BODY: Condition = { target: "body", op: "contains", value: '"__proto__"' };

  it("matches only when the body condition held too, once a body is given", () => {
    expect(matchPatch(only(BODY), request({ body: enc('{"__proto__":{"x":1}}') }))).toEqual({
      matched: true,
      bodyPending: false,
    });
    expect(matchPatch(only(BODY), request({ body: enc('{"a":1}') }))).toEqual({ matched: false, bodyPending: false });
  });

  it("leaves the body pending when every other condition held and no body is given: never matched", () => {
    const cond: Condition = { target: "method", op: "equals", value: "POST" };
    expect(matchPatch(only(cond, BODY), request({ method: "POST" }))).toEqual({ matched: false, bodyPending: true });
    expect(matchPatch(only(cond, BODY), request({ method: "POST", body: null }))).toEqual({
      matched: false,
      bodyPending: true,
    });
    expect(matchPatch(only(BODY), request({}))).toEqual({ matched: false, bodyPending: true });
  });

  it("does not leave the body pending when another condition failed", () => {
    const cond: Condition = { target: "method", op: "equals", value: "POST" };
    expect(matchPatch(only(cond, BODY), request({ method: "GET" }))).toEqual({ matched: false, bodyPending: false });
    expect(matchPatch({ ...only(BODY), methods: ["POST"] }, request({ method: "GET" }))).toEqual({
      matched: false,
      bodyPending: false,
    });
  });

  it("checks an empty body: present does not hold, length_over does not hold", () => {
    expect(matchPatch(only(BODY), request({ body: new Uint8Array(0) }))).toEqual({
      matched: false,
      bodyPending: false,
    });
    expect(matches([{ target: "body", op: "present" }], { body: new Uint8Array(0) })).toBe(false);
    expect(matches([{ target: "body", op: "present" }], { body: enc("x") })).toBe(true);
    expect(matches([{ target: "body", op: "length_over", value: "1" }], { body: new Uint8Array(0) })).toBe(false);
  });

  it("measures length_over of a body in bytes", () => {
    const over = (value: string, body: Uint8Array) => matches([{ target: "body", op: "length_over", value }], { body });
    expect(over("3", enc("éé"))).toBe(true); // 4 bytes
    expect(over("4", enc("éé"))).toBe(false);
  });

  it("reads a binary body as UTF-8 with replacement characters, still finding ASCII text in it", () => {
    const binary = new Uint8Array([0xff, 0xfe, 0x00, ...enc('"__proto__"'), 0xc3]);
    expect(matches([BODY], { body: binary })).toBe(true);
    expect(matches([BODY], { body: new Uint8Array([0xff, 0x00, 0x80, 0x81]) })).toBe(false);
  });

  it("compares the body raw and percent-decoded once, case-insensitively", () => {
    expect(matches([BODY], { body: enc("%22__PROTO__%22") })).toBe(true);
    expect(matches([{ target: "body", op: "contains", value: "a b" }], { body: enc("a+b") })).toBe(false);
  });

  it("never leaves a patch without a body condition pending", () => {
    expect(matchPatch(only(PROTO_KEY), request({ query: "__proto__=1", body: enc("x") }))).toEqual({
      matched: true,
      bodyPending: false,
    });
    expect(matchPatch(only(PROTO_KEY), request({ query: "__proto__=1" }))).toEqual({
      matched: true,
      bodyPending: false,
    });
  });

  it("compares the body with JSON \\uXXXX escapes decoded as well", () => {
    const proto: Condition = { target: "body", op: "contains", value: "__proto__" };
    expect(matches([proto], { body: enc('{"__proto__":{}}') })).toBe(true);
    expect(matches([proto], { body: enc('{"\\u005f\\u005fproto\\u005f\\u005f":{}}') })).toBe(true);
    expect(matches([proto], { body: enc('{"\\u005F_\\u0070roto__":{}}') })).toBe(true);
    expect(matches([proto], { body: enc('{"__pr\\u006fto__":{}}') })).toBe(true);
    expect(matches([proto], { body: enc('{"__pr\\u006gto__":{}}') })).toBe(false);
  });

  it("combines surrogate pairs, decodes every code point and leaves malformed escapes as they are", () => {
    const emoji: Condition = { target: "body", op: "contains", value: "a\\ud83d" };
    // A lone or malformed escape stays as written, so the raw text still matches.
    expect(matches([emoji], { body: enc('"a\\ud83d"') })).toBe(true);
    const text = (value: string): Condition => ({ target: "body", op: "equals", value });
    expect(matches([text("x\\u12")], { body: enc("x\\u12") })).toBe(true);
    expect(matches([text("\\uzzzz")], { body: enc("\\uzzzz") })).toBe(true);
    // A pair decodes to one code point and decoding carries on after it; a lone half stays a lone half.
    expect(matches([text("A")], { body: enc("\\ud83d\\ude00A") })).toBe(false);
    expect(
      matches([{ target: "body", op: "ends_with", value: "_proto__" }], { body: enc("\\ud83d\\ude00\\u005fproto__") }),
    ).toBe(true);
    expect(
      matches([{ target: "body", op: "ends_with", value: "_proto__" }], { body: enc("\\ud83d\\u005fproto__") }),
    ).toBe(true);
    expect(matches([text("A")], { body: enc("\\u0041") })).toBe(true);
    expect(matches([text("AB")], { body: enc("\\u0041\\u0042") })).toBe(true);
  });
});

describe("matchPatch: input caps and cost", () => {
  it("scans only the first 16,384 characters of the path, the query and a header value", () => {
    const pad = "a".repeat(PATCH_LIMITS.pathMax);
    expect(
      matches([{ target: "path", op: "contains", value: "zz" }], { path: `/${pad}zz`, rawPath: `/${pad}zz` }),
    ).toBe(false);
    expect(
      matches([{ target: "path", op: "contains", value: "zz" }], {
        path: `/${pad.slice(3)}zz`,
        rawPath: `/${pad.slice(3)}zz`,
      }),
    ).toBe(true);
    expect(matches([PROTO_KEY], { query: `x=${pad}&__proto__=1` })).toBe(false);
    expect(
      matches([{ target: "header", name: "x-a", op: "ends_with", value: "zz" }], { headers: { "x-a": `${pad}zz` } }),
    ).toBe(false);
  });

  it("measures length_over on the whole path and header value, not the scanned prefix", () => {
    const long = `/${"a".repeat(20_000)}`;
    expect(matches([{ target: "path", op: "length_over", value: "10000" }], { path: long, rawPath: long })).toBe(true);
    expect(
      matches([{ target: "header", name: "x-a", op: "length_over", value: "10000" }], {
        headers: { "x-a": "a".repeat(20_000) },
      }),
    ).toBe(true);
  });

  it("stays linear on adversarial input: 50 patches of 8 contains conditions over capped inputs", () => {
    const value = `${"a".repeat(255)}b`;
    const patch = only(...Array.from({ length: 8 }, () => ({ target: "path", op: "contains", value }) as Condition));
    const worst = request({ path: `/${"a".repeat(100_000)}`, rawPath: `/${"a".repeat(100_000)}` });
    const started = performance.now();
    for (let n = 0; n < PATCH_LIMITS.perBundle; n++) expect(matchPatch(patch, worst).matched).toBe(false);
    // Naive search would cost 50 × 8 × 2 × 16,384 × 256 ≈ 3.4e9 comparisons; linear search a few million.
    expect(performance.now() - started).toBeLessThan(1000);
  });

  it("never throws on odd input", () => {
    const odd = request({
      path: "",
      rawPath: "",
      query: "%%%&==&=&%",
      headers: { "": "", "x-a": "\u0000\ud800" },
      body: new Uint8Array([0xed, 0xa0, 0x80]),
    });
    for (const target of PATCH_TARGETS) {
      const name = target === "header" ? { name: "x-a" } : {};
      expect(() => matchPatch(only({ target, op: "contains", value: "x", ...name } as Condition), odd)).not.toThrow();
    }
  });
});

describe("patchRequestOf", () => {
  it("splits the target, decodes the path once and resolves dot segments", () => {
    expect(patchRequestOf({ method: "GET", target: "/a/./b/../%63?x=1#frag" })).toEqual({
      method: "GET",
      path: "/a/c",
      rawPath: "/a/./b/../%63",
      query: "x=1",
      headers: {},
      body: new Uint8Array(0),
    });
    expect(patchRequestOf({ method: "GET", target: "/a//b/" }).path).toBe("/a/b");
    expect(patchRequestOf({ method: "GET", target: "/../.." }).path).toBe("/");
    expect(patchRequestOf({ method: "GET", target: "/" }).path).toBe("/");
  });

  it("sets the body as UTF-8 bytes and the content type as a header", () => {
    const req = patchRequestOf({
      method: "POST",
      target: "/x",
      headers: { "x-a": "1" },
      body: '{"a":"é"}',
      content_type: "application/json",
    });
    expect(req.headers).toEqual({ "x-a": "1", "content-type": "application/json" });
    expect(req.body).toEqual(new TextEncoder().encode('{"a":"é"}'));
  });
});

// --- Amendment A6 (review fixes) -------------------------------------------------------------------------------

describe("matchPatch: json_key (A6, F6)", () => {
  const enc = (text: string) => new TextEncoder().encode(text);
  const key = (value: string, body: string) =>
    matches([{ target: "body", op: "json_key", value }], { body: enc(body) });

  it("holds for the quoted name followed by optional JSON whitespace and a colon", () => {
    expect(key("constructor", '{"constructor":{"prototype":{}}}')).toBe(true);
    expect(key("constructor", '{"constructor" : 1}')).toBe(true);
    expect(key("constructor", '{"constructor"\r\n\t :1}')).toBe(true);
    expect(key("prototype", '{"constructor":{"prototype":{"isAdmin":true}}}')).toBe(true);
  });

  it("does not hold for the word as a value, in prose, or followed by anything but whitespace and a colon", () => {
    expect(key("constructor", '{"role":"constructor","stage":"prototype"}')).toBe(false);
    expect(key("constructor", '{"text":"the constructor: a function"}')).toBe(false);
    expect(key("constructor", '["constructor" ,1]')).toBe(false);
    expect(key("constructor", '{"constructor"\u00a0:1}')).toBe(false); // the escape text itself is no whitespace
    expect(key("constructor", `{"constructor"${"\u000b"}:1}`)).toBe(false);
    expect(key("constructor", '{"constructors":1}')).toBe(false);
    expect(key("constructor", '{"xconstructor":1}')).toBe(false);
  });

  it("finds a later occurrence after an earlier one that is a value", () => {
    expect(key("constructor", '{"a":"constructor","constructor":1}')).toBe(true);
    expect(key("a", '{"x":"a","a"   :1}')).toBe(true);
  });

  it("folds ASCII case and reads every decoded form: JSON escapes and percent-decoding", () => {
    expect(key("constructor", '{"CONSTRUCTOR":1}')).toBe(true);
    expect(key("constructor", '{"\\u0063onstructor":1}'.replace("\\\\", "\\"))).toBe(true);
    expect(key("constructor", "%7B%22constructor%22%3A1%7D")).toBe(true);
  });

  it("writes the name as a JSON string literal: a quote or backslash in it is escaped", () => {
    expect(key('a"b', '{"a\\"b":1}')).toBe(true);
    expect(key("a\\b", '{"a\\\\b":1}')).toBe(true);
  });

  it("stays linear on many near occurrences", () => {
    const body = `${'"constructor" '.repeat(20_000)}`;
    const started = performance.now();
    expect(key("constructor", body)).toBe(false);
    expect(performance.now() - started).toBeLessThan(500);
  });
});

describe("matchPatch: query pairs split like qs (A6, F3)", () => {
  const PROTO: Condition = { target: "query_key", op: "contains", value: "__proto__" };
  const key = (value: string): Condition => ({ target: "query_key", op: "equals", value });

  it("splits at ]= when the segment has one, else at the first =", () => {
    expect(matches([PROTO], { query: "a[b=c][__proto__]=x" })).toBe(true);
    const value: Condition = { target: "query_value", name: "a[b=c][__proto__]", op: "equals", value: "x" };
    expect(matches([value], { query: "a[b=c][__proto__]=x" })).toBe(true);
    expect(matches([{ target: "query_value", name: "a[x]", op: "equals", value: "1=2" }], { query: "a[x]=1=2" })).toBe(
      true,
    );
    expect(matches([key("a=b]")], { query: "a=b]=c" })).toBe(true);
  });

  it("offers the key of the first = as well, as older qs versions split (Jev qs_plus_first_equals, 0.49)", () => {
    expect(matches([key("a[b")], { query: "a[b=c][__proto__]=x" })).toBe(true);
    expect(matches([key("a")], { query: "a=b]=c" })).toBe(true);
  });

  it("never takes a value for a key: a value of __proto__ does not match a key condition", () => {
    expect(matches([PROTO], { query: "q=__proto__&sort[name]=asc" })).toBe(false);
    expect(matches([PROTO], { query: "sort=__proto__" })).toBe(false);
    expect(matches([PROTO], { query: "a[x]=__proto__]=1" })).toBe(false);
  });
});

describe("matchPatch: body character sets (A6, F1)", () => {
  const PROTO: Condition = { target: "body", op: "contains", value: '"__proto__"' };
  const TEXT = '{"__proto__":{"x":1}}';
  const utf16 = (text: string, big: boolean): Uint8Array => {
    const out = new Uint8Array(text.length * 2);
    for (let i = 0; i < text.length; i++) {
      const unit = text.charCodeAt(i);
      out[2 * i + (big ? 1 : 0)] = unit & 0xff;
      out[2 * i + (big ? 0 : 1)] = unit >> 8;
    }
    return out;
  };
  const utf32 = (text: string, big: boolean): Uint8Array => {
    const points = [...text].map((char) => char.codePointAt(0) as number);
    const out = new Uint8Array(points.length * 4);
    points.forEach((point, i) => {
      for (let b = 0; b < 4; b++) out[4 * i + (big ? 3 - b : b)] = (point >>> (8 * b)) & 0xff;
    });
    return out;
  };
  const withBom = (bom: number[], bytes: Uint8Array) => new Uint8Array([...bom, ...bytes]);
  const body = (contentType: string | undefined, bytes: Uint8Array) =>
    matchPatch(
      only(PROTO),
      request({ headers: contentType === undefined ? {} : { "content-type": contentType }, body: bytes }),
    );

  it("decodes UTF-16 and UTF-32 named by the charset parameter, in any case and quoted", () => {
    expect(body("application/json; charset=utf-16le", utf16(TEXT, false)).matched).toBe(true);
    expect(body("application/json;charset=UTF-16BE", utf16(TEXT, true)).matched).toBe(true);
    expect(body('application/json; charset="utf-16le"', utf16(TEXT, false)).matched).toBe(true);
    expect(body("application/json; charset=utf-32le", utf32(TEXT, false)).matched).toBe(true);
    expect(body("application/json; Charset=UTF-32BE", utf32(TEXT, true)).matched).toBe(true);
    expect(body("application/json; charset=utf-8", new TextEncoder().encode(TEXT)).matched).toBe(true);
  });

  it("reads utf-16 and utf-32 without an order, and a body without a charset, by the byte order mark", () => {
    expect(body("application/json; charset=utf-16", withBom([0xfe, 0xff], utf16(TEXT, true))).matched).toBe(true);
    expect(body("application/json; charset=utf-16", utf16(TEXT, false)).matched).toBe(true); // no mark: LE
    expect(body("application/json", withBom([0xff, 0xfe], utf16(TEXT, false))).matched).toBe(true);
    expect(body("application/json", withBom([0xfe, 0xff], utf16(TEXT, true))).matched).toBe(true);
    expect(body(undefined, withBom([0xff, 0xfe, 0, 0], utf32(TEXT, false))).matched).toBe(true);
    expect(body(undefined, withBom([0, 0, 0xfe, 0xff], utf32(TEXT, true))).matched).toBe(true);
    expect(body(undefined, withBom([0xef, 0xbb, 0xbf], new TextEncoder().encode(TEXT))).matched).toBe(true);
  });

  it("does not match a benign body in any of these encodings", () => {
    const benign = '{"name":"proto"}';
    expect(body("application/json; charset=utf-16le", utf16(benign, false)).matched).toBe(false);
    expect(body("application/json; charset=utf-32be", utf32(benign, true)).matched).toBe(false);
  });

  it("scans ASCII-compatible single-byte charsets as Latin-1 (Jev native_indexof_latin1)", () => {
    const latin = (charset: string, text: string) =>
      body(
        `application/x-www-form-urlencoded; charset=${charset}`,
        Uint8Array.from(text, (char) => char.charCodeAt(0)),
      );
    const FORM = 'a=1&b={"__proto__":1}&caf\xe9=\xff';
    for (const charset of ["iso-8859-1", "ISO-8859-15", "windows-1252", "cp1251", "us-ascii", "latin1", "koi8-r"]) {
      expect(latin(charset, FORM).matched, charset).toBe(true);
      expect(latin(charset, "a=1&b=proto&caf\xe9=\xff").matched, charset).toBe(false);
    }
  });

  it("reads an empty charset= as UTF-8", () => {
    expect(body("application/json; charset=", new TextEncoder().encode(TEXT)).matched).toBe(true);
    expect(body("application/json; charset=", new TextEncoder().encode('{"a":1}')).matched).toBe(false);
  });

  it("counts a body in any other character set as a match of its body conditions (D-062)", () => {
    for (const charset of ["utf-7", "ebcdic", "shift_jis", "gb2312", "x-unknown"]) {
      expect(body(`application/json; charset=${charset}`, new TextEncoder().encode("{}")).matched, charset).toBe(true);
    }
    // An empty body has nothing to decode: no match.
    expect(body("application/json; charset=shift_jis", new Uint8Array(0)).matched).toBe(false);
    // Non-body conditions still decide first.
    const scoped = only({ target: "method", op: "equals", value: "PUT" }, PROTO);
    expect(
      matchPatch(
        scoped,
        request({ headers: { "content-type": "text/plain; charset=koi8-r" }, body: new Uint8Array([1]) }),
      ),
    ).toEqual({ matched: false, bodyPending: false });
  });

  it("never throws on truncated or invalid UTF-16 and UTF-32", () => {
    for (const charset of ["utf-16le", "utf-16be", "utf-32le", "utf-32be"]) {
      for (const bytes of [
        new Uint8Array([0x41]),
        new Uint8Array([0xff, 0xff, 0xff, 0x7f, 0x00]),
        new Uint8Array([0x00, 0xd8, 0, 0]),
      ]) {
        expect(() => body(`text/plain; charset=${charset}`, bytes)).not.toThrow();
      }
    }
  });

  it("measures length_over in bytes, whatever the encoding", () => {
    const over = { target: "body", op: "length_over", value: "40" } as Condition;
    expect(
      matches([over], { headers: { "content-type": "text/plain; charset=utf-16le" }, body: utf16(TEXT, false) }),
    ).toBe(true);
  });
});

// --- Amendment A11 (second review) -----------------------------------------------------------------------------

describe("A11: content-type parameters as content-type 2.x reads them (H2)", () => {
  const theirs = (header: string): string | undefined => contentType.parse(header).parameters.charset?.toLowerCase();

  it.each([
    ['application/json; x="a;charset=utf-8;"; charset=utf-16le', "utf-16le"],
    ["application/json; charset=utf-8; charset=utf-16le", "utf-8"],
    ['text/xml; charset="utf-\\16le"', "utf-16le"],
    ["text/xml;CHARSET = UTF-16LE ", "utf-16le"],
    ['text/xml; charset="utf-8', undefined],
    ["text/xml; charset", undefined],
    ["text/xml; charset=", ""],
    ['text/xml; a="\\""; charset=utf-16be', "utf-16be"],
    ["text/xml", undefined],
    ['text/xml; charset="utf-8"junk; charset=utf-16le', "utf-8"],
    ["; charset=utf-7", "utf-7"],
    ["text/xml; =x; charset=latin1", "latin1"],
  ])("%j → %j", (header, expected) => {
    expect(theirs(header)).toBe(expected);
    expect(charsetOfContentType(header)).toBe(expected);
  });

  it("agrees with content-type on 20,000 generated headers", () => {
    let state = 20_261_112;
    const rand = (): number => {
      state = (Math.imul(state, 1_664_525) + 1_013_904_223) >>> 0;
      return state / 4_294_967_296;
    };
    const PIECES = [
      "charset",
      "CharSet",
      "x",
      "boundary",
      "=",
      "=",
      ";",
      ";",
      ";",
      " ",
      "\t",
      '"',
      '"',
      "\\",
      "utf-8",
      "UTF-16LE",
      "latin1",
      "a;charset=utf-7",
      ",",
      "é",
      "text/plain",
      "/",
    ];
    for (let i = 0; i < 20_000; i++) {
      let header = rand() < 0.8 ? "text/plain" : "";
      for (let n = Math.floor(rand() * 14); n > 0; n--) header += PIECES[Math.floor(rand() * PIECES.length)];
      expect([header, charsetOfContentType(header)]).toEqual([header, theirs(header)]);
    }
  });
});

describe("A11: charsets", () => {
  const PROTO: Condition = { target: "body", op: "contains", value: '"__proto__"' };
  const TEXT = '{"__proto__":{"x":1}}';
  const be16 = (text: string) => Uint8Array.from(Buffer.from(text, "utf16le").swap16());
  const be32 = (text: string) => {
    const out = Buffer.alloc(text.length * 4);
    for (let i = 0; i < text.length; i++) out.writeUInt32BE(text.charCodeAt(i), i * 4);
    return Uint8Array.from(out);
  };
  const body = (type: string, bytes: Uint8Array) =>
    matchPatch(only(PROTO), request({ headers: { "content-type": type }, body: bytes }));

  it("H1: utf-16 and utf-32 without a byte order mark are scanned in both byte orders", () => {
    expect(body("application/json; charset=utf-16", be16(TEXT)).matched).toBe(true);
    expect(body("application/json; charset=utf-16", Uint8Array.from(Buffer.from(TEXT, "utf16le"))).matched).toBe(true);
    expect(body("application/json; charset=utf-32", be32(TEXT)).matched).toBe(true);
    expect(body("application/json; charset=UCS-4", be32(TEXT)).matched).toBe(true);
    expect(body("application/json; charset=utf-16", be16('{"a":1}')).matched).toBe(false);
  });

  it("H2: a quoted ; before the charset does not hide it", () => {
    expect(
      body('application/json; x="a;charset=utf-8;"; charset=utf-16le', Uint8Array.from(Buffer.from(TEXT, "utf16le")))
        .matched,
    ).toBe(true);
  });

  it("L1: charset names are canonicalised as iconv-lite does, and every listed name is ASCII-compatible there", () => {
    const ascii = Uint8Array.from({ length: 128 }, (_, i) => i);
    const all = Uint8Array.from({ length: 256 }, (_, i) => i);
    for (const name of LATIN1_CHARSETS) {
      expect(iconv.encodingExists(name), name).toBe(true);
      expect(iconv.decode(ascii, name), name).toBe(String.fromCharCode(...ascii));
      expect(iconv.decode(all, name).length, name).toBe(256);
    }
    const latin = (charset: string) =>
      body(
        `text/plain; charset=${charset}`,
        Uint8Array.from(`\xe9${TEXT}`, (char) => char.charCodeAt(0)),
      );
    for (const charset of [
      "ISO_8859-1",
      "iso_8859-1:1987",
      "windows-874",
      "cp874",
      "IBM866",
      "csISOLatin1",
      "TIS-620",
      "macintosh",
      "ISO88591",
      "l9",
    ]) {
      expect(latin(charset), charset).toEqual({ matched: true, bodyPending: false });
    }
    // Not ASCII-compatible single-byte charsets: not read (D-062).
    for (const charset of ["shift_jis", "gbk", "utf-7", "hex", "base64", "viscii", "cp864", "iso646jp"]) {
      expect(LATIN1_CHARSETS as readonly string[]).not.toContain(charset.replace(/[^a-z0-9]/g, ""));
      expect(latin(charset).undecodable, charset).toBe(true);
    }
  });

  it("M2: a body in an unknown charset matches as undecodable; the state is part of PATCH_BODY_STATES", () => {
    expect(PATCH_BODY_STATES).toEqual(["checked", "unchecked", "undecodable"]);
    expect(body("text/plain; charset=shift_jis", new TextEncoder().encode("hello"))).toEqual({
      matched: true,
      bodyPending: false,
      undecodable: true,
    });
    expect(body("text/plain; charset=utf-8", new TextEncoder().encode(TEXT)).undecodable).toBeUndefined();
    // A patch without a body condition is never undecodable.
    expect(
      matchPatch(
        only(PROTO_KEY),
        request({
          query: "__proto__=1",
          headers: { "content-type": "text/plain; charset=shift_jis" },
          body: new Uint8Array([1]),
        }),
      ),
    ).toEqual({ matched: true, bodyPending: false });
  });
});
