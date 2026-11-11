import { matchPatch, patchRequestOf, type VirtualPatch, VirtualPatchSchema } from "@antireverse/protocol";

// The Virtual patch catalog (slice 20, D-061): request-level exploit patterns for well-known npm advisories, curated
// by Anti Reverse. Data only; the API reads it through the `PatchCatalog` dependency, so tests run on a fixture
// catalog. Every advisory id here was checked against the public OSV API when it was written, and the package and
// affected ranges are pinned in test/patch-catalog.test.ts. A patch id is stable across catalog versions: an admin's
// mode is stored under it.

export interface PatchCatalog {
  /** `YYYY-MM-DD.n`: the date the catalog was last changed and the change of that day. */
  readonly version: string;
  /** The entries, in catalog order, each id once. Deeply frozen. */
  readonly patches: readonly VirtualPatch[];
  /** The entry with this id, or undefined. */
  get(id: string): VirtualPatch | undefined;
}

function freeze<T>(value: T): T {
  if (typeof value === "object" && value !== null && !Object.isFrozen(value)) {
    for (const member of Object.values(value)) freeze(member);
    Object.freeze(value);
  }
  return value;
}

/**
 * A catalog of `entries`: each one valid (`VirtualPatchSchema`), each id once, each reference exploit matched and
 * each benign request not (`matchPatch` over `patchRequestOf`). Throws on the first entry that fails, naming its id.
 */
export function createPatchCatalog(version: string, entries: readonly unknown[]): PatchCatalog {
  const byId = new Map<string, VirtualPatch>();
  const patches: VirtualPatch[] = [];
  for (const entry of entries) {
    const patch = VirtualPatchSchema.parse(entry);
    if (byId.has(patch.id)) throw new Error(`The catalog lists ${patch.id} twice.`);
    if (!matchPatch(patch, patchRequestOf(patch.reference.exploit)).matched) {
      throw new Error(`The reference exploit of ${patch.id} does not match it.`);
    }
    const benign = matchPatch(patch, patchRequestOf(patch.reference.benign));
    if (benign.matched || benign.bodyPending) throw new Error(`The benign request of ${patch.id} matches it.`);
    byId.set(patch.id, patch);
    patches.push(patch);
  }
  freeze(patches);
  return Object.freeze({
    version,
    patches,
    get: (id: string) => byId.get(id),
  });
}

/** The catalog Anti Reverse ships. */
export const PATCH_CATALOG: PatchCatalog = createPatchCatalog("2026-11-11.4", [
  {
    // qs before 6.10.3 (and the 6.2.4 … 6.9.7 backports) lets `__proto__` in a query key poison the parsed
    // object's prototype; Express parses `req.query` with qs, so the request alone reaches it.
    id: "vp_qs_proto_query_key",
    title: "qs prototype poisoning through __proto__ in query keys",
    advisories: ["GHSA-hrpp-h998-j3pp", "CVE-2022-24999"],
    package: "qs",
    conditions: [{ target: "query_key", op: "contains", value: "__proto__" }],
    reference: {
      exploit: { method: "GET", target: "/search?a[__proto__]b&a[__proto__]&a[length]=100000000" },
      benign: { method: "GET", target: "/search?q=__proto__&sort[name]=asc" },
    },
  },
  {
    // The same qs flaw through an urlencoded body: Express's `urlencoded({ extended: true })` parses it with qs.
    // Matched on the raw and the percent-decoded body, so `%5B__proto__%5D` is seen as well (plan A6 F4).
    id: "vp_qs_proto_form_body",
    title: "qs prototype poisoning through __proto__ keys in a form body",
    advisories: ["GHSA-hrpp-h998-j3pp", "CVE-2022-24999"],
    package: "qs",
    conditions: [{ target: "body", op: "contains", value: "[__proto__]" }],
    reference: {
      exploit: {
        method: "POST",
        target: "/search",
        content_type: "application/x-www-form-urlencoded",
        body: "a[__proto__]b&a[__proto__]&a[length]=100000000",
      },
      benign: {
        method: "POST",
        target: "/comment",
        content_type: "application/x-www-form-urlencoded",
        body: "text=never+use+__proto__&tag=proto",
      },
    },
  },
  {
    // lodash before 4.17.12: `defaultsDeep` copies `constructor.prototype` from a parsed JSON body onto
    // Object.prototype.
    id: "vp_lodash_constructor_prototype",
    title: "lodash prototype pollution through constructor.prototype in JSON",
    advisories: ["GHSA-jf85-cpcp-j695", "CVE-2019-10744"],
    package: "lodash",
    conditions: [
      // No content-type condition: a JSON parser may be mounted for any type.
      // Keys, not words (plan A6 F6): `"constructor"` then optional JSON whitespace and `:`.
      { target: "body", op: "json_key", value: "constructor" },
      { target: "body", op: "json_key", value: "prototype" },
    ],
    reference: {
      exploit: {
        method: "POST",
        target: "/settings",
        content_type: "application/json",
        body: '{"constructor":{"prototype":{"isAdmin":true}}}',
      },
      benign: {
        method: "POST",
        target: "/settings",
        content_type: "application/json",
        body: '{"role":"constructor","stage":"prototype"}',
      },
    },
  },
  {
    // The same lodash flaw when `defaultsDeep` merges `req.query`: qs turns `constructor[prototype][x]` into
    // `{ constructor: { prototype: { x } } }` (plan A6 F4).
    id: "vp_lodash_constructor_prototype_query",
    title: "lodash prototype pollution through constructor[prototype] in query keys",
    advisories: ["GHSA-jf85-cpcp-j695", "CVE-2019-10744"],
    package: "lodash",
    // Two conditions (plan A11 H3): `constructor[prototype]` and `[constructor][prototype]` parse to the same object.
    conditions: [
      { target: "query_key", op: "contains", value: "constructor" },
      { target: "query_key", op: "contains", value: "[prototype]" },
    ],
    reference: {
      exploit: { method: "GET", target: "/settings?constructor[prototype][isAdmin]=1" },
      benign: { method: "GET", target: "/settings?constructor=Object&stage=prototype" },
    },
  },
  {
    // And when it merges an urlencoded body parsed with qs (plan A6 F4).
    id: "vp_lodash_constructor_prototype_form",
    title: "lodash prototype pollution through constructor[prototype] in a form body",
    advisories: ["GHSA-jf85-cpcp-j695", "CVE-2019-10744"],
    package: "lodash",
    // Two conditions, as for the query (plan A11 H4).
    conditions: [
      { target: "body", op: "contains", value: "constructor" },
      { target: "body", op: "contains", value: "[prototype]" },
    ],
    reference: {
      exploit: {
        method: "POST",
        target: "/settings",
        content_type: "application/x-www-form-urlencoded",
        body: "constructor[prototype][isAdmin]=true",
      },
      benign: {
        method: "POST",
        target: "/settings",
        content_type: "application/x-www-form-urlencoded",
        body: "constructor=Ford&stage=prototype",
      },
    },
  },
  {
    // lodash 3.7.0 … 4.17.18: `zipObjectDeep` and the deep setters accept `__proto__` taken from request data. The
    // patch sees `__proto__` as a JSON key (plan A6 F6); as a path inside a string value (`"__proto__.x"`) it is not
    // matched, so that prose and values naming it never are.
    id: "vp_lodash_proto_json",
    title: "lodash prototype pollution through __proto__ in JSON",
    advisories: ["GHSA-p6mc-m468-83gw", "CVE-2020-8203"],
    package: "lodash",
    // No content-type condition (plan A11 M1): a JSON parser may be mounted for any type.
    conditions: [{ target: "body", op: "json_key", value: "__proto__" }],
    reference: {
      exploit: {
        method: "POST",
        target: "/import",
        content_type: "application/json",
        body: '{"__proto__":{"polluted":"yes"}}',
      },
      benign: {
        method: "POST",
        target: "/import",
        content_type: "application/json",
        body: '{"text":"never assign obj.__proto__ in JS"}',
      },
    },
  },
  {
    // The same lodash flaw through a path written in a string value (`zipObjectDeep(["__proto__.x"], …)`, `set`):
    // `__proto__` followed by a dot. Prose naming `__proto__` without a dot after it does not match.
    id: "vp_lodash_proto_path",
    title: "lodash prototype pollution through a __proto__. path",
    advisories: ["GHSA-p6mc-m468-83gw", "CVE-2020-8203"],
    package: "lodash",
    // The path starts a JSON string (plan A11 M3): `"__proto__.`.
    conditions: [{ target: "body", op: "contains", value: '"__proto__.' }],
    reference: {
      exploit: {
        method: "POST",
        target: "/import",
        content_type: "application/json",
        body: '{"paths":["__proto__.polluted"],"values":["yes"]}',
      },
      benign: {
        method: "POST",
        target: "/import",
        content_type: "application/json",
        body: '{"text":"Never assign to obj.__proto__."}',
      },
    },
  },
  {
    // And through `constructor.prototype` written as a path.
    id: "vp_lodash_constructor_path",
    title: "lodash prototype pollution through a constructor.prototype path",
    advisories: ["GHSA-p6mc-m468-83gw", "CVE-2020-8203"],
    package: "lodash",
    conditions: [{ target: "body", op: "contains", value: '"constructor.prototype.' }],
    reference: {
      exploit: {
        method: "POST",
        target: "/import",
        content_type: "application/json",
        body: '{"paths":["constructor.prototype.polluted"],"values":["yes"]}',
      },
      benign: {
        method: "POST",
        target: "/import",
        content_type: "application/json",
        body: '{"text":"In JS, Foo.constructor.prototype is Function.prototype"}',
      },
    },
  },
  {
    // xml2js before 0.5.0 builds objects from element names, `__proto__` included.
    id: "vp_xml2js_proto_element",
    title: "xml2js prototype pollution through a __proto__ element",
    advisories: ["GHSA-776f-qx25-q3cc", "CVE-2023-0842"],
    package: "xml2js",
    // No content-type condition (plan A6 F7): an XML body parser may be mounted for any type.
    conditions: [{ target: "body", op: "contains", value: "<__proto__" }],
    reference: {
      exploit: {
        method: "POST",
        target: "/feed",
        content_type: "application/xml",
        body: "<root><__proto__><polluted>yes</polluted></__proto__></root>",
      },
      benign: {
        method: "POST",
        target: "/feed",
        content_type: "application/xml",
        body: "<root><proto>__proto__</proto></root>",
      },
    },
  },
]);
