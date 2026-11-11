import {
  EXAMPLE_VIRTUAL_PATCH,
  matchPatch,
  patchRequestOf,
  type VirtualPatch,
  VirtualPatchSchema,
} from "@antireverse/protocol";
import { describe, expect, it } from "vitest";
import { createPatchCatalog, PATCH_CATALOG } from "../src/patches/catalog.ts";
import { FIXTURE_PATCH_CATALOG } from "./fixtures/patch-catalog.ts";

// Pinned when the catalog was written (2026-11-11): every advisory id below was fetched from the public OSV API
// (`https://api.osv.dev/v1/vulns/<id>`) — the GHSA record and its CVE alias, each resolving to the other — and
// the npm package and affected ranges copied from the GHSA record. A change of the catalog's advisories or
// packages fails here until the new ids are checked against OSV the same way.
const VERIFIED = {
  "GHSA-hrpp-h998-j3pp": {
    cve: "CVE-2022-24999",
    package: "qs",
    ranges: [
      ["6.10.0", "6.10.3"],
      ["6.9.0", "6.9.7"],
      ["6.8.0", "6.8.3"],
      ["6.7.0", "6.7.3"],
      ["6.6.0", "6.6.1"],
      ["6.5.0", "6.5.3"],
      ["6.4.0", "6.4.1"],
      ["6.3.0", "6.3.3"],
      ["0", "6.2.4"],
    ],
  },
  "GHSA-jf85-cpcp-j695": { cve: "CVE-2019-10744", package: "lodash", ranges: [["0", "4.17.12"]] },
  "GHSA-p6mc-m468-83gw": { cve: "CVE-2020-8203", package: "lodash", ranges: [["3.7.0", "4.17.19"]] },
  "GHSA-776f-qx25-q3cc": { cve: "CVE-2023-0842", package: "xml2js", ranges: [["0", "0.5.0"]] },
} as const;

describe("the patch catalog", () => {
  it("covers 3–5 advisories, each GHSA id with its verified CVE alias and package", () => {
    const covered = new Map<string, string>();
    for (const patch of PATCH_CATALOG.patches) {
      for (const id of patch.advisories) covered.set(id, patch.package);
    }
    const ghsas = [...covered.keys()].filter((id) => id.startsWith("GHSA-")).sort();
    expect(ghsas).toEqual(Object.keys(VERIFIED).sort());
    expect(ghsas.length).toBeGreaterThanOrEqual(3);
    expect(ghsas.length).toBeLessThanOrEqual(5);
    for (const [ghsa, verified] of Object.entries(VERIFIED)) {
      expect(covered.get(ghsa)).toBe(verified.package);
      // Each patch lists the GHSA id and its CVE alias together.
      expect(covered.get(verified.cve)).toBe(verified.package);
    }
    // Nothing unverified: every id the catalog names is a pinned GHSA id or its CVE alias.
    const pinned = new Set(Object.entries(VERIFIED).flatMap(([ghsa, v]) => [ghsa, v.cve]));
    expect([...covered.keys()].filter((id) => !pinned.has(id))).toEqual([]);
  });

  it("pins the affected ranges recorded from OSV (introduced, fixed)", () => {
    expect(VERIFIED["GHSA-hrpp-h998-j3pp"].ranges).toHaveLength(9);
    expect(VERIFIED["GHSA-jf85-cpcp-j695"].ranges).toEqual([["0", "4.17.12"]]);
    expect(VERIFIED["GHSA-p6mc-m468-83gw"].ranges).toEqual([["3.7.0", "4.17.19"]]);
    expect(VERIFIED["GHSA-776f-qx25-q3cc"].ranges).toEqual([["0", "0.5.0"]]);
  });

  it("is versioned, and every entry is a valid VirtualPatch with a unique id", () => {
    expect(PATCH_CATALOG.version).toMatch(/^\d{4}-\d{2}-\d{2}\.\d+$/);
    const ids = PATCH_CATALOG.patches.map((patch) => patch.id);
    expect(new Set(ids).size).toBe(ids.length);
    for (const patch of PATCH_CATALOG.patches) expect(VirtualPatchSchema.parse(patch)).toEqual(patch);
  });

  for (const catalog of [PATCH_CATALOG, FIXTURE_PATCH_CATALOG]) {
    for (const patch of catalog.patches) {
      it(`${patch.id}: its reference exploit matches and its benign request does not`, () => {
        expect(matchPatch(patch, patchRequestOf(patch.reference.exploit))).toEqual({
          matched: true,
          bodyPending: false,
        });
        expect(matchPatch(patch, patchRequestOf(patch.reference.benign)).matched).toBe(false);
      });
    }
  }

  it("finds a patch by id, and nothing for an unknown id", () => {
    const first = PATCH_CATALOG.patches[0] as VirtualPatch;
    expect(PATCH_CATALOG.get(first.id)).toEqual(first);
    expect(PATCH_CATALOG.get("vp_not_in_catalog")).toBeUndefined();
    expect(PATCH_CATALOG.get("__proto__")).toBeUndefined();
  });

  it("lodash patches do not match ordinary JSON that uses constructor as a key", () => {
    const request = patchRequestOf({
      method: "POST",
      target: "/cars",
      content_type: "application/json",
      body: '{"constructor":"Ford","model":"T","prototype_year":1908}',
    });
    for (const patch of PATCH_CATALOG.patches.filter((p) => p.package === "lodash")) {
      expect(matchPatch(patch, request).matched).toBe(false);
    }
  });

  it("the qs query patch does not match __proto__ as a query value", () => {
    const qs = PATCH_CATALOG.get("vp_qs_proto_query_key") as VirtualPatch;
    expect(qs.reference.benign.target).toContain("q=__proto__");
    for (const target of ["/search?q=__proto__", "/search?q=a%5B__proto__%5D", "/search?note=x[__proto__]"]) {
      expect(matchPatch(qs, patchRequestOf({ method: "GET", target })).matched).toBe(false);
    }
  });

  it("the qs patch sees through percent-encoding and mixed case of the key", () => {
    const qs = PATCH_CATALOG.patches.find((p) => p.package === "qs") as VirtualPatch;
    for (const target of ["/s?a%5B%5F%5Fproto%5F%5F%5D=1", "/s?a[__PROTO__]=1", "/s?__proto__[x]=1"]) {
      expect(matchPatch(qs, patchRequestOf({ method: "GET", target })).matched).toBe(true);
    }
  });

  describe("review fixes (plan A6)", () => {
    const byId = (id: string) => {
      const patch = PATCH_CATALOG.get(id);
      if (patch === undefined) throw new Error(`${id} is missing from the catalog.`);
      return patch;
    };
    const matches = (id: string, reference: Parameters<typeof patchRequestOf>[0]) =>
      matchPatch(byId(id), patchRequestOf(reference)).matched;
    const form = (target: string, body: string) => ({
      method: "POST" as const,
      target,
      content_type: "application/x-www-form-urlencoded",
      body,
    });

    it("is version 2026-11-11.2 or later", () => {
      expect(PATCH_CATALOG.version >= "2026-11-11.2").toBe(true);
    });

    it("F5: no body patch is scoped by method", () => {
      for (const patch of PATCH_CATALOG.patches) {
        if (patch.conditions.some((condition) => condition.target === "body")) expect(patch.methods).toBeUndefined();
      }
    });

    it("F7: the xml2js patch has no content-type condition and matches whatever the request claims", () => {
      const xml = byId("vp_xml2js_proto_element");
      expect(xml.conditions.some((condition) => condition.target === "header")).toBe(false);
      const body = "<root><__proto__><polluted>yes</polluted></__proto__></root>";
      for (const content_type of ["text/plain", "application/octet-stream", "text/xml; charset=utf-8"]) {
        expect(matches("vp_xml2js_proto_element", { method: "PUT", target: "/feed", content_type, body })).toBe(true);
      }
    });

    it("F4: qs __proto__ keys in an urlencoded body, bracketed raw or percent-encoded, for the qs advisories", () => {
      const qs = byId("vp_qs_proto_form_body");
      expect(qs.package).toBe("qs");
      expect([...qs.advisories].sort()).toEqual(["CVE-2022-24999", "GHSA-hrpp-h998-j3pp"]);
      for (const body of [
        "a[__proto__]b&a[__proto__]&a[length]=100000000",
        "a%5B__proto__%5D=1",
        "a%5B%5F%5Fproto%5F%5F%5D=1",
      ]) {
        expect(matches("vp_qs_proto_form_body", form("/search", body))).toBe(true);
      }
      expect(matches("vp_qs_proto_form_body", form("/comment", "text=never+use+__proto__"))).toBe(false);
    });

    it("F4: lodash constructor[prototype] in query keys and in urlencoded bodies, for CVE-2019-10744", () => {
      for (const id of ["vp_lodash_constructor_prototype_query", "vp_lodash_constructor_prototype_form"]) {
        const patch = byId(id);
        expect(patch.package).toBe("lodash");
        expect([...patch.advisories].sort()).toEqual(["CVE-2019-10744", "GHSA-jf85-cpcp-j695"]);
      }
      for (const target of ["/s?constructor[prototype][isAdmin]=1", "/s?constructor%5Bprototype%5D%5BisAdmin%5D=1"]) {
        expect(matches("vp_lodash_constructor_prototype_query", { method: "GET", target })).toBe(true);
      }
      expect(
        matches("vp_lodash_constructor_prototype_query", {
          method: "GET",
          target: "/s?role=constructor&stage=prototype",
        }),
      ).toBe(false);
      for (const body of ["constructor[prototype][isAdmin]=true", "constructor%5Bprototype%5D%5BisAdmin%5D=true"]) {
        expect(matches("vp_lodash_constructor_prototype_form", form("/settings", body))).toBe(true);
      }
      expect(
        matches("vp_lodash_constructor_prototype_form", form("/settings", "role=constructor&stage=prototype")),
      ).toBe(false);
    });
  });

  describe("F6: lodash JSON patches match keys (json_key), not words in values or prose", () => {
    const json = (body: string) =>
      patchRequestOf({ method: "POST", target: "/settings", content_type: "application/json", body });
    const patch = (id: string) => PATCH_CATALOG.get(id) as VirtualPatch;
    const keysOf = (id: string) =>
      patch(id)
        .conditions.filter((condition) => condition.target === "body")
        .map((condition) => [condition.op, condition.value]);

    it("uses json_key for constructor and prototype, and for __proto__", () => {
      expect(keysOf("vp_lodash_constructor_prototype").sort()).toEqual([
        ["json_key", "constructor"],
        ["json_key", "prototype"],
      ]);
      expect(keysOf("vp_lodash_proto_json")).toEqual([["json_key", "__proto__"]]);
    });

    it("its benign references hold the words as values and as prose", () => {
      expect(patch("vp_lodash_constructor_prototype").reference.benign.body).toContain(
        '{"role":"constructor","stage":"prototype"}',
      );
      expect(patch("vp_lodash_proto_json").reference.benign.body).toContain(
        '{"text":"never assign obj.__proto__ in JS"}',
      );
    });

    it("does not match the words as values or in prose", () => {
      const benign = [
        '{"role":"constructor","stage":"prototype"}',
        '{"text":"never assign obj.__proto__ in JS"}',
        '{"text":"the constructor of a prototype"}',
        '{"paths":["__proto__.polluted"]}',
      ];
      for (const body of benign) {
        expect(matchPatch(patch("vp_lodash_constructor_prototype"), json(body)).matched).toBe(false);
        expect(matchPatch(patch("vp_lodash_proto_json"), json(body)).matched).toBe(false);
      }
    });

    it("matches the keys with JSON whitespace and with \\u escapes", () => {
      for (const body of [
        '{"constructor":{"prototype":{"isAdmin":true}}}',
        '{ "constructor" : { "prototype"\n: { "isAdmin": true } } }',
        '{"\\u0063onstructor":{"prototype":{"isAdmin":true}}}',
      ]) {
        expect(matchPatch(patch("vp_lodash_constructor_prototype"), json(body)).matched).toBe(true);
      }
      for (const body of [
        '{"__proto__":{"polluted":"yes"}}',
        '{"a": {"__proto__" :\t{"x":1}}}',
        '{"\\u005f_proto__":{}}',
      ]) {
        expect(matchPatch(patch("vp_lodash_proto_json"), json(body)).matched).toBe(true);
      }
    });
  });

  describe("path patches for CVE-2020-8203 and no content type on JSON patches (Jev add_path_patch_drop_ct)", () => {
    const patch = (id: string) => {
      const found = PATCH_CATALOG.get(id);
      if (found === undefined) throw new Error(`${id} is missing from the catalog.`);
      return found;
    };
    const body = (text: string, content_type = "application/json") =>
      patchRequestOf({ method: "POST", target: "/import", content_type, body: text });

    it("is version 2026-11-11.3 or later", () => {
      expect(PATCH_CATALOG.version >= "2026-11-11.3").toBe(true);
    });

    it("adds __proto__. and constructor.prototype path patches for GHSA-p6mc-m468-83gw / CVE-2020-8203", () => {
      for (const [id, needle] of [
        ["vp_lodash_proto_path", "__proto__."],
        ["vp_lodash_constructor_path", "constructor.prototype."],
      ] as const) {
        const entry = patch(id);
        expect(entry.package).toBe("lodash");
        expect([...entry.advisories].sort()).toEqual(["CVE-2020-8203", "GHSA-p6mc-m468-83gw"]);
        expect(entry.conditions).toEqual([{ target: "body", op: "contains", value: `"${needle}` }]);
        expect(entry.methods).toBeUndefined();
      }
      expect(matchPatch(patch("vp_lodash_proto_path"), body('{"paths":["__proto__.polluted"]}')).matched).toBe(true);
      expect(
        matchPatch(patch("vp_lodash_constructor_path"), body('{"paths":["constructor.prototype.polluted"]}')).matched,
      ).toBe(true);
      for (const prose of [
        '{"text":"never assign obj.__proto__ in JS"}',
        '{"text":"the constructor prototype chain"}',
      ]) {
        expect(matchPatch(patch("vp_lodash_proto_path"), body(prose)).matched).toBe(false);
        expect(matchPatch(patch("vp_lodash_constructor_path"), body(prose)).matched).toBe(false);
      }
    });

    it("vp_lodash_constructor_prototype has no content-type condition and matches whatever type is claimed", () => {
      const entry = patch("vp_lodash_constructor_prototype");
      expect(entry.conditions.some((condition) => condition.target === "header")).toBe(false);
      for (const type of ["text/plain", "application/x-www-form-urlencoded"]) {
        expect(matchPatch(entry, body('{"constructor":{"prototype":{"isAdmin":true}}}', type)).matched).toBe(true);
      }
    });

    it("/search?q=__proto__ matches no qs patch", () => {
      for (const entry of PATCH_CATALOG.patches.filter((p) => p.package === "qs")) {
        expect(matchPatch(entry, patchRequestOf({ method: "GET", target: "/search?q=__proto__" })).matched).toBe(false);
      }
    });
  });

  describe("second review fixes (plan A11)", () => {
    const patch = (id: string) => {
      const found = PATCH_CATALOG.get(id);
      if (found === undefined) throw new Error(`${id} is missing from the catalog.`);
      return found;
    };
    const json = (text: string, content_type = "application/json") =>
      patchRequestOf({ method: "POST", target: "/import", content_type, body: text });
    const form = (text: string) => json(text, "application/x-www-form-urlencoded");
    const get = (target: string) => patchRequestOf({ method: "GET", target });

    it("is version 2026-11-11.4 or later", () => {
      expect(PATCH_CATALOG.version >= "2026-11-11.4").toBe(true);
    });

    it("H3: the lodash query patch also matches [constructor][prototype]", () => {
      const entry = patch("vp_lodash_constructor_prototype_query");
      for (const target of [
        "/s?constructor[prototype][isAdmin]=1",
        "/s?[constructor][prototype][isAdmin]=1",
        "/s?a[constructor][prototype][isAdmin]=1",
        "/s?%5Bconstructor%5D%5Bprototype%5D%5BisAdmin%5D=1",
      ]) {
        expect(matchPatch(entry, get(target)).matched).toBe(true);
      }
      for (const target of ["/s?constructor=Object&stage=prototype", "/s?x[prototype]=1", "/s?role=constructor"]) {
        expect(matchPatch(entry, get(target)).matched).toBe(false);
      }
    });

    it("H4: the lodash form patch also matches [constructor][prototype]", () => {
      const entry = patch("vp_lodash_constructor_prototype_form");
      for (const text of [
        "constructor[prototype][isAdmin]=true",
        "[constructor][prototype][isAdmin]=true",
        "a%5Bconstructor%5D%5Bprototype%5D%5BisAdmin%5D=true",
      ]) {
        expect(matchPatch(entry, form(text)).matched).toBe(true);
      }
      for (const text of ["constructor=Ford&stage=prototype", "x[prototype]=1", "role=constructor"]) {
        expect(matchPatch(entry, form(text)).matched).toBe(false);
      }
    });

    it("M1: vp_lodash_proto_json has no content-type condition", () => {
      const entry = patch("vp_lodash_proto_json");
      expect(entry.conditions).toEqual([{ target: "body", op: "json_key", value: "__proto__" }]);
      expect(matchPatch(entry, json('{"__proto__":{"polluted":"yes"}}', "text/plain")).matched).toBe(true);
    });

    it("M3: the path patches need the path to start a JSON string", () => {
      expect(patch("vp_lodash_proto_path").conditions).toEqual([
        { target: "body", op: "contains", value: '"__proto__.' },
      ]);
      expect(patch("vp_lodash_constructor_path").conditions).toEqual([
        { target: "body", op: "contains", value: '"constructor.prototype.' },
      ]);
      expect(patch("vp_lodash_proto_path").reference.exploit.body).toBe(
        '{"paths":["__proto__.polluted"],"values":["yes"]}',
      );
      expect(patch("vp_lodash_constructor_path").reference.exploit.body).toBe(
        '{"paths":["constructor.prototype.polluted"],"values":["yes"]}',
      );
      expect(patch("vp_lodash_proto_path").reference.benign.body).toBe('{"text":"Never assign to obj.__proto__."}');
      expect(patch("vp_lodash_constructor_path").reference.benign.body).toBe(
        '{"text":"In JS, Foo.constructor.prototype is Function.prototype"}',
      );
      const benign = [
        json('{"text":"Never assign to obj.__proto__."}'),
        form("text=see+obj.__proto__.x"),
        json('{"text":"In JS, Foo.constructor.prototype is Function.prototype"}'),
      ];
      for (const request of benign) {
        expect(matchPatch(patch("vp_lodash_proto_path"), request).matched).toBe(false);
        expect(matchPatch(patch("vp_lodash_constructor_path"), request).matched).toBe(false);
      }
    });
  });

  describe("createPatchCatalog", () => {
    // A valid entry of its own, so that these tests do not depend on the protocol example's reference requests.
    const ENTRY: VirtualPatch = {
      ...EXAMPLE_VIRTUAL_PATCH,
      reference: {
        exploit: { method: "GET", target: "/search?q[__proto__][polluted]=1" },
        benign: { method: "GET", target: "/search?q[name]=proto" },
      },
    };

    it("refuses an entry whose reference exploit does not match", () => {
      const broken = {
        ...ENTRY,
        reference: { ...ENTRY.reference, exploit: ENTRY.reference.benign },
      };
      expect(() => createPatchCatalog("2026-11-11.1", [broken])).toThrow(/exploit/);
    });

    it("refuses an entry whose benign request matches", () => {
      const broken = {
        ...ENTRY,
        reference: { ...ENTRY.reference, benign: ENTRY.reference.exploit },
      };
      expect(() => createPatchCatalog("2026-11-11.1", [broken])).toThrow(/benign/);
    });

    it("refuses a duplicate id and an invalid entry", () => {
      expect(() => createPatchCatalog("2026-11-11.1", [ENTRY, ENTRY])).toThrow(/twice/);
      expect(() => createPatchCatalog("2026-11-11.1", [{ ...ENTRY, id: "bad" }])).toThrow();
    });

    it("keeps the entries deeply frozen", () => {
      const catalog = createPatchCatalog("2026-11-11.1", [ENTRY]);
      expect(Object.isFrozen(catalog.patches)).toBe(true);
      expect(Object.isFrozen(catalog.patches[0]?.conditions)).toBe(true);
    });
  });
});
