import { createPatchCatalog } from "../../src/patches/catalog.ts";

// The catalog tests run on: patches for the fixture advisories of advisories.json (synthetic packages and ids).
//   vp_fixture_range_query   vuln-range, GHSA-fx01-0001-rang (by its id)
//   vp_fixture_last_header   vuln-last, CVE-2026-90002 (by the alias of GHSA-fx01-0002-last only)
//   vp_fixture_scoped_body   @fixture/vuln-scoped, GHSA-fx01-0005-scop; body-dependent
//   vp_fixture_range_medium  vuln-range, GHSA-fx01-0009-medi (the medium advisory of the same package)
//   vp_fixture_wrong_package other-package, GHSA-fx01-0001-rang: the advisory matches, the package never does
export const FIXTURE_PATCH_CATALOG = createPatchCatalog("2026-11-11.0", [
  {
    id: "vp_fixture_range_query",
    title: "vuln-range prototype pollution through query keys",
    advisories: ["GHSA-fx01-0001-rang", "CVE-2026-90001"],
    package: "vuln-range",
    methods: ["GET"],
    conditions: [{ target: "query_key", op: "contains", value: "__proto__" }],
    reference: {
      exploit: { method: "GET", target: "/search?q[__proto__][x]=1" },
      benign: { method: "GET", target: "/search?q=__proto__" },
    },
  },
  {
    id: "vp_fixture_last_header",
    title: "vuln-last header exploit",
    advisories: ["CVE-2026-90002"],
    package: "vuln-last",
    conditions: [{ target: "header", name: "x-exploit", op: "equals", value: "boom" }],
    reference: {
      exploit: { method: "GET", target: "/", headers: { "x-exploit": "boom" } },
      benign: { method: "GET", target: "/", headers: { "x-exploit": "fine" } },
    },
  },
  {
    id: "vp_fixture_scoped_body",
    title: "@fixture/vuln-scoped body exploit",
    advisories: ["GHSA-fx01-0005-scop"],
    package: "@fixture/vuln-scoped",
    methods: ["POST"],
    path: "/upload",
    conditions: [{ target: "body", op: "contains", value: "pwn" }],
    reference: {
      exploit: { method: "POST", target: "/upload", body: "data=pwn" },
      benign: { method: "POST", target: "/upload", body: "data=ok" },
    },
  },
  {
    id: "vp_fixture_range_medium",
    title: "vuln-range medium query value exploit",
    advisories: ["GHSA-fx01-0009-medi"],
    package: "vuln-range",
    conditions: [{ target: "query_value", name: "cmd", op: "equals", value: "evil" }],
    reference: {
      exploit: { method: "GET", target: "/run?cmd=evil" },
      benign: { method: "GET", target: "/run?cmd=good" },
    },
  },
  {
    id: "vp_fixture_wrong_package",
    title: "Same advisory, another package",
    advisories: ["GHSA-fx01-0001-rang"],
    package: "other-package",
    conditions: [{ target: "path", op: "equals", value: "/never" }],
    reference: {
      exploit: { method: "GET", target: "/never" },
      benign: { method: "GET", target: "/always" },
    },
  },
]);
