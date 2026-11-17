import { describe, expect, it } from "vitest";
import {
  CAMPAIGN_END_REASONS,
  CAMPAIGN_LIMITS,
  CAMPAIGN_REFUSAL_REASONS,
  type CampaignCatalogProbe,
  campaignCatalog,
  FATAL_CAMPAIGN_REFUSALS,
  inCampaignCatalog,
  statusOfEndReason,
} from "../src/index.ts";

// Slice 15a, fourth independent safety review, R1 (D-110): an engine declares the probes it may send — exact method
// and path, and for each query name the shape of its value. Nothing an engine chooses freely can reach a request, a
// log row or a Finding.

const HEX = "0123456789abcdef";
const CATALOG: CampaignCatalogProbe[] = [
  { method: "GET", path: "/" },
  { method: "GET", path: "/search", query: { q: { exact: '"><airverse-probe-marker>' } } },
  { method: "GET", path: "/reflect", query: { m: { token: { prefix: "airverse-", hex: 16 } }, lang: { exact: "en" } } },
  { method: "HEAD", path: "/api/orders/1001" },
];

describe("review4 R1: the probe catalog of an engine", () => {
  it("is validated when it is declared: bounded, canonical, without duplicates, and frozen", () => {
    const catalog = campaignCatalog(CATALOG);
    expect(catalog).toEqual(CATALOG);
    expect(Object.isFrozen(catalog)).toBe(true);
    expect(Object.isFrozen(catalog[2]?.query?.m)).toBe(true);
    // A copy: changing what was passed in changes nothing.
    expect(catalog).not.toBe(CATALOG);
    const bad: unknown[] = [
      "not a list",
      [{ method: "POST", path: "/" }],
      [{ method: "GET", path: "/a/../b" }],
      [{ method: "GET", path: "/a?b=1" }],
      [{ method: "GET", path: "https://other.example/" }],
      [{ method: "GET", path: "/", extra: 1 }],
      [{ method: "GET", path: "/", query: { "bad name": { exact: "x" } } }],
      [{ method: "GET", path: "/", query: { q: { exact: "x".repeat(CAMPAIGN_LIMITS.queryValueMax + 1) } } }],
      [{ method: "GET", path: "/", query: { q: { exact: "line\nbreak" } } }],
      [{ method: "GET", path: "/", query: { q: { anything: true } } }],
      [{ method: "GET", path: "/", query: { q: { exact: "x", token: { prefix: "", hex: 16 } } } }],
      [{ method: "GET", path: "/", query: { q: { token: { prefix: "a b", hex: 16 } } } }],
      [{ method: "GET", path: "/", query: { q: { token: { prefix: "m-", hex: 4 } } } }],
      [{ method: "GET", path: "/", query: { q: { token: { prefix: "m-", hex: 65 } } } }],
      [
        {
          method: "GET",
          path: "/",
          query: Object.fromEntries(Array.from({ length: 9 }, (_, i) => [`p${i}`, { exact: "1" }])),
        },
      ],
      [
        { method: "GET", path: "/" },
        { method: "GET", path: "/" },
      ],
      Array.from({ length: CAMPAIGN_LIMITS.catalogProbesMax + 1 }, (_, i) => ({ method: "GET", path: `/p${i}` })),
      [{ method: "GET", path: "/", query: { q: { exact: "é".repeat(400) } } }],
    ];
    for (const value of bad)
      expect(() => campaignCatalog(value as never), JSON.stringify(value).slice(0, 80)).toThrow(TypeError);
  });

  it("holds a probe that is exactly one of its entries, and no other", () => {
    const catalog = campaignCatalog(CATALOG);
    const inside: unknown[] = [
      { method: "GET", path: "/" },
      { method: "GET", path: "/search", query: { q: '"><airverse-probe-marker>' } },
      { method: "GET", path: "/reflect", query: { m: `airverse-${HEX}`, lang: "en" } },
      { method: "GET", path: "/reflect", query: { lang: "en", m: "airverse-ffffffffffffffff" } },
      { method: "HEAD", path: "/api/orders/1001" },
    ];
    const outside: unknown[] = [
      { method: "HEAD", path: "/" },
      { method: "GET", path: "/api/orders/1001" },
      { method: "GET", path: "/other" },
      { method: "GET", path: "/", query: {} },
      { method: "GET", path: "/", query: { q: "x" } },
      { method: "GET", path: "/search" },
      { method: "GET", path: "/search", query: { q: "a body, 300 characters of it" } },
      { method: "GET", path: "/search", query: { q: '"><airverse-probe-marker>', b: "more" } },
      { method: "GET", path: "/reflect", query: { m: "airverse-0123456789abcdeF", lang: "en" } },
      { method: "GET", path: "/reflect", query: { m: `airverse-${HEX}0`, lang: "en" } },
      { method: "GET", path: "/reflect", query: { m: `text of a response ${HEX}`, lang: "en" } },
      { method: "GET", path: "/reflect", query: { m: `airverse-${HEX}` } },
      { method: "GET", path: "/reflect", query: { m: 7, lang: "en" } },
      { method: "GET", path: "/search", query: "q=x" },
      { method: "GET", path: "/", extra: "member" },
      null,
      "GET /",
    ];
    for (const probe of inside) expect(inCampaignCatalog(catalog, probe), JSON.stringify(probe)).toBe(true);
    for (const probe of outside) expect(inCampaignCatalog(catalog, probe), JSON.stringify(probe)).toBe(false);
  });

  it("a probe that is not in the catalog, in any way, ends the Campaign as failed", () => {
    for (const reason of [
      "malformed_probe",
      "method_not_allowed",
      "path_not_canonical",
      "query_not_canonical",
      "not_in_catalog",
    ] as const) {
      expect(CAMPAIGN_REFUSAL_REASONS).toContain(reason);
      expect(FATAL_CAMPAIGN_REFUSALS).toContain(reason);
      expect(CAMPAIGN_END_REASONS).toContain(reason);
      expect(statusOfEndReason(reason, true)).toBe("failed");
    }
  });
});
