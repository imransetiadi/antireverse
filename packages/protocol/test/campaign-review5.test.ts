import { describe, expect, it } from "vitest";
import {
  CAMPAIGN_ASKED_BUCKETS,
  CAMPAIGN_LIMITS,
  type CampaignCatalogProbe,
  CampaignRequestSchema,
  campaignAskedBucket,
  campaignCatalog,
  campaignCatalogTarget,
  inCampaignCatalog,
} from "../src/index.ts";

// Slice 15a, fifth independent safety review. How much a refused probe asked for is kept as one of four buckets
// (D-113). A catalog bounds the bits a token can carry, names the checks each probe serves, and gives the request
// target its own name order.

describe("review5: how much a refused probe asked for is a bucket", () => {
  it("has four buckets: nothing, at most 256, at most 1,024, more", () => {
    expect(CAMPAIGN_ASKED_BUCKETS).toEqual([0, 256, 1024, 1_000_000]);
    expect([0, 1, 255, 256, 257, 1024, 1025, 999_999, 5_000_000].map(campaignAskedBucket)).toEqual([
      0, 256, 256, 256, 1024, 1024, 1_000_000, 1_000_000, 1_000_000,
    ]);
    expect([-1, Number.NaN, Number.POSITIVE_INFINITY, 0.4].map(campaignAskedBucket)).toEqual([0, 0, 1_000_000, 256]);
  });

  it("a row of the request log holds a bucket or null, no other number", () => {
    const row = {
      seq: 1,
      at: "2026-11-16T10:00:00.000Z",
      method: "OTHER",
      target: null,
      outcome: "refused",
      reason: "not_in_catalog",
      status: null,
      failure: null,
      bytes: 0,
      ms: 0,
    };
    for (const asked of [0, 256, 1024, 1_000_000, null]) {
      expect(CampaignRequestSchema.safeParse({ ...row, asked_chars: asked }).success, String(asked)).toBe(true);
    }
    for (const asked of [1, 97, 255, 257, 1023, 65_536, 999_999]) {
      expect(CampaignRequestSchema.safeParse({ ...row, asked_chars: asked }).success, String(asked)).toBe(false);
    }
  });
});

describe("review5: the probe catalog", () => {
  it("allows one token per probe, of at most 32 hex characters: 128 bits a request, not 2,048", () => {
    expect(CAMPAIGN_LIMITS.catalogTokenHexMax).toBe(32);
    const token = (hex: number) => ({ token: { prefix: "m-", hex } });
    expect(() => campaignCatalog([{ method: "GET", path: "/r", query: { a: token(32) } }])).not.toThrow();
    expect(() => campaignCatalog([{ method: "GET", path: "/r", query: { a: token(33) } }])).toThrow(TypeError);
    expect(() => campaignCatalog([{ method: "GET", path: "/r", query: { a: token(64) } }])).toThrow(TypeError);
    expect(() => campaignCatalog([{ method: "GET", path: "/r", query: { a: token(8), b: token(8) } }])).toThrow(
      TypeError,
    );
    // The review's catalog: eight tokens of 64.
    const eight = Object.fromEntries(Array.from({ length: 8 }, (_, i) => [`t${i}`, token(64)]));
    expect(() => campaignCatalog([{ method: "GET", path: "/r", query: eight }])).toThrow(TypeError);
  });

  it("names the checks a probe serves: known shapes only, a few at most", () => {
    const catalog = campaignCatalog([
      { method: "GET", path: "/", checks: ["RW-01"] },
      { method: "GET", path: "/both", checks: ["RW-02", "RW-03"] },
      { method: "GET", path: "/none" },
    ]);
    expect(catalog.map((probe) => probe.checks)).toEqual([["RW-01"], ["RW-02", "RW-03"], undefined]);
    expect(Object.isFrozen(catalog[1]?.checks)).toBe(true);
    for (const checks of [
      ["rw-01"],
      [""],
      ["RW-01", "RW-01"],
      Array.from({ length: 9 }, (_, i) => `RW-0${i}`),
      "RW-01",
    ]) {
      expect(() => campaignCatalog([{ method: "GET", path: "/", checks } as never]), JSON.stringify(checks)).toThrow(
        TypeError,
      );
    }
  });

  it("gives the request target the catalog's name order, whatever order the engine used", () => {
    const entry: CampaignCatalogProbe = {
      method: "GET",
      path: "/search",
      query: { q: { exact: "a b" }, lang: { exact: "en" }, m: { token: { prefix: "m-", hex: 8 } } },
    };
    const catalog = campaignCatalog([entry]);
    const orders = [
      { q: "a b", lang: "en", m: "m-0123abcd" },
      { m: "m-0123abcd", lang: "en", q: "a b" },
      { lang: "en", m: "m-0123abcd", q: "a b" },
    ];
    for (const query of orders) {
      const probe = { method: "GET", path: "/search", query };
      expect(inCampaignCatalog(catalog, probe)).toBe(true);
      expect(campaignCatalogTarget(catalog, probe)).toEqual({
        entry: catalog[0],
        target: "/search?q=a%20b&lang=en&m=m-0123abcd",
      });
    }
    expect(campaignCatalogTarget(catalog, { method: "GET", path: "/search", query: { q: "a b" } })).toBeNull();
    expect(campaignCatalogTarget(catalog, { method: "GET", path: "/other" })).toBeNull();
    expect(
      campaignCatalogTarget(campaignCatalog([{ method: "GET", path: "/" }]), { method: "GET", path: "/" }),
    ).toEqual({ entry: { method: "GET", path: "/" }, target: "/" });
  });
});
