import { describe, expect, it } from "vitest";
import { type CampaignCatalogProbe, campaignCatalog, campaignCatalogTarget } from "../src/index.ts";

// Slice 15a, sixth independent safety review. A refused catalog probe is logged with its token value masked (F7): the
// value was never sent, and it is 128 bits of the engine's choosing. And a catalog cannot name a query parameter
// `__proto__`.

describe("review6 F7: the target of a catalog probe as a refused row keeps it", () => {
  const entry: CampaignCatalogProbe = {
    method: "GET",
    path: "/reflect",
    query: { lang: { exact: "en" }, m: { token: { prefix: "airverse-", hex: 32 } } },
  };
  const catalog = campaignCatalog([entry, { method: "GET", path: "/" }]);

  it("masks the token: the prefix and a fixed word, whatever the engine chose", () => {
    const targets = ["0123456789abcdef0123456789abcdef", "ffffffffffffffffffffffffffffffff"].map((hex) =>
      campaignCatalogTarget(catalog, { method: "GET", path: "/reflect", query: { m: `airverse-${hex}`, lang: "en" } }),
    );
    expect(targets.map((found) => found?.target)).toEqual([
      "/reflect?lang=en&m=airverse-0123456789abcdef0123456789abcdef",
      "/reflect?lang=en&m=airverse-ffffffffffffffffffffffffffffffff",
    ]);
    expect(targets.map((found) => found?.masked)).toEqual([
      "/reflect?lang=en&m=airverse-[token]",
      "/reflect?lang=en&m=airverse-[token]",
    ]);
  });

  it("a probe without a token is its own target", () => {
    expect(campaignCatalogTarget(catalog, { method: "GET", path: "/" })).toMatchObject({ target: "/", masked: "/" });
  });
});

describe("review6: a catalog's query names", () => {
  it("refuses `__proto__`, `constructor` and `prototype` as names", () => {
    for (const name of ["__proto__", "constructor", "prototype"]) {
      const query = JSON.parse(`{"${name}":{"exact":"x"}}`) as Record<string, { exact: string }>;
      expect(Object.keys(query)).toEqual([name]);
      expect(() => campaignCatalog([{ method: "GET", path: "/", query }]), name).toThrow(TypeError);
    }
    // And a probe that carries such a name is never one of a catalog's.
    const catalog = campaignCatalog([{ method: "GET", path: "/", query: { q: { exact: "x" } } }]);
    const probe = JSON.parse('{"method":"GET","path":"/","query":{"__proto__":"x"}}') as unknown;
    expect(campaignCatalogTarget(catalog, probe)).toBeNull();
  });
});
