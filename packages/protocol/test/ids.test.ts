import { createHash } from "node:crypto";
import { describe, expect, it } from "vitest";
import { ID_PATTERNS, type IdPrefix } from "../src/index.ts";
import { newId, seedId } from "../src/server.ts";

describe("newId", () => {
  it("returns the prefix followed by 24 lowercase hex characters", () => {
    expect(newId("org")).toMatch(/^org_[0-9a-f]{24}$/);
    expect(newId("app")).toMatch(/^app_[0-9a-f]{24}$/);
    expect(newId("key")).toMatch(/^key_[0-9a-f]{24}$/);
    expect(newId("rul")).toMatch(/^rul_[0-9a-f]{24}$/);
    expect(newId("bld")).toMatch(/^bld_[0-9a-f]{24}$/);
    expect(newId("inc")).toMatch(/^inc_[0-9a-f]{24}$/);
    expect(newId("dtc")).toMatch(/^dtc_[0-9a-f]{24}$/);
    expect(newId("chn")).toMatch(/^chn_[0-9a-f]{24}$/);
    expect(newId("dlv")).toMatch(/^dlv_[0-9a-f]{24}$/);
    expect(newId("cny")).toMatch(/^cny_[0-9a-f]{24}$/);
    expect(newId("cnt")).toMatch(/^cnt_[0-9a-f]{24}$/);
    expect(newId("alw")).toMatch(/^alw_[0-9a-f]{24}$/);
    expect(newId("fnd")).toMatch(/^fnd_[0-9a-f]{24}$/);
    expect(newId("tgt")).toMatch(/^tgt_[0-9a-f]{24}$/);
    expect(newId("roe")).toMatch(/^roe_[0-9a-f]{24}$/);
    expect(newId("rcp")).toMatch(/^rcp_[0-9a-f]{24}$/);
    expect(newId("asm")).toMatch(/^asm_[0-9a-f]{24}$/);
    expect(newId("aud")).toMatch(/^aud_[0-9a-f]{24}$/);
  });

  it("returns an identifier that matches the pattern of its prefix and of no other", () => {
    const prefixes: IdPrefix[] = [
      "org",
      "app",
      "key",
      "rul",
      "bld",
      "inc",
      "dtc",
      "chn",
      "dlv",
      "cny",
      "cnt",
      "alw",
      "fnd",
      "tgt",
      "roe",
      "rcp",
      "asm",
      "aud",
    ];
    expect(Object.keys(ID_PATTERNS).sort()).toEqual([...prefixes].sort());
    for (const prefix of prefixes) {
      const id = newId(prefix);
      expect(prefixes.filter((candidate) => ID_PATTERNS[candidate].test(id))).toEqual([prefix]);
    }
  });

  it("has no identifier pattern for an actor hash: it is derived (actorHash), never generated", () => {
    expect(ID_PATTERNS).not.toHaveProperty("iph");
  });

  it("has no identifier pattern for a beacon token: it is derived (deriveBeaconToken), never generated", () => {
    expect(ID_PATTERNS).not.toHaveProperty("bcn");
    // @ts-expect-error "bcn" is not an IdPrefix.
    const generate = () => newId("bcn");
    expect(typeof generate).toBe("function");
  });

  it("returns 1,000 unique identifiers", () => {
    const ids = new Set(Array.from({ length: 1000 }, () => newId("org")));
    expect(ids.size).toBe(1000);
  });
});

describe("seedId", () => {
  it("returns the first 16 hex characters of the SHA-256 of the seed value", () => {
    const seed = "1234567890";
    const expected = createHash("sha256").update(seed).digest("hex").slice(0, 16);
    expect(seedId(seed)).toBe(expected);
    expect(seedId(seed)).toMatch(/^[0-9a-f]{16}$/);
  });

  it("is stable for one seed and differs between seeds", () => {
    expect(seedId("abc")).toBe(seedId("abc"));
    expect(seedId("abc")).not.toBe(seedId("abd"));
  });

  it("never equals the seed value itself", () => {
    const seed = "a".repeat(16);
    expect(seedId(seed)).not.toBe(seed);
  });
});
