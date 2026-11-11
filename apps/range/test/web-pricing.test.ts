// Proves the reference web bundle (apps/range/web) behaves as expected; the Harden slice protects it and
// re-runs equivalence against the protected output.
import { expect, it } from "vitest";
import { quote } from "../web/src/index.ts";
import { discounted, format, priceOf } from "../web/src/pricing.ts";

it("prices the known tiers", () => {
  expect(priceOf("free")).toBe(0);
  expect(priceOf("pro")).toBe(1900);
  expect(priceOf("enterprise-eu")).toBe(9900);
});

it("rejects an unknown tier", () => {
  expect(() => priceOf("gold")).toThrow(/unknown tier/);
});

it("formats euros with the non-ASCII symbol", () => {
  expect(format(1900)).toBe("€19.00");
});

it("applies a discount and quotes end to end", () => {
  expect(discounted(1900, 10)).toBe(1710);
  expect(quote("pro", 10)).toBe("€17.10");
});
