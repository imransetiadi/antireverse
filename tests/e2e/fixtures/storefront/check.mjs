// The storefront's equivalence check: node check.mjs
import assert from "node:assert/strict";
import { addressProblems, addToCart, applyCode, createCart, euros, renderSummary, summary } from "./src/storefront.js";

const cart = applyCode(addToCart(addToCart(createCart(), "hoodie-zip"), "tee-organic", 2), "bundle15");
assert.equal(summary(cart, "DE").total, 9095);
assert.match(renderSummary(summary(cart, "DE")), /^Shipping {2}free$/m);
assert.equal(euros(123456), "1.234,56 €");
assert.deepEqual(
  addressProblems({ name: "Ada", street: "Main 1", city: "Bonn", postalCode: "53111", country: "de" }),
  [],
);
console.log("ok");
