// A self-contained behaviour check for the reference bundle, used as the equivalence command when the bundle
// is hardened (it needs no test runner or node_modules, so it runs inside the equivalence runner's temp copy):
//   node --experimental-strip-types check.ts
import assert from "node:assert/strict";
import { buildReport, quote, renderTable, toCsv } from "./src/index.ts";
import { discounted, format, priceOf } from "./src/pricing.ts";

assert.equal(priceOf("free"), 0);
assert.equal(priceOf("pro"), 1900);
assert.equal(priceOf("enterprise-eu"), 9900);
assert.throws(() => priceOf("gold"), /unknown tier/);
assert.equal(format(1900), "€19.00");
assert.equal(discounted(1900, 10), 1710);
assert.equal(quote("pro", 10), "€17.10");
const orders = [
  { id: "o1", date: "2026-01-05", tier: "pro", seats: 3 },
  { id: "o2", date: "2026-02-20", tier: "business", seats: 2, discountPct: 10 },
];
assert.equal(toCsv(buildReport(orders, "tier")).split("\r\n")[1], "business,1,2,8820,0,8820");
assert.match(renderTable(buildReport(orders, "month")), /^Feb 2026 +1 +2 +€88\.20 +€88\.20 +60\.7%$/m);
console.log("ok");
