// Optional cost print for the `harden` engine: the gzip size overhead of each profile on a representative
// module, so a regression in the budget story is visible. Run with `tsx packages/harden/bench/overhead.bench.ts`.
// It is not a pass/fail gate — the engine's per-file budget guard is.
import { gzipSync } from "node:zlib";
import { harden } from "../src/engine.ts";

const MODULE = `
const TIERS = { free: 0, pro: 1900, business: 4900, "enterprise-eu": 9900 };
export function priceOf(tier) {
  const cents = TIERS[tier];
  if (cents === undefined) throw new Error("unknown tier: " + tier);
  return cents;
}
export function label(tier) {
  return "the " + tier + " plan costs " + priceOf(tier) + " cents per seat each month";
}
`;

const gz = (s: string): number => gzipSync(Buffer.from(s, "utf8")).length;
const origGz = gz(MODULE);

for (const profile of ["light", "balanced", "maximum"] as const) {
  const result = harden({ "m.mjs": MODULE }, { profile, seed: 1 });
  const out = result.files[0]?.code ?? "";
  const overhead = ((gz(out) - origGz) / origGz) * 100;
  process.stdout.write(
    `${profile.padEnd(9)} gzip overhead ${overhead.toFixed(1)}% (budget 35%)  mangled=${result.transform.mangled} strings=${result.transform.strings_encrypted} mangle_only=${result.transform.files_mangle_only}\n`,
  );
}
