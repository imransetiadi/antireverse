// Shared test helpers for the harden package. Not a *.test.ts, so vitest does not collect it.
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { pathToFileURL } from "node:url";

/** Temp files written during a test, cleaned up by `cleanupModules`. */
const temps: string[] = [];

/**
 * Writes `code` to a fresh temp module and dynamically imports it, returning its namespace. The default
 * extension is `.mjs` so Node runs it as ESM without a TypeScript loader. Use this to prove behaviour of the
 * protected output end to end (imports, exports, string decoding, globals).
 */
export async function importModule(code: string, ext = ".mjs"): Promise<Record<string, unknown>> {
  const dir = mkdtempSync(join(tmpdir(), "harden-test-"));
  const file = join(dir, `mod${ext}`);
  writeFileSync(file, code, "utf8");
  temps.push(dir);
  // A unique query defeats the module cache across calls with identical paths (there are none, but be safe).
  return (await import(`${pathToFileURL(file).href}?t=${Date.now()}-${Math.random()}`)) as Record<string, unknown>;
}

/** Removes everything `importModule` wrote. Call in `afterAll`. */
export function cleanupModules(): void {
  for (const dir of temps.splice(0)) rmSync(dir, { recursive: true, force: true });
}

/**
 * A module large (and incompressible) enough to hold the Canaries and the Clone Beacon within the default 35%
 * gzip size budget: the beacon statement is ~430 gzip bytes, so the host file needs ~1.6 KB of gzip. Exports
 * `priceOf`, `quote`, `table` and `SKUS` (200 pseudo-random ids) for behaviour checks.
 */
export function beaconHostModule(): string {
  const skus = Array.from({ length: 200 }, (_, i) =>
    createHash("sha256").update(`sku-${i}`).digest("hex").slice(0, 20),
  );
  return `
const TIERS = { free: 0, pro: 1900, business: 4900, "enterprise-eu": 9900, team: 2900, startup: 1500 };
export function priceOf(tier) {
  const cents = TIERS[tier];
  if (cents === undefined) throw new Error("unknown tier: " + tier);
  return cents;
}
export function label(tier) {
  return "the " + tier + " plan costs " + priceOf(tier) + " cents per seat each month, billed yearly";
}
export function discounted(cents, pct) {
  const factor = 1 - pct / 100;
  return Math.round(cents * factor);
}
export function format(cents) {
  const euros = (cents / 100).toFixed(2);
  return "EUR " + euros;
}
export function quote(tier, pct = 0) {
  return format(discounted(priceOf(tier), pct)) + " / " + label(tier);
}
export function table() {
  return Object.keys(TIERS).map((tier) => [tier, quote(tier, 10)]);
}
export const SKUS = ${JSON.stringify(skus)};
`;
}
