import { discounted, format, priceOf } from "./pricing.ts";

export { buildReport, renderTable, toCsv } from "./reports.ts";

export function quote(tier: string, pct = 0): string {
  return format(discounted(priceOf(tier), pct));
}
