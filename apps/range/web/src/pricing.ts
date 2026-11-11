// A small browser module with real logic, used as the thing Harden protects end to end.
// It imports, exports, reads a global, uses string-keyed objects, template and non-ASCII strings.
const TIERS: Record<string, number> = { free: 0, pro: 1900, business: 4900, "enterprise-eu": 9900 };

export function priceOf(tier: string): number {
  const cents = TIERS[tier];
  if (cents === undefined) throw new Error(`unknown tier: ${tier}`);
  return cents;
}

/** Format as euros; keeps a non-ASCII symbol to prove strings survive protection. */
export function format(cents: number): string {
  return `€${(cents / 100).toFixed(2)}`;
}

export function discounted(cents: number, pct: number): number {
  return Math.round(cents * (1 - pct / 100));
}
