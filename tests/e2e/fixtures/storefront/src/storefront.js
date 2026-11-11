// Cart, checkout summary and delivery address checks for a small shop's product page. Browser ES module; the
// clone-beacon browser e2e hardens it (with the Clone Beacon) and serves it under an allowed and a clone name.
const CATALOG = {
  "tee-classic": { name: "Classic tee", cents: 1900, weightGrams: 180, stock: 120 },
  "tee-organic": { name: "Organic tee", cents: 2400, weightGrams: 190, stock: 80 },
  "tee-longsleeve": { name: "Long-sleeve tee", cents: 2900, weightGrams: 240, stock: 45 },
  "hoodie-zip": { name: "Zip hoodie", cents: 5900, weightGrams: 620, stock: 30 },
  "hoodie-pullover": { name: "Pullover hoodie", cents: 5400, weightGrams: 590, stock: 25 },
  "cap-logo": { name: "Logo cap", cents: 1500, weightGrams: 90, stock: 200 },
  "beanie-wool": { name: "Wool beanie", cents: 1800, weightGrams: 80, stock: 60 },
  "mug-enamel": { name: "Enamel mug", cents: 1200, weightGrams: 310, stock: 150 },
  "bottle-steel": { name: "Steel bottle", cents: 2200, weightGrams: 350, stock: 70 },
  "tote-canvas": { name: "Canvas tote", cents: 1400, weightGrams: 150, stock: 90 },
  "sticker-pack": { name: "Sticker pack", cents: 500, weightGrams: 20, stock: 500 },
  "poster-a2": { name: "A2 poster", cents: 1600, weightGrams: 140, stock: 40 },
};

/** VAT in percent by destination country (prices include VAT). */
const VAT = {
  AT: 20,
  BE: 21,
  DE: 19,
  DK: 25,
  ES: 21,
  FI: 25.5,
  FR: 20,
  IE: 23,
  IT: 22,
  LU: 17,
  NL: 21,
  PT: 23,
  SE: 25,
};

/** Postal code shapes by country, for a first check before the carrier's own validation. */
const POSTAL = {
  AT: /^\d{4}$/,
  BE: /^\d{4}$/,
  DE: /^\d{5}$/,
  DK: /^\d{4}$/,
  ES: /^\d{5}$/,
  FI: /^\d{5}$/,
  FR: /^\d{5}$/,
  IE: /^[A-Z]\d{2} ?[A-Z\d]{4}$/,
  IT: /^\d{5}$/,
  LU: /^\d{4}$/,
  NL: /^\d{4} ?[A-Z]{2}$/,
  PT: /^\d{4}-\d{3}$/,
  SE: /^\d{3} ?\d{2}$/,
};

const SHIPPING = [
  { upToGrams: 500, cents: 490, days: 2 },
  { upToGrams: 2000, cents: 690, days: 3 },
  { upToGrams: 10000, cents: 1290, days: 4 },
];
const FREE_SHIPPING_FROM = 7500;
const MAX_QUANTITY = 99;
const CODES = {
  WELCOME10: { pct: 10, minCents: 0, label: "Welcome discount" },
  BUNDLE15: { pct: 15, minCents: 6000, label: "Bundle discount" },
  STUDENT20: { pct: 20, minCents: 2000, label: "Student discount" },
};

export function product(sku) {
  const item = CATALOG[sku];
  if (item === undefined) throw new Error(`unknown product: ${sku}`);
  return item;
}

/** Cents as euros the German way: 123456 → "1.234,56 €". */
export function euros(cents) {
  const sign = cents < 0 ? "-" : "";
  const abs = Math.abs(Math.round(cents));
  const whole = String(Math.floor(abs / 100)).replace(/\B(?=(\d{3})+(?!\d))/g, ".");
  return `${sign}${whole},${String(abs % 100).padStart(2, "0")} €`;
}

export function createCart() {
  return { lines: [], code: null };
}

export function addToCart(cart, sku, quantity = 1) {
  if (!Number.isInteger(quantity) || quantity <= 0 || quantity > MAX_QUANTITY) throw new Error("invalid quantity");
  const item = product(sku);
  const line = cart.lines.find((entry) => entry.sku === sku);
  const wanted = Math.min(MAX_QUANTITY, (line?.quantity ?? 0) + quantity);
  if (wanted > item.stock) throw new Error(`only ${item.stock} left of ${item.name}`);
  const lines =
    line === undefined
      ? [...cart.lines, { sku, quantity: wanted }]
      : cart.lines.map((entry) => (entry.sku === sku ? { sku, quantity: wanted } : entry));
  return { ...cart, lines };
}

export function setQuantity(cart, sku, quantity) {
  if (quantity === 0) return removeFromCart(cart, sku);
  const without = removeFromCart(cart, sku);
  return addToCart(without, sku, quantity);
}

export function removeFromCart(cart, sku) {
  return { ...cart, lines: cart.lines.filter((entry) => entry.sku !== sku) };
}

export function applyCode(cart, code) {
  const upper = String(code).trim().toUpperCase();
  if (CODES[upper] === undefined) throw new Error(`unknown code: ${code}`);
  return { ...cart, code: upper };
}

export function subtotal(cart) {
  return cart.lines.reduce((sum, line) => sum + product(line.sku).cents * line.quantity, 0);
}

export function weight(cart) {
  return cart.lines.reduce((sum, line) => sum + product(line.sku).weightGrams * line.quantity, 0);
}

export function discount(cart) {
  if (cart.code === null) return 0;
  const rule = CODES[cart.code];
  const base = subtotal(cart);
  return base < rule.minCents ? 0 : Math.round((base * rule.pct) / 100);
}

/** How much more to spend for free shipping, or 0 when it already applies. */
export function untilFreeShipping(cart) {
  return Math.max(0, FREE_SHIPPING_FROM - (subtotal(cart) - discount(cart)));
}

export function shippingBand(cart) {
  const grams = weight(cart);
  if (grams === 0) return null;
  const band = SHIPPING.find((entry) => grams <= entry.upToGrams);
  if (band === undefined) throw new Error(`too heavy to ship: ${grams} g`);
  return band;
}

export function shipping(cart) {
  const band = shippingBand(cart);
  if (band === null || untilFreeShipping(cart) === 0) return 0;
  return band.cents;
}

/** The delivery date for an order placed at `now`: working days only, cut-off at 14:00. */
export function deliveryDate(cart, now) {
  const band = shippingBand(cart);
  if (band === null) return null;
  const date = new Date(now.getTime());
  let days = band.days + (date.getHours() >= 14 ? 1 : 0);
  while (days > 0) {
    date.setDate(date.getDate() + 1);
    const day = date.getDay();
    if (day !== 0 && day !== 6) days -= 1;
  }
  return date.toISOString().slice(0, 10);
}

/** Problems with a delivery address, as messages for the form (empty when it can be shipped to). */
export function addressProblems(address) {
  const problems = [];
  const name = String(address.name ?? "").trim();
  if (name.length < 2) problems.push("Enter the recipient's name.");
  if (String(address.street ?? "").trim().length < 3) problems.push("Enter the street and house number.");
  if (String(address.city ?? "").trim().length < 2) problems.push("Enter the city.");
  const country = String(address.country ?? "").toUpperCase();
  const shape = POSTAL[country];
  if (shape === undefined) problems.push("We do not ship to this country yet.");
  else if (
    !shape.test(
      String(address.postalCode ?? "")
        .trim()
        .toUpperCase(),
    )
  ) {
    problems.push("Check the postal code.");
  }
  return problems;
}

export function summary(cart, country = "DE") {
  const rate = VAT[country];
  if (rate === undefined) throw new Error(`we do not ship to ${country}`);
  const total = subtotal(cart) - discount(cart) + shipping(cart);
  const vat = Math.round((total * rate) / (100 + rate));
  return {
    items: cart.lines.reduce((sum, line) => sum + line.quantity, 0),
    subtotal: subtotal(cart),
    discount: discount(cart),
    discountLabel: cart.code === null ? null : CODES[cart.code].label,
    shipping: shipping(cart),
    vat,
    vatRate: rate,
    total,
    lines: cart.lines.map((line) => ({
      name: product(line.sku).name,
      quantity: line.quantity,
      amount: euros(product(line.sku).cents * line.quantity),
    })),
  };
}

export function renderSummary(view) {
  const rows = view.lines.map((line) => `${line.quantity} × ${line.name}  ${line.amount}`);
  rows.push(`Subtotal  ${euros(view.subtotal)}`);
  if (view.discount > 0) rows.push(`${view.discountLabel}  -${euros(view.discount)}`);
  rows.push(`Shipping  ${view.shipping === 0 ? "free" : euros(view.shipping)}`);
  rows.push(`Total  ${euros(view.total)} (incl. ${euros(view.vat)} VAT at ${view.vatRate}%)`);
  return rows.join("\n");
}
