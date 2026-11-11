import type { Shield } from "@antireverse/shield-node";
import express, { type Express } from "express";

export interface RangeOptions {
  /** The Shield that observes this server. A disabled Shield works too. */
  shield: Pick<Shield, "express">;
}

const HOME_PAGE = `<!doctype html>
<html lang="en">
  <head>
    <meta charset="utf-8">
    <title>ar-range — reference target</title>
  </head>
  <body>
    <h1>ar-range</h1>
    <p>A reference target for Airverse. Shield sees every request to this server and applies the Policy of its App.</p>
    <ul>
      <li><code>GET /api/products/:id</code> — a synthetic product as JSON</li>
      <li><code>POST /api/login</code> — always answers 401</li>
      <li><code>GET /api/admin/reports</code> — synthetic reports as JSON; block it with a Rule for <code>/api/admin/**</code></li>
    </ul>
  </body>
</html>
`;

const PRODUCT_NAMES = ["Lantern", "Compass", "Canteen", "Field notebook", "Rope", "Tarp", "Whistle", "Map case"];

/** What the admin area "protects": synthetic, fixed, and about nobody. */
const REPORTS = [
  { id: "rpt_orders_weekly", title: "Orders per week", rows: 52 },
  { id: "rpt_stock_levels", title: "Stock levels", rows: PRODUCT_NAMES.length },
  { id: "rpt_login_failures", title: "Failed logins per day", rows: 30 },
];

/**
 * The reference target (ar-range): a small Express application with Shield in front of its routes.
 * It holds no data and has no real vulnerabilities in this slice: products are synthetic and derived from the
 * identifier, the login route never reads what it is sent, and the admin reports are a fixed synthetic list.
 * The admin route has no protection of its own: it is there to show a Rule for `/api/admin/**` blocking it.
 */
export function createRangeServer(options: RangeOptions): Express {
  const app = express();
  app.disable("x-powered-by");

  // In front of Shield: health probes are not traffic of the App.
  app.get("/healthz", (_req, res) => {
    res.json({ status: "ok" });
  });

  app.use(options.shield.express());

  app.get("/", (_req, res) => {
    res.type("html").send(HOME_PAGE);
  });

  app.get("/api/products/:id", (req, res) => {
    const id = String(req.params.id);
    if (!/^\d{1,9}$/.test(id)) {
      res.status(404).json({ error: "not_found" });
      return;
    }
    const n = Number(id);
    res.json({ id, name: PRODUCT_NAMES[n % PRODUCT_NAMES.length], price_cents: 500 + ((n * 137) % 4_500) });
  });

  app.post("/api/login", (_req, res) => {
    res.status(401).json({ error: "invalid_credentials" });
  });

  app.get("/api/admin/reports", (_req, res) => {
    res.json({ reports: REPORTS });
  });

  return app;
}
