import { createHash } from "node:crypto";
import { parseRouteEntry } from "./assessment.ts";

/**
 * The digest of a route inventory, as a Manifest's `routes_digest` (slice 12a): the SHA-256 hex of the JSON of the
 * entries as `METHOD /path` with the method upper-cased, sorted by UTF-16 code unit. Input order and method case do
 * not change it; the input is not changed. Throws a TypeError for an entry that is not a route (`parseRouteEntry`).
 */
export function routesDigest(routes: readonly string[]): string {
  const canonical = routes
    .map((entry) => {
      const route = parseRouteEntry(entry);
      if (route === null) throw new TypeError("A route is `METHOD /path` with `:param` segments.");
      return `${route.method} ${route.path}`;
    })
    .sort((a, b) => (a < b ? -1 : a > b ? 1 : 0));
  return createHash("sha256").update(JSON.stringify(canonical), "utf8").digest("hex");
}
