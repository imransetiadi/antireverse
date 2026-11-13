// Reads the route inventory given with `--routes <file>` (slice 12a): a JSON array of `METHOD /path` strings with
// `:param` segments, at most 2,000, each once (method compared without case) — the protocol's
// `RouteInventorySchema`. The inventory is what W1 Map is judged against, so it is never given to the agent, never
// written into the output bundle and never printed: error messages name an entry by its position, not its value.
import { readFileSync } from "node:fs";
import { parseRouteEntry, ROUTE_LIMITS, RouteInventorySchema } from "@antireverse/protocol";

export type ReadRoutesResult = { routes: string[] } | { error: string };

const count = (n: number) => n.toLocaleString("en-US");

export function readRoutes(file: string): ReadRoutesResult {
  let raw: string;
  try {
    raw = readFileSync(file, "utf8");
  } catch {
    return { error: "cannot be read" };
  }
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    return { error: "is not JSON" };
  }
  if (!Array.isArray(value)) return { error: 'must be a JSON array of "METHOD /path" strings' };
  if (value.length > ROUTE_LIMITS.routesMax) {
    return { error: `lists ${count(value.length)} routes; at most ${count(ROUTE_LIMITS.routesMax)} are accepted` };
  }
  const seen = new Map<string, number>();
  for (let index = 0; index < value.length; index++) {
    const route = parseRouteEntry(value[index]);
    if (route === null) {
      return {
        error: `entry ${index + 1} is not "METHOD /path" (path segments of A-Z a-z 0-9 . _ ~ - or :param, at most ${ROUTE_LIMITS.pathMax} characters)`,
      };
    }
    const key = `${route.method} ${route.path}`;
    const first = seen.get(key);
    if (first !== undefined) return { error: `lists a route twice (entries ${first + 1} and ${index + 1})` };
    seen.set(key, index);
  }
  // The protocol's schema is the contract; the checks above only make its refusals readable without echoing values.
  const parsed = RouteInventorySchema.safeParse(value);
  if (!parsed.success) return { error: "is not a valid route inventory" };
  return { routes: parsed.data };
}
