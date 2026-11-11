import { EXPOSURE_LIMITS, InventorySchema } from "@antireverse/protocol";
import { Hono } from "hono";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db } from "../db/db.ts";
import { type IncidentQueue, matchInventory } from "../exposure/match.ts";
import type { Logger } from "../log.ts";
import { problem } from "../problem.ts";
import { validateJson } from "../validate.ts";

/**
 * `POST /v1/inventory` (Shield key): the packages installed where Shield runs, sent once at its start. Stored as
 * the inventory of the sending instance (`instance_id`; none: the shared legacy instance) of the key's App
 * Environment, replacing that instance's previous one; the runtime set (the live instances' union) is matched at once; Incidents for
 * newly opened Critical or High Findings are opened after the commit. Answers 202 with an empty object.
 */
/** Inventories a Shield key may send at once, and the time in which one more becomes available (plan A7, M4). */
export const INVENTORY_BURST = 5;
export const INVENTORY_REFILL_MS = 60_000;
/** Keys tracked at once; past it, the buckets that are full again are dropped. */
const BUCKETS_MAX = 10_000;

/**
 * A token bucket per Shield key: `INVENTORY_BURST` tokens, one more every `INVENTORY_REFILL_MS`. `take` answers 0
 * when a token was taken, else the milliseconds until the next one.
 */
export function createInventoryLimiter(now: () => Date) {
  const buckets = new Map<string, { tokens: number; at: number }>();
  const level = (bucket: { tokens: number; at: number }, ms: number) =>
    Math.min(INVENTORY_BURST, bucket.tokens + (ms - bucket.at) / INVENTORY_REFILL_MS);
  return {
    take(keyId: string): number {
      const clock = now().getTime();
      if (buckets.size >= BUCKETS_MAX) {
        for (const [id, bucket] of buckets) if (level(bucket, clock) >= INVENTORY_BURST) buckets.delete(id);
      }
      const known = buckets.get(keyId);
      // A clock that steps back counts as no time passing (second review L-D): never a negative refill.
      const ms = Math.max(clock, known?.at ?? clock);
      const bucket = known ?? { tokens: INVENTORY_BURST, at: ms };
      const tokens = level(bucket, ms);
      if (tokens < 1) {
        buckets.set(keyId, { tokens, at: ms });
        return Math.ceil((1 - tokens) * INVENTORY_REFILL_MS);
      }
      buckets.set(keyId, { tokens: tokens - 1, at: ms });
      return 0;
    },
  };
}

export function inventoryRoutes(deps: {
  db: Db;
  /** Opens the Incidents of new Findings after the response. */
  incidents: IncidentQueue;
  now?: (() => Date) | undefined;
  logger?: Logger | undefined;
}): Hono<AppEnv> {
  const { db } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const limiter = createInventoryLimiter(now);

  routes.post(
    "/v1/inventory",
    requireKey(db, "shield"),
    limitBody(EXPOSURE_LIMITS.componentsBytesMax, "inventory-payload-too-large"),
    validateJson(InventorySchema),
    async (c) => {
      const { organizationId, appId, environment, keyId } = c.var.principal;
      const { components, instance_id: instance } = c.req.valid("json");
      // Counted only for an inventory that would be stored: a refused body costs no token.
      const waitMs = limiter.take(keyId);
      if (waitMs > 0) {
        c.header("Retry-After", String(Math.max(1, Math.ceil(waitMs / 1_000))));
        return problem(c, "too-many-inventories");
      }
      const result = await db.tx({ organizationId }, (q) =>
        matchInventory(q, {
          organizationId,
          appId,
          environment,
          source: "runtime",
          buildId: null,
          instance,
          components,
          at: now(),
        }),
      );
      deps.incidents.enqueue(organizationId, result.opened);
      return c.json({}, 202);
    },
  );

  return routes;
}
