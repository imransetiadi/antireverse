import { UsageQuerySchema, usageMonthOf, usageMonthRefusal } from "@antireverse/protocol";
import { Hono } from "hono";
import type { WindowLimiter } from "../attestation/limiter.ts";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import { usageOfMonth } from "../stores/usage.ts";
import { validateQuery } from "../validate.ts";

// Usage (slice 17a): `GET /v1/usage?month=YYYY-MM`, admin keys only, tenant-isolated by row-level security. The month
// defaults to the current UTC month; a month in the future or older than `USAGE_HISTORY_MONTHS` is refused with the
// validation problem. Reads take from the per-Organization budget of audit reads (shared with audit verification and
// export and the Organization export). Refused while the Organization's deletion is pending (the key gate).

export function usageRoutes(deps: {
  db: Db;
  /** The per-Organization budget of audit reads. */
  reads: WindowLimiter;
  now?: (() => Date) | undefined;
}): Hono<AppEnv> {
  const { db, reads } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();

  routes.get("/v1/usage", requireKey(db, "admin"), validateQuery(UsageQuerySchema), async (c) => {
    const { organizationId } = c.var.principal;
    const at = now();
    const month = c.req.valid("query").month ?? usageMonthOf(at);
    const refusal = usageMonthRefusal(month, at);
    if (refusal !== null) return problem(c, "validation", [{ path: "month", message: refusal }]);
    const taken = reads.take(organizationId, at.getTime());
    if (!taken.allowed) {
      c.header("Retry-After", String(taken.retryAfterS));
      return problem(c, "too-many-audit-reads");
    }
    const body = await db.tx({ organizationId }, (q) => usageOfMonth(q, organizationId, month, at));
    if (body === null) return problem(c, "not-found");
    return c.json(body);
  });

  return routes;
}
