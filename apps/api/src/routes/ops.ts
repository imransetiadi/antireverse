import { createHash, timingSafeEqual } from "node:crypto";
import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import type { AppEnv } from "../auth/authenticate.ts";
import { problem } from "../problem.ts";
import type { SloService } from "../slo/service.ts";

// Slice 18d: the operator routes. `GET /v1/ops/slo` (JSON, `SloReportSchema`) and `GET /metrics` (Prometheus text) take
// the operator token of `AR_OPS_TOKEN` only, as `Authorization: Bearer <token>`, compared in constant time over
// SHA-256 digests (no length leak). Without the token configured they answer 404, as if they did not exist. Tenant keys
// are not tokens: they get the 401 of any wrong token. Not audited as tenant actions, not counted in SLO-07.

const BEARER = /^Bearer (\S+)$/i;

const digest = (text: string): Buffer => createHash("sha256").update(text, "utf8").digest();

export function opsRoutes(deps: { slo?: SloService | undefined; token?: string | undefined }): Hono<AppEnv> {
  const routes = new Hono<AppEnv>();
  const { slo } = deps;
  const expected = deps.token === undefined ? undefined : digest(deps.token);

  const guard = createMiddleware(async (c, next) => {
    if (expected === undefined || slo === undefined) return problem(c, "not-found");
    const presented = BEARER.exec(c.req.header("authorization") ?? "")?.[1];
    if (presented === undefined || !timingSafeEqual(digest(presented), expected)) return problem(c, "unauthorized");
    await next();
  });

  routes.get("/v1/ops/slo", guard, async (c) => c.json(await (slo as SloService).report()));
  routes.get("/metrics", guard, async (c) =>
    c.body(await (slo as SloService).metrics(), 200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" }),
  );
  return routes;
}
