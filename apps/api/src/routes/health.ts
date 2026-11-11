import { Hono } from "hono";
import type { AppEnv } from "../auth/authenticate.ts";

export function healthRoutes(): Hono<AppEnv> {
  const routes = new Hono<AppEnv>();
  routes.get("/healthz", (c) => c.json({ status: "ok" }));
  return routes;
}
