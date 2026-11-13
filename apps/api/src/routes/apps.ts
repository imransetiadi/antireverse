import {
  type AppResponse,
  type AppSetupResponse,
  CreateAppRequestSchema,
  type CreateAppResponse,
  ENVIRONMENTS,
  ID_PATTERNS,
  type ListAppsResponse,
} from "@antireverse/protocol";
import { generateKey, newId } from "@antireverse/protocol/server";
import { Hono } from "hono";
import { z } from "zod";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import { findApp, insertApp, listApps } from "../stores/apps.ts";
import { insertKey } from "../stores/keys.ts";
import { appSetup, firstEnvironment } from "../stores/setup.ts";
import { validateJson, validateQuery } from "../validate.ts";

/** `?environment=`: optional; without it, the set-up is of the Environment of the App's first Shield key. */
const SetupQuerySchema = z.object({ environment: z.enum(ENVIRONMENTS).optional() });

export function appRoutes(deps: { db: Db }): Hono<AppEnv> {
  const { db } = deps;
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");

  // Creates the App and one Shield key for the chosen Environment. The key leaves the API in this response only.
  routes.post("/v1/apps", admin, limitBody(), validateJson(CreateAppRequestSchema), async (c) => {
    const { organizationId } = c.var.principal;
    const { name, environment } = c.req.valid("json");
    const appId = newId("app");
    const shieldKey = generateKey("shield", environment);
    const app = await db.tx({ organizationId }, async (q) => {
      const created = await insertApp(q, { id: appId, organizationId, name });
      await insertKey(q, {
        id: newId("key"),
        organizationId,
        kind: "shield",
        appId,
        environment,
        generated: shieldKey,
      });
      return created;
    });
    const { key, prefix, last4 } = shieldKey;
    return c.json({ app, shield_key: { key, prefix, last4, environment } } satisfies CreateAppResponse, 201);
  });

  routes.get("/v1/apps", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const apps = await db.tx({ organizationId }, (q) => listApps(q));
    return c.json({ apps } satisfies ListAppsResponse);
  });

  routes.get("/v1/apps/:appId", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const appId = c.req.param("appId");
    // Another Organization's App is invisible to this transaction: it is "not found" like any other.
    const app = ID_PATTERNS.app.test(appId) ? await db.tx({ organizationId }, (q) => findApp(q, appId)) : null;
    if (app === null) return problem(c, "not-found");
    return c.json({ app } satisfies AppResponse);
  });

  // When each set-up step of one App Environment was first done (slice 16). Read only; polled by the Console.
  routes.get("/v1/apps/:appId/setup", admin, validateQuery(SetupQuerySchema), async (c) => {
    const { organizationId } = c.var.principal;
    const appId = c.req.param("appId");
    const query = c.req.valid("query");
    if (!ID_PATTERNS.app.test(appId)) return problem(c, "not-found");
    const setup = await db.tx({ organizationId }, async (q) => {
      // Another Organization's App is invisible to this transaction: "not found" like any other.
      if ((await findApp(q, appId)) === null) return null;
      const environment = query.environment ?? (await firstEnvironment(q, appId)) ?? "development";
      return appSetup(q, { organizationId, appId, environment });
    });
    if (setup === null) return problem(c, "not-found");
    return c.json({ setup } satisfies AppSetupResponse);
  });

  return routes;
}
