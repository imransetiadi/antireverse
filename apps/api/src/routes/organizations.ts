import {
  CreateOrganizationRequestSchema,
  type CreateOrganizationResponse,
  type OrganizationResponse,
} from "@antireverse/protocol";
import { generateKey, newId } from "@antireverse/protocol/server";
import { Hono } from "hono";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import { insertKey } from "../stores/keys.ts";
import { findOrganization, insertOrganization } from "../stores/organizations.ts";
import { validateJson } from "../validate.ts";

export function organizationRoutes(deps: { db: Db }): Hono<AppEnv> {
  const { db } = deps;
  const routes = new Hono<AppEnv>();

  // Creates the Organization and its first admin key. The key leaves the API in this response only.
  routes.post("/v1/organizations", limitBody(), validateJson(CreateOrganizationRequestSchema), async (c) => {
    const { name } = c.req.valid("json");
    const id = newId("org");
    const adminKey = generateKey("admin");
    const organization = await db.tx({ organizationId: id }, async (q) => {
      const created = await insertOrganization(q, { id, name });
      await insertKey(q, { id: newId("key"), organizationId: id, kind: "admin", generated: adminKey });
      return created;
    });
    const { key, prefix, last4 } = adminKey;
    return c.json({ organization, admin_key: { key, prefix, last4 } } satisfies CreateOrganizationResponse, 201);
  });

  routes.get("/v1/organization", requireKey(db, "admin"), async (c) => {
    const { organizationId } = c.var.principal;
    const organization = await db.tx({ organizationId }, (q) => findOrganization(q, organizationId));
    if (organization === null) return problem(c, "not-found");
    return c.json({ organization } satisfies OrganizationResponse);
  });

  return routes;
}
