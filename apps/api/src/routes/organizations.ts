import {
  CreateOrganizationRequestSchema,
  type CreateOrganizationResponse,
  type OrganizationResponse,
} from "@antireverse/protocol";
import { generateKey, newId } from "@antireverse/protocol/server";
import { Hono } from "hono";
import { audit, quoted, requestIdOf } from "../audit.ts";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import { insertKey } from "../stores/keys.ts";
import { findOrganization, insertOrganization } from "../stores/organizations.ts";
import { validateJson } from "../validate.ts";

export function organizationRoutes(deps: { db: Db; now?: (() => Date) | undefined }): Hono<AppEnv> {
  const { db } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();

  // Creates the Organization and its first admin key. The key leaves the API in this response only. Public (no key
  // exists yet); its audit entry is the Organization's first, by the key it creates (slice 18a).
  routes.post("/v1/organizations", limitBody(), validateJson(CreateOrganizationRequestSchema), async (c) => {
    const { name } = c.req.valid("json");
    const id = newId("org");
    const adminKey = generateKey("admin");
    const keyId = newId("key");
    const reason = c.get("reason");
    const organization = await db.tx({ organizationId: id }, async (q) => {
      const created = await insertOrganization(q, { id, name });
      await insertKey(q, { id: keyId, organizationId: id, kind: "admin", generated: adminKey });
      await audit(
        q,
        { organizationId: id, keyId, requestId: requestIdOf(c), reason },
        {
          action: "organization.create",
          target: { kind: "organization", id },
          summary: `Created the Organization ${quoted(name)} and its first admin key ${keyId}.`,
          at: now(),
        },
      );
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
