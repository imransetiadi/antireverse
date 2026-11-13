import {
  type AllowlistEntry,
  type AllowlistEntryResponse,
  CONTAINMENT_LIMITS,
  CreateAllowlistEntryRequestSchema,
  ID_PATTERNS,
  type ListAllowlistResponse,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { Hono } from "hono";
import { audit, auditActor } from "../audit.ts";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import { lockOrganization } from "../stores/alert-channels.ts";
import {
  allowlistHas,
  countAllowlist,
  deleteAllowlistEntry,
  insertAllowlistEntry,
  listAllowlist,
} from "../stores/allowlist.ts";
import { validateJson } from "../validate.ts";

/** SQL state of a unique violation: the same CIDR added twice at once. */
const UNIQUE_VIOLATION = "23505";

/** The Organization's never-block ranges. Every App's Policy Bundle carries them; Shield lets them through. */
export function allowlistRoutes(deps: { db: Db; now?: () => Date }): Hono<AppEnv> {
  const { db } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");

  routes.get("/v1/allowlist", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const entries = await db.tx({ organizationId }, (q) => listAllowlist(q));
    return c.json({ entries } satisfies ListAllowlistResponse);
  });

  // The CIDR must be canonical (400 otherwise, nothing is rewritten); the same CIDR twice, or one past the
  // limit, is a 409.
  routes.post("/v1/allowlist", admin, limitBody(), validateJson(CreateAllowlistEntryRequestSchema), async (c) => {
    const { organizationId, keyId } = c.var.principal;
    const { cidr, note } = c.req.valid("json");
    const actor = auditActor(c);
    // A failed statement aborts the transaction, so a concurrent duplicate is caught outside it.
    let result: AllowlistEntry | "allowlist-duplicate" | "allowlist-limit";
    try {
      result = await db.tx({ organizationId }, async (q) => {
        // Serialises additions per Organization, so that the limit holds under concurrent requests.
        await lockOrganization(q, organizationId);
        if (await allowlistHas(q, cidr)) return "allowlist-duplicate";
        if ((await countAllowlist(q)) >= CONTAINMENT_LIMITS.allowlistMax) return "allowlist-limit";
        const at = now();
        const entry = await insertAllowlistEntry(q, {
          organizationId,
          id: newId("alw"),
          cidr,
          note,
          createdAt: at,
          createdBy: keyId,
        });
        await audit(q, actor, {
          action: "allowlist_entry.create",
          target: { kind: "allowlist_entry", id: entry.id },
          summary: `Added ${cidr} to the never-block allowlist.`,
          at,
        });
        return entry;
      });
    } catch (error) {
      if ((error as { code?: unknown }).code !== UNIQUE_VIOLATION) throw error;
      result = "allowlist-duplicate";
    }
    if (typeof result === "string") return problem(c, "conflict", undefined, result);
    return c.json({ entry: result } satisfies AllowlistEntryResponse, 201);
  });

  routes.delete("/v1/allowlist/:entryId", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const entryId = c.req.param("entryId");
    const actor = auditActor(c);
    // A malformed id is an entry that does not exist; another Organization's is invisible to the transaction.
    const deleted = ID_PATTERNS.alw.test(entryId)
      ? await db.tx({ organizationId }, async (q) => {
          const cidr = await deleteAllowlistEntry(q, entryId);
          if (cidr === null) return false;
          await audit(q, actor, {
            action: "allowlist_entry.delete",
            target: { kind: "allowlist_entry", id: entryId },
            summary: `Removed ${cidr} from the never-block allowlist.`,
            at: now(),
          });
          return true;
        })
      : false;
    if (!deleted) return problem(c, "not-found");
    return c.body(null, 204);
  });

  return routes;
}
