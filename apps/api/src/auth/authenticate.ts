import type { Environment } from "@antireverse/protocol";
import { hashKey, type KeyKind, parseKey } from "@antireverse/protocol/server";
import type { Context, MiddlewareHandler } from "hono";
import { createMiddleware } from "hono/factory";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import { pendingDeletion } from "../stores/deletions.ts";
import { findActiveKey } from "../stores/keys.ts";

/** Who a request acts as. Every member comes from the stored key, never from the request. */
export type Principal =
  | { kind: "admin"; keyId: string; organizationId: string }
  | { kind: "shield"; keyId: string; organizationId: string; appId: string; environment: Environment };

export type PrincipalOf<K extends KeyKind> = Extract<Principal, { kind: K }>;

/**
 * The Hono environment of the API: an authenticated route has its principal in `c.var.principal`. Every request has
 * an id (`requestId`, slice 18a); a mutating request may carry a validated reason (`reason`, `X-Airverse-Reason`).
 */
export type AppEnv = { Variables: { principal: Principal; requestId: string; reason?: string | undefined } };

const BEARER = /^Bearer (\S+)$/i;

/**
 * The key a request presents as `Authorization: Bearer <key>`, if it presents one. Behind `requireKey`
 * it is the key of the principal. It is a secret: derive from it, never log, store or return it.
 */
export function presentedKey(c: Context): string | undefined {
  return BEARER.exec(c.req.header("authorization") ?? "")?.[1];
}

/**
 * The active key with this hash and whether its Organization's deletion is pending, in one transaction; null when
 * there is no such key (unknown, revoked, or purged with its Organization).
 */
export async function lookUpKey(db: Db, keyHash: string): Promise<{ key: Principal; pending: boolean } | null> {
  return db.tx("none", async (q) => {
    const key = await findActiveKey(q, keyHash);
    if (key === null) return null;
    // Slice 18b: in the same transaction, scoped to the key's own Organization (and to nothing else), whether its
    // deletion is pending.
    await q.query("SELECT set_config('app.tenant_id', $1, true)", [key.organizationId]);
    return { key, pending: (await pendingDeletion(q)) !== null };
  });
}

/**
 * True while the key with this hash would still pass `requireKey` on a route closed during a deletion: it exists, is
 * not revoked, and its Organization is not pending deletion. A long-lived response (a live stream) asks it again.
 */
export async function keyStillValid(db: Db, keyHash: string): Promise<boolean> {
  const found = await lookUpKey(db, keyHash);
  return found !== null && !found.pending;
}

export interface RequireKeyOptions {
  /**
   * Slice 18b: the route stays open to a key of an Organization whose deletion is pending (the deletion status, its
   * cancellation, the export). Default false: such a key is refused with 403 `organization-deletion-pending`.
   */
  duringDeletion?: boolean;
}

/**
 * Requires a key of the given kind in `Authorization: Bearer <key>`.
 * No header, a malformed, unknown or revoked key: 401 (one answer for all, so that it does not say
 * whether a key exists). A key of an Organization whose deletion is pending, of either kind: 403
 * `organization-deletion-pending`, unless the route allows it (`duringDeletion`). A valid key of the other kind: 403.
 */
export function requireKey<K extends KeyKind>(
  db: Db,
  kind: K,
  options: RequireKeyOptions = {},
): MiddlewareHandler<{ Variables: { principal: PrincipalOf<K> } }> {
  return createMiddleware<{ Variables: { principal: PrincipalOf<K> } }>(async (c, next) => {
    const presented = presentedKey(c);
    // A key that is not well formed cannot exist: answer without asking the database.
    if (presented === undefined || parseKey(presented) === null) return problem(c, "unauthorized");

    const found = await lookUpKey(db, hashKey(presented));
    if (found === null) return problem(c, "unauthorized");
    const { key } = found;
    if (found.pending && options.duringDeletion !== true) return problem(c, "organization-deletion-pending");
    if (key.kind !== kind) return problem(c, "forbidden");

    c.set("principal", key as PrincipalOf<K>);
    return next();
  });
}
