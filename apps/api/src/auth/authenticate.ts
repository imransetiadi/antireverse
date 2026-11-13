import type { Environment } from "@antireverse/protocol";
import { hashKey, type KeyKind, parseKey } from "@antireverse/protocol/server";
import type { Context, MiddlewareHandler } from "hono";
import { createMiddleware } from "hono/factory";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
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
 * Requires a key of the given kind in `Authorization: Bearer <key>`.
 * No header, a malformed, unknown or revoked key: 401 (one answer for all, so that it does not say
 * whether a key exists). A valid key of the other kind: 403.
 */
export function requireKey<K extends KeyKind>(
  db: Db,
  kind: K,
): MiddlewareHandler<{ Variables: { principal: PrincipalOf<K> } }> {
  return createMiddleware<{ Variables: { principal: PrincipalOf<K> } }>(async (c, next) => {
    const presented = presentedKey(c);
    // A key that is not well formed cannot exist: answer without asking the database.
    if (presented === undefined || parseKey(presented) === null) return problem(c, "unauthorized");

    const hash = hashKey(presented);
    const key = await db.tx("none", (q) => findActiveKey(q, hash));
    if (key === null) return problem(c, "unauthorized");
    if (key.kind !== kind) return problem(c, "forbidden");

    c.set("principal", key as PrincipalOf<K>);
    return next();
  });
}
