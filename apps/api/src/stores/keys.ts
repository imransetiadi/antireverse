import type { Environment } from "@antireverse/protocol";
import type { GeneratedKey } from "@antireverse/protocol/server";
import { hashKey } from "@antireverse/protocol/server";
import type { Principal } from "../auth/authenticate.ts";
import type { Queryable } from "../db/db.ts";

export type NewKey = { id: string; organizationId: string; generated: GeneratedKey } & (
  | { kind: "admin" }
  | { kind: "shield"; appId: string; environment: Environment }
);

/** Stores a key as its SHA-256 hash plus the two display fragments. The key itself is not stored. */
export async function insertKey(q: Queryable, key: NewKey): Promise<void> {
  await q.query(
    `INSERT INTO api_keys (id, organization_id, kind, app_id, environment, key_hash, prefix, last4)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
    [
      key.id,
      key.organizationId,
      key.kind,
      key.kind === "shield" ? key.appId : null,
      key.kind === "shield" ? key.environment : null,
      hashKey(key.generated.key),
      key.generated.prefix,
      key.generated.last4,
    ],
  );
}

interface LookupRow {
  key_id: string;
  organization_id: string;
  kind: "admin" | "shield";
  app_id: string | null;
  environment: Environment | null;
}

/** The principal of the key with this hash, or null when there is none or it was revoked. Needs no tenant. */
export async function findActiveKey(q: Queryable, keyHash: string): Promise<Principal | null> {
  const { rows } = await q.query<LookupRow>("SELECT * FROM auth_lookup_key($1)", [keyHash]);
  const row = rows[0];
  if (row === undefined) return null;
  if (row.kind === "admin") return { kind: "admin", keyId: row.key_id, organizationId: row.organization_id };
  if (row.app_id === null || row.environment === null) return null;
  return {
    kind: "shield",
    keyId: row.key_id,
    organizationId: row.organization_id,
    appId: row.app_id,
    environment: row.environment,
  };
}
