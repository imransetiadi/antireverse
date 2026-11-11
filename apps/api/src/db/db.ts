import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import { acquireDataDirLock } from "./lock.ts";
import { migrate } from "./migrate.ts";

/** The only database capability request code ever holds: SQL inside one transaction. */
export interface Queryable {
  query<R = Record<string, unknown>>(sql: string, params?: unknown[]): Promise<{ rows: R[] }>;
}

/** Which Organization's rows a transaction may see and write. `"none"`: no tenant rows at all. */
export type Scope = { organizationId: string } | "none";

export interface Db {
  /**
   * Runs `fn` in one transaction as the role `ar_app` with `app.tenant_id` set for that transaction only.
   * All transactions share one in-process lock: await nothing but SQL inside `fn`.
   */
  tx<T>(scope: Scope, fn: (q: Queryable) => Promise<T>): Promise<T>;
  close(): Promise<void>;
}

/**
 * The database as the sync path holds it (`vulns:sync`, the post-sync re-match): every request capability, plus
 * transactions as the owner. Only `openDb` hands this out; request code receives a plain `Db`.
 */
export interface OwnedDb extends Db {
  /**
   * Runs `fn` in one transaction as the database owner (`SET LOCAL ROLE NONE`: the role returns to the request role
   * when the transaction ends, committed or not). For the definer functions of the sync path only.
   */
  owner<T>(fn: (q: Queryable) => Promise<T>): Promise<T>;
}

/** The role every request runs as. Created by the first migration. */
const REQUEST_ROLE = "ar_app";
const MIGRATIONS_DIRECTORY = fileURLToPath(new URL("../../migrations", import.meta.url));

/**
 * Opens the database and applies pending migrations. Without `dataDir` the database lives in memory.
 * With it, this process becomes the directory's single owner until `close()` (pid lock `<dataDir>.lock`).
 */
export async function openDb(options: { dataDir?: string } = {}): Promise<OwnedDb> {
  const { dataDir } = options;
  const releaseLock = dataDir === undefined ? () => {} : acquireDataDirLock(dataDir);

  let pg: PGlite;
  try {
    pg = await PGlite.create(dataDir);
  } catch (error) {
    releaseLock();
    throw error;
  }
  try {
    // Migrations need the owner. Everything after this line is fail-closed: the session role is switched
    // once and stays switched through errors and rollbacks, so no query can run as the superuser.
    await migrate(pg, MIGRATIONS_DIRECTORY);
    await pg.exec(`SET ROLE ${REQUEST_ROLE}`);
  } catch (error) {
    await pg.close().catch(() => {});
    releaseLock();
    throw error;
  }

  let closing: Promise<void> | undefined;
  return {
    tx(scope, fn) {
      return pg.transaction(async (tx) => {
        const tenant = scope === "none" ? "" : scope.organizationId;
        await tx.query("SELECT set_config('app.tenant_id', $1, true)", [tenant]);
        // Only the transaction is handed out, and only its query method: the outer handle would deadlock
        // inside a transaction and would escape the tenant scope outside of one.
        return fn({ query: (sql, params) => tx.query(sql, params) });
      });
    },
    owner(fn) {
      return pg.transaction(async (tx) => {
        await tx.query("SET LOCAL ROLE NONE");
        await tx.query("SELECT set_config('app.tenant_id', '', true)");
        return fn({ query: (sql, params) => tx.query(sql, params) });
      });
    },
    close() {
      closing ??= pg.close().finally(releaseLock);
      return closing;
    },
  };
}
