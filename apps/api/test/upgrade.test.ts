import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import {
  AuditVerifyResponseSchema,
  BundlePayloadSchema,
  ListAppsResponseSchema,
  ListEventsResponseSchema,
  SignedBundleSchema,
} from "@antireverse/protocol";
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { attachDb } from "../src/db/db.ts";
import { migrate } from "../src/db/migrate.ts";
import { GLOBAL_TABLES } from "./data-seed.ts";
import {
  applyEra,
  ERA_SEEDS,
  type EraContext,
  type EraTenant,
  eraContext,
  MIGRATIONS_DIRECTORY,
  migrationFiles,
  snapshotTables,
  type TableRow,
  type TableSnapshot,
} from "./era-seed.ts";
import { bearer, makeTestApi, type TestApi, verifySignature } from "./helpers.ts";

// Slice 18h: the local upgrade check (gate criterion gate-upgrade-local). No version has been released, so "a
// previous version" is every migration prefix 0001…K below the head. One database walks the migrations in order —
// migration K, then the era seed of K (era-seed.ts) — and after each step is copied; the copy is upgraded to the head
// in one start-up (`attachDb`: the code `openDb` runs) and must still hold every row, verify its audit chain, isolate
// its tenants and answer through the API's routes with the keys seeded at 0001.

type Row = TableRow;
type Snapshot = TableSnapshot;

const FILES = migrationFiles();

const canonical = (row: Row, columns: readonly string[]): string =>
  JSON.stringify(columns.map((column) => [column, row[column] ?? null]));

/**
 * What the upgrade lost or changed: every row of every table of the earlier version must be found at the head with the
 * same value in every column it had. A migration may add rows and columns; a column it removes must be listed in
 * `DROPPED_COLUMNS`, and a value it rewrites fails here until the test says why that is meant.
 */
function lostRows(before: Snapshot, after: Snapshot, prefix: string): string[] {
  const problems: string[] = [];
  for (const [table, rows] of before) {
    // The migrator's own table: it grows by the migrations applied, which the test compares by name.
    if (table === "schema_migrations") continue;
    const now = after.get(table);
    if (now === undefined) {
      problems.push(`${table}: the table is gone`);
      continue;
    }
    const had = Object.keys(rows[0] ?? {});
    const has = new Set(Object.keys(now[0] ?? rows[0] ?? {}));
    for (const column of had) {
      if (!has.has(column) && !DROPPED_COLUMNS.has(`${table}.${column}`)) {
        problems.push(`${table}.${column}: the column is gone`);
      }
    }
    const columns = had.filter((column) => has.has(column)).sort();
    const remaining = new Map<string, number>();
    for (const row of now) {
      const key = canonical(row, columns);
      remaining.set(key, (remaining.get(key) ?? 0) + 1);
    }
    for (const row of rows) {
      const key = canonical(row, columns);
      const left = remaining.get(key) ?? 0;
      if (left === 0) {
        problems.push(`${table}: a row of ${prefix} is missing or changed at the head: ${key.slice(0, 300)}`);
      } else remaining.set(key, left - 1);
    }
  }
  return problems;
}

const versionsOf = (tables: Snapshot): unknown[] =>
  (tables.get("schema_migrations") ?? []).map((row) => row.version).sort();

/**
 * Rows the database itself refuses to change, by table: a trigger makes them final, so the write probe cannot rewrite
 * them — and neither can anything else, which is why a constraint they violate could not block a later change.
 * `where` narrows the probe to the rows that may still change; without it the table is left out.
 */
const FINAL_ROWS: ReadonlyMap<string, { why: string; where?: string }> = new Map([
  ["containments", { why: "0009: a lifted containment cannot change", where: "lifted_at IS NULL" }],
  ["campaigns", { why: "0039: a Campaign that ended is final, and the seeded one has ended" }],
  ["campaign_requests", { why: "0039: a request log row is settled once, and the seeded one is settled" }],
  ["campaign_findings", { why: "0039: the Findings of a Campaign that ended are final" }],
]);

/**
 * The write probe (review L4): every row of every table of the earlier version is rewritten with its own values, in a
 * transaction that is rolled back. PostgreSQL checks a rewritten row against every CHECK constraint (one added NOT
 * VALID too) and runs the table's triggers, so a migration that leaves old rows readable but not writable fails here.
 * Rows a trigger has made final are the exception (`FINAL_ROWS`).
 */
async function unwritableRows(pg: PGlite, before: Snapshot): Promise<string[]> {
  const problems: string[] = [];
  for (const [table, rows] of before) {
    if (table === "schema_migrations") continue;
    const final = FINAL_ROWS.get(table);
    if (final !== undefined && final.where === undefined) continue;
    // Any column that may be assigned: an identity column that is always generated may not.
    const { rows: columns } = await pg.query<{ column_name: string }>(
      `SELECT column_name FROM information_schema.columns
       WHERE table_schema = 'public' AND table_name = $1 AND identity_generation IS DISTINCT FROM 'ALWAYS'
         AND is_generated = 'NEVER'
       ORDER BY ordinal_position LIMIT 1`,
      [table],
    );
    const column = columns[0]?.column_name;
    if (column === undefined) {
      problems.push(`${table}: no column to rewrite`);
      continue;
    }
    await pg.transaction(async (tx) => {
      try {
        const where = final?.where === undefined ? "" : ` WHERE ${final.where}`;
        const { affectedRows } = await tx.query(`UPDATE "${table}" SET "${column}" = "${column}"${where}`);
        if (final === undefined && (affectedRows ?? 0) < rows.length) {
          problems.push(`${table}: only ${affectedRows} of ${rows.length} rows rewritten`);
        }
        if ((affectedRows ?? 0) === 0 && rows.length > 0) problems.push(`${table}: no row rewritten`);
      } catch (error) {
        problems.push(`${table}: ${error instanceof Error ? error.message : String(error)}`);
      }
      await tx.rollback();
    });
  }
  return problems;
}

/** Columns a later migration removed on purpose, with the migration and what replaced them. */
const DROPPED_COLUMNS: ReadonlyMap<string, string> = new Map([
  ["targets.verify_window_start", "0023: the attempt window moved to verify_limits"],
  ["targets.verify_attempts", "0023: the attempt count moved to verify_limits"],
]);

async function tablesOf(pg: PGlite): Promise<string[]> {
  const { rows } = await pg.query<{ table_name: string }>(
    `SELECT table_name FROM information_schema.tables
     WHERE table_schema = 'public' AND table_type = 'BASE TABLE' ORDER BY 1`,
  );
  return rows.map((row) => row.table_name);
}

async function emptyTables(pg: PGlite): Promise<string[]> {
  const empty: string[] = [];
  for (const table of await tablesOf(pg)) {
    const { rows } = await pg.query<{ n: number }>(`SELECT count(*)::int AS n FROM "${table}"`);
    if ((rows[0]?.n ?? 0) === 0) empty.push(table);
  }
  return empty;
}

describe("upgrade from every earlier schema version (slice 18h)", () => {
  let pg: PGlite;
  let ctx: EraContext;
  let step: string;
  const applied: string[] = [];

  beforeAll(async () => {
    pg = await PGlite.create();
    ctx = eraContext();
    step = mkdtempSync(join(tmpdir(), "ar-upgrade-step-"));
  });

  afterAll(async () => {
    await pg.close();
    rmSync(step, { recursive: true, force: true });
  });

  it("has a seed step only for migrations that exist", () => {
    expect(Object.keys(ERA_SEEDS).filter((file) => !FILES.includes(file))).toEqual([]);
  });

  // The tests below share one database and run in order: each applies one migration and its seed, then upgrades a
  // copy of that version to the head (the head itself is copied too: nothing is pending for it, and it is served).
  it.each(FILES)(
    "%s: applies over the data of the version before it; that version upgrades to the head",
    async (file) => {
      // 1. This migration alone, through the migrator, over a database that holds a row in every table.
      expect(await applyEra(pg, ctx, step, file)).toEqual([file]);
      applied.push(file);
      // 2. A table without a row would be a table whose upgrade is never tested.
      expect(await emptyTables(pg), `tables without a seeded row after ${file} (add them to era-seed.ts)`).toEqual([]);

      // 3. A copy of this version, upgraded by the start-up path itself: `attachDb` is what `openDb` runs on a data
      // directory — the migrator over whatever is pending, then the switch to the request role.
      const before = await snapshotTables(pg);
      expect(versionsOf(before)).toEqual(FILES.filter((f) => f <= file));
      const tenants = structuredClone({ a: ctx.a, b: ctx.b });
      const copy = await PGlite.create({ loadDataDir: await pg.dumpDataDir("none") });
      let api: TestApi | undefined;
      try {
        const db = await attachDb(copy);
        // The test owns the instance: as the owner again, to look at every table past row-level security.
        await copy.exec("RESET ROLE");
        const upgraded = await snapshotTables(copy);
        // Exactly the pending migrations were applied.
        expect(versionsOf(upgraded)).toEqual(FILES);
        // Run again, the migrator applies nothing and changes nothing.
        expect(await migrate(copy, MIGRATIONS_DIRECTORY)).toEqual([]);
        expect(await snapshotTables(copy)).toEqual(upgraded);
        expect(lostRows(before, upgraded, file)).toEqual([]);
        // Every earlier row can still be written (review L4): a constraint that old rows violate would not stop a
        // read, and would stop every later change of them.
        expect(await unwritableRows(copy, before)).toEqual([]);

        // 4. The head's own code on it, as the request role again, exactly as `attachDb` left the session.
        await copy.exec("SET ROLE ar_app");
        expect((await copy.query<{ role: string }>("SELECT current_user AS role")).rows[0]?.role).toBe("ar_app");
        api = await makeTestApi({ db });
        await expectIsolation(api, tenants.a, tenants.b, before);
        await expectServed(api, tenants.a, tenants.b, file);
      } finally {
        if (api) await api.close();
        else if (!copy.closed) await copy.close();
      }
    },
  );

  it("walked every migration", () => {
    expect(applied).toEqual(FILES);
  });
});

/** Row-level security after the upgrade: a tenant's transaction sees its own rows of every tenant table, all of them, and no other's. */
async function expectIsolation(api: TestApi, a: EraTenant, b: EraTenant, before: Snapshot): Promise<void> {
  const tenantTables = [...before.keys()].filter(
    (table) =>
      !(table in GLOBAL_TABLES) && table !== "organizations" && "organization_id" in (before.get(table)?.[0] ?? {}),
  );
  expect(tenantTables).toContain("apps");
  for (const tenant of [a, b]) {
    await api.db.tx({ organizationId: tenant.organizationId }, async (q) => {
      for (const table of tenantTables) {
        const { rows } = await q.query<{ organization_id: string }>(`SELECT organization_id FROM "${table}"`);
        const own = (before.get(table) ?? []).filter((row) => row.organization_id === tenant.organizationId).length;
        expect(new Set(rows.map((row) => row.organization_id)), table).toEqual(
          own === 0 ? new Set() : new Set([tenant.organizationId]),
        );
        expect(rows.length, table).toBeGreaterThanOrEqual(own);
      }
    });
  }
  await api.db.tx("none", async (q) => {
    for (const table of ["organizations", ...tenantTables]) {
      const { rows } = await q.query(`SELECT 1 FROM "${table}"`);
      expect(rows, `${table} without a tenant`).toEqual([]);
    }
  });
}

/** The upgraded data through the API's routes, with the keys whose hashes were seeded at 0001. */
async function expectServed(api: TestApi, a: EraTenant, b: EraTenant, prefix: string): Promise<void> {
  const get = async (path: string, key: string) => {
    const res = await api.app.request(path, { headers: bearer(key) });
    expect(res.status, `${path}: ${await res.clone().text()}`).toBe(200);
    return res.json();
  };
  // Each admin key lists its own App and not the other's.
  for (const [own, other] of [
    [a, b],
    [b, a],
  ] as const) {
    const apps = ListAppsResponseSchema.parse(await get("/v1/apps", own.adminKey)).apps.map((app) => app.id);
    expect(apps).toContain(own.appId);
    expect(apps).not.toContain(other.appId);
  }
  // The Events of 0001, read back.
  const events = ListEventsResponseSchema.parse(await get(`/v1/apps/${a.appId}/events`, a.adminKey));
  expect(events.events.map((event) => event.event_id).sort()).toEqual([...a.eventIds].sort());
  // The Shield key still authenticates, and its Policy Bundle is signed: from 0002 on it carries version 2.
  const signed = SignedBundleSchema.parse(await get("/v1/policy-bundle", a.shieldKey));
  expect(verifySignature(api.signer.publicKey, signed.bundle, signed.signature)).toBe(true);
  const bundle = BundlePayloadSchema.parse(JSON.parse(signed.bundle));
  if (prefix >= "0002") {
    expect(bundle.version).toBe(2);
    expect(bundle.rules).toEqual([expect.objectContaining({ path: "/login", mode: "enforce" })]);
  }
  // The audit chain of each tenant verifies, with every entry written before the upgrade.
  for (const tenant of [a, b]) {
    const { verify } = AuditVerifyResponseSchema.parse(await get("/v1/audit/verify", tenant.adminKey));
    expect(verify).toEqual({
      valid: true,
      entries: tenant.auditEntries,
      last_seq: tenant.auditEntries,
      first_broken_seq: null,
    });
  }
  if (prefix >= "0006") {
    const incidents = (await get("/v1/incidents", a.adminKey)) as { incidents: { id: string }[] };
    expect(incidents.incidents.map((incident) => incident.id)).toEqual([a.incidentId]);
  }
  if (prefix >= "0039") {
    const campaigns = (await get("/v1/campaigns", a.adminKey)) as { campaigns: { id: string; status: string }[] };
    expect(campaigns.campaigns).toEqual([expect.objectContaining({ id: a.campaignId, status: "completed" })]);
    expect(((await get("/v1/campaigns", b.adminKey)) as { campaigns: unknown[] }).campaigns).toEqual([]);
  }
}
