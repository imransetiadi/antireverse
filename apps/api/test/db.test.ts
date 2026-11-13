import { type ChildProcess, spawn } from "node:child_process";
import { once } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { generateKey, hashKey, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { type Db, openDb, type Queryable } from "../src/db/db.ts";

// PGlite compiles PostgreSQL on start-up: about a second on an idle machine, several under load.
vi.setConfig({ testTimeout: 30_000, hookTimeout: 30_000 });

const TENANT_SQL = "SELECT current_setting('app.tenant_id', true) AS tenant";

async function insertOrganization(db: Db, name: string): Promise<string> {
  const id = newId("org");
  await db.tx({ organizationId: id }, (q) =>
    q.query("INSERT INTO organizations (id, name) VALUES ($1, $2)", [id, name]),
  );
  return id;
}

function insertApp(q: Queryable, organizationId: string, name: string): Promise<{ rows: { id: string }[] }> {
  return q.query<{ id: string }>("INSERT INTO apps (id, organization_id, name) VALUES ($1, $2, $3) RETURNING id", [
    newId("app"),
    organizationId,
    name,
  ]);
}

describe("database and tenancy", () => {
  let db: Db;
  let orgA: string;
  let orgB: string;
  let appA: string;

  beforeAll(async () => {
    db = await openDb();
    orgA = await insertOrganization(db, "Organization A");
    orgB = await insertOrganization(db, "Organization B");
    appA = await db.tx({ organizationId: orgA }, async (q) => {
      const { rows } = await insertApp(q, orgA, "App of A");
      return rows[0]?.id ?? "";
    });
  });

  afterAll(async () => {
    await db.close();
  });

  it("has the five tables in a fresh in-memory database", async () => {
    const { rows } = await db.tx("none", (q) =>
      q.query<{ tablename: string }>("SELECT tablename FROM pg_tables WHERE schemaname = 'public'"),
    );
    expect(rows.map((row) => row.tablename)).toEqual(
      expect.arrayContaining(["organizations", "apps", "api_keys", "events", "policy_versions"]),
    );
  });

  it("runs every transaction as ar_app, whatever the scope", async () => {
    for (const scope of ["none", { organizationId: orgA }] as const) {
      const { rows } = await db.tx(scope, (q) => q.query<{ current_user: string }>("SELECT current_user"));
      expect(rows[0]?.current_user).toBe("ar_app");
    }
  });

  it("is still ar_app after a callback throws and after an SQL error", async () => {
    await expect(
      db.tx({ organizationId: orgA }, async () => {
        throw new Error("callback failed");
      }),
    ).rejects.toThrow("callback failed");
    await expect(db.tx("none", (q) => q.query("SELECT * FROM no_such_table"))).rejects.toThrow();

    const { rows } = await db.tx("none", (q) => q.query<{ current_user: string }>("SELECT current_user"));
    expect(rows[0]?.current_user).toBe("ar_app");
  });

  it("rolls back what a failed transaction wrote", async () => {
    await expect(
      db.tx({ organizationId: orgA }, async (q) => {
        await insertApp(q, orgA, "Never committed");
        throw new Error("abort");
      }),
    ).rejects.toThrow("abort");
    const { rows } = await db.tx({ organizationId: orgA }, (q) =>
      q.query("SELECT id FROM apps WHERE name = 'Never committed'"),
    );
    expect(rows).toHaveLength(0);
  });

  it("hides Organization A's App from Organization B, also when B asks for it by identifier", async () => {
    const own = await db.tx({ organizationId: orgA }, (q) => q.query("SELECT id FROM apps"));
    expect(own.rows).toEqual([{ id: appA }]);

    const all = await db.tx({ organizationId: orgB }, (q) => q.query("SELECT id FROM apps"));
    expect(all.rows).toHaveLength(0);
    const byId = await db.tx({ organizationId: orgB }, (q) => q.query("SELECT id FROM apps WHERE id = $1", [appA]));
    expect(byId.rows).toHaveLength(0);
  });

  it("rejects Organization B inserting or moving a row into Organization A", async () => {
    await expect(db.tx({ organizationId: orgB }, (q) => insertApp(q, orgA, "Planted by B"))).rejects.toThrow(
      /row-level security/,
    );
    const updated = await db.tx({ organizationId: orgB }, (q) =>
      q.query("UPDATE apps SET name = 'Renamed by B' WHERE id = $1 RETURNING id", [appA]),
    );
    expect(updated.rows).toHaveLength(0);

    const { rows } = await db.tx({ organizationId: orgA }, (q) => q.query("SELECT name FROM apps"));
    expect(rows).toEqual([{ name: "App of A" }]);
  });

  it("has one epoch, readable without a tenant and by every tenant, that the request role cannot change", async () => {
    const read = (scope: "none" | { organizationId: string }) =>
      db.tx(scope, (q) => q.query<{ epoch: string }>("SELECT epoch FROM database_epoch"));
    const none = await read("none");
    expect(none.rows).toHaveLength(1);
    expect(none.rows[0]?.epoch).toMatch(/^[0-9a-f]{32}$/);
    expect((await read({ organizationId: orgA })).rows).toEqual(none.rows);
    expect((await read({ organizationId: orgB })).rows).toEqual(none.rows);

    for (const sql of [
      "UPDATE database_epoch SET epoch = repeat('0', 32)",
      "INSERT INTO database_epoch (epoch) VALUES (repeat('1', 32))",
      "DELETE FROM database_epoch",
      "TRUNCATE database_epoch",
    ]) {
      await expect(
        db.tx("none", (q) => q.query(sql)),
        sql,
      ).rejects.toThrow(/permission denied/);
    }
    expect((await read("none")).rows).toEqual(none.rows);
  });

  it("gives every new database an epoch of its own", async () => {
    const other = await openDb();
    try {
      const mine = await db.tx("none", (q) => q.query<{ epoch: string }>("SELECT epoch FROM database_epoch"));
      const theirs = await other.tx("none", (q) => q.query<{ epoch: string }>("SELECT epoch FROM database_epoch"));
      expect(theirs.rows[0]?.epoch).toMatch(/^[0-9a-f]{32}$/);
      expect(theirs.rows[0]?.epoch).not.toBe(mine.rows[0]?.epoch);
    } finally {
      await other.close();
    }
  });

  it("does not let the request role delete rows", async () => {
    await expect(db.tx({ organizationId: orgA }, (q) => q.query("DELETE FROM apps"))).rejects.toThrow(
      /permission denied/,
    );
  });

  it("shows nothing without a tenant and resolves keys only through auth_lookup_key", async () => {
    const shield = generateKey("shield", "staging");
    const revoked = generateKey("admin");
    const shieldKeyId = newId("key");
    const revokedKeyId = newId("key");
    await db.tx({ organizationId: orgA }, async (q) => {
      await q.query(
        `INSERT INTO api_keys (id, organization_id, kind, app_id, environment, key_hash, prefix, last4)
         VALUES ($1, $2, 'shield', $3, 'staging', $4, $5, $6)`,
        [shieldKeyId, orgA, appA, hashKey(shield.key), shield.prefix, shield.last4],
      );
      await q.query(
        `INSERT INTO api_keys (id, organization_id, kind, key_hash, prefix, last4, revoked_at)
         VALUES ($1, $2, 'admin', $3, $4, $5, now())`,
        [revokedKeyId, orgA, hashKey(revoked.key), revoked.prefix, revoked.last4],
      );
    });

    const seen = await db.tx("none", async (q) => ({
      organizations: (await q.query("SELECT id FROM organizations")).rows,
      apps: (await q.query("SELECT id FROM apps")).rows,
      keys: (await q.query("SELECT id FROM api_keys")).rows,
      events: (await q.query("SELECT event_id FROM events")).rows,
      lookup: (await q.query("SELECT * FROM auth_lookup_key($1)", [hashKey(shield.key)])).rows,
      revoked: (await q.query("SELECT * FROM auth_lookup_key($1)", [hashKey(revoked.key)])).rows,
      unknown: (await q.query("SELECT * FROM auth_lookup_key($1)", [hashKey(generateKey("admin").key)])).rows,
    }));

    expect(seen.organizations).toHaveLength(0);
    expect(seen.apps).toHaveLength(0);
    expect(seen.keys).toHaveLength(0);
    expect(seen.events).toHaveLength(0);
    expect(seen.lookup).toEqual([
      { key_id: shieldKeyId, organization_id: orgA, kind: "shield", app_id: appA, environment: "staging" },
    ]);
    expect(seen.revoked).toHaveLength(0);
    expect(seen.unknown).toHaveLength(0);
  });

  it("gives 20 concurrent transactions of 20 Organizations their own tenant", async () => {
    const organizations = Array.from({ length: 20 }, () => newId("org"));
    const seen = await Promise.all(
      organizations.map((organizationId) =>
        db.tx({ organizationId }, async (q) => {
          const first = await q.query<{ tenant: string }>(TENANT_SQL);
          const second = await q.query<{ tenant: string }>(TENANT_SQL);
          return [first.rows[0]?.tenant, second.rows[0]?.tenant];
        }),
      ),
    );
    expect(seen).toEqual(organizations.map((organizationId) => [organizationId, organizationId]));
  });

  it("leaves no tenant behind after a transaction resolves or rejects", async () => {
    const readTenant = () =>
      db.tx("none", async (q) => (await q.query<{ tenant: string }>(TENANT_SQL)).rows[0]?.tenant);

    await db.tx({ organizationId: orgA }, (q) => q.query("SELECT 1"));
    expect(await readTenant()).toBe("");

    await expect(
      db.tx({ organizationId: orgB }, async () => {
        throw new Error("rejected");
      }),
    ).rejects.toThrow("rejected");
    expect(await readTenant()).toBe("");
  });
});

describe("data directory", () => {
  const root = mkdtempSync(join(tmpdir(), "ar-api-db-"));
  const children: ChildProcess[] = [];

  afterAll(() => {
    for (const child of children) child.kill("SIGKILL");
    rmSync(root, { recursive: true, force: true });
  });

  it("owns the data directory while open, and opening it again applies migrations once and keeps the data", async () => {
    const dataDir = join(root, "twice", "pg");
    const lockFile = `${dataDir}.lock`;

    const first = await openDb({ dataDir });
    let organizationId: string;
    try {
      // The pid lock sits beside the directory; a second open is refused before it can touch the files.
      expect(readFileSync(lockFile, "utf8").trim()).toBe(String(process.pid));
      await expect(openDb({ dataDir })).rejects.toThrow(/in use by process/);
      organizationId = await insertOrganization(first, "Persisted");
    } finally {
      await first.close();
    }
    expect(existsSync(lockFile)).toBe(false);

    const second = await openDb({ dataDir });
    try {
      const organization = await second.tx({ organizationId }, (q) => q.query("SELECT name FROM organizations"));
      expect(organization.rows).toEqual([{ name: "Persisted" }]);
      const applied = await second.tx("none", (q) => q.query("SELECT version FROM schema_migrations ORDER BY version"));
      expect(applied.rows).toEqual([
        { version: "0001_init.sql" },
        { version: "0002_policies.sql" },
        { version: "0003_epoch.sql" },
        { version: "0004_builds.sql" },
        { version: "0005_apps_seq.sql" },
        { version: "0006_incidents.sql" },
        { version: "0007_canaries.sql" },
        { version: "0008_containment.sql" },
        { version: "0009_containment_final.sql" },
        { version: "0010_beacon.sql" },
        { version: "0011_beacon_per_app.sql" },
        { version: "0012_attestation.sql" },
        { version: "0013_incident_advisory.sql" },
        { version: "0014_exposure.sql" },
        { version: "0015_finding_withdrawn.sql" },
        { version: "0016_exposure_review.sql" },
        { version: "0017_exposure_review2.sql" },
        { version: "0018_patches.sql" },
        { version: "0019_credential_stuffing.sql" },
        { version: "0020_simulation_index.sql" },
        { version: "0021_prove.sql" },
        { version: "0022_prove_recheck.sql" },
        { version: "0023_prove_review.sql" },
        { version: "0024_email_alerts.sql" },
        { version: "0025_email_caps.sql" },
        { version: "0026_assessments.sql" },
        { version: "0027_assessment_calls.sql" },
        { version: "0028_artifact_expiry_lock.sql" },
        { version: "0029_build_logic.sql" },
        { version: "0030_setup_index.sql" },
        { version: "0031_audit.sql" },
        { version: "0032_audit_chain_trigger.sql" },
        { version: "0033_data_controls.sql" },
        { version: "0034_data_controls_review.sql" },
      ]);
    } finally {
      await second.close();
    }
  });

  it("refuses a data directory another live process holds, and replaces the lock once that process is dead", async () => {
    const dataDir = join(root, "contended", "pg");
    const lockFile = `${dataDir}.lock`;
    const holder = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"], { stdio: "ignore" });
    children.push(holder);
    await once(holder, "spawn");
    mkdirSync(join(root, "contended"), { recursive: true });
    writeFileSync(lockFile, `${holder.pid}\n`);

    await expect(openDb({ dataDir })).rejects.toThrow(new RegExp(`in use by process ${holder.pid}`));
    expect(readFileSync(lockFile, "utf8").trim()).toBe(String(holder.pid));

    holder.kill("SIGKILL");
    await once(holder, "exit");

    const db = await openDb({ dataDir });
    try {
      expect(readFileSync(lockFile, "utf8").trim()).toBe(String(process.pid));
    } finally {
      await db.close();
    }
  });
});
