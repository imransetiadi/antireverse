import { copyFileSync, mkdtempSync, readdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { PGlite } from "@electric-sql/pglite";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RETENTION_CLASSES } from "../src/data/retention.ts";
import { migrate } from "../src/db/migrate.ts";
import { tenantTables } from "./data-seed.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 18c: migration 0035 (the Event retention setting, the run record), who may run the sweep, and the catalog
// classification of every tenant table as swept or kept.

const MIGRATIONS = fileURLToPath(new URL("../migrations", import.meta.url));
const RETENTION_MIGRATION = "0035_retention.sql";

describe("migration 0035", () => {
  it("sets Organizations that exist at release to 395 days, new ones to 30, and refuses any other value", async () => {
    const before = mkdtempSync(join(tmpdir(), "ar-mig-"));
    const pg = await PGlite.create();
    try {
      const files = readdirSync(MIGRATIONS).filter((f) => f.endsWith(".sql"));
      expect(files).toContain(RETENTION_MIGRATION);
      for (const file of files.filter((f) => f < RETENTION_MIGRATION))
        copyFileSync(join(MIGRATIONS, file), join(before, file));
      await migrate(pg, before);
      await pg.query("INSERT INTO organizations (id, name) VALUES ('org_000000000000000000000001', 'Old')");
      await pg.query(
        "INSERT INTO apps (id, organization_id, name) VALUES ('app_000000000000000000000001', 'org_000000000000000000000001', 'Shop')",
      );
      for (const [at, status] of [
        ["2026-01-02T00:00:00Z", "missing"],
        ["2026-01-03T00:00:00Z", "valid"],
        ["2026-01-04T00:00:00Z", "valid"],
      ]) {
        await pg.query(
          `INSERT INTO events (organization_id, event_id, app_id, environment, ts, received_at, type, payload)
           VALUES ('org_000000000000000000000001', gen_random_uuid(), 'app_000000000000000000000001', 'staging', $1, $1,
             'request.decision', jsonb_build_object('attestation', jsonb_build_object('status', $2::text)))`,
          [at, status],
        );
      }
      expect(await migrate(pg, MIGRATIONS)).toEqual(files.filter((f) => f >= RETENTION_MIGRATION));
      // The set-up record is backfilled from the Events there are.
      const milestones = await pg.query<Record<string, unknown>>(
        "SELECT organization_id, app_id, environment, shield_first_at, guard_first_at FROM setup_milestones",
      );
      expect(milestones.rows).toEqual([
        {
          organization_id: "org_000000000000000000000001",
          app_id: "app_000000000000000000000001",
          environment: "staging",
          shield_first_at: new Date("2026-01-02T00:00:00Z"),
          guard_first_at: new Date("2026-01-03T00:00:00Z"),
        },
      ]);
      await pg.query("INSERT INTO organizations (id, name) VALUES ('org_000000000000000000000002', 'New')");
      const { rows } = await pg.query<{ id: string; event_retention_days: number }>(
        "SELECT id, event_retention_days FROM organizations ORDER BY id",
      );
      expect(rows).toEqual([
        { id: "org_000000000000000000000001", event_retention_days: 395 },
        { id: "org_000000000000000000000002", event_retention_days: 30 },
      ]);
      for (const days of [7, 30, 90, 180, 395]) {
        await pg.query("UPDATE organizations SET event_retention_days = $1 WHERE id = 'org_000000000000000000000002'", [
          days,
        ]);
      }
      for (const days of [0, 14, 365, 396]) {
        await expect(
          pg.query("UPDATE organizations SET event_retention_days = $1 WHERE id = 'org_000000000000000000000002'", [
            days,
          ]),
        ).rejects.toMatchObject({ code: "23514" });
      }
    } finally {
      await pg.close();
      rmSync(before, { recursive: true, force: true });
    }
  });
});

describe("retention privileges", () => {
  let api: TestApi;
  let a = "";
  let b = "";
  beforeAll(async () => {
    api = await makeTestApi();
    a = (await createOrganization(api, "Acme")).organization.id;
    b = (await createOrganization(api, "Bravo")).organization.id;
    await api.db.owner((q) =>
      q.query(
        "INSERT INTO retention_runs (organization_id, ran_at, complete, counts) VALUES ($1, now(), true, '{}'), ($2, now(), true, '{}')",
        [a, b],
      ),
    );
  });
  afterAll(async () => {
    await api.close();
  });

  it("the request role cannot run the sweep, with or without a tenant", async () => {
    for (const scope of [{ organizationId: a }, "none" as const]) {
      await expect(api.db.tx(scope, (q) => q.query("SELECT retention_sweep(now(), 100)"))).rejects.toMatchObject({
        code: "42501",
      });
    }
  });

  it("the request role changes the setting of its own Organization only", async () => {
    const changed = await api.db.tx({ organizationId: a }, async (q) => {
      await q.query("UPDATE organizations SET event_retention_days = 7 WHERE id = $1", [b]);
      await q.query("UPDATE organizations SET event_retention_days = 90 WHERE id = $1", [a]);
      return true;
    });
    expect(changed).toBe(true);
    const days = await api.db.owner(async (q) => {
      const { rows } = await q.query<{ id: string; event_retention_days: number }>(
        "SELECT id, event_retention_days FROM organizations WHERE id = ANY($1) ORDER BY id",
        [[a, b]],
      );
      return Object.fromEntries(rows.map((row) => [row.id, row.event_retention_days]));
    });
    expect(days).toEqual({ [a]: 90, [b]: 30 });
  });

  it("the request role reads its own runs and set-up record and cannot write either", async () => {
    const seen = await api.db.tx({ organizationId: a }, async (q) => {
      const { rows } = await q.query<{ organization_id: string }>("SELECT organization_id FROM retention_runs");
      return rows.map((row) => row.organization_id);
    });
    expect(seen).toEqual([a]);
    expect(
      await api.db.tx({ organizationId: a }, async (q) => (await q.query("SELECT * FROM setup_milestones")).rows),
    ).toEqual([]);
    for (const sql of [
      "INSERT INTO retention_runs (organization_id, ran_at, complete, counts) VALUES ($1, now(), true, '{}')",
      "UPDATE retention_runs SET counts = '{}' WHERE organization_id = $1",
      "DELETE FROM retention_runs WHERE organization_id = $1",
      "INSERT INTO setup_milestones (organization_id, app_id, environment) VALUES ($1, 'app_x', 'staging')",
      "UPDATE setup_milestones SET shield_first_at = now() WHERE organization_id = $1",
      "DELETE FROM setup_milestones WHERE organization_id = $1",
    ]) {
      await expect(api.db.tx({ organizationId: a }, (q) => q.query(sql, [a]))).rejects.toMatchObject({
        code: "42501",
      });
    }
  });

  it("classifies every tenant table of the catalog as swept (with its rule) or kept (with its reason)", async () => {
    const tables = await tenantTables(api);
    expect(tables.length).toBeGreaterThan(25);
    expect(tables.filter((table) => !(table in RETENTION_CLASSES))).toEqual([]);
    // No stale names.
    expect(Object.keys(RETENTION_CLASSES).filter((table) => !tables.includes(table))).toEqual([]);
    for (const [table, kind] of Object.entries(RETENTION_CLASSES)) {
      const text = "rule" in kind ? kind.rule : kind.reason;
      expect(text.length, table).toBeGreaterThan(10);
    }
    for (const swept of ["events", "containments", "incidents", "detections", "alert_deliveries", "assessments"]) {
      expect(RETENTION_CLASSES[swept], swept).toHaveProperty("rule");
    }
    for (const kept of ["builds", "audit_entries", "audit_heads"]) {
      expect(RETENTION_CLASSES[kept], kept).toHaveProperty("reason");
    }
  });

  it("fails the classification for a new tenant table", async () => {
    const other = await makeTestApi();
    try {
      await other.db.owner((q) => q.query("CREATE TABLE app_notes (organization_id text NOT NULL, note text)"));
      expect((await tenantTables(other)).filter((table) => !(table in RETENTION_CLASSES))).toEqual(["app_notes"]);
    } finally {
      await other.close();
    }
  });
});
