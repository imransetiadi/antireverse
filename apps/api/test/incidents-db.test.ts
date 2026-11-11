import { generateSigningSecret, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { type Db, openDb } from "../src/db/db.ts";

// Opening the database runs every migration; under a busy machine that can pass the default 10 s hook
// timeout, so this file uses the same limits as the other API tests (test/helpers.ts, test/db.test.ts).
vi.setConfig({ testTimeout: 30_000, hookTimeout: 30_000 });

// The tables of slice 06 at the SQL level: tenant isolation by row-level security, and what the request role
// may change. Routes and stores have their own tests.

const T = "2026-11-10T12:00:00.000Z";

describe("detection tables", () => {
  let db: Db;
  let orgA: string;
  let orgB: string;
  let appA: string;
  let incidentA: string;
  let channelA: string;

  async function organization(name: string): Promise<string> {
    const id = newId("org");
    await db.tx({ organizationId: id }, (q) =>
      q.query("INSERT INTO organizations (id, name) VALUES ($1, $2)", [id, name]),
    );
    return id;
  }

  beforeAll(async () => {
    db = await openDb();
    orgA = await organization("A");
    orgB = await organization("B");
    appA = newId("app");
    incidentA = newId("inc");
    channelA = newId("chn");
    await db.tx({ organizationId: orgA }, async (q) => {
      await q.query("INSERT INTO apps (id, organization_id, name) VALUES ($1, $2, 'App')", [appA, orgA]);
      await q.query(
        `INSERT INTO incidents (id, organization_id, app_id, environment, rule, severity, title, status, ip_prefix,
           first_seen, last_seen, detection_count, created_at, updated_at)
         VALUES ($1, $2, $3, 'development', 'blocked-burst', 'high', 'Blocked burst', 'open', '203.0.113.0/24',
           $4, $4, 1, $4, $4)`,
        [incidentA, orgA, appA, T],
      );
      await q.query(
        `INSERT INTO detections (id, organization_id, incident_id, app_id, environment, rule, ip_prefix, count,
           window_start, window_end, detected_at)
         VALUES ($1, $2, $3, $4, 'development', 'blocked-burst', '203.0.113.0/24', 20, $5, $5, $5)`,
        [newId("dtc"), orgA, incidentA, appA, T],
      );
      await q.query(
        `INSERT INTO alert_channels (id, organization_id, kind, name, url, signing_secret, created_at)
         VALUES ($1, $2, 'webhook', 'Hook', 'https://hooks.example.com/x', $3, $4)`,
        [channelA, orgA, generateSigningSecret(), T],
      );
      await q.query(
        `INSERT INTO alert_deliveries (id, organization_id, channel_id, incident_id, attempt, outcome, status_code, at)
         VALUES ($1, $2, $3, $4, 1, 'delivered', 200, $5)`,
        [newId("dlv"), orgA, channelA, incidentA, T],
      );
    });
  });
  afterAll(async () => {
    await db.close();
  });

  const TABLES = ["incidents", "detections", "alert_channels", "alert_deliveries"];

  it("shows each table's rows to their own Organization only, and none without a tenant", async () => {
    for (const table of TABLES) {
      const own = await db.tx({ organizationId: orgA }, (q) => q.query(`SELECT 1 FROM ${table}`));
      expect(own.rows, table).toHaveLength(1);
      const other = await db.tx({ organizationId: orgB }, (q) => q.query(`SELECT 1 FROM ${table}`));
      expect(other.rows, table).toHaveLength(0);
      const none = await db.tx("none", (q) => q.query(`SELECT 1 FROM ${table}`));
      expect(none.rows, table).toHaveLength(0);
    }
  });

  it("refuses a row planted into another Organization", async () => {
    await expect(
      db.tx({ organizationId: orgB }, (q) =>
        q.query(
          `INSERT INTO alert_channels (id, organization_id, kind, name, url, created_at)
           VALUES ($1, $2, 'slack', 'Planted', 'https://hooks.example.com/y', $3)`,
          [newId("chn"), orgA, T],
        ),
      ),
    ).rejects.toThrow(/row-level security/);
  });

  it("lets the request role change an Incident's status and counters, nothing else, and delete no Incident", async () => {
    const updated = await db.tx({ organizationId: orgA }, (q) =>
      q.query(
        "UPDATE incidents SET status = 'acknowledged', detection_count = 2, updated_at = $2 WHERE id = $1 RETURNING id",
        [incidentA, T],
      ),
    );
    expect(updated.rows).toHaveLength(1);
    await expect(
      db.tx({ organizationId: orgA }, (q) =>
        q.query("UPDATE incidents SET rule = 'failed-signin-burst' WHERE id = $1", [incidentA]),
      ),
    ).rejects.toThrow(/permission denied/);
    await expect(
      db.tx({ organizationId: orgA }, (q) => q.query("DELETE FROM incidents WHERE id = $1", [incidentA])),
    ).rejects.toThrow(/permission denied/);
  });

  it.each(["detections", "alert_deliveries"])("keeps %s append-only", async (table) => {
    await expect(db.tx({ organizationId: orgA }, (q) => q.query(`UPDATE ${table} SET id = id`))).rejects.toThrow(
      /permission denied/,
    );
    await expect(db.tx({ organizationId: orgA }, (q) => q.query(`DELETE FROM ${table}`))).rejects.toThrow(
      /permission denied/,
    );
  });

  it("lets the request role delete a channel but not change it; its delivery records stay", async () => {
    await expect(
      db.tx({ organizationId: orgA }, (q) =>
        q.query("UPDATE alert_channels SET url = 'https://evil.example' WHERE id = $1", [channelA]),
      ),
    ).rejects.toThrow(/permission denied/);
    const other = await db.tx({ organizationId: orgB }, (q) =>
      q.query("DELETE FROM alert_channels WHERE id = $1 RETURNING id", [channelA]),
    );
    expect(other.rows).toHaveLength(0);
    const own = await db.tx({ organizationId: orgA }, (q) =>
      q.query("DELETE FROM alert_channels WHERE id = $1 RETURNING id", [channelA]),
    );
    expect(own.rows).toHaveLength(1);
    const deliveries = await db.tx({ organizationId: orgA }, (q) => q.query("SELECT 1 FROM alert_deliveries"));
    expect(deliveries.rows).toHaveLength(1);
  });

  it("allows one open or acknowledged Incident per group, and any number of resolved ones", async () => {
    const insert = (status: string) =>
      db.tx({ organizationId: orgA }, (q) =>
        q.query(
          `INSERT INTO incidents (id, organization_id, app_id, environment, rule, severity, title, status, ip_prefix,
             first_seen, last_seen, detection_count, created_at, updated_at)
           VALUES ($1, $2, $3, 'development', 'blocked-burst', 'high', 'Blocked burst', $4, '203.0.113.0/24',
             $5, $5, 1, $5, $5)`,
          [newId("inc"), orgA, appA, status, T],
        ),
      );
    // incidentA is acknowledged now: a second active Incident of the same group is refused.
    await expect(insert("open")).rejects.toThrow(/duplicate key/);
    await insert("resolved");
    await insert("resolved");
  });
});
