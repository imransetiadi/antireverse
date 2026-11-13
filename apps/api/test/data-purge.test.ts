import { AuditVerifyResponseSchema } from "@antireverse/protocol";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createPurgeJob } from "../src/data/purge.ts";
import { DELETION_TABLE } from "../src/stores/deletions.ts";
import {
  GLOBAL_TABLES,
  makeDataApi,
  requestDeletion,
  rowsOf,
  type Seeded,
  seedOrganization,
  tablesWithoutOrganization,
  tablesWithoutRows,
  tenantTables,
} from "./data-seed.ts";
import { bearer, captureLogger, expectNoKeyLogged, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 18b, TC-CON-007: the purge leaves no row of the Organization in any table that has an `organization_id`
// column — taken from the catalog, so a table added later is covered without touching this test (but must be
// seeded in data-seed.ts, or the first test fails). The only exception is the deletion's own tombstone.

const T0 = Date.parse("2026-11-13T09:00:00.000Z");
const DAY = 86_400_000;

describe("organization purge (catalog-wide)", () => {
  let api: TestApi & { auditSigner: import("../src/signer.ts").Signer };
  const clock = { ms: T0 };
  const now = () => new Date(clock.ms);
  let a: Seeded;
  let b: Seeded;
  let tables: string[];
  let before: Record<string, number>;
  let deletionId: string;

  beforeAll(async () => {
    api = await makeDataApi(now);
    a = await seedOrganization(api, "Acme", { now });
    b = await seedOrganization(api, "Bravo", { now });
    tables = (await tenantTables(api)).filter((table) => table !== DELETION_TABLE);
  });
  afterAll(async () => {
    expectNoKeyLogged(api);
    await api.close();
  });

  it("has an organization_id column in every table of the schema but the named global ones", async () => {
    expect(await tablesWithoutOrganization(api)).toEqual([]);
    // Every global table named exists: no stale names.
    const all = await api.db.owner(async (q) => {
      const { rows } = await q.query<{ table_name: string }>(
        "SELECT table_name FROM information_schema.tables WHERE table_schema = 'public' AND table_type = 'BASE TABLE'",
      );
      return rows.map((row) => row.table_name);
    });
    expect(Object.keys(GLOBAL_TABLES).filter((table) => !all.includes(table))).toEqual([]);
  });

  it("the seed gives both Organizations rows in every tenant table of the catalog", async () => {
    expect(tables.length).toBeGreaterThan(25);
    expect((await tablesWithoutRows(api, a.organizationId)).filter((t) => t !== DELETION_TABLE)).toEqual([]);
    expect((await tablesWithoutRows(api, b.organizationId)).filter((t) => t !== DELETION_TABLE)).toEqual([]);
    before = await rowsOf(api, b.organizationId, [...tables, "organizations"]);
  });

  it("the request role can neither run the purge nor delete audit rows, whatever it sets", async () => {
    const scope = { organizationId: a.organizationId };
    await expect(
      api.db.tx(scope, (q) => q.query("SELECT organization_purge($1, $2)", [a.organizationId, now()])),
    ).rejects.toMatchObject({ code: "42501" });
    await expect(
      api.db.tx("none", (q) => q.query("SELECT organization_purge($1, $2)", [a.organizationId, now()])),
    ).rejects.toMatchObject({ code: "42501" });
    for (const sql of [
      "DELETE FROM audit_entries",
      "DELETE FROM audit_heads",
      "UPDATE audit_entries SET summary = 'x'",
    ]) {
      await expect(
        api.db.tx(scope, async (q) => {
          await q.query("SELECT set_config('airverse.purge_organization', $1, true)", [a.organizationId]);
          await q.query(sql);
        }),
      ).rejects.toMatchObject({ code: "42501" });
    }
    // The tombstones are the owner's: the request role reads them only through its definer functions.
    await expect(api.db.tx(scope, (q) => q.query(`SELECT * FROM ${DELETION_TABLE}`))).rejects.toMatchObject({
      code: "42501",
    });
    await expect(
      api.db.tx(scope, (q) => q.query(`INSERT INTO ${DELETION_TABLE} (id) VALUES ('del_0')`)),
    ).rejects.toMatchObject({ code: "42501" });
  });

  it("purges every row of the Organization in every tenant table, the audit chain included", async () => {
    deletionId = await requestDeletion(api, a);
    const logger = captureLogger();
    const job = createPurgeJob({ db: api.db, signer: api.auditSigner, now, logger });
    clock.ms += 7 * DAY + 1;
    expect(await job.runOnce()).toMatchObject({ due: 1, purged: 1, failed: 0 });
    const left = await rowsOf(api, a.organizationId, [...tables, "organizations"]);
    expect(Object.entries(left).filter(([, n]) => n !== 0)).toEqual([]);
    // Nothing of it remains in the tombstone but identifiers, times and the report.
    const tombstone = await api.db.owner(async (q) => {
      const { rows } = await q.query<Record<string, unknown>>(`SELECT * FROM ${DELETION_TABLE} WHERE id = $1`, [
        deletionId,
      ]);
      return rows[0];
    });
    expect(tombstone).toMatchObject({ organization_name: null, reason: null, organization_id: a.organizationId });
    expect(tombstone?.purged_at).toBeInstanceOf(Date);
    expect(logger.lines.join("\n")).not.toContain("Acme");
  });

  it("leaves the other Organization untouched, its audit chain valid", async () => {
    expect(await rowsOf(api, b.organizationId, [...tables, "organizations"])).toEqual(before);
    const res = await api.app.request("/v1/audit/verify", { headers: bearer(b.admin) });
    expect(res.status).toBe(200);
    expect(AuditVerifyResponseSchema.parse(await res.json()).verify.valid).toBe(true);
  });

  it("refuses the purged Organization's keys as unknown", async () => {
    expect((await api.app.request("/v1/organization", { headers: bearer(a.admin) })).status).toBe(401);
    expect((await api.app.request("/v1/policy-bundle", { headers: bearer(a.shield) })).status).toBe(401);
  });
});

describe("catalog blind spot", () => {
  it("names a new table keyed only by an App, so that it cannot be missed by the purge", async () => {
    const api = await makeTestApi();
    try {
      await api.db.owner((q) => q.query("CREATE TABLE app_notes (app_id text NOT NULL, note text NOT NULL)"));
      expect(await tablesWithoutOrganization(api)).toEqual(["app_notes"]);
    } finally {
      await api.close();
    }
  });
});
