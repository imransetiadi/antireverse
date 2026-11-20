import { hashKey } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { provisionProbeTenant } from "../src/probe/tenant.ts";
import { findActiveKey } from "../src/stores/keys.ts";
import { readSystemOrganization } from "../src/stores/system-organizations.ts";
import { GLOBAL_TABLES } from "./data-seed.ts";
import { createOrganization, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 18g: the probe's own Organization. One, registered in the owner-only table `system_organizations`; found again
// at every start, with fresh keys whose plaintext is only ever returned (never stored), the old ones revoked.

const NOW = new Date("2026-11-20T08:00:00.000Z");

describe("the probe's system Organization", () => {
  let api: TestApi;
  beforeAll(async () => {
    api = await makeTestApi();
  });
  afterAll(async () => {
    await api.close();
  });

  const count = async (sql: string, params: unknown[] = []): Promise<number> =>
    api.db.owner(async (q) => Number((await q.query<{ n: number }>(sql, params)).rows[0]?.n));
  const active = (key: string) => api.db.tx("none", (q) => findActiveKey(q, hashKey(key)));

  it("has no registered Organization before the first provisioning, and the registry is an operator table", async () => {
    expect(await api.db.owner((q) => readSystemOrganization(q, "probe"))).toBeNull();
    expect(GLOBAL_TABLES.system_organizations).toMatch(/probe/);
    // The request role cannot read or write the registry, whatever tenant it sets.
    for (const sql of [
      "SELECT * FROM system_organizations",
      "INSERT INTO system_organizations (kind, org_id, app_id, created_at) VALUES ('probe', 'org_000000000000000000000000', 'app_000000000000000000000000', now())",
      "DELETE FROM system_organizations",
    ]) {
      await expect(api.db.tx("none", (q) => q.query(sql))).rejects.toMatchObject({ code: "42501" });
    }
  });

  it("creates one Organization and App with working keys, 7-day Event retention and system audit entries", async () => {
    const tenant = await provisionProbeTenant({ db: api.db, now: () => NOW });
    expect(tenant.organizationId).toMatch(/^org_[0-9a-f]{24}$/);
    expect(tenant.appId).toMatch(/^app_[0-9a-f]{24}$/);
    expect(await api.db.owner((q) => readSystemOrganization(q, "probe"))).toEqual({
      organizationId: tenant.organizationId,
      appId: tenant.appId,
    });
    expect(await active(tenant.adminKey)).toMatchObject({ kind: "admin", organizationId: tenant.organizationId });
    expect(await active(tenant.shieldKey)).toMatchObject({
      kind: "shield",
      organizationId: tenant.organizationId,
      appId: tenant.appId,
      environment: "production",
    });
    expect(
      await count("SELECT event_retention_days AS n FROM organizations WHERE id = $1", [tenant.organizationId]),
    ).toBe(7);
    const { rows } = await api.db.owner((q) =>
      q.query<{ action: string; actor_kind: string }>(
        "SELECT action, actor_kind FROM audit_entries WHERE organization_id = $1 ORDER BY seq",
        [tenant.organizationId],
      ),
    );
    expect(rows).toEqual([
      { action: "organization.create", actor_kind: "system" },
      { action: "app.create", actor_kind: "system" },
    ]);
    // The keys are stored as hashes only.
    const stored = await api.db.owner((q) =>
      q.query("SELECT * FROM api_keys WHERE organization_id = $1", [tenant.organizationId]),
    );
    const text = JSON.stringify(stored.rows);
    expect(text).not.toContain(tenant.adminKey);
    expect(text).not.toContain(tenant.shieldKey);
  });

  it("finds the same Organization at the next start, removes the old keys and adds no Organization, App or audit entry", async () => {
    const first = await api.db.owner((q) => readSystemOrganization(q, "probe"));
    const before = await provisionProbeTenant({ db: api.db, now: () => NOW });
    const organizations = await count("SELECT count(*)::int AS n FROM organizations");
    const entries = await count("SELECT count(*)::int AS n FROM audit_entries");
    const again = await provisionProbeTenant({ db: api.db, now: () => new Date(NOW.getTime() + 60_000) });
    expect({ organizationId: again.organizationId, appId: again.appId }).toEqual(first);
    expect(again.adminKey).not.toBe(before.adminKey);
    expect(again.shieldKey).not.toBe(before.shieldKey);
    expect(await active(before.adminKey)).toBeNull();
    expect(await active(before.shieldKey)).toBeNull();
    expect(await active(again.adminKey)).not.toBeNull();
    expect(await active(again.shieldKey)).not.toBeNull();
    expect(await count("SELECT count(*)::int AS n FROM organizations")).toBe(organizations);
    expect(await count("SELECT count(*)::int AS n FROM apps")).toBe(1);
    expect(await count("SELECT count(*)::int AS n FROM audit_entries")).toBe(entries);
    expect(await count("SELECT count(*)::int AS n FROM system_organizations")).toBe(1);
    expect(
      await count("SELECT count(*)::int AS n FROM api_keys WHERE organization_id = $1", [again.organizationId]),
    ).toBe(2);
  });

  it("revokes only its own keys: a tenant's keys stay valid across the probe's provisioning", async () => {
    const acme = await createOrganization(api);
    expect(await active(acme.admin_key.key)).not.toBeNull();
    await provisionProbeTenant({ db: api.db, now: () => new Date(NOW.getTime() + 120_000) });
    expect(await active(acme.admin_key.key)).toMatchObject({ organizationId: acme.organization.id });
    expect(
      await count("SELECT count(*)::int AS n FROM api_keys WHERE organization_id = $1 AND revoked_at IS NOT NULL", [
        acme.organization.id,
      ]),
    ).toBe(0);
  });

  it("completes a provisioning that stopped after the registry row was written", async () => {
    const other = await makeTestApi();
    try {
      await other.db.owner((q) =>
        q.query(
          "INSERT INTO system_organizations (kind, org_id, app_id, created_at) VALUES ('probe', 'org_0123456789abcdef01234567', 'app_0123456789abcdef01234567', $1)",
          [NOW.toISOString()],
        ),
      );
      const tenant = await provisionProbeTenant({ db: other.db, now: () => NOW });
      expect(tenant.organizationId).toBe("org_0123456789abcdef01234567");
      expect(tenant.appId).toBe("app_0123456789abcdef01234567");
      const n = await other.db.owner(async (q) => (await q.query("SELECT id FROM organizations")).rows.length);
      expect(n).toBe(1);
    } finally {
      await other.close();
    }
  });
});
