import {
  AppResponseSchema,
  CreateAppResponseSchema,
  ListAppsResponseSchema,
  SHIELD_KEY_PATTERN,
} from "@antireverse/protocol";
import { hashKey, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  bearer,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  type TestApi,
} from "./helpers.ts";

describe("Apps", () => {
  let api: TestApi;
  let adminA: string;
  let adminB: string;
  let organizationA: string;

  beforeAll(async () => {
    api = await makeTestApi();
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    adminA = a.admin_key.key;
    adminB = b.admin_key.key;
    organizationA = a.organization.id;
  });
  afterAll(async () => {
    await api.close();
  });

  it("creates an App whose Shield key is for development by default", async () => {
    const res = await api.app.request("/v1/apps", json({ name: " Storefront " }, bearer(adminA)));
    expect(res.status).toBe(201);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const created = CreateAppResponseSchema.parse(await res.json());
    api.issuedKeys.push(created.shield_key.key);

    expect(created.app.name).toBe("Storefront");
    expect(created.shield_key.key).toMatch(SHIELD_KEY_PATTERN);
    expect(created.shield_key.key.startsWith("ark_dev_")).toBe(true);
    expect(created.shield_key.environment).toBe("development");
    expect(created.shield_key.prefix).toBe(created.shield_key.key.slice(0, 14));
    expect(created.shield_key.last4).toBe(created.shield_key.key.slice(-4));
  });

  it.each([
    ["production", "ark_prod_"],
    ["staging", "ark_stg_"],
    ["development", "ark_dev_"],
  ] as const)("issues a Shield key for %s starting %s", async (environment, scheme) => {
    const created = await createAppFor(api, adminA, { name: `App for ${environment}`, environment });
    expect(created.shield_key.key.startsWith(scheme)).toBe(true);
    expect(created.shield_key.environment).toBe(environment);
  });

  it("stores the hash of the Shield key with its App and Environment, and never the key", async () => {
    const created = await createAppFor(api, adminA, { name: "Hashed", environment: "staging" });

    const { rows } = await api.db.tx({ organizationId: organizationA }, (q) =>
      q.query<Record<string, unknown>>("SELECT * FROM api_keys WHERE app_id = $1", [created.app.id]),
    );
    expect(rows).toHaveLength(1);
    expect(rows[0]).toMatchObject({
      organization_id: organizationA,
      kind: "shield",
      app_id: created.app.id,
      environment: "staging",
      key_hash: hashKey(created.shield_key.key),
      prefix: created.shield_key.prefix,
      last4: created.shield_key.last4,
    });
    expect(JSON.stringify(rows)).not.toContain(created.shield_key.key.slice(-43));
  });

  it.each([
    ["an unknown Environment", { name: "Storefront", environment: "qa" }, "environment"],
    ["an empty name", { name: "" }, "name"],
    ["a name of 81 characters", { name: "n".repeat(81) }, "name"],
    ["a name with CR/LF", { name: "Shop\r\nBcc: x@y.z" }, "name"],
    ["a name with a Unicode line separator", { name: "Shop\u2028X" }, "name"],
    ["a name with a zero-width character", { name: "Shop\u200b" }, "name"],
  ])("refuses %s", async (_label, body, path) => {
    const problem = await expectProblem(await api.app.request("/v1/apps", json(body, bearer(adminA))), 400);
    expect(problem.errors?.[0]?.path).toBe(path);
  });

  it("lists only the caller's Apps, newest first", async () => {
    const fresh = await createOrganization(api, "Lists");
    const first = await createAppFor(api, fresh.admin_key.key, { name: "First" });
    const second = await createAppFor(api, fresh.admin_key.key, { name: "Second" });
    const third = await createAppFor(api, fresh.admin_key.key, { name: "Third" });
    const foreign = await createAppFor(api, adminB, { name: "Of B" });

    const res = await api.app.request("/v1/apps", { headers: bearer(fresh.admin_key.key) });
    expect(res.status).toBe(200);
    const { apps } = ListAppsResponseSchema.parse(await res.json());
    expect(apps).toEqual([third.app, second.app, first.app]);

    const resB = await api.app.request("/v1/apps", { headers: bearer(adminB) });
    const listB = ListAppsResponseSchema.parse(await resB.json());
    expect(listB.apps).toEqual([foreign.app]);
  });

  it("orders Apps by true creation order even when they share a millisecond", async () => {
    // Three Apps stamped at the same instant, whose ids do not sort in creation order: ordering by id
    // would reverse two of them. Only a monotonic insertion column gives a stable, true creation order.
    const org = await createOrganization(api, "SameMillisecond");
    const sharedAt = "2026-11-10T13:00:00.000Z";
    const ids = [
      `app_${"0".repeat(24)}`, // inserted first
      `app_${"f".repeat(24)}`, // inserted second
      `app_${"a".repeat(24)}`, // inserted third
    ];
    await api.db.tx({ organizationId: org.organization.id }, async (q) => {
      for (const id of ids) {
        await q.query("INSERT INTO apps (id, organization_id, name, created_at) VALUES ($1, $2, $3, $4::timestamptz)", [
          id,
          org.organization.id,
          `App ${id.slice(-1)}`,
          sharedAt,
        ]);
      }
    });

    const res = await api.app.request("/v1/apps", { headers: bearer(org.admin_key.key) });
    expect(res.status).toBe(200);
    const { apps } = ListAppsResponseSchema.parse(await res.json());
    // Newest first is the reverse of insertion order, regardless of how the ids sort.
    expect(apps.map((app) => app.id)).toEqual([ids[2], ids[1], ids[0]]);
  });

  it("lists nothing for an Organization without Apps", async () => {
    const empty = await createOrganization(api, "Empty");
    const res = await api.app.request("/v1/apps", { headers: bearer(empty.admin_key.key) });
    expect(await res.json()).toEqual({ apps: [] });
  });

  it("returns one App to its Organization", async () => {
    const created = await createAppFor(api, adminA, { name: "Single" });
    const res = await api.app.request(`/v1/apps/${created.app.id}`, { headers: bearer(adminA) });
    expect(res.status).toBe(200);
    expect(AppResponseSchema.parse(await res.json())).toEqual({ app: created.app });
  });

  it("answers 404 for another Organization's App exactly as for an App that does not exist", async () => {
    const created = await createAppFor(api, adminA, { name: "Private" });

    const foreign = await api.app.request(`/v1/apps/${created.app.id}`, { headers: bearer(adminB) });
    const missing = await api.app.request(`/v1/apps/${newId("app")}`, { headers: bearer(adminB) });
    const malformed = await api.app.request("/v1/apps/not-an-app", { headers: bearer(adminB) });

    const foreignProblem = await expectProblem(foreign, 404);
    expect(await expectProblem(missing, 404)).toEqual(foreignProblem);
    expect(await expectProblem(malformed, 404)).toEqual(foreignProblem);
    expect(JSON.stringify(foreignProblem)).not.toContain(created.app.id);
  });

  it("never logs a key", () => {
    expectNoKeyLogged(api);
  });
});
