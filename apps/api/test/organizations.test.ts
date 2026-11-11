import { ADMIN_KEY_PATTERN, CreateOrganizationResponseSchema, OrganizationResponseSchema } from "@antireverse/protocol";
import { hashKey } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import {
  bearer,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  type TestApi,
} from "./helpers.ts";

describe("Organizations", () => {
  let api: TestApi;

  beforeAll(async () => {
    api = await makeTestApi();
  });
  afterAll(async () => {
    await api.close();
  });

  it("answers the health check", async () => {
    const res = await api.app.request("/healthz");
    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({ status: "ok" });
  });

  it("creates an Organization with a trimmed name and returns its admin key once", async () => {
    const res = await api.app.request("/v1/organizations", json({ name: " Acme " }));
    expect(res.status).toBe(201);
    expect(res.headers.get("cache-control")).toBe("no-store");
    const body = CreateOrganizationResponseSchema.parse(await res.json());
    api.issuedKeys.push(body.admin_key.key);

    expect(body.organization.name).toBe("Acme");
    expect(body.admin_key.key).toMatch(ADMIN_KEY_PATTERN);
    expect(body.admin_key.prefix).toBe(body.admin_key.key.slice(0, 10));
    expect(body.admin_key.last4).toBe(body.admin_key.key.slice(-4));
  });

  it("stores the hash of the admin key and never the key", async () => {
    const { organization, admin_key } = await createOrganization(api, "Hashed");

    const stored = await api.db.tx({ organizationId: organization.id }, async (q) => ({
      keys: (await q.query<Record<string, unknown>>("SELECT * FROM api_keys")).rows,
      organizations: (await q.query("SELECT * FROM organizations")).rows,
    }));

    expect(stored.keys).toHaveLength(1);
    expect(stored.keys[0]).toMatchObject({
      organization_id: organization.id,
      kind: "admin",
      app_id: null,
      environment: null,
      key_hash: hashKey(admin_key.key),
      prefix: admin_key.prefix,
      last4: admin_key.last4,
      revoked_at: null,
    });
    expect(JSON.stringify(stored)).not.toContain(admin_key.key);
    expect(JSON.stringify(stored)).not.toContain(admin_key.key.slice(4));
  });

  it("ignores an identifier or key the client supplies", async () => {
    const res = await api.app.request(
      "/v1/organizations",
      json({ name: "Chosen", id: "org_000000000000000000000000", admin_key: "aro_chosen" }),
    );
    expect(res.status).toBe(201);
    const body = CreateOrganizationResponseSchema.parse(await res.json());
    api.issuedKeys.push(body.admin_key.key);
    expect(body.organization.id).not.toBe("org_000000000000000000000000");
  });

  it.each([
    ["an empty name", json({ name: "" })],
    ["a name of spaces only", json({ name: "   " })],
    ["a name of 81 characters", json({ name: "n".repeat(81) })],
    ["a name that is not a string", json({ name: 42 })],
    ["no name", json({})],
    ["a JSON value that is not an object", json(["Acme"])],
  ])("refuses %s with a problem that points at the name", async (_label, init) => {
    const problem = await expectProblem(await api.app.request("/v1/organizations", init), 400);
    expect(problem.errors?.[0]?.path).toBe(_label === "a JSON value that is not an object" ? "" : "name");
    expect(problem.errors?.[0]?.message).toEqual(expect.any(String));
  });

  it("refuses a missing body", async () => {
    const problem = await expectProblem(await api.app.request("/v1/organizations", { method: "POST" }), 400);
    expect(problem.errors?.[0]?.path).toBe("name");
  });

  it("refuses invalid JSON", async () => {
    const res = await api.app.request("/v1/organizations", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: '{"name": "Acme"',
    });
    const problem = await expectProblem(res, 400);
    expect(problem.title).toBe("Malformed JSON");
  });

  it("accepts a name of exactly 80 characters", async () => {
    const { organization } = await createOrganization(api, "n".repeat(80));
    expect(organization.name).toHaveLength(80);
  });

  it("returns the caller's Organization to its admin key", async () => {
    const first = await createOrganization(api, "First");
    const second = await createOrganization(api, "Second");

    const res = await api.app.request("/v1/organization", { headers: bearer(second.admin_key.key) });
    expect(res.status).toBe(200);
    expect(OrganizationResponseSchema.parse(await res.json())).toEqual({ organization: second.organization });

    const other = await api.app.request("/v1/organization", { headers: bearer(first.admin_key.key) });
    expect(OrganizationResponseSchema.parse(await other.json())).toEqual({ organization: first.organization });
  });

  it("never logs a key", () => {
    expectNoKeyLogged(api);
  });
});
