import {
  type BuildManifest,
  BuildResponseSchema,
  EXAMPLE_BUILD_MANIFEST,
  EXAMPLE_ROUTE_INVENTORY,
  ROUTE_LIMITS,
} from "@antireverse/protocol";
import { newId, routesDigest } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bearer, createAppFor, createOrganization, expectProblem, json, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 12a: the route inventory a tenant registers beside the Manifest for W1 Map. Verified against the Manifest's
// `route_count` and `routes_digest` like components, stored per Build under row-level security, never returned.

const ROUTES = [...EXAMPLE_ROUTE_INVENTORY];

function manifestFor(appId: string, overrides: Partial<BuildManifest> = {}): BuildManifest {
  return {
    ...EXAMPLE_BUILD_MANIFEST,
    build_id: newId("bld"),
    app_id: appId,
    route_count: ROUTES.length,
    routes_digest: routesDigest(ROUTES),
    ...overrides,
  };
}

describe("Build registration with a route inventory", () => {
  let api: TestApi;
  let adminA: string;
  let orgA: string;
  let orgB: string;
  let appId: string;

  const register = (body: unknown) =>
    Promise.resolve(api.app.request(`/v1/apps/${appId}/builds`, json(body, bearer(adminA))));

  async function storedRoutes(organizationId: string, buildId: string): Promise<unknown[]> {
    const { rows } = await api.db.tx({ organizationId }, (q) =>
      q.query<{ routes: unknown }>("SELECT routes FROM build_routes WHERE build_id = $1", [buildId]),
    );
    return rows.map((row) => row.routes);
  }

  beforeAll(async () => {
    api = await makeTestApi();
    const a = await createOrganization(api, "A");
    const b = await createOrganization(api, "B");
    adminA = a.admin_key.key;
    orgA = a.organization.id;
    orgB = b.organization.id;
    appId = (await createAppFor(api, adminA, { name: "Shop" })).app.id;
  });
  afterAll(async () => {
    await api.close();
  });

  it("stores the routes with the Build and never returns them", async () => {
    const manifest = manifestFor(appId);
    const res = await register({ manifest, routes: ROUTES });
    expect(res.status).toBe(201);
    const text = await res.text();
    expect(text).not.toContain("/api/checkout");
    const { build } = BuildResponseSchema.parse(JSON.parse(text));
    expect(build.route_count).toBe(ROUTES.length);
    expect(build.routes_digest).toBe(routesDigest(ROUTES));
    expect(await storedRoutes(orgA, manifest.build_id)).toEqual([ROUTES]);

    const read = await api.app.request(`/v1/apps/${appId}/builds/${manifest.build_id}`, { headers: bearer(adminA) });
    expect(await read.text()).not.toContain("/api/checkout");
    const list = await api.app.request(`/v1/apps/${appId}/builds`, { headers: bearer(adminA) });
    expect(await list.text()).not.toContain("/api/checkout");
  });

  it("keeps the routes invisible to another Organization (row-level security)", async () => {
    const manifest = manifestFor(appId);
    expect((await register({ manifest, routes: ROUTES })).status).toBe(201);
    expect(await storedRoutes(orgB, manifest.build_id)).toEqual([]);
  });

  it("stores no routes for a Build registered without them", async () => {
    const manifest = manifestFor(appId, { route_count: undefined, routes_digest: undefined });
    delete manifest.route_count;
    delete manifest.routes_digest;
    expect((await register({ manifest })).status).toBe(201);
    expect(await storedRoutes(orgA, manifest.build_id)).toEqual([]);
  });

  it("refuses routes whose number differs from route_count with 400 and stores nothing", async () => {
    const manifest = manifestFor(appId, { route_count: ROUTES.length + 1 });
    const problem = await expectProblem(await register({ manifest, routes: ROUTES }), 400);
    expect(problem.errors?.map((error) => error.path)).toContain("routes");
    expect(await storedRoutes(orgA, manifest.build_id)).toEqual([]);
  });

  it("refuses routes whose digest differs from routes_digest with 400 and registers nothing", async () => {
    const manifest = manifestFor(appId, { routes_digest: routesDigest(ROUTES.slice(1)) });
    const problem = await expectProblem(await register({ manifest, routes: ROUTES }), 400);
    expect(problem.errors).toEqual([
      { path: "manifest.routes_digest", message: "Must equal the digest of the routes sent." },
    ]);
    const read = await api.app.request(`/v1/apps/${appId}/builds/${manifest.build_id}`, { headers: bearer(adminA) });
    expect(read.status).toBe(404);
  });

  it("requires route_count and routes_digest when routes are sent", async () => {
    const manifest = manifestFor(appId);
    delete manifest.route_count;
    delete manifest.routes_digest;
    const problem = await expectProblem(await register({ manifest, routes: ROUTES }), 400);
    expect(problem.errors?.map((error) => error.path).sort()).toEqual([
      "manifest.route_count",
      "manifest.routes_digest",
    ]);
  });

  it("refuses more than 2,000 routes with 400", async () => {
    const routes = Array.from({ length: ROUTE_LIMITS.routesMax + 1 }, (_, index) => `GET /r/${index}`);
    const manifest = manifestFor(appId, { routes_digest: routesDigest(routes) });
    delete manifest.route_count;
    const problem = await expectProblem(await register({ manifest, routes }), 400);
    expect(problem.errors?.map((error) => error.path)).toContain("routes");
  });

  it("accepts 2,000 routes of the longest form in one body", async () => {
    const long = `/${"a".repeat(ROUTE_LIMITS.pathMax - 6)}`;
    const routes = Array.from({ length: ROUTE_LIMITS.routesMax }, (_, index) =>
      `DELETE ${long}${String(index).padStart(5, "0")}`.slice(0, 7 + ROUTE_LIMITS.pathMax),
    );
    const manifest = manifestFor(appId, { route_count: routes.length, routes_digest: routesDigest(routes) });
    const res = await register({ manifest, routes });
    expect(res.status).toBe(201);
  });
});
