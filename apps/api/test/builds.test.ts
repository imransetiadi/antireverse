import {
  BUILD_LIMITS,
  type BuildManifest,
  BuildResponseSchema,
  EXAMPLE_BUILD_MANIFEST,
  ID_PATTERNS,
  ListBuildsResponseSchema,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
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

const T0 = Date.parse("2026-11-10T12:00:00.000Z");

/** A valid Manifest for `appId`, with a fresh Build id, built from the documented example. */
function manifestFor(appId: string, overrides: Partial<BuildManifest> = {}): BuildManifest {
  return { ...EXAMPLE_BUILD_MANIFEST, build_id: newId("bld"), app_id: appId, ...overrides };
}

describe("Builds", () => {
  let api: TestApi;
  const clock = { now: new Date(T0) };
  let adminA: string;
  let adminB: string;
  let shieldA: string;
  let appId: string;

  /** Registers `manifest` for `appId` with the given admin key and returns the raw response. */
  function register(adminKey: string, path: string, manifest: unknown): Promise<Response> {
    return Promise.resolve(api.app.request(`/v1/apps/${path}/builds`, json({ manifest }, bearer(adminKey))));
  }

  beforeAll(async () => {
    api = await makeTestApi({ now: () => clock.now });
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    adminA = a.admin_key.key;
    adminB = b.admin_key.key;
    const created = await createAppFor(api, adminA, { name: "Storefront" });
    appId = created.app.id;
    shieldA = created.shield_key.key;
  });
  afterAll(async () => {
    await api.close();
  });

  describe("register", () => {
    it("registers a Build and returns it with the stamped registered_at", async () => {
      clock.now = new Date(T0 + 1_000);
      const manifest = manifestFor(appId);
      const res = await register(adminA, appId, manifest);
      expect(res.status).toBe(201);
      expect(res.headers.get("cache-control")).toBe("no-store");
      const { build } = BuildResponseSchema.parse(await res.json());
      expect(build).toEqual({ ...manifest, registered_at: new Date(T0 + 1_000).toISOString() });
    });

    it("refuses a Manifest whose app_id does not match the route with 400", async () => {
      const manifest = manifestFor(newId("app"));
      const problem = await expectProblem(await register(adminA, appId, manifest), 400);
      expect(problem.errors?.[0]?.path).toBe("manifest.app_id");
    });

    it("refuses a repeated Build id with 409 and stores nothing new", async () => {
      const manifest = manifestFor(appId);
      expect((await register(adminA, appId, manifest)).status).toBe(201);
      const repeat = await register(adminA, appId, manifest);
      const problem = await expectProblem(repeat, 409);
      expect(problem.type).toBe("https://antireverse.dev/problems/conflict");
    });

    it("refuses a Manifest with more than 1000 artifacts with 400", async () => {
      const artifacts = Array.from({ length: BUILD_LIMITS.artifactsMax + 1 }, (_, i) => ({
        path: `d/${i}.js`,
        sha256: "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        bytes: 1,
      }));
      const problem = await expectProblem(await register(adminA, appId, manifestFor(appId, { artifacts })), 400);
      expect(problem.errors?.[0]?.path).toBe("manifest.artifacts");
    });

    it("refuses a body larger than the limit with 413 before it parses the Manifest", async () => {
      const init = json({ manifest: { blob: "x".repeat(BUILD_LIMITS.manifestBytesMax + 10) } }, bearer(adminA));
      await expectProblem(await api.app.request(`/v1/apps/${appId}/builds`, init), 413);
    });
  });

  describe("read", () => {
    it("lists Builds newest first, by registered_at then Build id", async () => {
      const fresh = (await createAppFor(api, adminA, { name: "Listed" })).app.id;
      clock.now = new Date(T0 + 10_000);
      const oldest = manifestFor(fresh);
      await register(adminA, fresh, oldest);

      clock.now = new Date(T0 + 20_000);
      const middle = manifestFor(fresh);
      await register(adminA, fresh, middle);

      // Two Builds at the same instant: the tiebreak is Build id, descending, so the order is stable.
      clock.now = new Date(T0 + 30_000);
      const tieLow = manifestFor(fresh, { build_id: `bld_${"0".repeat(24)}` });
      const tieHigh = manifestFor(fresh, { build_id: `bld_${"f".repeat(24)}` });
      await register(adminA, fresh, tieLow);
      await register(adminA, fresh, tieHigh);

      const res = await api.app.request(`/v1/apps/${fresh}/builds`, { headers: bearer(adminA) });
      expect(res.status).toBe(200);
      const { builds } = ListBuildsResponseSchema.parse(await res.json());
      expect(builds.map((b) => b.build_id)).toEqual([
        tieHigh.build_id,
        tieLow.build_id,
        middle.build_id,
        oldest.build_id,
      ]);
    });

    it("lists nothing for an App without Builds", async () => {
      const empty = (await createAppFor(api, adminA, { name: "Empty" })).app.id;
      const res = await api.app.request(`/v1/apps/${empty}/builds`, { headers: bearer(adminA) });
      expect(res.status).toBe(200);
      expect(await res.json()).toEqual({ builds: [] });
    });

    it("returns one Build by its id", async () => {
      const detailApp = (await createAppFor(api, adminA, { name: "Detail" })).app.id;
      clock.now = new Date(T0 + 30_000);
      const manifest = manifestFor(detailApp);
      await register(adminA, detailApp, manifest);

      const res = await api.app.request(`/v1/apps/${detailApp}/builds/${manifest.build_id}`, {
        headers: bearer(adminA),
      });
      expect(res.status).toBe(200);
      const { build } = BuildResponseSchema.parse(await res.json());
      expect(build).toEqual({ ...manifest, registered_at: new Date(T0 + 30_000).toISOString() });
    });

    it("answers 404 for an unknown, malformed or foreign Build id", async () => {
      const res = await api.app.request(`/v1/apps/${appId}/builds/${newId("bld")}`, { headers: bearer(adminA) });
      await expectProblem(res, 404);
      const malformed = await api.app.request(`/v1/apps/${appId}/builds/not-a-build`, { headers: bearer(adminA) });
      await expectProblem(malformed, 404);
    });
  });

  describe("tenancy and keys", () => {
    it("answers 404 to another Organization on register, list and detail", async () => {
      const manifest = manifestFor(appId);
      await register(adminA, appId, manifest);

      await expectProblem(await register(adminB, appId, manifestFor(appId)), 404);
      await expectProblem(await api.app.request(`/v1/apps/${appId}/builds`, { headers: bearer(adminB) }), 404);
      await expectProblem(
        await api.app.request(`/v1/apps/${appId}/builds/${manifest.build_id}`, { headers: bearer(adminB) }),
        404,
      );
    });

    it("answers 404 for an unknown or malformed App on every route", async () => {
      const unknown = newId("app");
      await expectProblem(await register(adminA, unknown, manifestFor(unknown)), 404);
      await expectProblem(await api.app.request(`/v1/apps/${unknown}/builds`, { headers: bearer(adminA) }), 404);
      await expectProblem(await register(adminA, "not-an-app", manifestFor(appId)), 404);
      await expectProblem(await api.app.request("/v1/apps/not-an-app/builds", { headers: bearer(adminA) }), 404);
    });

    it("answers 403 to a Shield key and 401 without a key, on every route", async () => {
      const manifest = manifestFor(appId);
      await expectProblem(await register(shieldA, appId, manifest), 403);
      await expectProblem(await api.app.request(`/v1/apps/${appId}/builds`, { headers: bearer(shieldA) }), 403);
      await expectProblem(
        await api.app.request(`/v1/apps/${appId}/builds/${manifest.build_id}`, { headers: bearer(shieldA) }),
        403,
      );

      await expectProblem(await api.app.request(`/v1/apps/${appId}/builds`, json({ manifest })), 401);
      await expectProblem(await api.app.request(`/v1/apps/${appId}/builds`), 401);
      await expectProblem(await api.app.request(`/v1/apps/${appId}/builds/${manifest.build_id}`), 401);
    });
  });

  it("the build routes answer, and never a key in a log line", () => {
    expect(ID_PATTERNS.bld.test(EXAMPLE_BUILD_MANIFEST.build_id)).toBe(true);
    expectNoKeyLogged(api);
  });
});
