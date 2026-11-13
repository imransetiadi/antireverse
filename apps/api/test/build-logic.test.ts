import {
  type BuildManifest,
  EXAMPLE_BUILD_MANIFEST,
  EXAMPLE_LOGIC,
  LOGIC_LIMITS,
  type LogicFile,
} from "@antireverse/protocol";
import { logicDigest, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { bearer, createAppFor, createOrganization, expectProblem, json, makeTestApi, type TestApi } from "./helpers.ts";

// Slice 12b: the logic file (W3 Logic) a tenant registers beside the Manifest. Verified against the Manifest's
// `logic_count` and `logic_digest` like routes, stored per Build under row-level security, never returned.

const LOGIC: LogicFile = EXAMPLE_LOGIC;
/** A hidden vector's output that no response may contain: unique to the example's vectors. */
const HIDDEN_MARK = "24199";

function manifestFor(appId: string, overrides: Partial<BuildManifest> = {}): BuildManifest {
  return {
    ...EXAMPLE_BUILD_MANIFEST,
    build_id: newId("bld"),
    app_id: appId,
    logic_count: LOGIC.functions.length,
    logic_digest: logicDigest(LOGIC),
    ...overrides,
  };
}

describe("Build registration with a logic file", () => {
  let api: TestApi;
  let adminA: string;
  let adminB: string;
  let orgA: string;
  let orgB: string;
  let appId: string;

  const register = (body: unknown) =>
    Promise.resolve(api.app.request(`/v1/apps/${appId}/builds`, json(body, bearer(adminA))));

  async function storedLogic(organizationId: string, buildId: string): Promise<unknown[]> {
    const { rows } = await api.db.tx({ organizationId }, (q) =>
      q.query<{ logic: unknown }>("SELECT logic FROM build_logic WHERE build_id = $1", [buildId]),
    );
    return rows.map((row) => row.logic);
  }

  beforeAll(async () => {
    api = await makeTestApi();
    const a = await createOrganization(api, "A");
    const b = await createOrganization(api, "B");
    adminA = a.admin_key.key;
    adminB = b.admin_key.key;
    orgA = a.organization.id;
    orgB = b.organization.id;
    appId = (await createAppFor(api, adminA, { name: "Shop" })).app.id;
  });
  afterAll(async () => {
    await api.close();
  });

  it("stores the logic file with the Build and never returns it", async () => {
    const manifest = manifestFor(appId);
    const res = await register({ manifest, logic: LOGIC });
    expect(res.status).toBe(201);
    const text = await res.text();
    expect(text).not.toContain(HIDDEN_MARK);
    expect(text).not.toContain("price-with-tax");
    expect(JSON.parse(text).build.logic_digest).toBe(logicDigest(LOGIC));
    expect(await storedLogic(orgA, manifest.build_id)).toEqual([LOGIC]);

    for (const path of [`/v1/apps/${appId}/builds/${manifest.build_id}`, `/v1/apps/${appId}/builds`]) {
      const read = await api.app.request(path, { headers: bearer(adminA) });
      expect(read.status).toBe(200);
      const body = await read.text();
      expect(body).not.toContain(HIDDEN_MARK);
      expect(body).not.toContain("price-with-tax");
    }
  });

  it("keeps the logic file invisible to another Organization (row-level security)", async () => {
    const manifest = manifestFor(appId);
    expect((await register({ manifest, logic: LOGIC })).status).toBe(201);
    expect(await storedLogic(orgB, manifest.build_id)).toEqual([]);
    const other = await api.app.request(`/v1/apps/${appId}/builds/${manifest.build_id}`, { headers: bearer(adminB) });
    expect(other.status).toBe(404);
  });

  it("gives the request role no UPDATE and no DELETE on stored logic, under FORCE row-level security", async () => {
    const { rows } = await api.db.tx("none", (q) =>
      q.query<{ privilege_type: string }>(
        `SELECT privilege_type FROM information_schema.role_table_grants
         WHERE grantee = 'ar_app' AND table_name = 'build_logic' ORDER BY privilege_type`,
      ),
    );
    expect(rows.map((row) => row.privilege_type)).toEqual(["INSERT", "SELECT"]);
    const security = await api.db.tx("none", (q) =>
      q.query<{ relrowsecurity: boolean; relforcerowsecurity: boolean }>(
        "SELECT relrowsecurity, relforcerowsecurity FROM pg_class WHERE relname = 'build_logic'",
      ),
    );
    expect(security.rows).toEqual([{ relrowsecurity: true, relforcerowsecurity: true }]);
  });

  it("refuses a logic file whose digest differs from logic_digest with 400 and registers nothing", async () => {
    const other: LogicFile = {
      functions: [{ ...(LOGIC.functions[0] as LogicFile["functions"][number]), description: "Another description." }],
    };
    const manifest = manifestFor(appId, { logic_digest: logicDigest(other) });
    const problem = await expectProblem(await register({ manifest, logic: LOGIC }), 400);
    expect(problem.errors).toEqual([
      { path: "manifest.logic_digest", message: "Must equal the digest of the logic sent." },
    ]);
    const read = await api.app.request(`/v1/apps/${appId}/builds/${manifest.build_id}`, { headers: bearer(adminA) });
    expect(read.status).toBe(404);
  });

  it("requires logic_count and logic_digest when logic is sent, and refuses a count mismatch", async () => {
    const manifest = manifestFor(appId);
    delete manifest.logic_count;
    delete manifest.logic_digest;
    const problem = await expectProblem(await register({ manifest, logic: LOGIC }), 400);
    expect(problem.errors?.map((error) => error.path).sort()).toEqual([
      "manifest.logic_count",
      "manifest.logic_digest",
    ]);
    const counted = manifestFor(appId, { logic_count: 2 });
    const mismatch = await expectProblem(await register({ manifest: counted, logic: LOGIC }), 400);
    expect(mismatch.errors?.map((error) => error.path)).toContain("logic");
  });

  it("accepts a logic file near 1 MB in one body", async () => {
    const big = "x".repeat(480);
    const vectors = Array.from({ length: LOGIC_LIMITS.vectorsMax }, (_, index) => ({
      input: [index, big],
      output: `${big}${index}`,
    }));
    const logic: LogicFile = {
      functions: Array.from({ length: LOGIC_LIMITS.functionsMax }, (_, index) => ({
        id: `fn-${index}`,
        description: "A large function.",
        examples: [],
        vectors,
      })),
    };
    const bytes = Buffer.byteLength(JSON.stringify(logic));
    expect(bytes).toBeGreaterThan(950_000);
    expect(bytes).toBeLessThanOrEqual(LOGIC_LIMITS.fileBytesMax);
    const manifest = manifestFor(appId, { logic_count: logic.functions.length, logic_digest: logicDigest(logic) });
    expect((await register({ manifest, logic })).status).toBe(201);
  });
});
