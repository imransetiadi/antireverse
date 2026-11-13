import {
  type Environment,
  EXAMPLE_POLICY_RULE,
  ID_PATTERNS,
  LIMITS,
  type Policy,
  PolicyResponseSchema,
  type PolicyRule,
  type PolicyVersionSummary,
  PolicyVersionsResponseSchema,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../src/app.ts";
import type { Db } from "../src/db/db.ts";
import {
  bearer,
  captureLogger,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  policyPath,
  publishPolicy,
  put,
  type TestApi,
  tick,
  withReason,
} from "./helpers.ts";

const T0 = Date.parse("2026-11-10T11:00:00.000Z");

const monitorRule = { name: "User export", path: "/api/users/*/export", methods: ["GET", "POST"] };
const enforceRule = { name: "Admin area", path: "/api/admin/**", mode: "enforce" };

describe("Policies", () => {
  let api: TestApi;
  const clock = { now: new Date(T0) };
  let organizationA: string;
  let adminA: string;
  let adminPrefixA: string;
  let adminB: string;
  let shieldA: string;

  /** A new App of Organization A: every test starts from a Policy that was never published. */
  async function freshApp(adminKey = adminA): Promise<string> {
    return (await createAppFor(api, adminKey, { name: "Storefront" })).app.id;
  }

  async function readPolicy(appId: string, environment: Environment = "development", key = adminA): Promise<Policy> {
    const res = await api.app.request(policyPath(appId, environment), { headers: bearer(key) });
    expect(res.status).toBe(200);
    return PolicyResponseSchema.parse(await res.json()).policy;
  }

  async function readVersions(
    appId: string,
    environment: Environment = "development",
  ): Promise<PolicyVersionSummary[]> {
    const res = await api.app.request(policyPath(appId, environment, "/versions"), { headers: bearer(adminA) });
    expect(res.status).toBe(200);
    return PolicyVersionsResponseSchema.parse(await res.json()).versions;
  }

  function storedVersions(appId: string): Promise<Record<string, unknown>[]> {
    return api.db
      .tx({ organizationId: organizationA }, (q) =>
        q.query<Record<string, unknown>>("SELECT * FROM policy_versions WHERE app_id = $1 ORDER BY version", [appId]),
      )
      .then((result) => result.rows);
  }

  beforeAll(async () => {
    api = await makeTestApi({ now: () => clock.now });
    const a = await createOrganization(api, "Organization A");
    const b = await createOrganization(api, "Organization B");
    organizationA = a.organization.id;
    adminA = a.admin_key.key;
    adminPrefixA = a.admin_key.prefix;
    adminB = b.admin_key.key;
    shieldA = (await createAppFor(api, adminA)).shield_key.key;
  });
  afterAll(async () => {
    await api.close();
  });

  describe("read", () => {
    it.each(["production", "staging", "development"] as const)(
      "has version 0 and no Rules in %s before anything is published",
      async (environment) => {
        const appId = await freshApp();
        const res = await api.app.request(policyPath(appId, environment), { headers: bearer(adminA) });
        expect(res.status).toBe(200);
        expect(res.headers.get("cache-control")).toBe("no-store");
        expect(await res.json()).toEqual({
          policy: { app_id: appId, environment, version: 0, rules: [], published_at: null },
        });
      },
    );
  });

  describe("publish", () => {
    it("publishes version 1, then version 2, each with its Rules in order and its time", async () => {
      const appId = await freshApp();
      clock.now = new Date(T0 + 1_000);

      const res = await api.app.request(
        policyPath(appId, "development"),
        put({ rules: [enforceRule, monitorRule] }, withReason(bearer(adminA))),
      );
      expect(res.status).toBe(201);
      expect(res.headers.get("cache-control")).toBe("no-store");
      const first = PolicyResponseSchema.parse(await res.json()).policy;

      expect(first).toMatchObject({
        app_id: appId,
        environment: "development",
        version: 1,
        published_at: new Date(T0 + 1_000).toISOString(),
      });
      expect(first.rules.map((rule) => rule.name)).toEqual(["Admin area", "User export"]);
      expect(await readPolicy(appId)).toEqual(first);

      clock.now = new Date(T0 + 2_000);
      const second = await publishPolicy(api, adminA, appId, "development", [monitorRule, enforceRule, ...first.rules]);
      expect(second.version).toBe(2);
      expect(second.published_at).toBe(new Date(T0 + 2_000).toISOString());
      expect(second.rules.map((rule) => rule.name)).toEqual(["User export", "Admin area", "Admin area", "User export"]);
      expect(await readPolicy(appId)).toEqual(second);
    });

    it("gives a Rule without an id a new one, and keeps the id of a Rule that has one", async () => {
      const appId = await freshApp();
      const first = await publishPolicy(api, adminA, appId, "development", [monitorRule, enforceRule]);
      const [a, b] = first.rules;
      if (a === undefined || b === undefined) throw new Error("Two Rules were published.");
      expect(a.id).toMatch(ID_PATTERNS.rul);
      expect(b.id).toMatch(ID_PATTERNS.rul);
      expect(a.id).not.toBe(b.id);

      // The Console sends the whole list back: known Rules with their id, a new Rule without.
      const second = await publishPolicy(api, adminA, appId, "development", [
        { ...b, mode: "monitor" },
        { name: "Login", path: "/login", methods: ["POST"] },
        a,
        EXAMPLE_POLICY_RULE,
      ]);
      expect(second.rules.map((rule) => rule.id)).toEqual([
        b.id,
        expect.stringMatching(ID_PATTERNS.rul),
        a.id,
        EXAMPLE_POLICY_RULE.id,
      ]);
      expect(second.rules[0]).toEqual({ ...b, mode: "monitor" });
      expect(second.rules[2]).toEqual(a);
      expect(second.rules[3]).toEqual(EXAMPLE_POLICY_RULE);
      expect(new Set(second.rules.map((rule) => rule.id)).size).toBe(4);
    });

    it("completes a Rule: every method, block, Monitor mode, a trimmed name, and no unknown member", async () => {
      const appId = await freshApp();
      const policy = await publishPolicy(api, adminA, appId, "development", [
        { name: "  Login  ", path: "/login", organization_id: "org_else", when: { rate: 1 }, published_by: "me" },
      ]);
      expect(policy.rules).toEqual([
        {
          id: expect.stringMatching(ID_PATTERNS.rul),
          name: "Login",
          path: "/login",
          methods: [],
          action: "block",
          mode: "monitor",
        },
      ]);
      const [row] = await storedVersions(appId);
      expect(row?.rules).toEqual(policy.rules);
    });

    it("publishes an empty list of Rules as a version of its own", async () => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "development", [enforceRule]);
      const emptied = await publishPolicy(api, adminA, appId, "development", []);
      expect(emptied).toMatchObject({ version: 2, rules: [] });
      expect(await readPolicy(appId)).toEqual(emptied);
    });

    it("keeps the Policies of the three Environments of one App apart", async () => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      await publishPolicy(api, adminA, appId, "development", [monitorRule, enforceRule]);
      const production = await publishPolicy(api, adminA, appId, "production", [enforceRule]);

      expect(production.version).toBe(1);
      expect((await readPolicy(appId, "development")).version).toBe(2);
      expect(await readPolicy(appId, "production")).toEqual(production);
      expect((await readPolicy(appId, "staging")).version).toBe(0);
    });

    it("stores who published as the prefix of the admin key, never the key", async () => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "staging", [monitorRule]);

      const rows = await storedVersions(appId);
      expect(rows).toHaveLength(1);
      expect(rows[0]).toMatchObject({
        organization_id: organizationA,
        app_id: appId,
        environment: "staging",
        version: 1,
        published_by: adminPrefixA,
      });
      expect(JSON.stringify(rows)).not.toContain(adminA.slice(-43));
    });

    it("accepts a Monitor Rule for every path, and an acknowledged Enforce Rule for one segment", async () => {
      const appId = await freshApp();
      const res = await api.app.request(
        policyPath(appId, "development"),
        put(
          {
            rules: [
              { name: "Everything, observed", path: "/**", mode: "monitor" },
              { name: "Top level", path: "/*", mode: "enforce" },
              { name: "Home", path: "/", mode: "enforce" },
            ],
            allow_broad: true,
          },
          withReason(bearer(adminA)),
        ),
      );
      expect(res.status).toBe(201);
      const { policy } = PolicyResponseSchema.parse(await res.json());
      expect(policy.rules.map((rule) => rule.mode)).toEqual(["monitor", "enforce", "enforce"]);
    });
  });

  describe("validation", () => {
    const valid = { name: "Login", path: "/login" };
    const fifty = Array.from({ length: 50 }, (_, index) => ({ name: `Rule ${index}`, path: `/r/${index}` }));
    const id = "rul_0123456789abcdef01234567";

    it("accepts 50 Rules", async () => {
      const appId = await freshApp();
      const policy = await publishPolicy(api, adminA, appId, "development", fifty);
      expect(policy.rules).toHaveLength(50);
      expect(policy.rules.map((rule) => rule.path)).toEqual(fifty.map((rule) => rule.path));
    });

    it.each([
      ["51 Rules", { rules: [...fifty, valid] }, "rules"],
      ["no Rule list", {}, "rules"],
      ["a Rule list that is not a list", { rules: "all" }, "rules"],
      ["a pattern without a leading slash", { rules: [{ ...valid, path: "api" }] }, "rules.0.path"],
      ["a pattern with an empty segment", { rules: [valid, valid, { ...valid, path: "/a//b" }] }, "rules.2.path"],
      ["a pattern with ** in the middle", { rules: [{ ...valid, path: "/a/**/b" }] }, "rules.0.path"],
      ["a pattern with a query string", { rules: [{ ...valid, path: "/a?x=1" }] }, "rules.0.path"],
      ["a pattern of 257 characters", { rules: [{ ...valid, path: `/${"a".repeat(256)}` }] }, "rules.0.path"],
      ["a pattern with a NUL character", { rules: [{ ...valid, path: "/a\u0000b" }] }, "rules.0.path"],
      ["a missing pattern", { rules: [{ name: "Login" }] }, "rules.0.path"],
      ["an unknown method", { rules: [valid, { ...valid, methods: ["GET", "get"] }] }, "rules.1.methods.1"],
      ["a method listed twice", { rules: [{ ...valid, methods: ["GET", "GET"] }] }, "rules.0.methods"],
      [
        "9 methods",
        {
          rules: [
            { ...valid, methods: ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"] },
          ],
        },
        "rules.0.methods",
      ],
      ["an empty name", { rules: [{ ...valid, name: "   " }] }, "rules.0.name"],
      ["a name of 81 characters", { rules: [{ ...valid, name: "n".repeat(81) }] }, "rules.0.name"],
      ["a name with a NUL character", { rules: [{ ...valid, name: "Log\u0000in" }] }, "rules.0.name"],
      ["a name with a lone surrogate", { rules: [{ ...valid, name: "Log\ud800in" }] }, "rules.0.name"],
      ["an unknown action", { rules: [{ ...valid, action: "allow" }] }, "rules.0.action"],
      ["an unknown mode", { rules: [{ ...valid, mode: "shadow" }] }, "rules.0.mode"],
      ["a malformed Rule id", { rules: [{ ...valid, id: "rul_1" }] }, "rules.0.id"],
      ["an App id as a Rule id", { rules: [{ ...valid, id: newId("app") }] }, "rules.0.id"],
      ["the same Rule id twice", { rules: [{ ...valid, id }, valid, { ...valid, id }] }, "rules.2.id"],
      [
        "an Enforce Rule that blocks every request",
        { rules: [valid, { name: "Everything", path: "/**", mode: "enforce" }] },
        "rules.1.mode",
      ],
      [
        "an Enforce Rule that blocks every request, even for one method",
        { rules: [{ name: "Every GET", path: "/**", methods: ["GET"], mode: "enforce" }] },
        "rules.0.mode",
      ],
    ])("refuses %s and stores nothing", async (_label, body, path) => {
      const appId = await freshApp();

      const res = await api.app.request(policyPath(appId, "development"), put(body, withReason(bearer(adminA))));

      const problem = await expectProblem(res, 400);
      expect(problem.errors?.[0]?.path).toBe(path);
      expect(problem.errors?.[0]?.message).toEqual(expect.any(String));
      expect((await readPolicy(appId)).version).toBe(0);
      expect(await storedVersions(appId)).toEqual([]);
    });

    it("names every Rule that is wrong, not only the first", async () => {
      const appId = await freshApp();
      const body = {
        rules: [
          { name: "Everything", path: "/**", mode: "enforce", id },
          { ...valid, id },
          { name: "Everything again", path: "/**", mode: "enforce" },
        ],
      };
      const problem = await expectProblem(
        await api.app.request(policyPath(appId, "development"), put(body, withReason(bearer(adminA)))),
        400,
      );
      expect(problem.errors?.map((error) => error.path).sort()).toEqual(["rules.0.mode", "rules.1.id", "rules.2.mode"]);
    });

    it.each([
      ["a body that is not JSON", "{ rules: ["],
      ["no body", undefined],
    ])("refuses %s", async (_label, body) => {
      const appId = await freshApp();
      const init: RequestInit = {
        method: "PUT",
        headers: { "content-type": "application/json", ...bearer(adminA) },
        ...(body === undefined ? {} : { body }),
      };
      await expectProblem(await api.app.request(policyPath(appId, "development"), init), 400);
      expect(await storedVersions(appId)).toEqual([]);
    });

    it("refuses a body over the size limit, on publish and on rollback", async () => {
      const appId = await freshApp();
      const padding = "x".repeat(LIMITS.bodyBytesMax);

      const publish = await api.app.request(
        policyPath(appId, "development"),
        put({ rules: [valid], padding }, withReason(bearer(adminA))),
      );
      await expectProblem(publish, 413);

      const rollback = await api.app.request(
        policyPath(appId, "development", "/rollback"),
        json({ version: 1, padding }, withReason(bearer(adminA))),
      );
      await expectProblem(rollback, 413);
      expect(await storedVersions(appId)).toEqual([]);
    });
  });

  describe("tenancy", () => {
    const routes = (appId: string, environment = "development"): [string, string, RequestInit][] => [
      ["GET", policyPath(appId, environment), {}],
      ["PUT", policyPath(appId, environment), put({ rules: [enforceRule] })],
      ["GET", policyPath(appId, environment, "/versions"), {}],
      ["POST", policyPath(appId, environment, "/rollback"), json({ version: 1 })],
    ];

    function call(path: string, init: RequestInit, key?: string): Promise<Response> {
      const headers = new Headers(init.headers);
      if (key !== undefined) headers.set("authorization", `Bearer ${key}`);
      return Promise.resolve(api.app.request(path, { ...init, headers }));
    }

    it("answers 404 to another Organization exactly as for an App that does not exist, and changes nothing", async () => {
      const appId = await freshApp();
      const published = await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      const missing = newId("app");

      for (const [index, [method, path, init]] of routes(appId).entries()) {
        const foreign = await expectProblem(await call(path, init, adminB), 404);
        const unknown = await expectProblem(await call(routes(missing)[index]?.[1] ?? "", init, adminB), 404);
        expect(foreign, `${method} ${path}`).toEqual(unknown);
        expect(JSON.stringify(foreign)).not.toContain(appId);
      }

      expect(await readPolicy(appId)).toEqual(published);
      expect(await storedVersions(appId)).toHaveLength(1);
    });

    it.each([
      ["a malformed App identifier", "not-an-app", "development"],
      ["an App identifier in capitals", "APP_0123456789ABCDEF01234567", "development"],
      ["an unknown Environment", null, "qa"],
      ["an Environment in capitals", null, "Production"],
      ["the Environment tag of a key", null, "prod"],
    ])("answers 404 for %s", async (_label, appId, environment) => {
      const target = appId ?? (await freshApp());
      for (const [method, path, init] of routes(target, environment)) {
        const res = await call(path, init, adminA);
        await expectProblem(res, 404);
        expect(res.status, `${method} ${path}`).toBe(404);
      }
      if (appId === null) expect(await storedVersions(target)).toEqual([]);
    });

    it("answers 403 to a Shield key and 401 without a key, on every route", async () => {
      const appId = await freshApp();
      for (const [method, path, init] of routes(appId)) {
        const shield = await call(path, init, shieldA);
        await expectProblem(shield, 403);
        const none = await call(path, init);
        await expectProblem(none, 401);
        expect(none.headers.get("www-authenticate"), `${method} ${path}`).toBe("Bearer");
      }
      expect(await storedVersions(appId)).toEqual([]);
    });

    it("hides the stored versions of one Organization from every other, in the database itself", async () => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      const other = await createOrganization(api, "Organization C");
      const organizationC = other.organization.id;
      const appOfC = await freshApp(other.admin_key.key);
      const insert = `INSERT INTO policy_versions (organization_id, app_id, environment, version, rules, published_by)
                      VALUES ($1, $2, 'development', 7, '[]'::jsonb, 'aro_test')`;

      const asC = await api.db.tx({ organizationId: organizationC }, (q) =>
        q.query("SELECT version FROM policy_versions WHERE app_id = $1", [appId]),
      );
      expect(asC.rows).toEqual([]);
      const withoutTenant = await api.db.tx("none", (q) => q.query("SELECT version FROM policy_versions"));
      expect(withoutTenant.rows).toEqual([]);

      // Organization C can write a version neither under A's name nor without a tenant.
      await expect(
        api.db.tx({ organizationId: organizationC }, (q) => q.query(insert, [organizationA, appId])),
      ).rejects.toMatchObject({ code: "42501" });
      await expect(api.db.tx("none", (q) => q.query(insert, [organizationC, appOfC]))).rejects.toMatchObject({
        code: "42501",
      });
      // A published version is never changed or removed: the request role may only read and add.
      await expect(
        api.db.tx({ organizationId: organizationA }, (q) => q.query("UPDATE policy_versions SET rules = '[]'::jsonb")),
      ).rejects.toMatchObject({ code: "42501" });
      await expect(
        api.db.tx({ organizationId: organizationA }, (q) => q.query("DELETE FROM policy_versions")),
      ).rejects.toMatchObject({ code: "42501" });
      expect(await storedVersions(appId)).toHaveLength(1);
    });
  });

  describe("versions", () => {
    it("lists nothing before anything is published", async () => {
      expect(await readVersions(await freshApp())).toEqual([]);
    });

    it("lists the newest 20 versions first, with the number of Rules and of Rules in Enforce mode", async () => {
      const appId = await freshApp();
      const rulesOf = (version: number): unknown[] => [
        ...Array.from({ length: version % 4 }, (_, index) => ({ name: `Observed ${index}`, path: `/m/${index}` })),
        ...Array.from({ length: version % 3 }, (_, index) => ({
          name: `Blocked ${index}`,
          path: `/e/${index}`,
          mode: "enforce",
        })),
      ];
      for (let version = 1; version <= 22; version++) {
        clock.now = new Date(T0 + version * 60_000);
        await publishPolicy(api, adminA, appId, "development", rulesOf(version));
      }
      await publishPolicy(api, adminA, appId, "staging", [enforceRule]);

      const versions = await readVersions(appId);

      expect(versions).toHaveLength(20);
      expect(versions.map((entry) => entry.version)).toEqual(Array.from({ length: 20 }, (_, index) => 22 - index));
      for (const entry of versions) {
        expect(entry).toEqual({
          version: entry.version,
          published_at: new Date(T0 + entry.version * 60_000).toISOString(),
          rule_count: (entry.version % 4) + (entry.version % 3),
          enforced_count: entry.version % 3,
        });
      }
      expect((await readVersions(appId, "staging")).map((entry) => entry.version)).toEqual([1]);
    });
  });

  describe("rollback", () => {
    function rollback(appId: string, body: unknown, environment: Environment = "development"): Promise<Response> {
      return Promise.resolve(
        api.app.request(policyPath(appId, environment, "/rollback"), json(body, withReason(bearer(adminA)))),
      );
    }

    it("publishes the Rules of the named version as the next version", async () => {
      const appId = await freshApp();
      const first = await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      const second = await publishPolicy(api, adminA, appId, "development", [...first.rules, enforceRule]);
      clock.now = new Date(T0 + 5_000);

      const res = await rollback(appId, { version: 1 });

      expect(res.status).toBe(201);
      const third = PolicyResponseSchema.parse(await res.json()).policy;
      expect(third).toEqual({
        app_id: appId,
        environment: "development",
        version: 3,
        rules: first.rules,
        published_at: new Date(T0 + 5_000).toISOString(),
      });
      expect(await readPolicy(appId)).toEqual(third);
      expect(
        (await readVersions(appId)).map((entry) => [entry.version, entry.rule_count, entry.enforced_count]),
      ).toEqual([
        [3, 1, 0],
        [2, 2, 1],
        [1, 1, 0],
      ]);
      // Rolling forward again is the same action: the Rules of version 2 return as version 4.
      const fourth = PolicyResponseSchema.parse(await (await rollback(appId, { version: 2 })).json()).policy;
      expect(fourth).toMatchObject({ version: 4, rules: second.rules });
      const rows = await storedVersions(appId);
      expect(rows.map((row) => row.published_by)).toEqual(Array(4).fill(adminPrefixA));
    });

    it.each<[string, { version: number }, Environment]>([
      ["a version that was never published", { version: 3 }, "development"],
      ["a version of another Environment", { version: 2 }, "staging"],
    ])("answers 404 for %s and publishes nothing", async (_label, body, environment) => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      await publishPolicy(api, adminA, appId, "development", [enforceRule]);
      await publishPolicy(api, adminA, appId, "staging", [enforceRule]);

      await expectProblem(await rollback(appId, body, environment), 404);

      expect(await storedVersions(appId)).toHaveLength(3);
    });

    it.each([
      ["version 0", { version: 0 }],
      ["a negative version", { version: -1 }],
      ["a version that is text", { version: "1" }],
      ["a fractional version", { version: 1.5 }],
      ["a version beyond every integer", { version: 1e30 }],
      ["no version", {}],
    ])("refuses %s", async (_label, body) => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "development", [monitorRule]);

      const problem = await expectProblem(await rollback(appId, body), 400);

      expect(problem.errors?.[0]?.path).toBe("version");
      expect(await storedVersions(appId)).toHaveLength(1);
    });

    it("answers 404, not 500, for a version larger than the database can hold", async () => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      for (const version of [2_147_483_647, 2_147_483_648, Number.MAX_SAFE_INTEGER]) {
        await expectProblem(await rollback(appId, { version }), 404);
      }
      expect(await storedVersions(appId)).toHaveLength(1);
    });

    it("refuses to bring back an Enforce Rule that blocks every request", async () => {
      const appId = await freshApp();
      // Such a version cannot be published; one stored before the guardrail existed must not return either.
      const everything: PolicyRule = { ...EXAMPLE_POLICY_RULE, path: "/**", mode: "enforce" };
      await api.db.tx({ organizationId: organizationA }, (q) =>
        q.query(
          `INSERT INTO policy_versions (organization_id, app_id, environment, version, rules, published_by)
           VALUES ($1, $2, 'development', 1, $3::jsonb, 'aro_before')`,
          [organizationA, appId, JSON.stringify([{ ...EXAMPLE_POLICY_RULE, mode: "monitor" }, everything])],
        ),
      );

      const problem = await expectProblem(await rollback(appId, { version: 1 }), 400);

      expect(problem.errors).toEqual([{ path: "rules.1.mode", message: expect.any(String) }]);
      expect(await storedVersions(appId)).toHaveLength(1);
    });
  });

  describe("concurrent publishes", () => {
    it("gives 10 publishes at once the versions 1 to 10, each exactly once", async () => {
      const appId = await freshApp();

      const responses = await Promise.all(
        Array.from({ length: 10 }, (_, index) =>
          api.app.request(
            policyPath(appId, "development"),
            put({ rules: [{ name: `Publisher ${index}`, path: `/p/${index}` }] }, withReason(bearer(adminA))),
          ),
        ),
      );

      expect(responses.map((res) => res.status)).toEqual(Array(10).fill(201));
      const policies = await Promise.all(
        responses.map(async (res) => PolicyResponseSchema.parse(await res.json()).policy),
      );
      expect(policies.map((policy) => policy.version).sort((a, b) => a - b)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

      // Every publisher's Rules are stored under the version it was told, and nobody's are lost.
      const rows = await storedVersions(appId);
      expect(rows.map((row) => row.version)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
      for (const policy of policies) expect(rows[policy.version - 1]?.rules).toEqual(policy.rules);
      expect(new Set(policies.map((policy) => policy.rules[0]?.name)).size).toBe(10);
      expect((await readPolicy(appId)).version).toBe(10);
    });

    it("gives publishes and rollbacks at once consecutive versions as well", async () => {
      const appId = await freshApp();
      const first = await publishPolicy(api, adminA, appId, "development", [monitorRule]);

      const responses = await Promise.all(
        Array.from({ length: 8 }, (_, index) =>
          index % 2 === 0
            ? api.app.request(
                policyPath(appId, "development"),
                put({ rules: [enforceRule] }, withReason(bearer(adminA))),
              )
            : api.app.request(
                policyPath(appId, "development", "/rollback"),
                json({ version: 1 }, withReason(bearer(adminA))),
              ),
        ),
      );

      expect(responses.map((res) => res.status)).toEqual(Array(8).fill(201));
      const policies = await Promise.all(
        responses.map(async (res) => PolicyResponseSchema.parse(await res.json()).policy),
      );
      expect(policies.map((policy) => policy.version).sort((a, b) => a - b)).toEqual([2, 3, 4, 5, 6, 7, 8, 9]);
      for (const [index, policy] of policies.entries()) {
        if (index % 2 === 1) expect(policy.rules).toEqual(first.rules);
      }
    });

    /** A database on which the first `losses` publishing transactions lose the race for their version. */
    function racing(losses: number): { db: Db; attempts: () => number } {
      let attempts = 0;
      const db: Db = {
        tx: (scope, fn) => {
          if (scope === "none") return api.db.tx(scope, fn);
          return api.db.tx(scope, async (q) => {
            const result = await fn(q);
            attempts++;
            if (attempts <= losses) {
              // What a PostgreSQL server reports when another transaction took the version first.
              throw Object.assign(new Error('duplicate key value violates unique constraint "policy_versions_pkey"'), {
                code: "23505",
              });
            }
            return result;
          });
        },
        close: () => Promise.resolve(),
      };
      return { db, attempts: () => attempts };
    }

    it("publishes again when another transaction took the version first", async () => {
      const appId = await freshApp();
      const { db, attempts } = racing(2);
      const app = createApp({ db, bus: api.bus, signer: api.signer, logger: captureLogger() });

      const res = await app.request(
        policyPath(appId, "development"),
        put({ rules: [monitorRule] }, withReason(bearer(adminA))),
      );

      expect(res.status).toBe(201);
      expect(PolicyResponseSchema.parse(await res.json()).policy.version).toBe(1);
      expect(attempts()).toBe(3);
      expect(await storedVersions(appId)).toHaveLength(1);
    });

    it("gives up after a bounded number of attempts, with a 500 that says nothing", async () => {
      const appId = await freshApp();
      const { db, attempts } = racing(Number.POSITIVE_INFINITY);
      const logger = captureLogger();
      const app = createApp({ db, bus: api.bus, signer: api.signer, logger });

      const res = await app.request(
        policyPath(appId, "development"),
        put({ rules: [monitorRule] }, withReason(bearer(adminA))),
      );

      const problem = await expectProblem(res, 500);
      expect(JSON.stringify(problem)).not.toMatch(/duplicate|policy_versions/);
      expect(attempts()).toBeLessThanOrEqual(5);
      expect(logger.lines.join("\n")).not.toContain("duplicate key");
      expect(await storedVersions(appId)).toEqual([]);
    });
  });

  describe("broad Enforce Rules", () => {
    const BROAD = /most of the App's traffic.*allow_broad/;

    function publishWith(appId: string, body: Record<string, unknown>): Promise<Response> {
      return Promise.resolve(api.app.request(policyPath(appId, "development"), put(body, withReason(bearer(adminA)))));
    }

    it.each(["/*", "/*/**", "/*/admin"])(
      "refuses %s in Enforce mode without allow_broad, at the mode of that Rule, and stores nothing",
      async (path) => {
        const appId = await freshApp();
        for (const body of [
          { rules: [monitorRule, { name: "Broad", path, mode: "enforce" }] },
          { rules: [monitorRule, { name: "Broad", path, mode: "enforce" }], allow_broad: false },
        ]) {
          const problem = await expectProblem(await publishWith(appId, body), 400);
          expect(problem.type).toBe("https://antireverse.dev/problems/validation");
          expect(problem.errors).toEqual([{ path: "rules.1.mode", message: expect.stringMatching(BROAD) }]);
          // The pattern itself is not echoed.
          expect(JSON.stringify(problem)).not.toContain(`"${path}"`);
        }
        expect(await storedVersions(appId)).toEqual([]);
      },
    );

    it("publishes a broad Enforce Rule with allow_broad: true", async () => {
      const appId = await freshApp();
      const res = await publishWith(appId, {
        rules: [{ name: "Broad", path: "/*/admin", mode: "enforce" }],
        allow_broad: true,
      });
      expect(res.status).toBe(201);
      expect(PolicyResponseSchema.parse(await res.json()).policy.rules[0]).toMatchObject({
        path: "/*/admin",
        mode: "enforce",
      });
    });

    it("still refuses /** in Enforce mode with allow_broad: true, with the guardrail's own message", async () => {
      const appId = await freshApp();
      const problem = await expectProblem(
        await publishWith(appId, { rules: [{ name: "Everything", path: "/**", mode: "enforce" }], allow_broad: true }),
        400,
      );
      expect(problem.errors).toEqual([
        { path: "rules.0.mode", message: "A Rule for /** would block every request and cannot be in enforce mode." },
      ]);
      expect(await storedVersions(appId)).toEqual([]);
    });

    it("needs nothing for a broad Rule in Monitor mode, or a pattern whose first segment is not a wildcard", async () => {
      const appId = await freshApp();
      const res = await publishWith(appId, {
        rules: [
          { name: "Broad, observed", path: "/*", mode: "monitor" },
          { name: "Deep wildcard", path: "/api/*/admin", mode: "enforce" },
        ],
      });
      expect(res.status).toBe(201);
    });

    it("refuses to roll back to a version with a broad Enforce Rule unless allow_broad is true", async () => {
      const appId = await freshApp();
      const broad = await publishWith(appId, {
        rules: [{ name: "Broad", path: "/*", mode: "enforce" }],
        allow_broad: true,
      });
      expect(broad.status).toBe(201);
      await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      const rollback = (body: Record<string, unknown>) =>
        api.app.request(policyPath(appId, "development", "/rollback"), json(body, withReason(bearer(adminA))));

      const refused = await expectProblem(await rollback({ version: 1 }), 400);
      expect(refused.errors).toEqual([{ path: "rules.0.mode", message: expect.stringMatching(BROAD) }]);
      expect(await storedVersions(appId)).toHaveLength(2);

      const accepted = await rollback({ version: 1, allow_broad: true, expected_version: 2 });
      expect(accepted.status).toBe(201);
      expect(PolicyResponseSchema.parse(await accepted.json()).policy).toMatchObject({ version: 3 });
    });

    it("answers a stale expected version with 409 before it looks at broad Rules", async () => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      const res = await publishWith(appId, {
        rules: [{ name: "Broad", path: "/*", mode: "enforce" }],
        expected_version: 0,
      });
      await expectProblem(res, 409);
    });
  });

  describe("signature requirement (slice 04)", () => {
    const signedRule = {
      name: "Checkout",
      path: "/api/checkout/**",
      methods: ["POST"],
      mode: "enforce",
      requires: "signature",
    };

    function publishWith(appId: string, body: Record<string, unknown>): Promise<Response> {
      return Promise.resolve(api.app.request(policyPath(appId, "development"), put(body, withReason(bearer(adminA)))));
    }

    it("publishes, reads, lists and rolls back a Rule with requires: signature, and stores it", async () => {
      const appId = await freshApp();
      const first = await publishPolicy(api, adminA, appId, "development", [monitorRule, signedRule]);
      expect(first.rules[1]).toEqual({
        id: expect.stringMatching(ID_PATTERNS.rul),
        name: "Checkout",
        path: "/api/checkout/**",
        methods: ["POST"],
        action: "block",
        mode: "enforce",
        requires: "signature",
      });
      // A Rule without a requirement has no requires member at all, as before slice 04.
      expect("requires" in (first.rules[0] ?? {})).toBe(false);
      expect(await readPolicy(appId)).toEqual(first);

      const stored = (await storedVersions(appId))[0]?.rules as Record<string, unknown>[];
      expect(stored[1]?.requires).toBe("signature");
      expect("requires" in (stored[0] ?? {})).toBe(false);

      await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      const one = await api.app.request(policyPath(appId, "development", "/versions/1"), { headers: bearer(adminA) });
      expect(PolicyResponseSchema.parse(await one.json()).policy).toEqual(first);
      expect(
        (await readVersions(appId)).map((entry) => [entry.version, entry.rule_count, entry.enforced_count]),
      ).toEqual([
        [2, 1, 0],
        [1, 2, 1],
      ]);

      const res = await api.app.request(
        policyPath(appId, "development", "/rollback"),
        json({ version: 1, expected_version: 2 }, withReason(bearer(adminA))),
      );
      expect(res.status).toBe(201);
      expect(PolicyResponseSchema.parse(await res.json()).policy).toMatchObject({ version: 3, rules: first.rules });
    });

    it("refuses a requirement it does not know, at that Rule", async () => {
      const appId = await freshApp();
      const problem = await expectProblem(
        await publishWith(appId, { rules: [monitorRule, { ...signedRule, requires: "mtls" }] }),
        400,
      );
      expect(problem.errors?.[0]?.path).toBe("rules.1.requires");
      expect(await storedVersions(appId)).toEqual([]);
    });

    it("asks for allow_broad for an Enforce requirement Rule with a wildcard first segment, as for a block Rule", async () => {
      const appId = await freshApp();
      const broad = { ...signedRule, path: "/*/checkout" };
      const refused = await expectProblem(await publishWith(appId, { rules: [monitorRule, broad] }), 400);
      expect(refused.errors).toEqual([
        { path: "rules.1.mode", message: expect.stringMatching(/most of the App's traffic.*allow_broad/) },
      ]);
      expect(await storedVersions(appId)).toEqual([]);

      const everything = await expectProblem(
        await publishWith(appId, { rules: [{ ...signedRule, path: "/**" }], allow_broad: true }),
        400,
      );
      expect(everything.errors?.[0]?.path).toBe("rules.0.mode");

      // In Monitor mode a broad requirement Rule needs nothing.
      expect((await publishWith(appId, { rules: [{ ...broad, mode: "monitor" }] })).status).toBe(201);
      const accepted = await publishWith(appId, { rules: [broad], allow_broad: true });
      expect(accepted.status).toBe(201);
      expect(PolicyResponseSchema.parse(await accepted.json()).policy.rules[0]).toMatchObject({
        path: "/*/checkout",
        requires: "signature",
      });

      await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      const rollback = await expectProblem(
        await api.app.request(
          policyPath(appId, "development", "/rollback"),
          json({ version: 2 }, withReason(bearer(adminA))),
        ),
        400,
      );
      expect(rollback.errors?.[0]?.path).toBe("rules.0.mode");
    });
  });

  describe("limit Rules (slice 08)", () => {
    const loginLimit = {
      name: "Login protection",
      path: "/login",
      methods: ["POST"],
      limit: { requests: 10, window_s: 300, key: "ip", count: "failures" },
    };

    function publishWith(appId: string, body: Record<string, unknown>): Promise<Response> {
      return Promise.resolve(api.app.request(policyPath(appId, "development"), put(body, withReason(bearer(adminA)))));
    }

    it("publishes, reads, lists and rolls back a Rule with a limit, and stores it complete", async () => {
      const appId = await freshApp();
      const burst = { name: "Search", path: "/api/search", limit: { requests: 100, window_s: 60, key: "device" } };
      const first = await publishPolicy(api, adminA, appId, "development", [monitorRule, loginLimit, burst]);
      expect(first.rules[1]).toEqual({
        id: expect.stringMatching(ID_PATTERNS.rul),
        name: "Login protection",
        path: "/login",
        methods: ["POST"],
        action: "throttle",
        mode: "monitor",
        limit: { requests: 10, window_s: 300, key: "ip", count: "failures" },
      });
      // The members in the documented order, the limit last; `count` defaults to requests.
      expect(Object.keys(first.rules[1] ?? {})).toEqual(["id", "name", "path", "methods", "action", "mode", "limit"]);
      expect(Object.keys(first.rules[1]?.limit ?? {})).toEqual(["requests", "window_s", "key", "count"]);
      expect(first.rules[2]).toMatchObject({
        action: "throttle",
        methods: [],
        limit: { requests: 100, window_s: 60, key: "device", count: "requests" },
      });
      // A Rule without a limit has no limit member at all, as before slice 08.
      expect("limit" in (first.rules[0] ?? {})).toBe(false);
      expect(first.rules[0]).toMatchObject({ action: "block" });
      expect(await readPolicy(appId)).toEqual(first);
      expect(Object.keys((await readPolicy(appId)).rules[1] ?? {})).toEqual(Object.keys(first.rules[1] ?? {}));

      const stored = (await storedVersions(appId))[0]?.rules as Record<string, unknown>[];
      expect(stored[1]?.limit).toEqual({ requests: 10, window_s: 300, key: "ip", count: "failures" });
      expect(stored[2]?.limit).toEqual({ requests: 100, window_s: 60, key: "device", count: "requests" });
      expect("limit" in (stored[0] ?? {})).toBe(false);

      // An explicit action throttle is the same Rule; promoting to Enforce keeps the id and the limit.
      const promoted = await publishPolicy(api, adminA, appId, "development", [
        { ...first.rules[1], action: "throttle", mode: "enforce" },
      ]);
      expect(promoted.rules[0]).toEqual({ ...first.rules[1], mode: "enforce" });

      const one = await api.app.request(policyPath(appId, "development", "/versions/1"), { headers: bearer(adminA) });
      expect(PolicyResponseSchema.parse(await one.json()).policy).toEqual(first);
      expect(
        (await readVersions(appId)).map((entry) => [entry.version, entry.rule_count, entry.enforced_count]),
      ).toEqual([
        [2, 1, 1],
        [1, 3, 0],
      ]);

      const res = await api.app.request(
        policyPath(appId, "development", "/rollback"),
        json({ version: 1, expected_version: 2 }, withReason(bearer(adminA))),
      );
      expect(res.status).toBe(201);
      const rolledBack = PolicyResponseSchema.parse(await res.json()).policy;
      expect(rolledBack).toMatchObject({ version: 3, rules: first.rules });
      expect((await storedVersions(appId))[2]?.rules).toEqual(first.rules);
      expect(await readPolicy(appId)).toEqual(rolledBack);
    });

    it.each([
      ["a limit with the action block", { ...loginLimit, action: "block" }, "rules.1.action", /throttle/],
      [
        "the action throttle without a limit",
        { name: "No limit", path: "/x", action: "throttle" },
        "rules.1.limit",
        /limit/,
      ],
      ["a limit beside a requirement", { ...loginLimit, requires: "signature" }, "rules.1.requires", /requirement/],
      ["0 requests", { ...loginLimit, limit: { ...loginLimit.limit, requests: 0 } }, "rules.1.limit.requests", /./],
      [
        "more than 100,000 requests",
        { ...loginLimit, limit: { ...loginLimit.limit, requests: 100_001 } },
        "rules.1.limit.requests",
        /./,
      ],
      [
        "a fraction of a request",
        { ...loginLimit, limit: { ...loginLimit.limit, requests: 1.5 } },
        "rules.1.limit.requests",
        /./,
      ],
      [
        "a window of 0 seconds",
        { ...loginLimit, limit: { ...loginLimit.limit, window_s: 0 } },
        "rules.1.limit.window_s",
        /./,
      ],
      [
        "a window over an hour",
        { ...loginLimit, limit: { ...loginLimit.limit, window_s: 3_601 } },
        "rules.1.limit.window_s",
        /./,
      ],
      ["an unknown key", { ...loginLimit, limit: { ...loginLimit.limit, key: "account" } }, "rules.1.limit.key", /./],
      [
        "an unknown count",
        { ...loginLimit, limit: { ...loginLimit.limit, count: "errors" } },
        "rules.1.limit.count",
        /./,
      ],
      ["a limit without a key", { ...loginLimit, limit: { requests: 10, window_s: 300 } }, "rules.1.limit.key", /./],
      ["a limit that is not an object", { ...loginLimit, limit: 10 }, "rules.1.limit", /./],
    ])("refuses %s with 400 at that member, and stores nothing", async (_what, rule, path, message) => {
      const appId = await freshApp();
      const problem = await expectProblem(await publishWith(appId, { rules: [monitorRule, rule] }), 400);
      expect(problem.type).toBe("https://antireverse.dev/problems/validation");
      expect(problem.errors).toEqual([{ path, message: expect.stringMatching(message) }]);
      expect(await storedVersions(appId)).toEqual([]);
    });

    it("asks for allow_broad for an Enforce limit Rule with a wildcard first segment, as for a block Rule", async () => {
      const appId = await freshApp();
      const broad = { ...loginLimit, path: "/*/login", mode: "enforce" };
      for (const body of [{ rules: [monitorRule, broad] }, { rules: [monitorRule, broad], allow_broad: false }]) {
        const refused = await expectProblem(await publishWith(appId, body), 400);
        expect(refused.errors).toEqual([
          { path: "rules.1.mode", message: expect.stringMatching(/most of the App's traffic.*allow_broad/) },
        ]);
      }
      expect(await storedVersions(appId)).toEqual([]);

      // Every path in Enforce mode is refused even when acknowledged.
      const everything = await expectProblem(
        await publishWith(appId, { rules: [{ ...loginLimit, path: "/**", mode: "enforce" }], allow_broad: true }),
        400,
      );
      expect(everything.errors?.[0]?.path).toBe("rules.0.mode");

      // In Monitor mode a broad limit Rule needs nothing, also for every path.
      expect((await publishWith(appId, { rules: [{ ...broad, mode: "monitor" }] })).status).toBe(201);
      expect((await publishWith(appId, { rules: [{ ...loginLimit, path: "/**" }] })).status).toBe(201);
      const accepted = await publishWith(appId, { rules: [broad], allow_broad: true });
      expect(accepted.status).toBe(201);
      expect(PolicyResponseSchema.parse(await accepted.json()).policy.rules[0]).toMatchObject({
        path: "/*/login",
        action: "throttle",
        mode: "enforce",
        limit: loginLimit.limit,
      });

      // A rollback to the broad Enforce limit Rule asks again.
      await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      const rollback = await expectProblem(
        await api.app.request(
          policyPath(appId, "development", "/rollback"),
          json({ version: 3 }, withReason(bearer(adminA))),
        ),
        400,
      );
      expect(rollback.errors?.[0]?.path).toBe("rules.0.mode");
      const acknowledged = await api.app.request(
        policyPath(appId, "development", "/rollback"),
        json({ version: 3, allow_broad: true }, withReason(bearer(adminA))),
      );
      expect(acknowledged.status).toBe(201);
      expect(PolicyResponseSchema.parse(await acknowledged.json()).policy.rules[0]).toMatchObject({
        limit: loginLimit.limit,
      });
    });

    it("keeps the limit Rules of one Organization from every other", async () => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "development", [loginLimit]);
      for (const res of [
        await api.app.request(policyPath(appId, "development"), { headers: bearer(adminB) }),
        await api.app.request(policyPath(appId, "development", "/versions/1"), { headers: bearer(adminB) }),
        await api.app.request(
          policyPath(appId, "development"),
          put({ rules: [loginLimit] }, withReason(bearer(adminB))),
        ),
      ]) {
        const problem = await expectProblem(res, 404);
        expect(JSON.stringify(problem)).not.toContain("limit");
      }
      expect(await storedVersions(appId)).toHaveLength(1);
    });
  });

  describe("one version", () => {
    it("reads the Rules of a published version, and 404 for one that is not there", async () => {
      const appId = await freshApp();
      clock.now = new Date(T0 + 5_000);
      const first = await publishPolicy(api, adminA, appId, "development", [monitorRule, enforceRule]);
      await publishPolicy(api, adminA, appId, "development", []);

      const res = await api.app.request(policyPath(appId, "development", "/versions/1"), { headers: bearer(adminA) });
      expect(res.status).toBe(200);
      expect(res.headers.get("cache-control")).toBe("no-store");
      expect(PolicyResponseSchema.parse(await res.json()).policy).toEqual(first);

      for (const version of ["3", "0", "-1", "1.5", "abc", "2147483648", "99999999999999999999"]) {
        const missing = await api.app.request(policyPath(appId, "development", `/versions/${version}`), {
          headers: bearer(adminA),
        });
        await expectProblem(missing, 404);
      }
      await expectProblem(
        await api.app.request(policyPath(appId, "staging", "/versions/1"), { headers: bearer(adminA) }),
        404,
      );
    });

    it("answers 404 to another Organization and 403 to a Shield key", async () => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      const path = policyPath(appId, "development", "/versions/1");
      await expectProblem(await api.app.request(path, { headers: bearer(adminB) }), 404);
      await expectProblem(await api.app.request(path, { headers: bearer(shieldA) }), 403);
      await expectProblem(await api.app.request(path), 401);
    });
  });

  describe("expected version", () => {
    const CONFLICT = {
      type: "https://antireverse.dev/problems/conflict",
      title: "Conflict",
      status: 409,
      detail: "This resource was changed by someone else in the meantime. Reload it and try again.",
    };

    function publishOver(appId: string, body: Record<string, unknown>): Promise<Response> {
      return Promise.resolve(api.app.request(policyPath(appId, "development"), put(body, withReason(bearer(adminA)))));
    }
    function rollbackOver(appId: string, body: Record<string, unknown>): Promise<Response> {
      return Promise.resolve(
        api.app.request(policyPath(appId, "development", "/rollback"), json(body, withReason(bearer(adminA)))),
      );
    }

    it("publishes when the expected version is the current one, also version 0 before the first publish", async () => {
      const appId = await freshApp();

      const first = await publishOver(appId, { rules: [monitorRule], expected_version: 0 });
      expect(first.status).toBe(201);
      expect(PolicyResponseSchema.parse(await first.json()).policy.version).toBe(1);

      const second = await publishOver(appId, { rules: [enforceRule], expected_version: 1 });
      expect(second.status).toBe(201);
      expect(PolicyResponseSchema.parse(await second.json()).policy.version).toBe(2);
      expect(await storedVersions(appId)).toHaveLength(2);
    });

    it.each([
      ["an older version", 1],
      ["a version that does not exist yet", 3],
    ])("answers 409 conflict for %s, and stores nothing", async (_label, expected) => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      const current = await publishPolicy(api, adminA, appId, "development", [enforceRule]);

      const res = await publishOver(appId, { rules: [monitorRule, enforceRule], expected_version: expected });

      const problem = await expectProblem(res, 409);
      expect(problem).toEqual(CONFLICT);
      // Says nothing about the Rules of either version.
      expect(JSON.stringify(problem)).not.toMatch(/Admin area|User export|\/api\/|rul_|aro_/);
      expect(await storedVersions(appId)).toHaveLength(2);
      expect(await readPolicy(appId)).toEqual(current);
    });

    it("refuses an expected version that is not a whole number of 0 or more", async () => {
      const appId = await freshApp();
      for (const expected of [-1, 1.5, "0", null]) {
        const problem = await expectProblem(await publishOver(appId, { rules: [], expected_version: expected }), 400);
        expect(problem.errors?.[0]?.path).toBe("expected_version");
      }
      expect(await storedVersions(appId)).toHaveLength(0);
    });

    it("lets exactly one of two publishes based on the same version through", async () => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "development", [monitorRule]);

      const responses = await Promise.all([
        publishOver(appId, { rules: [{ ...monitorRule, mode: "monitor" }], expected_version: 1 }),
        publishOver(appId, { rules: [enforceRule], expected_version: 1 }),
      ]);

      expect(responses.map((res) => res.status).sort()).toEqual([201, 409]);
      const winner = responses.find((res) => res.status === 201);
      const loser = responses.find((res) => res.status === 409);
      if (winner === undefined || loser === undefined) throw new Error("expected one 201 and one 409");
      const policy = PolicyResponseSchema.parse(await winner.json()).policy;
      expect(policy.version).toBe(2);
      expect(await expectProblem(loser, 409)).toEqual(CONFLICT);
      expect(await storedVersions(appId)).toHaveLength(2);
      expect(await readPolicy(appId)).toEqual(policy);
    });

    it("rolls back when the expected version is current, and answers 409 when it is not", async () => {
      const appId = await freshApp();
      const first = await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      await publishPolicy(api, adminA, appId, "development", [enforceRule]);

      const stale = await rollbackOver(appId, { version: 1, expected_version: 1 });
      expect(await expectProblem(stale, 409)).toEqual(CONFLICT);
      expect(await storedVersions(appId)).toHaveLength(2);

      const current = await rollbackOver(appId, { version: 1, expected_version: 2 });
      expect(current.status).toBe(201);
      const policy = PolicyResponseSchema.parse(await current.json()).policy;
      expect(policy.version).toBe(3);
      expect(policy.rules).toEqual(first.rules);
    });

    it("still requires the version of a rollback when the expected version is given", async () => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "development", [monitorRule]);
      const problem = await expectProblem(await rollbackOver(appId, { expected_version: 1 }), 400);
      expect(problem.errors?.map((error) => error.path)).toEqual(["version"]);
      expect(await storedVersions(appId)).toHaveLength(1);
    });
  });

  describe("HEAD", () => {
    it("answers like GET without a body, and holds nothing open", async () => {
      const appId = await freshApp();
      await publishPolicy(api, adminA, appId, "development", [monitorRule]);

      for (const path of [policyPath(appId, "development"), policyPath(appId, "development", "/versions")]) {
        for (let index = 0; index < 25; index++) {
          const res = await api.app.request(path, { method: "HEAD", headers: bearer(adminA) });
          expect(res.status).toBe(200);
          expect(res.headers.get("content-type")).toMatch(/^application\/json/);
          expect(await res.text()).toBe("");
        }
      }
      await tick();
      expect(api.bus.count()).toBe(0);
      // HEAD never publishes: the PUT and POST routes do not answer it.
      const rollback = await api.app.request(policyPath(appId, "development", "/rollback"), {
        method: "HEAD",
        headers: bearer(adminA),
      });
      expect(rollback.status).toBe(404);
      expect(await storedVersions(appId)).toHaveLength(1);
    });
  });

  it("never logs a key, a Rule or a request body", () => {
    expectNoKeyLogged(api);
    const log = api.logger.lines.join("\n");
    expect(log).not.toMatch(/Admin area|User export|\/api\/admin|\/api\/users|rul_/);
    expect(log).toContain("route=/v1/apps/:appId/policies/:environment status=201");
    expect(log).toContain("route=/v1/apps/:appId/policies/:environment/versions status=200");
    expect(log).toContain("route=/v1/apps/:appId/policies/:environment/rollback status=201");
    expect(log).toContain("route=/v1/apps/:appId/policies/:environment status=409");
    expect(log).toContain("route=/v1/apps/:appId/policies/:environment/rollback status=409");
  });
});
