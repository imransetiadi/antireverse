import { generateKey, hashKey, newId } from "@antireverse/protocol/server";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { createApp } from "../src/app.ts";
import { createEventBus } from "../src/bus.ts";
import type { Db } from "../src/db/db.ts";
import {
  captureLogger,
  createAppFor,
  createOrganization,
  expectNoKeyLogged,
  expectProblem,
  json,
  makeTestApi,
  type TestApi,
} from "./helpers.ts";

describe("authentication", () => {
  let api: TestApi;
  let adminKey: string;
  let shieldKey: string;
  let appId: string;
  let organizationId: string;

  beforeAll(async () => {
    api = await makeTestApi();
    const organization = await createOrganization(api);
    adminKey = organization.admin_key.key;
    organizationId = organization.organization.id;
    const created = await createAppFor(api, adminKey);
    shieldKey = created.shield_key.key;
    appId = created.app.id;
  });
  afterAll(async () => {
    await api.close();
  });

  const adminRoutes = (): [string, string, RequestInit][] => [
    ["GET", "/v1/organization", {}],
    ["GET", "/v1/apps", {}],
    ["POST", "/v1/apps", json({ name: "Storefront" })],
    ["GET", `/v1/apps/${appId}`, {}],
  ];

  function call(path: string, init: RequestInit, authorization?: string): Promise<Response> {
    const headers = new Headers(init.headers);
    if (authorization !== undefined) headers.set("authorization", authorization);
    return Promise.resolve(api.app.request(path, { ...init, headers }));
  }

  it("answers 401 with WWW-Authenticate: Bearer when the key is missing, malformed or unknown", async () => {
    const unknown = generateKey("admin").key;
    api.issuedKeys.push(unknown);
    const attempts: [string, string | undefined][] = [
      ["no header", undefined],
      ["an empty header", ""],
      ["a scheme without a key", "Bearer"],
      ["a malformed key", "Bearer aro_short"],
      ["another scheme", `Basic ${adminKey}`],
      ["a key with trailing text", `Bearer ${adminKey} extra`],
      ["an unknown key", `Bearer ${unknown}`],
    ];
    const bodies = new Set<string>();
    for (const [method, path, init] of adminRoutes()) {
      for (const [label, authorization] of attempts) {
        const res = await call(path, init, authorization);
        expect(res.headers.get("www-authenticate"), `${method} ${path} with ${label}`).toBe("Bearer");
        const problem = await expectProblem(res, 401);
        bodies.add(JSON.stringify(problem));
        expect(JSON.stringify(problem)).not.toContain(unknown);
      }
    }
    // One answer for every cause: the response does not say whether a key exists.
    expect(bodies.size).toBe(1);
  });

  it("answers 403 when a Shield key is used where an admin key is required", async () => {
    for (const [method, path, init] of adminRoutes()) {
      const res = await call(path, init, `Bearer ${shieldKey}`);
      const problem = await expectProblem(res, 403);
      expect(res.headers.get("www-authenticate"), `${method} ${path}`).toBeNull();
      expect(JSON.stringify(problem)).not.toContain(shieldKey);
    }
  });

  it("accepts the scheme in any letter case", async () => {
    const res = await call("/v1/organization", {}, `bearer ${adminKey}`);
    expect(res.status).toBe(200);
  });

  it("answers 401 for a revoked admin key", async () => {
    const other = await createOrganization(api, "Revoked");
    await api.db.tx({ organizationId: other.organization.id }, (q) =>
      q.query("UPDATE api_keys SET revoked_at = now() WHERE key_hash = $1", [hashKey(other.admin_key.key)]),
    );
    const res = await call("/v1/organization", {}, `Bearer ${other.admin_key.key}`);
    await expectProblem(res, 401);
    expect(res.headers.get("www-authenticate")).toBe("Bearer");
  });

  it("answers 404 with a problem document for a route that does not exist, with or without a key", async () => {
    await expectProblem(await call("/v1/nothing-here", {}), 404);
    await expectProblem(await call("/", {}), 404);
    await expectProblem(await call("/v1/organizations", { method: "DELETE" }, `Bearer ${adminKey}`), 404);
  });

  it("answers 500 with a problem document that leaks nothing when something unexpected fails", async () => {
    const logger = captureLogger();
    const failing: Db = {
      tx: () => Promise.reject(new Error(`relation "secret_table" exploded for ${adminKey}`)),
      close: () => Promise.resolve(),
    };
    const app = createApp({ db: failing, bus: createEventBus(), signer: api.signer, logger });

    const res = await app.request("/v1/organizations", json({ name: "Acme" }));
    const problem = await expectProblem(res, 500);
    expect(JSON.stringify(problem)).not.toMatch(/secret_table|exploded|relation|aro_/);
    expect(problem.detail).toBeUndefined();

    // The failure is logged for the operator by kind only: an error message can quote request data.
    expect(logger.lines.some((line) => line.startsWith("error route=/v1/organizations Error"))).toBe(true);
    expect(logger.lines.join("\n")).not.toContain("secret_table");
    expect(logger.lines.join("\n")).not.toContain(adminKey);
    expect(logger.lines.join("\n")).not.toContain(adminKey.slice(4));
  });

  it("does not log a key that a client puts in the path, the query string or a body", async () => {
    await call(`/v1/apps/${adminKey}`, {}, `Bearer ${adminKey}`);
    await call(`/v1/apps?key=${adminKey}`, {}, `Bearer ${adminKey}`);
    await call(`/v1/unknown/${shieldKey}?token=${shieldKey}`, {});
    await call("/v1/apps", json({ name: shieldKey.slice(0, 60), environment: adminKey }), `Bearer ${adminKey}`);
    await call(`/v1/apps/${newId("app")}`, {}, `Bearer ${shieldKey}`);
    expectNoKeyLogged(api);
  });

  it("logs one line per request with the method, the route template, the status and the Organization", () => {
    const line = api.logger.lines.find((candidate) => candidate.includes("route=/v1/apps/:appId"));
    expect(line).toMatch(/^request method=GET route=\/v1\/apps\/:appId status=\d{3} ms=\d+/);
    expect(api.logger.lines.some((candidate) => candidate.includes(`organization=${organizationId}`))).toBe(true);
    expect(api.logger.lines.some((candidate) => candidate.includes(appId))).toBe(false);
  });
});
