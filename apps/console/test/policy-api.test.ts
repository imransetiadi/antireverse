// @vitest-environment node
import { EXAMPLE_POLICY, EXAMPLE_POLICY_RULE } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  ConflictError,
  getPolicy,
  getPolicyVersion,
  getSigningKey,
  listPolicyVersions,
  NotFoundError,
  publishPolicy,
  rollbackPolicy,
  UnauthorizedError,
  ValidationError,
} from "@/lib/api.ts";

const key = generateKey("admin").key;
const appId = EXAMPLE_POLICY.app_id;
const base = `http://api.test:9999/v1/apps/${appId}/policies`;
const signingKey = { key_id: "0123456789abcdef", algorithm: "Ed25519", public_key: "A".repeat(43) };
const versions = [
  { version: 2, published_at: "2026-11-10T09:00:00.000Z", rule_count: 2, enforced_count: 1 },
  { version: 1, published_at: "2026-11-10T08:00:00.000Z", rule_count: 1, enforced_count: 0 },
];

const fetchMock = vi.fn<typeof fetch>();

function json(status: number, body: unknown, contentType = "application/json"): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": contentType } });
}
function problem(status: number, extra: Record<string, unknown> = {}): Response {
  return json(status, { type: "about:blank", title: "Problem", status, ...extra }, "application/problem+json");
}
function lastCall(): { url: string; init: RequestInit; headers: Headers } {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  const init = (call[1] ?? {}) as RequestInit;
  return { url: String(call[0]), init, headers: new Headers(init.headers) };
}
async function caught(promise: Promise<unknown>): Promise<Error> {
  try {
    await promise;
  } catch (error) {
    return error as Error;
  }
  throw new Error("expected a rejection");
}

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("AR_API_URL", "http://api.test:9999");
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("api client — Policy requests", () => {
  it("reads the signing key without sending a key: the route needs none", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { ...signingKey, private_key: "stripped" }));
    expect(await getSigningKey()).toEqual(signingKey);
    const { url, init, headers } = lastCall();
    expect(url).toBe("http://api.test:9999/v1/signing-key");
    expect(init.method ?? "GET").toBe("GET");
    expect(init.cache).toBe("no-store");
    expect(headers.has("authorization")).toBe(false);
  });

  it("reads the Policy of an App and Environment with the session key", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { policy: { ...EXAMPLE_POLICY, secret: "stripped" } }));
    expect(await getPolicy(key, appId, "development")).toEqual({ policy: EXAMPLE_POLICY });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${base}/development`);
    expect(init.method ?? "GET").toBe("GET");
    expect(init.cache).toBe("no-store");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("publishes the full Rule list with PUT and returns the new Policy", async () => {
    const published = { ...EXAMPLE_POLICY, environment: "production", version: 2 };
    fetchMock.mockResolvedValueOnce(json(201, { policy: published }));
    const rules = [EXAMPLE_POLICY_RULE, { name: "Login", path: "/login", methods: ["POST"] }];
    expect(await publishPolicy(key, appId, "production", rules, 1)).toEqual({ policy: published });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${base}/production`);
    expect(init.method).toBe("PUT");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
    expect(headers.get("content-type")).toBe("application/json");
    // Existing Rules travel with their id so that the API keeps it; a new Rule has none.
    // With the version the Rules were read from: the API refuses the publish when that is no longer current.
    expect(JSON.parse(String(init.body))).toEqual({ rules, expected_version: 1 });
  });

  it("acknowledges broad Enforce Rules only when asked to: allow_broad on publish and rollback", async () => {
    const rules = [{ ...EXAMPLE_POLICY_RULE, path: "/*" }];
    fetchMock.mockResolvedValueOnce(json(201, { policy: EXAMPLE_POLICY }));
    await publishPolicy(key, appId, "production", rules, 1, { allowBroad: true });
    expect(JSON.parse(String(lastCall().init.body))).toEqual({ rules, expected_version: 1, allow_broad: true });

    fetchMock.mockResolvedValueOnce(json(201, { policy: EXAMPLE_POLICY }));
    await rollbackPolicy(key, appId, "production", 1, 2, { allowBroad: true });
    expect(JSON.parse(String(lastCall().init.body))).toEqual({ version: 1, expected_version: 2, allow_broad: true });

    fetchMock.mockResolvedValueOnce(json(201, { policy: EXAMPLE_POLICY }));
    await rollbackPolicy(key, appId, "production", 1, 2);
    expect(JSON.parse(String(lastCall().init.body))).toEqual({ version: 1, expected_version: 2 });
  });

  it("reads one published version with its Rules", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { policy: EXAMPLE_POLICY }));
    expect(await getPolicyVersion(key, appId, "staging", 1)).toEqual({ policy: EXAMPLE_POLICY });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${base}/staging/versions/1`);
    expect(init.method ?? "GET").toBe("GET");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);

    fetchMock.mockResolvedValueOnce(problem(404));
    expect(await caught(getPolicyVersion(key, appId, "staging", 9))).toBeInstanceOf(NotFoundError);
  });

  it("lists the versions of a Policy, newest first as the API returns them", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { versions }));
    expect(await listPolicyVersions(key, appId, "staging")).toEqual({ versions });
    const { url, headers } = lastCall();
    expect(url).toBe(`${base}/staging/versions`);
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("rolls back with POST { version, expected_version } and returns the new Policy", async () => {
    const rolledBack = { ...EXAMPLE_POLICY, version: 3 };
    fetchMock.mockResolvedValueOnce(json(201, { policy: rolledBack }));
    expect(await rollbackPolicy(key, appId, "development", 1, 2)).toEqual({ policy: rolledBack });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${base}/development/rollback`);
    expect(init.method).toBe("POST");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
    expect(JSON.parse(String(init.body))).toEqual({ version: 1, expected_version: 2 });
  });

  it("never lets an identifier change the path of a request", async () => {
    fetchMock.mockResolvedValueOnce(problem(404));
    await caught(getPolicy(key, "app_x/../../organization", "development"));
    expect(lastCall().url).toBe("http://api.test:9999/v1/apps/app_x%2F..%2F..%2Forganization/policies/development");
  });
});

describe("api client — Policy errors", () => {
  it("turns a response that fails its schema into ApiError", async () => {
    const responses: Array<[() => Promise<unknown>, unknown]> = [
      [() => getSigningKey(), { ...signingKey, public_key: "short" }],
      [() => getSigningKey(), { ...signingKey, algorithm: "RSA" }],
      [() => getPolicy(key, appId, "development"), { policy: { ...EXAMPLE_POLICY, version: -1 } }],
      [
        () => publishPolicy(key, appId, "development", [], 0),
        { policy: { ...EXAMPLE_POLICY, rules: [{ id: "rul_1" }] } },
      ],
      [() => listPolicyVersions(key, appId, "development"), { versions: [{ version: 0 }] }],
      [() => rollbackPolicy(key, appId, "development", 1, 2), { policy: null }],
    ];
    for (const [request, body] of responses) {
      fetchMock.mockResolvedValueOnce(json(200, body));
      const error = await caught(request());
      expect(error).toBeInstanceOf(ApiError);
      expect(error).not.toBeInstanceOf(ValidationError);
      expect((error as ApiError).status).toBe(502);
    }
  });

  it("maps 400 to ValidationError carrying the path of the Rule and field", async () => {
    const errors = [{ path: "rules.1.path", message: "Must be a path pattern" }];
    fetchMock.mockResolvedValueOnce(problem(400, { errors }));
    const error = await caught(publishPolicy(key, appId, "development", [EXAMPLE_POLICY_RULE], 1));
    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ValidationError).errors).toEqual(errors);
  });

  it("maps 401 to UnauthorizedError and 404 to NotFoundError on every Policy call that needs a key", async () => {
    const requests = [
      () => getPolicy(key, appId, "development"),
      () => publishPolicy(key, appId, "development", [], 0),
      () => listPolicyVersions(key, appId, "development"),
      () => rollbackPolicy(key, appId, "development", 7, 8),
    ];
    for (const request of requests) {
      fetchMock.mockResolvedValueOnce(problem(401));
      expect(await caught(request())).toBeInstanceOf(UnauthorizedError);
      fetchMock.mockResolvedValueOnce(problem(404));
      expect(await caught(request())).toBeInstanceOf(NotFoundError);
    }
  });

  it("maps 409 to ConflictError on publish and rollback, without the API's words beyond its title", async () => {
    const requests = [
      () => publishPolicy(key, appId, "development", [EXAMPLE_POLICY_RULE], 1),
      () => rollbackPolicy(key, appId, "development", 1, 2),
    ];
    for (const request of requests) {
      fetchMock.mockResolvedValueOnce(
        problem(409, {
          type: "https://antireverse.dev/problems/conflict",
          title: "Policy changed",
          detail: `Published by ${key}`,
        }),
      );
      const error = await caught(request());
      expect(error).toBeInstanceOf(ConflictError);
      expect(error).toBeInstanceOf(ApiError);
      expect((error as ApiError).status).toBe(409);
      expect(error.message).not.toContain(key);
    }
  });

  it("maps a failure of the signing key route and a network failure to a plain ApiError", async () => {
    fetchMock.mockResolvedValueOnce(problem(500));
    const failed = await caught(getSigningKey());
    expect(failed).toBeInstanceOf(ApiError);
    expect((failed as ApiError).status).toBe(500);

    fetchMock.mockRejectedValueOnce(new TypeError(`fetch failed for Bearer ${key}`));
    const unreachable = await caught(rollbackPolicy(key, appId, "development", 1, 2));
    expect((unreachable as ApiError).status).toBe(0);
    expect(unreachable.message).not.toContain(key);
  });

  it("never puts a key into an error message, even when the API echoes one", async () => {
    const echo = `The key ${key} was refused`;
    fetchMock.mockResolvedValueOnce(
      problem(400, { title: echo, detail: echo, errors: [{ path: "rules.0.name", message: echo }] }),
    );
    const error = await caught(publishPolicy(key, appId, "development", [EXAMPLE_POLICY_RULE], 1));
    const visible = JSON.stringify([error.message, error.stack, (error as ValidationError).errors]);
    expect(visible).not.toContain(key);
    expect(visible).not.toContain(key.slice(4));
  });
});
