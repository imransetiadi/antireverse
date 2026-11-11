// @vitest-environment node
import { EXAMPLE_ALLOWLIST_ENTRY, EXAMPLE_CONTAINMENT, EXAMPLE_INCIDENT } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  ConflictError,
  createAllowlistEntry,
  createContainment,
  deleteAllowlistEntry,
  liftContainment,
  listAllowlist,
  listContainments,
  NotFoundError,
  UnauthorizedError,
  ValidationError,
} from "@/lib/api.ts";

// Slice 09, contract P4: the Console's client for containment and the never-block list.

const admin = generateKey("admin");
const key = admin.key;
const API = "http://api.test:9999";
const incidentId = EXAMPLE_INCIDENT.id;
const containmentId = EXAMPLE_CONTAINMENT.id;
const entryId = EXAMPLE_ALLOWLIST_ENTRY.id;
const HASH = "iph_2932b22cf89905dbc929c64247ddad3e";
const lifted = {
  ...EXAMPLE_CONTAINMENT,
  status: "lifted" as const,
  lifted_at: "2026-11-10T08:40:00.000Z",
  lifted_by: "key_0123456789abcdef01234567",
};

const fetchMock = vi.fn<typeof fetch>();

function json(status: number, body: unknown, contentType = "application/json"): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": contentType } });
}
function problem(status: number, extra: Record<string, unknown> = {}): Response {
  return json(status, { type: "about:blank", title: "Conflict", status, ...extra }, "application/problem+json");
}
function lastCall(): { url: string; init: RequestInit; headers: Headers; body: unknown } {
  const call = fetchMock.mock.calls.at(-1);
  if (!call) throw new Error("fetch was not called");
  const init = (call[1] ?? {}) as RequestInit;
  const body = typeof init.body === "string" ? JSON.parse(init.body) : undefined;
  return { url: String(call[0]), init, headers: new Headers(init.headers), body };
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
  vi.stubEnv("AR_API_URL", API);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("api client — containments", () => {
  it("blocks an Actor of an Incident: POST with the target and the TTL, 201 returns the block", async () => {
    fetchMock.mockResolvedValueOnce(json(201, { containment: EXAMPLE_CONTAINMENT }));
    const body = { target: { kind: "actor" as const, ip_hash: HASH }, ttl_s: 3600 as const };
    expect(await createContainment(key, incidentId, body)).toEqual({ containment: EXAMPLE_CONTAINMENT });
    const { url, init, headers, body: sentBody } = lastCall();
    expect(url).toBe(`${API}/v1/incidents/${incidentId}/containments`);
    expect(init.method).toBe("POST");
    expect(init.cache).toBe("no-store");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
    expect(headers.get("content-type")).toBe("application/json");
    expect(sentBody).toEqual(body);
  });

  it("blocks the network with the typed prefix as confirm_prefix; 200 (an identical active block) also resolves", async () => {
    const network = {
      ...EXAMPLE_CONTAINMENT,
      target: { kind: "prefix" as const, ip_prefix: "203.0.113.0/24" },
    };
    fetchMock.mockResolvedValueOnce(json(200, { containment: network }));
    const body = { target: { kind: "prefix" as const }, ttl_s: 900 as const, confirm_prefix: "203.0.113.0/24" };
    expect(await createContainment(key, incidentId, body)).toEqual({ containment: network });
    expect(lastCall().body).toEqual(body);
  });

  it("encodes the identifiers in the paths", async () => {
    fetchMock.mockResolvedValueOnce(problem(404, { title: "Not found" }));
    await caught(createContainment(key, "inc/../x", { target: { kind: "actor", ip_hash: HASH }, ttl_s: 900 }));
    expect(lastCall().url).toBe(`${API}/v1/incidents/inc%2F..%2Fx/containments`);
    fetchMock.mockResolvedValueOnce(problem(404, { title: "Not found" }));
    await caught(liftContainment(key, "cnt/../x"));
    expect(lastCall().url).toBe(`${API}/v1/containments/cnt%2F..%2Fx/lift`);
  });

  it("maps 409 (resolved Incident, overlap, cap reached) to ConflictError naming the request and the status", async () => {
    fetchMock.mockResolvedValueOnce(problem(409));
    const error = await caught(
      createContainment(key, incidentId, { target: { kind: "actor", ip_hash: HASH }, ttl_s: 3600 }),
    );
    expect(error).toBeInstanceOf(ConflictError);
    expect((error as ApiError).status).toBe(409);
    expect(error.message).toBe(`POST /v1/incidents/${incidentId}/containments failed with status 409: Conflict`);
    // Without a reason the conflict is unexplained.
    expect((error as ConflictError).reason).toBeUndefined();
  });

  it.each(["incident-resolved", "actor-unknown", "prefix-allowlisted", "containment-limit"] as const)(
    "carries the API's conflict reason %s on ConflictError",
    async (reason) => {
      fetchMock.mockResolvedValueOnce(problem(409, { reason }));
      const error = await caught(
        createContainment(key, incidentId, { target: { kind: "actor", ip_hash: HASH }, ttl_s: 3600 }),
      );
      expect(error).toBeInstanceOf(ConflictError);
      expect((error as ConflictError).reason).toBe(reason);
      expect(fetchMock).toHaveBeenCalledTimes(1);
    },
  );

  it("drops a reason the contract does not know", async () => {
    fetchMock.mockResolvedValueOnce(problem(409, { reason: "something-else" }));
    const error = await caught(liftContainment(key, containmentId));
    expect(error).toBeInstanceOf(ConflictError);
    expect((error as ConflictError).reason).toBeUndefined();
  });

  it("maps 404 to NotFoundError and 400 to ValidationError", async () => {
    fetchMock.mockResolvedValueOnce(problem(404, { title: "Not found" }));
    expect(
      await caught(createContainment(key, incidentId, { target: { kind: "actor", ip_hash: HASH }, ttl_s: 3600 })),
    ).toBeInstanceOf(NotFoundError);
    fetchMock.mockResolvedValueOnce(
      problem(400, { title: "Invalid request", errors: [{ path: "confirm_prefix", message: "Invalid" }] }),
    );
    const invalid = await caught(
      createContainment(key, incidentId, { target: { kind: "prefix" }, ttl_s: 3600, confirm_prefix: "203.0.113.0/24" }),
    );
    expect(invalid).toBeInstanceOf(ValidationError);
    expect((invalid as ValidationError).errors.map((entry) => entry.path)).toEqual(["confirm_prefix"]);
  });

  it("lifts a block: POST to its lift route returns the lifted block", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { containment: lifted }));
    expect(await liftContainment(key, containmentId)).toEqual({ containment: lifted });
    const { url, init } = lastCall();
    expect(url).toBe(`${API}/v1/containments/${containmentId}/lift`);
    expect(init.method).toBe("POST");
  });

  it("maps 409 on lift (already lifted or expired) to ConflictError and 404 to NotFoundError", async () => {
    fetchMock.mockResolvedValueOnce(problem(409, { reason: "containment-ended" }));
    const error = await caught(liftContainment(key, containmentId));
    expect(error).toBeInstanceOf(ConflictError);
    expect((error as ConflictError).reason).toBe("containment-ended");
    expect(error.message).toBe(`POST /v1/containments/${containmentId}/lift failed with status 409: Conflict`);
    fetchMock.mockResolvedValueOnce(problem(404, { title: "Not found" }));
    expect(await caught(liftContainment(key, containmentId))).toBeInstanceOf(NotFoundError);
  });

  it("lists blocks, unfiltered or by App, Environment and status", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { containments: [EXAMPLE_CONTAINMENT] }));
    expect(await listContainments(key)).toEqual({ containments: [EXAMPLE_CONTAINMENT] });
    expect(lastCall().url).toBe(`${API}/v1/containments`);

    fetchMock.mockResolvedValueOnce(json(200, { containments: [] }));
    await listContainments(key, { status: "active" });
    expect(lastCall().url).toBe(`${API}/v1/containments?status=active`);

    fetchMock.mockResolvedValueOnce(json(200, { containments: [] }));
    await listContainments(key, { appId: EXAMPLE_CONTAINMENT.app_id, environment: "production", status: "active" });
    expect(lastCall().url).toBe(
      `${API}/v1/containments?app_id=${EXAMPLE_CONTAINMENT.app_id}&environment=production&status=active`,
    );
  });

  it("turns a response that fails the schema into ApiError 502", async () => {
    fetchMock.mockResolvedValueOnce(json(201, { containment: { ...EXAMPLE_CONTAINMENT, status: "paused" } }));
    const created = await caught(
      createContainment(key, incidentId, { target: { kind: "actor", ip_hash: HASH }, ttl_s: 3600 }),
    );
    expect(created).toBeInstanceOf(ApiError);
    expect((created as ApiError).status).toBe(502);

    // A lifted block must say who lifted it.
    fetchMock.mockResolvedValueOnce(json(200, { containment: { ...lifted, lifted_by: null } }));
    expect(((await caught(liftContainment(key, containmentId))) as ApiError).status).toBe(502);

    // A block carrying a full address instead of a prefix.
    fetchMock.mockResolvedValueOnce(
      json(200, { containments: [{ ...EXAMPLE_CONTAINMENT, target: { kind: "prefix", ip_prefix: "203.0.113.7" } }] }),
    );
    expect(((await caught(listContainments(key))) as ApiError).status).toBe(502);
  });

  it("maps 401 to UnauthorizedError", async () => {
    fetchMock.mockResolvedValueOnce(problem(401, { title: "Unauthorized" }));
    expect(await caught(listContainments(key))).toBeInstanceOf(UnauthorizedError);
  });
});

describe("api client — never block list", () => {
  it("lists the ranges", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { entries: [EXAMPLE_ALLOWLIST_ENTRY] }));
    expect(await listAllowlist(key)).toEqual({ entries: [EXAMPLE_ALLOWLIST_ENTRY] });
    const { url, headers } = lastCall();
    expect(url).toBe(`${API}/v1/allowlist`);
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("adds a range: POST with the CIDR and the note, 201 returns the entry", async () => {
    fetchMock.mockResolvedValueOnce(json(201, { entry: EXAMPLE_ALLOWLIST_ENTRY }));
    const input = { cidr: "198.51.100.0/24", note: "Office network" };
    expect(await createAllowlistEntry(key, input)).toEqual({ entry: EXAMPLE_ALLOWLIST_ENTRY });
    const { url, init, body } = lastCall();
    expect(url).toBe(`${API}/v1/allowlist`);
    expect(init.method).toBe("POST");
    expect(body).toEqual(input);
  });

  it("maps 409 on add to ConflictError and 400 at cidr to ValidationError", async () => {
    fetchMock.mockResolvedValueOnce(problem(409, { reason: "allowlist-limit" }));
    const conflict = await caught(createAllowlistEntry(key, { cidr: "198.51.100.0/24", note: "" }));
    expect(conflict).toBeInstanceOf(ConflictError);
    expect((conflict as ConflictError).reason).toBe("allowlist-limit");
    expect(conflict.message).toBe("POST /v1/allowlist failed with status 409: Conflict");

    fetchMock.mockResolvedValueOnce(
      problem(400, { title: "Invalid request", errors: [{ path: "cidr", message: "Must be a normalised CIDR" }] }),
    );
    const invalid = await caught(createAllowlistEntry(key, { cidr: "198.51.100.0/24", note: "" }));
    expect(invalid).toBeInstanceOf(ValidationError);
    expect((invalid as ValidationError).errors.map((entry) => entry.path)).toEqual(["cidr"]);
  });

  it("removes a range: 204 resolves; 404 is NotFoundError", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));
    await expect(deleteAllowlistEntry(key, entryId)).resolves.toBeUndefined();
    const { url, init } = lastCall();
    expect(url).toBe(`${API}/v1/allowlist/${entryId}`);
    expect(init.method).toBe("DELETE");

    fetchMock.mockResolvedValueOnce(problem(404, { title: "Not found" }));
    expect(await caught(deleteAllowlistEntry(key, entryId))).toBeInstanceOf(NotFoundError);
  });

  it("turns an entry or a list that fails the schema into ApiError 502", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { entries: [{ ...EXAMPLE_ALLOWLIST_ENTRY, cidr: "198.51.100.7/24" }] }));
    expect(((await caught(listAllowlist(key))) as ApiError).status).toBe(502);
    fetchMock.mockResolvedValueOnce(json(201, { entry: { ...EXAMPLE_ALLOWLIST_ENTRY, note: "x".repeat(81) } }));
    expect(((await caught(createAllowlistEntry(key, { cidr: "198.51.100.0/24", note: "" }))) as ApiError).status).toBe(
      502,
    );
  });

  it("never puts the key into a thrown message, even when the API echoes it", async () => {
    const echo = `key ${key}`;
    const calls = [
      () => createContainment(key, incidentId, { target: { kind: "actor", ip_hash: HASH }, ttl_s: 3600 }),
      () => liftContainment(key, containmentId),
      () => listContainments(key),
      () => listAllowlist(key),
      () => createAllowlistEntry(key, { cidr: "198.51.100.0/24", note: "" }),
      () => deleteAllowlistEntry(key, entryId),
    ];
    for (const run of calls) {
      for (const status of [400, 404, 409, 500]) {
        fetchMock.mockResolvedValueOnce(problem(status, { title: echo, errors: [{ path: "cidr", message: echo }] }));
        const error = await caught(run());
        const text = JSON.stringify([error.message, (error as Partial<ValidationError>).errors ?? []]);
        expect(text).not.toContain(key);
        expect(text).not.toContain(key.slice(4));
      }
    }
  });
});
