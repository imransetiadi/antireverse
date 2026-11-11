// @vitest-environment node
import { EXAMPLE_POLICY, EXAMPLE_SIMULATION_RESULT } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, NotFoundError, RateLimitedError, simulatePolicy, ValidationError } from "@/lib/api.ts";

// `POST /v1/apps/:appId/policy/simulate` as the Console calls it (slice 11).

const key = generateKey("admin").key;
const appId = EXAMPLE_POLICY.app_id;
const url = `http://api.test:9999/v1/apps/${appId}/policy/simulate`;

const fetchMock = vi.fn<typeof fetch>();

function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}
function problem(status: number, extra: Record<string, unknown> = {}, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify({ type: "about:blank", title: "Problem", status, ...extra }), {
    status,
    headers: { "content-type": "application/problem+json", ...headers },
  });
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

describe("simulatePolicy", () => {
  it("posts the Environment and the Rules with the admin key and returns the validated result", async () => {
    fetchMock.mockResolvedValue(json(200, { simulation: EXAMPLE_SIMULATION_RESULT, extra: "dropped" }));
    const answer = await simulatePolicy(key, appId, "staging", EXAMPLE_POLICY.rules);
    expect(answer).toEqual({ simulation: EXAMPLE_SIMULATION_RESULT });

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [calledUrl, init] = fetchMock.mock.calls[0] as [string, RequestInit];
    expect(calledUrl).toBe(url);
    expect(init.method).toBe("POST");
    expect(init.cache).toBe("no-store");
    const headers = new Headers(init.headers);
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
    expect(headers.get("content-type")).toBe("application/json");
    // Nothing of a publish travels: no expected version, no acknowledgement.
    expect(JSON.parse(String(init.body))).toEqual({ environment: "staging", rules: EXAMPLE_POLICY.rules });
  });

  it("rejects a 429 with RateLimitedError carrying the whole seconds of Retry-After", async () => {
    fetchMock.mockResolvedValue(problem(429, {}, { "retry-after": "42" }));
    const error = await caught(simulatePolicy(key, appId, "staging", []));
    expect(error).toBeInstanceOf(RateLimitedError);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as RateLimitedError).status).toBe(429);
    expect((error as RateLimitedError).retryAfter).toBe(42);
    expect(error.message).not.toContain(key);
  });

  it.each([
    ["no header", undefined],
    ["a date", "Wed, 11 Nov 2026 09:00:00 GMT"],
    ["a negative number", "-3"],
    ["a fraction", "1.5"],
    ["more digits than a wait can have", "1234567"],
  ])("leaves the wait unknown for %s", async (_name, value) => {
    fetchMock.mockResolvedValue(problem(429, {}, value === undefined ? {} : { "retry-after": value }));
    const error = await caught(simulatePolicy(key, appId, "staging", []));
    expect(error).toBeInstanceOf(RateLimitedError);
    expect((error as RateLimitedError).retryAfter).toBeUndefined();
  });

  it("rejects a 400 with ValidationError that says where, and a 404 with NotFoundError", async () => {
    fetchMock.mockResolvedValue(
      problem(400, { errors: [{ path: "rules.2.path", message: "Must be a path pattern" }] }),
    );
    const refused = await caught(simulatePolicy(key, appId, "staging", []));
    expect(refused).toBeInstanceOf(ValidationError);
    expect((refused as ValidationError).errors).toEqual([{ path: "rules.2.path", message: "Must be a path pattern" }]);

    fetchMock.mockResolvedValue(problem(404));
    expect(await caught(simulatePolicy(key, appId, "staging", []))).toBeInstanceOf(NotFoundError);
  });

  it("rejects a result that breaks the contract, and a failed transport, without the key", async () => {
    const [first] = EXAMPLE_SIMULATION_RESULT.rules;
    fetchMock.mockResolvedValue(
      json(200, { simulation: { ...EXAMPLE_SIMULATION_RESULT, rules: [{ ...first, would_block: 1_000_000 }] } }),
    );
    const broken = await caught(simulatePolicy(key, appId, "staging", []));
    expect(broken).toBeInstanceOf(ApiError);
    expect((broken as ApiError).status).toBe(502);

    fetchMock.mockRejectedValue(new Error(`connect ECONNREFUSED with ${key}`));
    const down = await caught(simulatePolicy(key, appId, "staging", []));
    expect((down as ApiError).status).toBe(0);
    expect(down.message).not.toContain(key);
  });
});
