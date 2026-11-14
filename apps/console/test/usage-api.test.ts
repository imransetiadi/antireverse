// @vitest-environment node
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  DeletionPendingError,
  getUsage,
  RateLimitedError,
  UnauthorizedError,
  ValidationError,
} from "@/lib/api.ts";
import { USAGE } from "./helpers/usage.ts";

// Slice 17a: the Console's client for `GET /v1/usage?month=YYYY-MM` — the month as given (the API validates it), the
// answer checked against the protocol, and each refusal as its own error.

const key = generateKey("admin").key;
const API = "http://api.test:9999";
const PROBLEMS = "https://antireverse.dev/problems/";

const fetchMock = vi.fn<typeof fetch>();
function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}
const problem = (status: number, kind: string, extra: Record<string, unknown> = {}) =>
  json(status, { type: `${PROBLEMS}${kind}`, title: "Problem", status, ...extra });
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
  vi.stubEnv("AR_API_URL", API);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("api client — usage", () => {
  it("reads the current month without a month, with the key", async () => {
    fetchMock.mockResolvedValueOnce(json(200, USAGE));
    expect(await getUsage(key)).toEqual(USAGE);
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/usage`);
    expect(init.method).toBe("GET");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("sends the month as given, encoded: the API is the one that validates it", async () => {
    fetchMock.mockResolvedValueOnce(json(200, USAGE));
    await getUsage(key, "2026-11");
    expect(lastCall().url).toBe(`${API}/v1/usage?month=2026-11`);
    fetchMock.mockResolvedValueOnce(json(200, USAGE));
    await getUsage(key, "2026/11&x=1");
    expect(lastCall().url).toBe(`${API}/v1/usage?month=2026%2F11%26x%3D1`);
  });

  it("refuses an answer outside the contract", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { ...USAGE, seats: 3 }));
    const error = await caught(getUsage(key));
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(502);
  });

  it("turns each refusal into its error: 400 with the path and message, 401, 403 pending, 429 with Retry-After", async () => {
    fetchMock.mockResolvedValueOnce(
      problem(400, "validation", { errors: [{ path: "month", message: "The month is in the future." }] }),
    );
    const invalid = await caught(getUsage(key, "2027-01"));
    expect(invalid).toBeInstanceOf(ValidationError);
    expect((invalid as ValidationError).errors).toEqual([{ path: "month", message: "The month is in the future." }]);

    fetchMock.mockResolvedValueOnce(problem(401, "unauthorized"));
    expect(await caught(getUsage(key))).toBeInstanceOf(UnauthorizedError);

    fetchMock.mockResolvedValueOnce(problem(403, "organization-deletion-pending"));
    expect(await caught(getUsage(key))).toBeInstanceOf(DeletionPendingError);

    fetchMock.mockResolvedValueOnce(
      json(
        429,
        { type: `${PROBLEMS}too-many-requests`, title: "Too many requests", status: 429 },
        { "retry-after": "42" },
      ),
    );
    const limited = await caught(getUsage(key));
    expect(limited).toBeInstanceOf(RateLimitedError);
    expect((limited as RateLimitedError).retryAfter).toBe(42);
  });
});
