// @vitest-environment node
import {
  EXAMPLE_RULES_OF_ENGAGEMENT,
  EXAMPLE_TARGET,
  type SignRulesOfEngagementRequest,
  verificationInstructions,
} from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  ConflictError,
  checkAuthorization,
  createTarget,
  deleteTarget,
  getCurrentRulesOfEngagement,
  getTarget,
  listRulesOfEngagement,
  listTargets,
  NotFoundError,
  RateLimitedError,
  signRulesOfEngagement,
  ValidationError,
  verifyTarget,
} from "@/lib/api.ts";

// Slice 14: the Console's client for Verified Targets, Rules of Engagement and the dry authorization check.

const key = generateKey("admin").key;
const API = "http://api.test:9999";
const TOKEN = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789_-AbCdE";
const targetId = EXAMPLE_TARGET.id;
const targetResponse = { target: EXAMPLE_TARGET, verification: verificationInstructions(EXAMPLE_TARGET.host, TOKEN) };
const signRequest: SignRulesOfEngagementRequest = {
  scope: [targetId],
  exclusions: ["/admin"],
  intensity: "safe-active",
  window: { days: ["mon"], from: "09:00", to: "17:00" },
  contacts: ["security@acme-shop.io"],
  confirm: "I authorise safe-active testing",
};

const fetchMock = vi.fn<typeof fetch>();
function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}
function problem(status: number, extra: Record<string, unknown> = {}, headers: Record<string, string> = {}): Response {
  return json(status, { type: "about:blank", title: "Refused", status, ...extra }, headers);
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

describe("api client — targets", () => {
  it("lists the targets with the admin key", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { targets: [EXAMPLE_TARGET] }));
    expect(await listTargets(key)).toEqual({ targets: [EXAMPLE_TARGET] });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/targets`);
    expect(init.method).toBe("GET");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("adds a host: POST with the host, 201 returns the target and how to prove it", async () => {
    fetchMock.mockResolvedValueOnce(json(201, targetResponse));
    expect(await createTarget(key, { host: "shop.acme-shop.io" })).toEqual(targetResponse);
    const { url, init, body } = lastCall();
    expect(url).toBe(`${API}/v1/targets`);
    expect(init.method).toBe("POST");
    expect(body).toEqual({ host: "shop.acme-shop.io" });
  });

  it("passes the API's field errors on as a ValidationError", async () => {
    fetchMock.mockResolvedValueOnce(problem(400, { errors: [{ path: "host", message: "Must be a public DNS name" }] }));
    const error = await caught(createTarget(key, { host: "10.0.0.1" }));
    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ValidationError).errors).toEqual([{ path: "host", message: "Must be a public DNS name" }]);
  });

  it("reads one target with its instructions, and refuses instructions of another host", async () => {
    fetchMock.mockResolvedValueOnce(json(200, targetResponse));
    expect(await getTarget(key, targetId)).toEqual(targetResponse);
    expect(lastCall().url).toBe(`${API}/v1/targets/${targetId}`);
    const wrong = { ...targetResponse, verification: verificationInstructions("other.acme-shop.io", TOKEN) };
    fetchMock.mockResolvedValueOnce(json(200, wrong));
    const error = await caught(getTarget(key, targetId));
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(502);
  });

  it("removes a target with DELETE; a target in the current scope rejects with ConflictError", async () => {
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));
    await deleteTarget(key, targetId);
    expect(lastCall().url).toBe(`${API}/v1/targets/${targetId}`);
    expect(lastCall().init.method).toBe("DELETE");
    fetchMock.mockResolvedValueOnce(problem(409));
    expect(await caught(deleteTarget(key, targetId))).toBeInstanceOf(ConflictError);
    fetchMock.mockResolvedValueOnce(problem(404));
    expect(await caught(deleteTarget(key, targetId))).toBeInstanceOf(NotFoundError);
  });

  it("verifies a target: POST …/verify returns the target and the outcome; 429 carries Retry-After", async () => {
    const outcome = {
      target: EXAMPLE_TARGET,
      result: { verified: false, dns: "no_record", file: "timeout", checked_at: "2026-11-12T08:05:00.000Z" },
    };
    fetchMock.mockResolvedValueOnce(json(200, outcome));
    expect(await verifyTarget(key, targetId)).toEqual(outcome);
    expect(lastCall().url).toBe(`${API}/v1/targets/${targetId}/verify`);
    expect(lastCall().init.method).toBe("POST");
    fetchMock.mockResolvedValueOnce(problem(429, {}, { "retry-after": "1200" }));
    const limited = await caught(verifyTarget(key, targetId));
    expect(limited).toBeInstanceOf(RateLimitedError);
    expect((limited as RateLimitedError).retryAfter).toBe(1200);
  });

  it("puts the target id into the path encoded", async () => {
    fetchMock.mockResolvedValueOnce(problem(404));
    await caught(getTarget(key, "a/b?c"));
    expect(lastCall().url).toBe(`${API}/v1/targets/a%2Fb%3Fc`);
  });
});

describe("api client — Rules of Engagement", () => {
  it("lists the versions newest first and reads the current one, null before the first", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { versions: [EXAMPLE_RULES_OF_ENGAGEMENT] }));
    expect(await listRulesOfEngagement(key)).toEqual({ versions: [EXAMPLE_RULES_OF_ENGAGEMENT] });
    expect(lastCall().url).toBe(`${API}/v1/rules-of-engagement`);
    fetchMock.mockResolvedValueOnce(json(200, { version: null }));
    expect(await getCurrentRulesOfEngagement(key)).toEqual({ version: null });
    expect(lastCall().url).toBe(`${API}/v1/rules-of-engagement/current`);
  });

  it("signs a version: POST with the content and the typed phrase, 201 returns the version", async () => {
    fetchMock.mockResolvedValueOnce(json(201, { version: EXAMPLE_RULES_OF_ENGAGEMENT }));
    expect(await signRulesOfEngagement(key, signRequest)).toEqual({ version: EXAMPLE_RULES_OF_ENGAGEMENT });
    const { url, init, body } = lastCall();
    expect(url).toBe(`${API}/v1/rules-of-engagement`);
    expect(init.method).toBe("POST");
    expect(body).toEqual(signRequest);
  });
});

describe("api client — authorize", () => {
  it("checks a test: POST /v1/prove/authorize returns allowed or the reason", async () => {
    const request = { host: "shop.acme-shop.io", path: "/", intensity: "passive" as const, at: "2026-11-12T10:00:00Z" };
    fetchMock.mockResolvedValueOnce(json(200, { allowed: false, reason: "outside_window" }));
    expect(await checkAuthorization(key, request)).toEqual({ allowed: false, reason: "outside_window" });
    const { url, init, body } = lastCall();
    expect(url).toBe(`${API}/v1/prove/authorize`);
    expect(init.method).toBe("POST");
    expect(body).toEqual(request);
    fetchMock.mockResolvedValueOnce(json(200, { allowed: true, roe_id: EXAMPLE_RULES_OF_ENGAGEMENT.id }));
    expect(await checkAuthorization(key, request)).toEqual({ allowed: true, roe_id: EXAMPLE_RULES_OF_ENGAGEMENT.id });
  });
});
