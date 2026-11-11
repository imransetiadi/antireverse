// @vitest-environment node
import { EXAMPLE_ADVISORY, EXAMPLE_FINDING, type Finding } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  type ApiError,
  ConflictError,
  getFinding,
  ignoreFinding,
  listFindings,
  NotFoundError,
  reopenFinding,
  UnauthorizedError,
  ValidationError,
} from "@/lib/api.ts";

// Slice 19: the Finding endpoints of the API client. Every response is validated against the protocol.
const admin = generateKey("admin");
const key = admin.key;
const API = "http://api.test:9999";
const findingId = EXAMPLE_FINDING.id;
const IGNORED: Finding = {
  ...EXAMPLE_FINDING,
  status: "ignored",
  ignore: { reason: "Not reachable", until: "2026-12-10T00:00:00.000Z", by: "key_0123456789abcdef01234567" },
};

const fetchMock = vi.fn<typeof fetch>();

function json(status: number, body: unknown, contentType = "application/json"): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": contentType } });
}
function problem(status: number, extra: Record<string, unknown> = {}): Response {
  return json(status, { type: "about:blank", title: "Problem", status, ...extra }, "application/problem+json");
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

describe("api client — Findings", () => {
  it("lists Findings with the session key, without caching and without a filter", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { findings: [EXAMPLE_FINDING] }));
    expect(await listFindings(key)).toEqual({ findings: [EXAMPLE_FINDING] });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/findings`);
    expect(init.method ?? "GET").toBe("GET");
    expect(init.cache).toBe("no-store");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("passes every filter as a query parameter, in a fixed order", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { findings: [] }));
    await listFindings(key, { severity: "high" });
    expect(lastCall().url).toBe(`${API}/v1/findings?severity=high`);

    fetchMock.mockResolvedValueOnce(json(200, { findings: [] }));
    await listFindings(key, {
      source: "runtime",
      status: "ignored",
      severity: "unknown",
      environment: "production",
      appId: EXAMPLE_FINDING.app_id,
      buildId: "bld_0123456789abcdef01234567",
      advisoryId: "CVE-2026-10001",
    });
    expect(lastCall().url).toBe(
      `${API}/v1/findings?app_id=${EXAMPLE_FINDING.app_id}&environment=production&status=ignored&severity=unknown&source=runtime&advisory_id=CVE-2026-10001&build_id=bld_0123456789abcdef01234567`,
    );
  });

  it("filters by advisory (id or alias) and by Build on the server, encoded", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { findings: [EXAMPLE_FINDING] }));
    await listFindings(key, { advisoryId: "GHSA-2c3m-4p5q-6r7v" });
    expect(lastCall().url).toBe(`${API}/v1/findings?advisory_id=GHSA-2c3m-4p5q-6r7v`);
    fetchMock.mockResolvedValueOnce(json(200, { findings: [] }));
    await listFindings(key, { buildId: "bld_0123456789abcdef01234567", source: "build" });
    expect(lastCall().url).toBe(`${API}/v1/findings?source=build&build_id=bld_0123456789abcdef01234567`);
    fetchMock.mockResolvedValueOnce(json(200, { findings: [] }));
    await listFindings(key, { advisoryId: "X-a:b/c" });
    expect(lastCall().url).toBe(`${API}/v1/findings?advisory_id=X-a%3Ab%2Fc`);
  });

  it("reads one Finding with its advisory", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { finding: EXAMPLE_FINDING, advisory: EXAMPLE_ADVISORY }));
    expect(await getFinding(key, findingId)).toEqual({ finding: EXAMPLE_FINDING, advisory: EXAMPLE_ADVISORY });
    expect(lastCall().url).toBe(`${API}/v1/findings/${findingId}`);
  });

  it("encodes the identifier in every path", async () => {
    fetchMock.mockResolvedValueOnce(problem(404));
    await caught(getFinding(key, "fnd/../x"));
    expect(lastCall().url).toBe(`${API}/v1/findings/fnd%2F..%2Fx`);
    fetchMock.mockResolvedValueOnce(problem(404));
    await caught(reopenFinding(key, "fnd/../x"));
    expect(lastCall().url).toBe(`${API}/v1/findings/fnd%2F..%2Fx/reopen`);
  });

  it("ignores a Finding with POST, a reason and an expiry", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { finding: IGNORED }));
    const request = { reason: "Not reachable", until: "2026-12-10T00:00:00.000Z" };
    expect(await ignoreFinding(key, findingId, request)).toEqual({ finding: IGNORED });
    const { url, init, headers, body } = lastCall();
    expect(url).toBe(`${API}/v1/findings/${findingId}/ignore`);
    expect(init.method).toBe("POST");
    expect(headers.get("content-type")).toBe("application/json");
    expect(body).toEqual(request);
  });

  it("reopens a Finding with POST and no body", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { finding: EXAMPLE_FINDING }));
    expect(await reopenFinding(key, findingId)).toEqual({ finding: EXAMPLE_FINDING });
    const { url, init, body } = lastCall();
    expect(url).toBe(`${API}/v1/findings/${findingId}/reopen`);
    expect(init.method).toBe("POST");
    expect(body).toBeUndefined();
  });

  it("maps 404, 409, 401 and 400 to their errors", async () => {
    fetchMock.mockResolvedValueOnce(problem(404));
    expect(await caught(getFinding(key, findingId))).toBeInstanceOf(NotFoundError);
    fetchMock.mockResolvedValueOnce(problem(409));
    expect(await caught(reopenFinding(key, findingId))).toBeInstanceOf(ConflictError);
    fetchMock.mockResolvedValueOnce(problem(401));
    expect(await caught(listFindings(key))).toBeInstanceOf(UnauthorizedError);
    fetchMock.mockResolvedValueOnce(problem(400, { errors: [{ path: "until", message: "Too far ahead" }] }));
    const error = await caught(ignoreFinding(key, findingId, { reason: "x", until: "2027-12-10T00:00:00.000Z" }));
    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ValidationError).errors).toEqual([{ path: "until", message: "Too far ahead" }]);
  });

  it("turns a response that fails the schema into ApiError 502", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { findings: [{ ...EXAMPLE_FINDING, severity: "severe" }] }));
    expect(((await caught(listFindings(key))) as ApiError).status).toBe(502);
    // The detail must carry the advisory.
    fetchMock.mockResolvedValueOnce(json(200, { finding: EXAMPLE_FINDING }));
    expect(((await caught(getFinding(key, findingId))) as ApiError).status).toBe(502);
    // An ignored Finding without its ignore breaks the contract.
    fetchMock.mockResolvedValueOnce(json(200, { finding: { ...EXAMPLE_FINDING, status: "ignored" } }));
    expect(((await caught(reopenFinding(key, findingId))) as ApiError).status).toBe(502);
  });
});
