// @vitest-environment node
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, getSloReport, NotFoundError, UnauthorizedError } from "@/lib/api.ts";
import { OPS_TOKEN, sloReport } from "./helpers/slo.ts";

// Slice 18d: the Console's client for `GET /v1/ops/slo` — the operator token as a bearer, the answer checked against
// the protocol, 404 (operator access off) and 401 (a token not accepted) as their own errors, and the token in no error.

const API = "http://api.test:9999";
const PROBLEMS = "https://antireverse.dev/problems/";
const fetchMock = vi.fn<typeof fetch>();
const json = (status: number, body: unknown): Response =>
  new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
const problem = (status: number, kind: string, title: string) =>
  json(status, { type: `${PROBLEMS}${kind}`, title, status });
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

describe("api client — operator SLOs", () => {
  it("reads the report with the operator token, uncached", async () => {
    const report = sloReport();
    fetchMock.mockResolvedValueOnce(json(200, report));
    expect(await getSloReport(OPS_TOKEN)).toEqual(report);
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).toBe(`${API}/v1/ops/slo`);
    expect((init as RequestInit).method).toBe("GET");
    expect((init as RequestInit).cache).toBe("no-store");
    expect(new Headers((init as RequestInit).headers).get("authorization")).toBe(`Bearer ${OPS_TOKEN}`);
    expect(String(url)).not.toContain(OPS_TOKEN);
  });

  it("names 401 and 404, without the token", async () => {
    fetchMock.mockResolvedValueOnce(problem(401, "unauthorized", "Unauthorized"));
    const refused = await caught(getSloReport(OPS_TOKEN));
    expect(refused).toBeInstanceOf(UnauthorizedError);
    expect(refused.message).not.toContain(OPS_TOKEN);

    fetchMock.mockResolvedValueOnce(problem(404, "not-found", "Not Found"));
    const off = await caught(getSloReport(OPS_TOKEN));
    expect(off).toBeInstanceOf(NotFoundError);
    expect(off.message).not.toContain(OPS_TOKEN);
  });

  it("refuses an answer outside the contract, and says when the API is unreachable", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { ...sloReport(), scope: "global" }));
    const bad = await caught(getSloReport(OPS_TOKEN));
    expect(bad).toBeInstanceOf(ApiError);
    expect((bad as ApiError).status).toBe(502);

    fetchMock.mockRejectedValueOnce(new TypeError(`fetch failed for Bearer ${OPS_TOKEN}`));
    const down = await caught(getSloReport(OPS_TOKEN));
    expect((down as ApiError).status).toBe(0);
    expect(down.message).not.toContain(OPS_TOKEN);
  });
});
