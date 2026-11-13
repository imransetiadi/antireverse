// @vitest-environment node
import { encodeAuditReason } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  cancelDeletion,
  DeletionPendingError,
  eraseSubject,
  fetchOrganizationExport,
  fetchSubjectExport,
  getDeletionStatus,
  getOrganization,
  NotFoundError,
  ReasonRequiredError,
  requestDeletion,
  ValidationError,
} from "@/lib/api.ts";
import { ERASE_REPORT, IP_HASH, PENDING, PENDING_PROBLEM } from "./helpers/deletion.ts";

// Slice 18b: the Console's client for data controls — the Organization export, the deletion with its grace period and
// subject requests by actor hash — and the 403 every other route answers while a deletion is pending.

const key = generateKey("admin").key;
const API = "http://api.test:9999";
const REASON = "Contract ended — customer asked for deletion";

const fetchMock = vi.fn<typeof fetch>();
function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
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
  vi.stubEnv("AR_API_URL", API);
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("api client — Organization deletion", () => {
  it("reads the pending deletion, or null", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { deletion: PENDING }));
    expect(await getDeletionStatus(key)).toEqual({ deletion: PENDING });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/organization/deletion`);
    expect(init.method).toBe("GET");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
    fetchMock.mockResolvedValueOnce(json(200, { deletion: null }));
    expect(await getDeletionStatus(key)).toEqual({ deletion: null });
  });

  it("requests the deletion with the typed name in the body and the reason in the header", async () => {
    fetchMock.mockResolvedValueOnce(json(201, { deletion: PENDING }));
    expect(await requestDeletion(key, { confirm_name: "Acme" }, { reason: REASON })).toEqual({ deletion: PENDING });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/organization/deletion`);
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ confirm_name: "Acme" });
    expect(headers.get("x-airverse-reason")).toBe(encodeAuditReason(REASON));
  });

  it("names a refused name and a missing reason", async () => {
    fetchMock.mockResolvedValueOnce(
      json(400, {
        type: "https://antireverse.dev/problems/validation",
        title: "Invalid request",
        status: 400,
        errors: [{ path: "confirm_name", message: "Must be the Organization's name" }],
      }),
    );
    const refused = await caught(requestDeletion(key, { confirm_name: "Acne" }, { reason: REASON }));
    expect(refused).toBeInstanceOf(ValidationError);
    expect((refused as ValidationError).errors.map((entry) => entry.path)).toEqual(["confirm_name"]);
    fetchMock.mockResolvedValueOnce(
      json(400, { type: "https://antireverse.dev/problems/reason-required", title: "Reason required", status: 400 }),
    );
    expect(await caught(requestDeletion(key, { confirm_name: "Acme" }))).toBeInstanceOf(ReasonRequiredError);
  });

  it("cancels with a DELETE that carries the reason; 404 when none is pending", async () => {
    const cancelled = { ...PENDING, status: "cancelled", cancelled_at: "2026-11-14T09:00:00.000Z" };
    fetchMock.mockResolvedValueOnce(json(200, { deletion: cancelled }));
    expect(await cancelDeletion(key, { reason: REASON })).toEqual({ deletion: cancelled });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/organization/deletion`);
    expect(init.method).toBe("DELETE");
    expect(init.body).toBeUndefined();
    expect(headers.get("x-airverse-reason")).toBe(encodeAuditReason(REASON));
    fetchMock.mockResolvedValueOnce(json(404, { type: "about:blank", title: "Not found", status: 404 }));
    expect(await caught(cancelDeletion(key, { reason: REASON }))).toBeInstanceOf(NotFoundError);
  });

  it("turns the 403 organization-deletion-pending of any route into a DeletionPendingError", async () => {
    fetchMock.mockResolvedValueOnce(json(403, PENDING_PROBLEM));
    const error = await caught(getOrganization(key));
    expect(error).toBeInstanceOf(DeletionPendingError);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(403);
    // Any other 403 stays a plain ApiError.
    fetchMock.mockResolvedValueOnce(json(403, { type: "about:blank", title: "Forbidden", status: 403 }));
    const other = await caught(getOrganization(key));
    expect(other).not.toBeInstanceOf(DeletionPendingError);
    expect((other as ApiError).status).toBe(403);
  });
});

describe("api client — exports and subject requests", () => {
  it("returns the raw export response, asking for NDJSON with the key", async () => {
    const upstream = new Response('{"kind":"manifest"}\n', { status: 200 });
    fetchMock.mockResolvedValueOnce(upstream);
    const signal = new AbortController().signal;
    expect(await fetchOrganizationExport(key, signal)).toBe(upstream);
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/organization/export`);
    expect(init.method).toBe("GET");
    expect(init.signal).toBe(signal);
    expect(headers.get("accept")).toBe("application/x-ndjson");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("posts the actor hash for a subject export and returns the raw response", async () => {
    const upstream = new Response("", { status: 200 });
    fetchMock.mockResolvedValueOnce(upstream);
    const signal = new AbortController().signal;
    expect(await fetchSubjectExport(key, IP_HASH, signal)).toBe(upstream);
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/subjects/export`);
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ ip_hash: IP_HASH });
    expect(headers.get("accept")).toBe("application/x-ndjson");
  });

  it("erases a subject with the reason and returns the report", async () => {
    const report = ERASE_REPORT;
    fetchMock.mockResolvedValueOnce(json(200, { report }));
    expect(await eraseSubject(key, IP_HASH, { reason: REASON })).toEqual({ report });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/subjects/erase`);
    expect(init.method).toBe("POST");
    expect(JSON.parse(String(init.body))).toEqual({ ip_hash: IP_HASH });
    expect(headers.get("x-airverse-reason")).toBe(encodeAuditReason(REASON));
  });
});
