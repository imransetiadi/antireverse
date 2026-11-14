// @vitest-environment node
import { encodeAuditReason } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { ApiError, getRetention, ReasonRequiredError, updateRetention, ValidationError } from "@/lib/api.ts";
import { RETENTION, RETENTION_RUN } from "./helpers/retention.ts";

// Slice 18c: the Console's client for the Event retention — read it with the fixed periods and the last run, change it
// with the reason header when it is shortened.

const key = generateKey("admin").key;
const API = "http://api.test:9999";
const REASON = "Storage policy: keep request metadata one week";

const fetchMock = vi.fn<typeof fetch>();
function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
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

describe("api client — retention", () => {
  it("reads the retention and the last run with the key", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { retention: RETENTION, last_run: RETENTION_RUN }));
    expect(await getRetention(key)).toEqual({ retention: RETENTION, last_run: RETENTION_RUN });
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/organization/retention`);
    expect(init.method).toBe("GET");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
    fetchMock.mockResolvedValueOnce(json(200, { retention: RETENTION, last_run: null }));
    expect((await getRetention(key)).last_run).toBeNull();
  });

  it("refuses an answer outside the contract (a period the protocol does not know)", async () => {
    fetchMock.mockResolvedValueOnce(
      json(200, { retention: { ...RETENTION, event_retention_days: 14 }, last_run: null }),
    );
    const error = await caught(getRetention(key));
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(502);
  });

  it("changes it with a PUT, the days in the body and the reason in the header when there is one", async () => {
    const answer = {
      retention: { ...RETENTION, event_retention_days: 7 },
      last_run: null,
      events_removed_before: "2026-11-07T09:00:00.000Z",
    };
    fetchMock.mockResolvedValueOnce(json(200, answer));
    expect(await updateRetention(key, { event_retention_days: 7 }, { reason: REASON })).toEqual(answer);
    let sent = lastCall();
    expect(sent.url).toBe(`${API}/v1/organization/retention`);
    expect(sent.init.method).toBe("PUT");
    expect(JSON.parse(String(sent.init.body))).toEqual({ event_retention_days: 7 });
    expect(sent.headers.get("x-airverse-reason")).toBe(encodeAuditReason(REASON));

    fetchMock.mockResolvedValueOnce(json(200, { ...answer, retention: { ...RETENTION, event_retention_days: 90 } }));
    await updateRetention(key, { event_retention_days: 90 });
    sent = lastCall();
    expect(sent.headers.has("x-airverse-reason")).toBe(false);
  });

  it("names a missing reason and a refused value", async () => {
    fetchMock.mockResolvedValueOnce(
      json(400, { type: "https://antireverse.dev/problems/reason-required", title: "Reason required", status: 400 }),
    );
    expect(await caught(updateRetention(key, { event_retention_days: 7 }))).toBeInstanceOf(ReasonRequiredError);
    fetchMock.mockResolvedValueOnce(
      json(400, {
        type: "https://antireverse.dev/problems/validation",
        title: "Invalid request",
        status: 400,
        errors: [{ path: "event_retention_days", message: "Invalid input" }],
      }),
    );
    const refused = await caught(updateRetention(key, { event_retention_days: 7 }));
    expect(refused).toBeInstanceOf(ValidationError);
    expect((refused as ValidationError).errors.map((entry) => entry.path)).toEqual(["event_retention_days"]);
  });
});
