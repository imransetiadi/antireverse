// @vitest-environment node
import { EXAMPLE_AUDIT_ENTRY, EXAMPLE_POLICY, EXAMPLE_SIGNED_AUDIT_HEAD, EXAMPLE_TARGET } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  createContainment,
  deleteTarget,
  fetchAuditExport,
  listAudit,
  publishPolicy,
  ReasonRequiredError,
  rollbackPolicy,
  setPatchMode,
  signRulesOfEngagement,
  ValidationError,
  verifyAudit,
} from "@/lib/api.ts";

// Slice 18a: the Console's client for the audit log, and the reason of a sensitive change, sent as the
// percent-encoded `X-Airverse-Reason` header.

const key = generateKey("admin").key;
const API = "http://api.test:9999";
const REASON_REQUIRED = "https://antireverse.dev/problems/reason-required";

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

describe("api client — audit log", () => {
  it("lists entries with the filters and the cursor in the query", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { entries: [EXAMPLE_AUDIT_ENTRY], next_cursor: "1" }));
    const page = await listAudit(key, {
      action: "policy.rule.promote",
      appId: EXAMPLE_AUDIT_ENTRY.app_id,
      from: "2026-11-01T00:00:00.000Z",
      to: "2026-11-14T00:00:00.000Z",
      cursor: "42",
      limit: 50,
    });
    expect(page).toEqual({ entries: [EXAMPLE_AUDIT_ENTRY], next_cursor: "1" });
    const { url, headers } = lastCall();
    const parsed = new URL(url);
    expect(parsed.pathname).toBe("/v1/audit");
    expect(Object.fromEntries(parsed.searchParams)).toEqual({
      action: "policy.rule.promote",
      app_id: EXAMPLE_AUDIT_ENTRY.app_id,
      from: "2026-11-01T00:00:00.000Z",
      to: "2026-11-14T00:00:00.000Z",
      cursor: "42",
      limit: "50",
    });
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("lists without a query when there are no filters", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { entries: [], next_cursor: null }));
    await listAudit(key);
    expect(lastCall().url).toBe(`${API}/v1/audit`);
  });

  it("refuses a list that does not match the contract", async () => {
    fetchMock.mockResolvedValueOnce(
      json(200, { entries: [{ ...EXAMPLE_AUDIT_ENTRY, hash: "nope" }], next_cursor: null }),
    );
    expect((await caught(listAudit(key))).message).toBe(
      "GET /v1/audit returned a response that does not match the contract",
    );
  });

  it("reads the chain verification", async () => {
    const verify = { valid: false, entries: 9, last_seq: 9, first_broken_seq: 4 };
    fetchMock.mockResolvedValueOnce(json(200, { verify, signed_head: EXAMPLE_SIGNED_AUDIT_HEAD }));
    expect(await verifyAudit(key)).toEqual({ verify, signed_head: EXAMPLE_SIGNED_AUDIT_HEAD });
    expect(lastCall().url).toBe(`${API}/v1/audit/verify`);
  });

  it("hands the raw export response over, with the admin key and the request's signal", async () => {
    const upstream = new Response('{"seq":1}\n', { status: 200, headers: { "content-type": "application/x-ndjson" } });
    fetchMock.mockResolvedValueOnce(upstream);
    const signal = new AbortController().signal;
    expect(await fetchAuditExport(key, signal)).toBe(upstream);
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/audit/export`);
    expect(init.signal).toBe(signal);
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });
});

describe("api client — the reason of a change", () => {
  const reason = "Stuffing on /login — 100 % sure, café";
  const encoded = encodeURIComponent(reason);

  it("sends the reason percent-encoded on every sensitive change, and no header without one", async () => {
    const calls: Array<() => Promise<unknown>> = [
      () => publishPolicy(key, EXAMPLE_POLICY.app_id, "development", [], 1, { reason }),
      () => rollbackPolicy(key, EXAMPLE_POLICY.app_id, "development", 1, 2, { reason }),
      () =>
        setPatchMode(
          key,
          EXAMPLE_POLICY.app_id,
          "vp_x",
          { environment: "development", mode: "enforce", confirm: "vp_x" },
          { reason },
        ),
      () =>
        createContainment(
          key,
          "inc_0123456789abcdef01234567",
          { target: { kind: "prefix" }, ttl_s: 900, confirm_prefix: "203.0.113.0/24" },
          { reason },
        ),
      () => deleteTarget(key, EXAMPLE_TARGET.id, { reason }),
      () =>
        signRulesOfEngagement(
          key,
          {
            scope: [EXAMPLE_TARGET.id],
            exclusions: [],
            intensity: "passive",
            window: { days: ["mon"], from: "09:00", to: "17:00" },
            contacts: ["a@b.io"],
            confirm: "I authorise passive testing",
          },
          { reason },
        ),
    ];
    for (const send of calls) {
      fetchMock.mockResolvedValueOnce(new Response(null, { status: 418 }));
      await caught(send());
      expect(lastCall().headers.get("x-airverse-reason")).toBe(encoded);
    }
    fetchMock.mockResolvedValueOnce(new Response(null, { status: 204 }));
    await deleteTarget(key, EXAMPLE_TARGET.id);
    expect(lastCall().headers.has("x-airverse-reason")).toBe(false);
  });

  it("rejects with ReasonRequiredError when the API asks for a reason", async () => {
    fetchMock.mockResolvedValueOnce(json(400, { type: REASON_REQUIRED, title: "Reason required", status: 400 }));
    const error = await caught(deleteTarget(key, EXAMPLE_TARGET.id));
    expect(error).toBeInstanceOf(ReasonRequiredError);
    expect(error).toBeInstanceOf(ValidationError);
    expect((error as ReasonRequiredError).status).toBe(400);
  });

  it("keeps any other 400 a plain ValidationError", async () => {
    fetchMock.mockResolvedValueOnce(
      json(400, {
        type: "https://antireverse.dev/problems/validation",
        title: "Invalid",
        status: 400,
        code: "reason-too-long",
        errors: [{ path: "headers.x-airverse-reason", message: "Too long" }],
      }),
    );
    const error = await caught(deleteTarget(key, EXAMPLE_TARGET.id, { reason }));
    expect(error).not.toBeInstanceOf(ReasonRequiredError);
    expect((error as ValidationError).errors).toEqual([{ path: "headers.x-airverse-reason", message: "Too long" }]);
    // The code of a refused reason (slice 18a review): the Console maps its messages on it, never on the text.
    expect((error as ValidationError).code).toBe("reason-too-long");
  });
});
