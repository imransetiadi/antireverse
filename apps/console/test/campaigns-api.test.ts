// @vitest-environment node
import { AUDIT_REASON_HEADER, CAMPAIGN_STAND_IN_NOTICE, STAND_IN_ENGINE } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import {
  ApiError,
  CampaignsUnavailableError,
  ConflictError,
  createCampaign,
  DeletionPendingError,
  enableCampaigns,
  getCampaign,
  getCampaignReport,
  getProveOperatorState,
  killCampaigns,
  listCampaignRequests,
  listCampaigns,
  NotFoundError,
  RateLimitedError,
  ReasonRequiredError,
  resumeCampaigns,
  stopCampaign,
  suspendCampaigns,
  UnauthorizedError,
  ValidationError,
} from "@/lib/api.ts";
import {
  campaignId,
  completed,
  highFinding,
  ORG_ID,
  operatorState,
  queued,
  refusedRequest,
  reportOf,
  sentRequest,
  stopped,
} from "./helpers/campaigns.ts";

// Slice 15a: the Console's client for Pentest Campaigns and the operator's switches.

const key = generateKey("admin").key;
const OPS_TOKEN = "operator-token-".padEnd(40, "z");
const API = "http://api.test:9999";
const PROBLEMS = "https://antireverse.dev/problems/";
const REASON = "Quarterly test of the staging shop";
const request = {
  target_id: completed.target_id,
  intensity: "safe-active" as const,
  confirm: `I authorise a test of ${completed.host}`,
  staging: true as const,
};

const fetchMock = vi.fn<typeof fetch>();
function json(status: number, body: unknown, headers: Record<string, string> = {}): Response {
  return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json", ...headers } });
}
function problem(
  status: number,
  name: string,
  extra: Record<string, unknown> = {},
  headers: Record<string, string> = {},
): Response {
  return json(status, { type: `${PROBLEMS}${name}`, title: "Refused", status, ...extra }, headers);
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

describe("api client — Campaigns", () => {
  it("lists the Campaigns with whether one can be created now", async () => {
    const answer = { campaigns: [completed], enabled: true, blocked: null, notice: CAMPAIGN_STAND_IN_NOTICE };
    fetchMock.mockResolvedValueOnce(json(200, answer));
    expect(await listCampaigns(key)).toEqual(answer);
    const { url, init, headers } = lastCall();
    expect(url).toBe(`${API}/v1/campaigns`);
    expect(init.method).toBe("GET");
    expect(headers.get("authorization")).toBe(`Bearer ${key}`);
  });

  it("creates a Campaign with the phrase, the declaration and the reason header", async () => {
    fetchMock.mockResolvedValueOnce(json(202, { campaign: queued }));
    expect(await createCampaign(key, request, { reason: REASON })).toEqual({ campaign: queued });
    const { url, init, headers, body } = lastCall();
    expect(url).toBe(`${API}/v1/campaigns`);
    expect(init.method).toBe("POST");
    expect(body).toEqual(request);
    expect(headers.get(AUDIT_REASON_HEADER)).toBe(encodeURIComponent(REASON));
  });

  it("names why Campaigns cannot be created: switched off, stopped by the operator, suspended", async () => {
    for (const [name, kind] of [
      ["campaigns-disabled", "disabled"],
      ["campaigns-stopped", "stopped"],
      ["campaigns-suspended", "suspended"],
    ] as const) {
      fetchMock.mockResolvedValueOnce(problem(403, name));
      const error = await caught(createCampaign(key, request, { reason: REASON }));
      expect(error).toBeInstanceOf(CampaignsUnavailableError);
      expect((error as CampaignsUnavailableError).kind).toBe(kind);
      expect((error as ApiError).status).toBe(403);
    }
    // A pending deletion keeps its own error; another 403 stays a plain ApiError.
    fetchMock.mockResolvedValueOnce(problem(403, "organization-deletion-pending"));
    expect(await caught(createCampaign(key, request))).toBeInstanceOf(DeletionPendingError);
    fetchMock.mockResolvedValueOnce(problem(403, "forbidden"));
    const other = await caught(createCampaign(key, request));
    expect(other).toBeInstanceOf(ApiError);
    expect(other).not.toBeInstanceOf(CampaignsUnavailableError);
  });

  it("hands on a refused field, a missing reason, each conflict reason and the wait of a 429", async () => {
    fetchMock.mockResolvedValueOnce(
      problem(400, "validation", { errors: [{ path: "confirm", message: "Type the exact phrase." }] }),
    );
    const invalid = await caught(createCampaign(key, request, { reason: REASON }));
    expect(invalid).toBeInstanceOf(ValidationError);
    expect((invalid as ValidationError).errors).toEqual([{ path: "confirm", message: "Type the exact phrase." }]);

    fetchMock.mockResolvedValueOnce(problem(400, "reason-required"));
    expect(await caught(createCampaign(key, request))).toBeInstanceOf(ReasonRequiredError);

    for (const reason of [
      "campaign-active",
      "campaign-target-not-verified",
      "campaign-no-rules",
      "campaign-target-out-of-scope",
      "campaign-rules-too-old",
      "campaign-intensity-exceeds",
    ] as const) {
      fetchMock.mockResolvedValueOnce(problem(409, "conflict", { reason }));
      const conflict = await caught(createCampaign(key, request, { reason: REASON }));
      expect(conflict).toBeInstanceOf(ConflictError);
      expect((conflict as ConflictError).reason).toBe(reason);
    }

    fetchMock.mockResolvedValueOnce(problem(429, "too-many-requests", {}, { "retry-after": "3600" }));
    const limited = await caught(createCampaign(key, request, { reason: REASON }));
    expect(limited).toBeInstanceOf(RateLimitedError);
    expect((limited as RateLimitedError).retryAfter).toBe(3600);

    fetchMock.mockResolvedValueOnce(problem(401, "unauthorized"));
    expect(await caught(createCampaign(key, request))).toBeInstanceOf(UnauthorizedError);
  });

  it("reads one Campaign, its request log and its report", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { campaign: completed }));
    expect(await getCampaign(key, campaignId)).toEqual({ campaign: completed });
    expect(lastCall().url).toBe(`${API}/v1/campaigns/${campaignId}`);

    fetchMock.mockResolvedValueOnce(json(200, { requests: [sentRequest, refusedRequest] }));
    expect((await listCampaignRequests(key, campaignId)).requests).toHaveLength(2);
    expect(lastCall().url).toBe(`${API}/v1/campaigns/${campaignId}/requests`);

    const report = reportOf(completed, [highFinding]);
    fetchMock.mockResolvedValueOnce(json(200, { report }));
    expect(await getCampaignReport(key, campaignId)).toEqual({ report });
    expect(lastCall().url).toBe(`${API}/v1/campaigns/${campaignId}/report`);
    expect(report.engine).toEqual(STAND_IN_ENGINE);

    fetchMock.mockResolvedValueOnce(problem(404, "not-found"));
    expect(await caught(getCampaign(key, campaignId))).toBeInstanceOf(NotFoundError);
  });

  it("refuses a report that does not match the contract", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { report: { ...reportOf(completed), findings: "none" } }));
    const error = await caught(getCampaignReport(key, campaignId));
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(502);
  });

  it("stops a Campaign with a reason, and says when it had already ended", async () => {
    fetchMock.mockResolvedValueOnce(json(200, { campaign: stopped }));
    expect(await stopCampaign(key, campaignId, { reason: "Wrong window" })).toEqual({ campaign: stopped });
    const { url, init, headers, body } = lastCall();
    expect(url).toBe(`${API}/v1/campaigns/${campaignId}/stop`);
    expect(init.method).toBe("POST");
    expect(body).toBeUndefined();
    expect(headers.get(AUDIT_REASON_HEADER)).toBe(encodeURIComponent("Wrong window"));

    fetchMock.mockResolvedValueOnce(problem(409, "conflict", { reason: "campaign-ended" }));
    const ended = await caught(stopCampaign(key, campaignId, { reason: "Wrong window" }));
    expect(ended).toBeInstanceOf(ConflictError);
    expect((ended as ConflictError).reason).toBe("campaign-ended");
  });
});

describe("api client — the operator's Campaign switches", () => {
  it("reads the state with the operator token", async () => {
    const state = operatorState({ active: 1 });
    fetchMock.mockResolvedValueOnce(json(200, state));
    expect(await getProveOperatorState(OPS_TOKEN)).toEqual(state);
    const { url, headers } = lastCall();
    expect(url).toBe(`${API}/v1/ops/prove`);
    expect(headers.get("authorization")).toBe(`Bearer ${OPS_TOKEN}`);
  });

  it("kills, enables, suspends and resumes with the reason in the body", async () => {
    const killed = operatorState({ killed: true, killed_at: "2026-11-16T10:00:00.000Z", stopped: 2 });
    fetchMock.mockResolvedValueOnce(json(200, killed));
    expect(await killCampaigns(OPS_TOKEN, "Incident 42")).toEqual(killed);
    expect(lastCall().url).toBe(`${API}/v1/ops/prove/kill`);
    expect(lastCall().init.method).toBe("POST");
    expect(lastCall().body).toEqual({ reason: "Incident 42" });
    expect(lastCall().headers.get(AUDIT_REASON_HEADER)).toBeNull();

    fetchMock.mockResolvedValueOnce(json(200, operatorState()));
    await enableCampaigns(OPS_TOKEN, "Incident 42 closed");
    expect(lastCall().url).toBe(`${API}/v1/ops/prove/enable`);
    expect(lastCall().body).toEqual({ reason: "Incident 42 closed" });

    fetchMock.mockResolvedValueOnce(json(200, operatorState()));
    await suspendCampaigns(OPS_TOKEN, ORG_ID, "Abuse report");
    expect(lastCall().url).toBe(`${API}/v1/ops/prove/organizations/${ORG_ID}/suspend`);
    expect(lastCall().body).toEqual({ reason: "Abuse report" });

    fetchMock.mockResolvedValueOnce(json(200, operatorState()));
    await resumeCampaigns(OPS_TOKEN, ORG_ID, "Cleared");
    expect(lastCall().url).toBe(`${API}/v1/ops/prove/organizations/${ORG_ID}/resume`);
  });

  it("passes on 401 and 404, and never puts the token in an error", async () => {
    fetchMock.mockResolvedValueOnce(problem(401, "unauthorized"));
    const unauthorized = await caught(killCampaigns(OPS_TOKEN, "x"));
    expect(unauthorized).toBeInstanceOf(UnauthorizedError);
    expect(unauthorized.message).not.toContain(OPS_TOKEN);
    fetchMock.mockResolvedValueOnce(problem(404, "not-found"));
    expect(await caught(suspendCampaigns(OPS_TOKEN, ORG_ID, "x"))).toBeInstanceOf(NotFoundError);
  });
});
