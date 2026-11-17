// @vitest-environment node
// Slice 15a: the report of a Campaign goes through the Console, which checks the session and hands the API's report on
// as a JSON download. The admin key never reaches the browser, and a refusal is never offered as a file.
import { CAMPAIGN_STAND_IN_NOTICE, CampaignReportSchema } from "@antireverse/protocol";
import { generateKey } from "@antireverse/protocol/server";
import { NextRequest } from "next/server";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import * as route from "@/app/api/campaigns/[campaignId]/report/route.ts";
import { campaignId, completed, highFinding, reportOf } from "./helpers/campaigns.ts";

const key = generateKey("admin").key;
const fetchMock = vi.fn<typeof fetch>();
const get = (cookie?: string, headers: Record<string, string> = {}, id: string = campaignId) =>
  route.GET(
    new NextRequest(`http://127.0.0.1:3000/api/campaigns/${id}/report`, {
      headers: { host: "127.0.0.1:3000", ...(cookie ? { cookie } : {}), ...headers },
    }),
    { params: Promise.resolve({ campaignId: id }) },
  );
const refusal = (status: number, name = "refused") =>
  new Response(JSON.stringify({ type: `https://antireverse.dev/problems/${name}`, title: "Refused", status }), {
    status,
    headers: { "content-type": "application/problem+json" },
  });

beforeEach(() => {
  fetchMock.mockReset();
  vi.stubGlobal("fetch", fetchMock);
  vi.stubEnv("AR_API_URL", "http://api.test:9999");
});
afterEach(() => {
  vi.unstubAllGlobals();
  vi.unstubAllEnvs();
});

describe("GET /api/campaigns/:campaignId/report", () => {
  it("exports the GET handler only", () => {
    expect(Object.keys(route)).toEqual(["GET"]);
  });

  it("refuses a cross-site request with 403 and no API call", async () => {
    for (const headers of <Record<string, string>[]>[
      { "sec-fetch-site": "cross-site" },
      { origin: "https://evil.example" },
    ]) {
      expect((await get(`ar_admin=${key}`, headers)).status).toBe(403);
    }
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("sends a browser without a session home, and one with a malformed id to the list, without calling the API", async () => {
    let response = await get();
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/");
    response = await get(`ar_admin=${key}`, {}, "cmp_nope");
    expect(response.status).toBe(303);
    expect(response.headers.get("location")).toBe("/prove/campaigns");
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("hands the report on as a JSON attachment named after the Campaign, with the notice, never cached", async () => {
    const report = reportOf(completed, [highFinding]);
    fetchMock.mockResolvedValue(
      new Response(JSON.stringify({ report }), { status: 200, headers: { "content-type": "application/json" } }),
    );
    const response = await get(`ar_admin=${key}`, { "sec-fetch-site": "same-origin" });
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe("application/json; charset=utf-8");
    expect(response.headers.get("content-disposition")).toBe(
      `attachment; filename="airverse-campaign-${campaignId}.json"`,
    );
    expect(response.headers.get("cache-control")).toBe("no-store");
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    const body = JSON.parse(await response.text()) as { report: unknown };
    expect(CampaignReportSchema.parse(body.report)).toEqual(report);
    expect((body.report as { notice: string }).notice).toBe(CAMPAIGN_STAND_IN_NOTICE);
    const [url, init] = fetchMock.mock.calls[0] ?? [];
    expect(String(url)).toBe(`http://api.test:9999/v1/campaigns/${campaignId}/report`);
    expect(new Headers(init?.headers).get("authorization")).toBe(`Bearer ${key}`);
  });

  it("never offers a refusal as a file: sign-in, Data controls, the list, or the Campaign with a notice", async () => {
    const cases: Array<[Response, string]> = [
      [refusal(401), "/sign-in?reason=expired"],
      [refusal(403, "organization-deletion-pending"), "/settings/data?blocked=1"],
      [refusal(404), "/prove/campaigns"],
      [refusal(500), `/prove/campaigns/${campaignId}?notice=report-failed`],
      // An answer outside the contract is not handed on either.
      [
        new Response(JSON.stringify({ report: { nonsense: true } }), { status: 200 }),
        `/prove/campaigns/${campaignId}?notice=report-failed`,
      ],
    ];
    for (const [upstream, location] of cases) {
      fetchMock.mockResolvedValueOnce(upstream);
      const response = await get(`ar_admin=${key}`);
      expect(response.status).toBe(303);
      expect(response.headers.get("location")).toBe(location);
      expect(response.headers.get("content-disposition")).toBeNull();
    }
    fetchMock.mockRejectedValueOnce(new Error(`connect ECONNREFUSED with ${key}`));
    const response = await get(`ar_admin=${key}`);
    expect(response.headers.get("location")).toBe(`/prove/campaigns/${campaignId}?notice=report-failed`);
    expect(await response.text()).not.toContain(key);
  });
});
