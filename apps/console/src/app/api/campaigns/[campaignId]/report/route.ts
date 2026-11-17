import { type CampaignReport, ID_PATTERNS } from "@antireverse/protocol";
import type { NextRequest } from "next/server";
import { goTo } from "@/features/data-controls/download.ts";
import { DeletionPendingError, getCampaignReport, NotFoundError, UnauthorizedError } from "@/lib/api.ts";
import { crossSiteRefusal, sessionKeyOf } from "@/lib/download-guard.ts";
import { ROUTES } from "@/lib/routes.ts";

// The report of one Campaign (slice 15a) as a JSON download: the Campaign, its checks, its Findings with redacted
// evidence, the engine tag, the notice that says what the results are not, and the report's limits. The session is
// checked here and the admin key stays on the server; the API's answer is validated against the protocol before it
// is handed on. A refusal is never offered as a file: the browser goes to sign-in, to Data controls (pending
// deletion), to the list (no such Campaign) or back to the Campaign, which says the report could not be made.
// The route types of `.next/types` come from `next typegen`, which this slice does not run: the context is written out.

export async function GET(
  request: NextRequest,
  context: { params: Promise<{ campaignId: string }> },
): Promise<Response> {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const key = sessionKeyOf(request);
  if (!key) return goTo(ROUTES.home);
  const { campaignId } = await context.params;
  if (!ID_PATTERNS.cmp.test(campaignId)) return goTo(ROUTES.campaigns);

  let report: CampaignReport;
  try {
    ({ report } = await getCampaignReport(key, campaignId));
  } catch (error) {
    // The error is not forwarded: it may quote the request that failed.
    if (error instanceof UnauthorizedError) return goTo(ROUTES.signInExpired);
    if (error instanceof DeletionPendingError) return goTo(ROUTES.dataControls({ blocked: true }));
    if (error instanceof NotFoundError) return goTo(ROUTES.campaigns);
    return goTo(ROUTES.campaign(campaignId, { notice: "report-failed" }));
  }
  return new Response(`${JSON.stringify({ report }, null, 2)}\n`, {
    status: 200,
    headers: {
      "content-type": "application/json; charset=utf-8",
      "content-disposition": `attachment; filename="airverse-campaign-${campaignId}.json"`,
      "cache-control": "no-store",
      "x-content-type-options": "nosniff",
    },
  });
}
