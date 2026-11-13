import type { NextRequest } from "next/server";
import { download, goTo, RETRY_AFTER } from "@/features/data-controls/download.ts";
import { fetchOrganizationExport } from "@/lib/api.ts";
import { crossSiteRefusal, sessionKeyOf } from "@/lib/download-guard.ts";
import { ROUTES } from "@/lib/routes.ts";

// The export of the whole Organization (slice 18b): the API's NDJSON — a manifest, every table's rows, a signed end
// line — streamed through to the browser as a download, never buffered here. Allowed while a deletion is pending. The
// session is checked here and the admin key stays on the server. A refusal goes back to Data controls, which says
// what happened (`?export=limited&retry=` after a 429 — the limit is shared with the audit log — or `?export=failed`),
// or to sign-in. No segment config is exported.

export async function GET(request: NextRequest): Promise<Response> {
  // Slice 18b review: another site cannot start the download; a malformed session never reaches the API.
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const key = sessionKeyOf(request);
  if (!key) return goTo(ROUTES.home);

  let upstream: Response;
  try {
    upstream = await fetchOrganizationExport(key, request.signal);
  } catch {
    // The error is not forwarded: a transport error may quote the request it could not send.
    return goTo(`${ROUTES.dataControls()}?export=failed`);
  }

  if (!upstream.ok) {
    await upstream.body?.cancel();
    if (upstream.status === 401) return goTo(ROUTES.signInExpired);
    if (upstream.status === 429) {
      const retry = upstream.headers.get("retry-after")?.trim() ?? "";
      return goTo(`${ROUTES.dataControls()}?export=limited${RETRY_AFTER.test(retry) ? `&retry=${retry}` : ""}`);
    }
    return goTo(`${ROUTES.dataControls()}?export=failed`);
  }
  return download(upstream, "airverse-export.ndjson");
}
