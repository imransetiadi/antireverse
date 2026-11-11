import { ID_PATTERNS } from "@antireverse/protocol";
import type { NextRequest } from "next/server";
import { fetchEventList } from "@/lib/api.ts";
import { SESSION_COOKIE } from "@/lib/session.ts";

// The list proxy: the live feed reads it whenever its stream opens, so that an Event ingested before the
// subscription, or while the feed was reconnecting, still appears. No segment config is exported.

function problem(status: number, title: string): Response {
  return new Response(JSON.stringify({ type: "about:blank", title, status }), {
    status,
    headers: { "content-type": "application/problem+json", "cache-control": "no-store" },
  });
}

export async function GET(request: NextRequest, context: RouteContext<"/api/apps/[appId]/events">): Promise<Response> {
  // Checked before anything else: a value that is not an App identifier never becomes part of an upstream URL.
  const { appId } = await context.params;
  if (!ID_PATTERNS.app.test(appId)) return problem(404, "Not Found");

  const key = request.cookies.get(SESSION_COOKIE)?.value;
  if (!key) return problem(401, "Unauthorized");

  let upstream: Response;
  try {
    upstream = await fetchEventList(key, appId, request.signal);
  } catch {
    // The error is not forwarded: a transport error may quote the request it could not send.
    return problem(502, "The Anti Reverse API could not be reached");
  }

  // The API's own answer — the list, or its 401 / 404 — with its own status and content type.
  return new Response(upstream.body, {
    status: upstream.status,
    headers: {
      "content-type": upstream.headers.get("content-type") ?? "application/octet-stream",
      "cache-control": "no-store",
    },
  });
}
