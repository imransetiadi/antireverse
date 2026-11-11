import { ID_PATTERNS } from "@antireverse/protocol";
import type { NextRequest } from "next/server";
import { openEventStream } from "@/lib/api.ts";
import { SESSION_COOKIE } from "@/lib/session.ts";

// The stream proxy: the browser's EventSource talks to the Console, and the Console — which holds the
// admin key in an httpOnly cookie — talks to the API. No segment config is exported from this file.

function problem(status: number, title: string): Response {
  return new Response(JSON.stringify({ type: "about:blank", title, status }), {
    status,
    headers: { "content-type": "application/problem+json", "cache-control": "no-store" },
  });
}

/**
 * Next would otherwise answer HEAD by running GET and discarding the body without cancelling it, which
 * leaves the upstream stream open. HEAD never reaches the API.
 */
export function HEAD(): Response {
  return new Response(null, { status: 405, headers: { allow: "GET", "cache-control": "no-store" } });
}

export async function GET(
  request: NextRequest,
  context: RouteContext<"/api/apps/[appId]/events/stream">,
): Promise<Response> {
  // Checked before anything else: a value that is not an App identifier never becomes part of an upstream URL.
  const { appId } = await context.params;
  if (!ID_PATTERNS.app.test(appId)) return problem(404, "Not Found");

  const key = request.cookies.get(SESSION_COOKIE)?.value;
  if (!key) return problem(401, "Unauthorized");

  let upstream: Response;
  try {
    // The request's signal closes the upstream stream as soon as the browser leaves.
    upstream = await openEventStream(key, appId, request.signal);
  } catch {
    // The error is not forwarded: a transport error may quote the request it could not send.
    return problem(502, "The Anti Reverse API could not be reached");
  }

  if (!upstream.ok || !upstream.body) {
    // 401, 404, 429, …: the API's own answer, with its own status and content type.
    return new Response(upstream.body, {
      status: upstream.ok ? 502 : upstream.status,
      headers: {
        "content-type": upstream.headers.get("content-type") ?? "application/octet-stream",
        "cache-control": "no-store",
      },
    });
  }

  return new Response(upstream.body, {
    status: 200,
    headers: {
      "content-type": "text/event-stream",
      "cache-control": "no-cache, no-transform",
      // Asks a reverse proxy in front of the Console not to buffer the stream.
      "x-accel-buffering": "no",
    },
  });
}
