import { AUDIT_EXPORT_CONTENT_TYPE } from "@antireverse/protocol";
import type { NextRequest } from "next/server";
import { fetchAuditExport } from "@/lib/api.ts";
import { ROUTES } from "@/lib/routes.ts";
import { SESSION_COOKIE } from "@/lib/session.ts";

// The export of the audit log (slice 18a): the API's NDJSON — the signed chain head, then every entry oldest first
// with its hashes — streamed to the browser as a download. The session is checked here and the admin key stays on the
// server. A refusal is never offered as a file: the browser goes back to the Audit log, which says what happened
// (`?export=limited&retry=` after a 429, `?export=failed` otherwise), or to sign-in. No segment config is exported.

/** Whole seconds, at most five digits: the only form of `Retry-After` that is read. */
const RETRY_AFTER = /^[0-9]{1,5}$/;

// A relative Location: the browser stays on the host it used (and keeps its session cookie), whatever Next.js
// makes of the request's own host.
const goTo = (path: string): Response =>
  new Response(null, { status: 303, headers: { location: path, "cache-control": "no-store" } });

export async function GET(request: NextRequest): Promise<Response> {
  const key = request.cookies.get(SESSION_COOKIE)?.value;
  if (!key) return goTo(ROUTES.home);

  let upstream: Response;
  try {
    upstream = await fetchAuditExport(key, request.signal);
  } catch {
    // The error is not forwarded: a transport error may quote the request it could not send.
    return goTo(`${ROUTES.audit()}?export=failed`);
  }

  if (!upstream.ok) {
    await upstream.body?.cancel();
    if (upstream.status === 401) return goTo(ROUTES.signInExpired);
    if (upstream.status === 429) {
      const retry = upstream.headers.get("retry-after")?.trim() ?? "";
      return goTo(`${ROUTES.audit()}?export=limited${RETRY_AFTER.test(retry) ? `&retry=${retry}` : ""}`);
    }
    return goTo(`${ROUTES.audit()}?export=failed`);
  }
  return new Response(upstream.body, {
    status: 200,
    headers: {
      "content-type": AUDIT_EXPORT_CONTENT_TYPE,
      "content-disposition": 'attachment; filename="airverse-audit.ndjson"',
      "cache-control": "no-store",
    },
  });
}
