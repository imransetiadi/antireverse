import { ACTOR_HASH_PATTERN } from "@antireverse/protocol";
import type { NextRequest } from "next/server";
import { download, goTo, isDeletionPending } from "@/features/data-controls/download.ts";
import { fetchSubjectExport } from "@/lib/api.ts";
import { crossSiteRefusal, readBounded, sessionKeyOf } from "@/lib/download-guard.ts";
import { ROUTES } from "@/lib/routes.ts";

// The export of one end user's records (slice 18b): the form of Data controls posts the actor hash here; the API's
// NDJSON is streamed through as a download. The actor hash never enters an address: it travels in the form body, and
// a refusal comes back to Data controls with a notice only — the form gives back what was typed (review 18b, L2).
// In order, before the API is called: a request another site made is refused (403); a missing or malformed session
// goes home before any of the body is read; a body over BODY_MAX bytes is refused (413) without reading it all.

/** A form of one actor hash is about 45 bytes; anything near this bound is not the Console's form. */
const BODY_MAX = 4096;

const back = (notice: "invalid" | "failed"): Response =>
  goTo(`${ROUTES.dataControls()}?subject_export=${notice}#subject`);

export async function POST(request: NextRequest): Promise<Response> {
  const refused = crossSiteRefusal(request);
  if (refused) return refused;
  const key = sessionKeyOf(request);
  if (!key) return goTo(ROUTES.home);

  const contentType = request.headers.get("content-type") ?? "";
  if (!contentType.startsWith("application/x-www-form-urlencoded")) return back("invalid");
  const text = await readBounded(request, BODY_MAX);
  if (text === null) {
    return new Response("Request body too large.", {
      status: 413,
      headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
    });
  }
  const subject = new URLSearchParams(text).get("subject")?.trim() ?? "";
  if (!ACTOR_HASH_PATTERN.test(subject)) return back("invalid");

  let upstream: Response;
  try {
    upstream = await fetchSubjectExport(key, subject, request.signal);
  } catch {
    return back("failed");
  }
  if (!upstream.ok) {
    if (upstream.status === 401) {
      await upstream.body?.cancel();
      return goTo(ROUTES.signInExpired);
    }
    if (await isDeletionPending(upstream)) return goTo(ROUTES.dataControls({ blocked: true }));
    return back("failed");
  }
  return download(upstream, "airverse-subject.ndjson");
}
