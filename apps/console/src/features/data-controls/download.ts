import "server-only";
import { DATA_EXPORT_CONTENT_TYPE } from "@antireverse/protocol";

// The downloads of Data controls (slice 18b): the API's NDJSON body handed on to the browser as it arrives — never
// read into memory here — or, for a refusal, a 303 back to a page that says what happened.

/** The only file names of the API that are handed on: `airverse-…​.ndjson`, nothing that could name a path. */
const API_FILE_NAME = /^attachment; filename="airverse-[A-Za-z0-9_-]{1,120}\.ndjson"$/;

/** Whole seconds, at most five digits: the only form of `Retry-After` that is read. */
export const RETRY_AFTER = /^[0-9]{1,5}$/;

// A relative Location: the browser stays on the host it used (and keeps its session cookie), whatever Next.js
// makes of the request's own host.
export const goTo = (path: string): Response =>
  new Response(null, { status: 303, headers: { location: path, "cache-control": "no-store" } });

/** The upstream body as a download, under the API's file name when it is one of its own, else `fallback`. */
export function download(upstream: Response, fallback: string): Response {
  const named = upstream.headers.get("content-disposition") ?? "";
  return new Response(upstream.body, {
    status: 200,
    headers: {
      "content-type": DATA_EXPORT_CONTENT_TYPE,
      "content-disposition": API_FILE_NAME.test(named) ? named : `attachment; filename="${fallback}"`,
      "cache-control": "no-store",
    },
  });
}

/** True for the API's 403 `organization-deletion-pending`; reads (and so consumes) the refusal's body. */
export async function isDeletionPending(upstream: Response): Promise<boolean> {
  if (upstream.status !== 403) {
    await upstream.body?.cancel();
    return false;
  }
  try {
    const body = (await upstream.json()) as { type?: unknown };
    return typeof body.type === "string" && body.type.endsWith("/organization-deletion-pending");
  } catch {
    return false;
  }
}
