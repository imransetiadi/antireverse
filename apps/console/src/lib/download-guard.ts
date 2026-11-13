import "server-only";
import { ADMIN_KEY_PATTERN } from "@antireverse/protocol";
import type { NextRequest } from "next/server";
import { SESSION_COOKIE } from "./session.ts";

// The checks every download route handler makes before anything else (slices 18a and 18b). A download is started by a
// link or a form, so its request carries the session cookie on a top-level navigation from another site too
// (SameSite=Lax): such a request is refused before the API is called, and before any of its body is read.

const forbidden = (): Response =>
  new Response("Cross-site request refused.", {
    status: 403,
    headers: { "content-type": "text/plain; charset=utf-8", "cache-control": "no-store" },
  });

/**
 * The Console's own origin as the browser addressed it: the forwarded host and scheme of a proxy in front, else the
 * Host header and the request's scheme. Null without a Host header (not a request a browser sent).
 */
function ownOrigin(request: NextRequest): string | null {
  const host = request.headers.get("x-forwarded-host") ?? request.headers.get("host");
  if (host === null) return null;
  const proto = request.headers.get("x-forwarded-proto") ?? request.nextUrl.protocol.replace(/:$/, "");
  return `${proto}://${host}`;
}

/**
 * 403 for a request another site made: `Sec-Fetch-Site` present and neither `same-origin` nor `none` (an address
 * typed or bookmarked), or an `Origin` that is not the Console's own. Null for a request the Console itself made.
 */
export function crossSiteRefusal(request: NextRequest): Response | null {
  const site = request.headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin" && site !== "none") return forbidden();
  const origin = request.headers.get("origin");
  if (origin !== null && origin !== ownOrigin(request)) return forbidden();
  return null;
}

/** The admin key of the session cookie, or undefined when there is none or the value is not shaped like one. */
export function sessionKeyOf(request: NextRequest): string | undefined {
  const value = request.cookies.get(SESSION_COOKIE)?.value;
  return value !== undefined && ADMIN_KEY_PATTERN.test(value) ? value : undefined;
}

/**
 * The request body as text, at most `max` bytes: null when its Content-Length or what is read says it is longer.
 * Reading stops at the first byte over the bound; nothing more is buffered.
 */
export async function readBounded(request: NextRequest, max: number): Promise<string | null> {
  const length = request.headers.get("content-length");
  if (length !== null && (!/^[0-9]{1,10}$/.test(length) || Number(length) > max)) return null;
  if (request.body === null) return "";
  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    total += value.byteLength;
    if (total > max) {
      await reader.cancel();
      return null;
    }
    chunks.push(value);
  }
  const bytes = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
}
