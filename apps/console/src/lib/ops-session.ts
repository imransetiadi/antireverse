import "server-only";
import { cookies } from "next/headers";

// Slice 18d: the operator session of `/ops`. Its value is the operator token (`AR_OPS_TOKEN` of the API), so it is
// httpOnly and never rendered. It is a cookie of its own, apart from the tenant session `ar_admin`: SameSite=Strict
// (never sent on a request another site starts), scoped to `/ops`, Secure in production as the tenant cookie is. A
// tenant session never stands in for it.

export const OPS_COOKIE = "ar_ops";
export const OPS_COOKIE_PATH = "/ops";
/** Eight hours: an operator's working session, shorter than the tenant session's seven days. */
export const OPS_SESSION_MAX_AGE_SECONDS = 28_800;
/** The shape the API requires of `AR_OPS_TOKEN`: 32 to 512 printable ASCII characters without spaces. */
export const OPS_TOKEN_PATTERN = /^[\x21-\x7e]{32,512}$/;

const secure = (): boolean => process.env.NODE_ENV === "production";

/** The operator token of the current request, or undefined without one (or with a value not shaped like one). */
export async function readOpsSession(): Promise<string | undefined> {
  const value = (await cookies()).get(OPS_COOKIE)?.value;
  return value !== undefined && OPS_TOKEN_PATTERN.test(value) ? value : undefined;
}

/** Stores the operator token. Only a Server Action or a Route Handler may call this. */
export async function writeOpsSession(token: string): Promise<void> {
  (await cookies()).set(OPS_COOKIE, token, {
    httpOnly: true,
    sameSite: "strict",
    path: OPS_COOKIE_PATH,
    secure: secure(),
    maxAge: OPS_SESSION_MAX_AGE_SECONDS,
  });
}

/** Ends the operator session. Only a Server Action or a Route Handler may call this. */
export async function clearOpsSession(): Promise<void> {
  (await cookies()).delete({ name: OPS_COOKIE, path: OPS_COOKIE_PATH });
}

/** The `Set-Cookie` value that ends the operator session, for a Route Handler's own response. */
export function expiredOpsCookie(): string {
  return `${OPS_COOKIE}=; Path=${OPS_COOKIE_PATH}; Max-Age=0; HttpOnly; SameSite=Strict${secure() ? "; Secure" : ""}`;
}

/**
 * True for a form another site sent: `Sec-Fetch-Site` present and neither `same-origin` nor `none`, or an `Origin`
 * whose host is not the Console's own (the forwarded host of a proxy in front, else the Host header). Next.js refuses
 * such a Server Action already; the operator actions check again, as the download routes do (download-guard.ts).
 */
export function isCrossSiteForm(headers: Headers): boolean {
  const site = headers.get("sec-fetch-site");
  if (site !== null && site !== "same-origin" && site !== "none") return true;
  const origin = headers.get("origin");
  if (origin === null) return false;
  const host = headers.get("x-forwarded-host") ?? headers.get("host");
  try {
    return host === null || new URL(origin).host !== host;
  } catch {
    return true;
  }
}
