import "server-only";
import type { Organization } from "@antireverse/protocol";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { getOrganization, UnauthorizedError } from "./api.ts";
import { ROUTES } from "./routes.ts";
import { readSession } from "./session.ts";

export interface Session {
  /** The admin key. Server-only: never pass it to a Client Component. */
  key: string;
  organization: Organization;
}

/**
 * The session guard of every signed-in page. Call it first in an async Server Component with no Suspense
 * boundary and no loading.tsx above it, so that the redirect is a real 307.
 * No session → `/`. A key the API no longer accepts → sign-in. Any other failure reaches the error screen.
 */
export async function requireSession(): Promise<Session> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);
  try {
    const { organization } = await getOrganization(key);
    return { key, organization };
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
}

/** The Organization of the session, or null without a session or with a key the API no longer accepts. */
export async function currentOrganization(): Promise<Organization | null> {
  const key = await readSession();
  if (!key) return null;
  try {
    return (await getOrganization(key)).organization;
  } catch (error) {
    if (error instanceof UnauthorizedError) return null;
    throw error;
  }
}

/**
 * True while the page is rendered as the answer to a Server Action. A Server Action that sets a cookie
 * makes Next.js re-render the current page inside the same POST; a page that shows a result once must
 * not redirect away during that render. Pages are otherwise only ever requested with GET.
 */
export async function isActionRequest(): Promise<boolean> {
  const requestHeaders = await headers();
  if (requestHeaders.has("next-action")) return true;
  const contentType = requestHeaders.get("content-type") ?? "";
  return contentType.startsWith("multipart/form-data") || contentType.startsWith("application/x-www-form-urlencoded");
}
