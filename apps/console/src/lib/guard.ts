import "server-only";
import type { Organization, OrganizationDeletion } from "@antireverse/protocol";
import { headers } from "next/headers";
import { redirect } from "next/navigation";
import { DeletionPendingError, getDeletionStatus, getOrganization, UnauthorizedError } from "./api.ts";
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
 * No session → `/`. A key the API no longer accepts → sign-in. An Organization pending deletion (slice 18b) → Data
 * controls, which says why the other pages are unavailable. Any other failure reaches the error screen.
 */
export async function requireSession(): Promise<Session> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);
  try {
    const { organization } = await getOrganization(key);
    return { key, organization };
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    if (error instanceof DeletionPendingError) redirect(ROUTES.dataControls({ blocked: true }));
    throw error;
  }
}

/** The session of Data controls (slice 18b): the Organization, or — while its deletion is pending — that deletion. */
export type DeletionSession =
  | { key: string; organization: Organization; deletion: null }
  | { key: string; organization: null; deletion: OrganizationDeletion };

/**
 * The session guard of the one page that stays open while a deletion is pending. Without a pending deletion it costs
 * the same single call as `requireSession`; with one, the API refuses to name the Organization and the deletion is
 * read instead. No session → `/`; a key the API no longer accepts → sign-in.
 */
export async function requireSessionDuringDeletion(): Promise<DeletionSession> {
  const key = await readSession();
  if (!key) redirect(ROUTES.home);
  try {
    try {
      const { organization } = await getOrganization(key);
      return { key, organization, deletion: null };
    } catch (error) {
      if (!(error instanceof DeletionPendingError)) throw error;
    }
    const { deletion } = await getDeletionStatus(key);
    // Cancelled between the two calls: the Organization can be read again.
    if (deletion === null) {
      const { organization } = await getOrganization(key);
      return { key, organization, deletion: null };
    }
    return { key, organization: null, deletion };
  } catch (error) {
    if (error instanceof UnauthorizedError) redirect(ROUTES.signInExpired);
    throw error;
  }
}

/**
 * The Organization of the session, or null without a session or with a key the API no longer accepts. An
 * Organization pending deletion (slice 18b) → Data controls, as `requireSession` does.
 */
export async function currentOrganization(): Promise<Organization | null> {
  const key = await readSession();
  if (!key) return null;
  try {
    return (await getOrganization(key)).organization;
  } catch (error) {
    if (error instanceof UnauthorizedError) return null;
    if (error instanceof DeletionPendingError) redirect(ROUTES.dataControls({ blocked: true }));
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
