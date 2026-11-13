import "server-only";
import { ApiError, listAudit, RateLimitedError, ValidationError, verifyAudit } from "@/lib/api.ts";
import { type AuditQuery, auditFilterFrom, filtered } from "./query.ts";

// What the Audit log page reads (slice 18a). Verify and export share a small per-Organization limit at the API, so the
// chain is checked only when the page is opened without filters; a filtered view offers "Verify chain" instead, and
// "Load more" never checks it.

export interface ChainRead {
  /** The verification with its signed head, or null when it could not be read. */
  result: Awaited<ReturnType<typeof verifyAudit>> | null;
  /** Set after a 429, with its Retry-After in seconds. */
  limited?: { retryAfter: number | undefined };
}

/** The chain verification. An UnauthorizedError is rethrown for the caller to send the person to sign in. */
export async function readChain(key: string): Promise<ChainRead> {
  try {
    return { result: await verifyAudit(key) };
  } catch (error) {
    if (error instanceof RateLimitedError) return { result: null, limited: { retryAfter: error.retryAfter } };
    if (error instanceof ApiError && error.status !== 401) return { result: null };
    throw error;
  }
}

/**
 * The first page of the log for `query`. When the API refuses the filters (400), every entry is listed instead and
 * `filtersApplied` is false. `verifyOnLoad`: check the chain too — done only for the unfiltered view.
 */
export async function loadAuditPage(key: string, query: AuditQuery, verifyOnLoad: boolean) {
  let page: Awaited<ReturnType<typeof listAudit>>;
  let filtersApplied = true;
  try {
    page = await listAudit(key, auditFilterFrom(query));
  } catch (error) {
    if (!(error instanceof ValidationError) || !filtered(query)) throw error;
    page = await listAudit(key, {});
    filtersApplied = false;
  }
  const chain = verifyOnLoad && !filtered(query) ? await readChain(key) : null;
  return { page, filtersApplied, chain };
}
