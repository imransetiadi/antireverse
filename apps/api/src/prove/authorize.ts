import {
  type AuthorizeRequest,
  AuthorizeRequestSchema,
  type AuthorizeResult,
  authorizeTest,
  TARGET_LIMITS,
  type Target,
} from "@antireverse/protocol";
import type { Db } from "../db/db.ts";
import { currentVersion } from "../stores/rules-of-engagement.ts";
import { listTargets } from "../stores/targets.ts";

// The authorization check every future test must pass (slice 14, D-069; slice 15 calls it before any traffic). It
// loads the Organization's targets and current signed Rules of Engagement in one transaction of that Organization
// (row-level security: another Organization's rows are invisible) and applies the protocol's pure `authorizeTest`.
// Freshness is always judged by the API's clock, never by a time the caller supplies (review F6). Nothing is started
// or recorded.

/** What slice 15 asks about: a test of `host` at `path` with `intensity`, now. A supplied `at` is ignored. */
export type AuthorizeTarget = Omit<AuthorizeRequest, "at"> & { at?: string };

/** `authorize(organizationId, request)`: may this test run now? */
export type Authorize = (organizationId: string, request: AuthorizeTarget) => Promise<AuthorizeResult>;

const MALFORMED = "An authorization request needs a host, a path starting with / and an intensity.";

/**
 * The check at an explicit time: the window is judged at `request.at`, freshness at `freshAt` (the API's clock). For
 * the dry check, which may ask about a test later in the week. Throws a TypeError for a malformed request.
 */
export async function evaluateAuthorization(
  db: Db,
  organizationId: string,
  request: AuthorizeRequest,
  freshAt: Date,
): Promise<AuthorizeResult> {
  const parsed = AuthorizeRequestSchema.safeParse(request);
  if (!parsed.success) throw new TypeError(MALFORMED);
  const state = await db.tx({ organizationId }, async (q) => ({
    targets: await listTargets(q),
    current: await currentVersion(q),
  }));
  return authorizeTest(state, parsed.data, { freshAt: freshAt.toISOString() });
}

/**
 * The API's `authorize` on `db` for slice 15: the test is judged at the API's clock (`now`) for both freshness and
 * the window; a caller-supplied `at` is ignored. A malformed request throws a TypeError, so a caller bug never turns
 * into traffic.
 */
export function createAuthorize(deps: { db: Db; now?: (() => Date) | undefined }): Authorize {
  const now = deps.now ?? (() => new Date());
  return (organizationId, request) => {
    const at = now();
    const { host, path, intensity } = request ?? ({} as AuthorizeTarget);
    return evaluateAuthorization(deps.db, organizationId, { host, path, intensity, at: at.toISOString() }, at);
  };
}

/**
 * Whether a target counts as verified at `at` for signing, by the same rule as `authorizeTest`: verified, with its
 * last successful ownership check at most `authorizeFreshnessS` before `at` and at most `authorizeClockSkewS`
 * after it.
 */
export function freshlyVerified(target: Pick<Target, "status" | "verified_at">, at: Date): boolean {
  if (target.status !== "verified" || target.verified_at === null) return false;
  const verified = Date.parse(target.verified_at);
  const time = at.getTime();
  return (
    Number.isFinite(verified) &&
    verified <= time + TARGET_LIMITS.authorizeClockSkewS * 1000 &&
    time - verified <= TARGET_LIMITS.authorizeFreshnessS * 1000
  );
}
