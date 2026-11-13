import {
  AuthorizeRequestSchema,
  type AuthorizeResult,
  CreateTargetRequestSchema,
  type CurrentRulesOfEngagementResponse,
  ID_PATTERNS,
  type ListRulesOfEngagementResponse,
  type ListTargetsResponse,
  type ProblemError,
  type RulesOfEngagementContent,
  type RulesOfEngagementResponse,
  SignRulesOfEngagementRequestSchema,
  TARGET_LIMITS,
  type Target,
  type TargetResponse,
  type VerifyTargetResponse,
  verificationInstructions,
} from "@antireverse/protocol";
import { generateVerificationToken, newId, rulesOfEngagementSha256 } from "@antireverse/protocol/server";
import { Hono } from "hono";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import { evaluateAuthorization, freshlyVerified } from "../prove/authorize.ts";
import { type ProveNetwork, runCheck } from "../prove/deps.ts";
import { lockOrganization } from "../stores/alert-channels.ts";
import { currentVersion, insertVersion, listVersions } from "../stores/rules-of-engagement.ts";
import {
  countTargets,
  deleteTarget,
  findTarget,
  hostTaken,
  insertTarget,
  listTargets,
  recordCheck,
  takeVerifyAttempt,
} from "../stores/targets.ts";
import { validateJson } from "../validate.ts";

// Prove (slice 14, D-069), for admins only: Verified Targets (add, list, show with the token, delete, verify),
// signed Rules of Engagement versions (list, current, sign) and the dry authorization check. Tenancy is row-level
// security: another Organization's target or version is a 404 like one that does not exist. No route logs a token.

/** SQL state of a unique violation: the same host added twice at once. */
const UNIQUE_VIOLATION = "23505";

/** Body of the dry check: the protocol request, `at` optional (default now). */
const DryAuthorizeRequestSchema = AuthorizeRequestSchema.partial({ at: true });

const NOT_SIGNABLE = "Must be a target of this Organization, verified within the last 26 hours.";

export function proveRoutes(deps: { db: Db; network: ProveNetwork; now?: (() => Date) | undefined }): Hono<AppEnv> {
  const { db, network } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");

  // --- Targets -------------------------------------------------------------------------------------------

  routes.get("/v1/targets", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const targets = await db.tx({ organizationId }, (q) => listTargets(q));
    return c.json({ targets } satisfies ListTargetsResponse);
  });

  routes.post("/v1/targets", admin, limitBody(), validateJson(CreateTargetRequestSchema), async (c) => {
    const { organizationId } = c.var.principal;
    const { host } = c.req.valid("json");
    const token = generateVerificationToken();
    let result: Target | "target-duplicate" | "target-limit";
    try {
      result = await db.tx({ organizationId }, async (q) => {
        // Serialises additions per Organization, so that the limit holds under concurrent requests.
        await lockOrganization(q, organizationId);
        if (await hostTaken(q, host)) return "target-duplicate";
        if ((await countTargets(q)) >= TARGET_LIMITS.targetsPerOrganization) return "target-limit";
        return insertTarget(q, { organizationId, id: newId("tgt"), host, token, createdAt: now() });
      });
    } catch (error) {
      if ((error as { code?: unknown }).code !== UNIQUE_VIOLATION) throw error;
      result = "target-duplicate";
    }
    if (typeof result === "string") return problem(c, "conflict", undefined, result);
    return c.json(
      { target: result, verification: verificationInstructions(host, token) } satisfies TargetResponse,
      201,
    );
  });

  routes.get("/v1/targets/:targetId", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const targetId = c.req.param("targetId");
    const found = ID_PATTERNS.tgt.test(targetId)
      ? await db.tx({ organizationId }, (q) => findTarget(q, targetId))
      : null;
    if (found === null) return problem(c, "not-found");
    return c.json({
      target: found.target,
      verification: verificationInstructions(found.target.host, found.token),
    } satisfies TargetResponse);
  });

  // A target in the scope of the current version cannot be deleted: sign a new version without it first.
  routes.delete("/v1/targets/:targetId", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const targetId = c.req.param("targetId");
    if (!ID_PATTERNS.tgt.test(targetId)) return problem(c, "not-found");
    const outcome = await db.tx({ organizationId }, async (q) => {
      // The same lock as signing: a version signed meanwhile is seen here, and a delete is seen by signing.
      await lockOrganization(q, organizationId);
      if ((await findTarget(q, targetId)) === null) return "not-found" as const;
      if ((await currentVersion(q))?.scope.includes(targetId) === true) return "target-in-scope" as const;
      await deleteTarget(q, targetId);
      return "deleted" as const;
    });
    if (outcome === "not-found") return problem(c, "not-found");
    if (outcome !== "deleted") return problem(c, "conflict", undefined, outcome);
    return c.body(null, 204);
  });

  // DNS first, then the file. The attempt is counted before the check (10 per host and 60 per Organization per hour,
  // kept across delete); the network check runs outside any transaction; its outcome is recorded in a second one,
  // only if no other check was recorded since this one started (review F3) — otherwise 409, and the newer stands.
  routes.post("/v1/targets/:targetId/verify", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const targetId = c.req.param("targetId");
    if (!ID_PATTERNS.tgt.test(targetId)) return problem(c, "not-found");
    const taken = await db.tx({ organizationId }, async (q) => {
      const found = await findTarget(q, targetId);
      if (found === null) return null;
      const attempt = await takeVerifyAttempt(q, { organizationId, host: found.target.host, at: now() });
      if (!attempt.allowed) return attempt;
      return {
        allowed: true as const,
        host: found.target.host,
        token: found.token,
        lastCheckedAt: found.target.last_checked_at,
      };
    });
    if (taken === null) return problem(c, "not-found");
    if (!taken.allowed) {
      c.header("Retry-After", String(taken.retryAfterS));
      return problem(c, "too-many-verifications");
    }
    const checked = await runCheck(network, taken.host, taken.token, now());
    const at = new Date(checked.result.checked_at);
    const recorded = await db.tx({ organizationId }, async (q) => {
      const target = await recordCheck(q, targetId, checked.outcome, at, {
        guard: { lastCheckedAt: taken.lastCheckedAt },
      });
      if (target !== null) return target;
      // Deleted while it was being checked, or a newer check was recorded meanwhile.
      return (await findTarget(q, targetId)) === null ? ("not-found" as const) : ("conflict" as const);
    });
    if (typeof recorded === "string") return problem(c, recorded);
    return c.json({ target: recorded, result: checked.result } satisfies VerifyTargetResponse);
  });

  // --- Rules of Engagement -------------------------------------------------------------------------------

  routes.get("/v1/rules-of-engagement", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const versions = await db.tx({ organizationId }, (q) => listVersions(q));
    return c.json({ versions } satisfies ListRulesOfEngagementResponse);
  });

  routes.get("/v1/rules-of-engagement/current", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const version = await db.tx({ organizationId }, (q) => currentVersion(q));
    return c.json({ version } satisfies CurrentRulesOfEngagementResponse);
  });

  // Signing: the typed confirmation is checked by the schema; every scope target must be a target of this
  // Organization, verified within the last 26 hours, at the moment of signing. The signer is the admin key.
  routes.post(
    "/v1/rules-of-engagement",
    admin,
    limitBody(),
    validateJson(SignRulesOfEngagementRequestSchema),
    async (c) => {
      const { organizationId, keyId } = c.var.principal;
      const body = c.req.valid("json");
      const content: RulesOfEngagementContent = {
        scope: body.scope,
        exclusions: body.exclusions,
        intensity: body.intensity,
        window: body.window,
        contacts: body.contacts,
      };
      const contentSha256 = rulesOfEngagementSha256(content);
      const signedAt = now();
      const outcome = await db.tx({ organizationId }, async (q) => {
        await lockOrganization(q, organizationId);
        const errors: ProblemError[] = [];
        for (const [index, targetId] of content.scope.entries()) {
          const found = await findTarget(q, targetId);
          if (found === null || !freshlyVerified(found.target, signedAt)) {
            errors.push({ path: `scope.${index}`, message: NOT_SIGNABLE });
          }
        }
        if (errors.length > 0) return { errors };
        return {
          version: await insertVersion(q, {
            organizationId,
            id: newId("roe"),
            content,
            signedBy: keyId,
            signedAt,
            contentSha256,
          }),
        };
      });
      if ("errors" in outcome) return problem(c, "validation", outcome.errors);
      return c.json({ version: outcome.version } satisfies RulesOfEngagementResponse, 201);
    },
  );

  // --- Authorization (dry) -------------------------------------------------------------------------------

  // `at` (default now) places the test in the window; freshness is always judged now (review F6).
  routes.post("/v1/prove/authorize", admin, limitBody(), validateJson(DryAuthorizeRequestSchema), async (c) => {
    const { organizationId } = c.var.principal;
    const body = c.req.valid("json");
    const at = now();
    const result = await evaluateAuthorization(db, organizationId, { ...body, at: body.at ?? at.toISOString() }, at);
    return c.json(result satisfies AuthorizeResult);
  });

  return routes;
}
