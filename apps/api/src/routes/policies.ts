import {
  ENVIRONMENTS,
  ID_PATTERNS,
  POLICY_LIMITS,
  type Policy,
  type PolicyResponse,
  type PolicyRule,
  type PolicyVersionsResponse,
  type ProblemError,
  PublishPolicyRequestSchema,
  RollbackPolicyRequestSchema,
} from "@antireverse/protocol";
import { Hono } from "hono";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db, Queryable } from "../db/db.ts";
import { guardrailErrors, prepareRules } from "../policy.ts";
import { problem } from "../problem.ts";
import { findApp, lockApp } from "../stores/apps.ts";
import {
  currentPolicy,
  currentVersion,
  findPolicyRules,
  findPolicyVersion,
  insertPolicyVersion,
  listPolicyVersions,
  type PolicyTarget,
} from "../stores/policies.ts";
import { validateJson } from "../validate.ts";

/** How often a publish is tried when another transaction takes its version first. */
const PUBLISH_ATTEMPTS = 5;
/** SQL state of a primary-key conflict: here, two publishes that computed the same next version. */
const UNIQUE_VIOLATION = "23505";

/**
 * A published Policy; the errors that refused it; a conflict when the edit was based on a version that is no
 * longer current; or null when the App or the version does not exist.
 */
type Published = { policy: Policy } | { errors: ProblemError[] } | { conflict: true } | null;

export function policyRoutes(deps: { db: Db; now?: () => Date }): Hono<AppEnv> {
  const { db } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");

  /** The Policy a path names, or null when the path cannot name one. Whether the App exists is the database's answer. */
  function targetOf(organizationId: string, appId: string, environment: string): PolicyTarget | null {
    const known = ENVIRONMENTS.find((candidate) => candidate === environment);
    return known === undefined || !ID_PATTERNS.app.test(appId) ? null : { organizationId, appId, environment: known };
  }

  /** Runs `read` for an App of the caller's Organization. Null when the path is malformed or the App is not theirs. */
  async function forApp<T>(target: PolicyTarget | null, read: (q: Queryable, target: PolicyTarget) => Promise<T>) {
    if (target === null) return null;
    return db.tx({ organizationId: target.organizationId }, async (q) =>
      (await findApp(q, target.appId)) === null ? null : read(q, target),
    );
  }

  /**
   * Publishes the Rules that `rulesOf` yields as the next version, in one transaction.
   *
   * Consecutive versions, each exactly once: the transaction first takes the App's row lock, so a second
   * publisher waits and then sees the first one's version. Should two transactions still compute the same
   * version (an isolation level under which the waiting one does not see the other's commit), the primary
   * key refuses the second and it is tried again from the start.
   *
   * With `expectedVersion`, the publish is refused as a conflict unless that is the current version. It is
   * compared under the same row lock, so of two publishes based on one version exactly one gets through.
   * Only then are the Rules judged: `allowBroad` acknowledges Enforce Rules with a broad pattern.
   */
  async function publish(
    target: PolicyTarget | null,
    publishedByKeyId: string,
    expectedVersion: number | undefined,
    allowBroad: boolean,
    rulesOf: (q: Queryable, target: PolicyTarget) => Promise<PolicyRule[] | null>,
  ): Promise<Published> {
    if (target === null) return null;
    for (let attempt = 1; ; attempt++) {
      try {
        return await db.tx({ organizationId: target.organizationId }, async (q) => {
          if (!(await lockApp(q, target.appId))) return null;
          if (expectedVersion !== undefined && (await currentVersion(q, target)) !== expectedVersion) {
            return { conflict: true };
          }
          const rules = await rulesOf(q, target);
          if (rules === null) return null;
          // Checked on whatever is about to be stored, also when it comes from an earlier version.
          const errors = guardrailErrors(rules, { allowBroad });
          if (errors.length > 0) return { errors };
          return { policy: await insertPolicyVersion(q, target, { rules, publishedAt: now(), publishedByKeyId }) };
        });
      } catch (error) {
        const lostTheVersion = (error as { code?: unknown }).code === UNIQUE_VIOLATION;
        if (!lostTheVersion || attempt >= PUBLISH_ATTEMPTS) throw error;
      }
    }
  }

  routes.get("/v1/apps/:appId/policies/:environment", admin, async (c) => {
    const target = targetOf(c.var.principal.organizationId, c.req.param("appId"), c.req.param("environment"));
    const policy = await forApp(target, currentPolicy);
    if (policy === null) return problem(c, "not-found");
    return c.json({ policy } satisfies PolicyResponse);
  });

  // Publishes the Rules of the body as the next version. The Console sends the whole list every time, with
  // `expected_version`: the version it edited. A publish since then makes this one a 409 that stores nothing.
  routes.put(
    "/v1/apps/:appId/policies/:environment",
    admin,
    limitBody(),
    validateJson(PublishPolicyRequestSchema),
    async (c) => {
      const { organizationId, keyId } = c.var.principal;
      const target = targetOf(organizationId, c.req.param("appId"), c.req.param("environment"));
      const body = c.req.valid("json");
      const prepared = prepareRules(body.rules);
      if ("errors" in prepared) return problem(c, "validation", prepared.errors);

      const published = await publish(target, keyId, body.expected_version, body.allow_broad === true, () =>
        Promise.resolve(prepared.rules),
      );
      if (published === null) return problem(c, "not-found");
      if ("conflict" in published) return problem(c, "conflict");
      if ("errors" in published) return problem(c, "validation", published.errors);
      return c.json({ policy: published.policy } satisfies PolicyResponse, 201);
    },
  );

  routes.get("/v1/apps/:appId/policies/:environment/versions", admin, async (c) => {
    const target = targetOf(c.var.principal.organizationId, c.req.param("appId"), c.req.param("environment"));
    const versions = await forApp(target, (q, policy) => listPolicyVersions(q, policy, POLICY_LIMITS.versionsListed));
    if (versions === null) return problem(c, "not-found");
    return c.json({ versions } satisfies PolicyVersionsResponse);
  });

  // One published version with its Rules: what a rollback to it would bring back.
  routes.get("/v1/apps/:appId/policies/:environment/versions/:version", admin, async (c) => {
    const target = targetOf(c.var.principal.organizationId, c.req.param("appId"), c.req.param("environment"));
    const text = c.req.param("version");
    // A path that cannot name a published version is a version that does not exist.
    const version = /^[1-9][0-9]{0,9}$/.test(text) ? Number(text) : null;
    const policy = version === null ? null : await forApp(target, (q, of) => findPolicyVersion(q, of, version));
    if (policy === null) return problem(c, "not-found");
    return c.json({ policy } satisfies PolicyResponse);
  });

  // Publishes the Rules of an earlier version as the next version: history is added to, never rewritten.
  routes.post(
    "/v1/apps/:appId/policies/:environment/rollback",
    admin,
    limitBody(),
    validateJson(RollbackPolicyRequestSchema),
    async (c) => {
      const { organizationId, keyId } = c.var.principal;
      const target = targetOf(organizationId, c.req.param("appId"), c.req.param("environment"));
      const { version, expected_version: expectedVersion, allow_broad: allowBroad } = c.req.valid("json");

      const published = await publish(target, keyId, expectedVersion, allowBroad === true, (q, policy) =>
        findPolicyRules(q, policy, version),
      );
      if (published === null) return problem(c, "not-found");
      if ("conflict" in published) return problem(c, "conflict");
      if ("errors" in published) return problem(c, "validation", published.errors);
      return c.json({ policy: published.policy } satisfies PolicyResponse, 201);
    },
  );

  return routes;
}
