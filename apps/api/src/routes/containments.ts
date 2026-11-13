import {
  CONTAINMENT_LIMITS,
  CONTAINMENT_STATUSES,
  type ConflictReason,
  type Containment,
  type ContainmentResponse,
  type ContainmentTarget,
  CreateContainmentRequestSchema,
  cidrOverlapsPrefix,
  ENVIRONMENTS,
  ID_PATTERNS,
  type ListContainmentsResponse,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { Hono } from "hono";
import { z } from "zod";
import { audit, auditActor, reasonMissing } from "../audit.ts";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db } from "../db/db.ts";
import type { PatchCatalog } from "../patches/catalog.ts";
import { problem } from "../problem.ts";
import { lockOrganization } from "../stores/alert-channels.ts";
import { allowlistCidrs } from "../stores/allowlist.ts";
import {
  CONTAINMENTS_LISTED,
  countActiveContainments,
  findActiveContainment,
  findContainment,
  insertContainment,
  liftContainment,
  listContainments,
} from "../stores/containments.ts";
import { findIncident, hasActor } from "../stores/incidents.ts";
import { validateJson, validateQuery } from "../validate.ts";

/** Query of `GET /v1/containments`: every filter optional. */
const ListContainmentsQuerySchema = z.object({
  app_id: z.string().regex(ID_PATTERNS.app, "Expected an App id.").optional(),
  environment: z.enum(ENVIRONMENTS).optional(),
  status: z.enum(CONTAINMENT_STATUSES).optional(),
});

/** The confirmation of a prefix block names the Incident's prefix, by fixed text: it never echoes either. */
const CONFIRM_MISMATCH = [{ path: "confirm_prefix", message: "Must equal the network prefix of the Incident." }];

type Outcome =
  | { kind: "created" | "existing"; containment: Containment }
  | { kind: "not-found" }
  | { kind: "confirm-mismatch" }
  | { kind: "conflict"; reason: ConflictReason };

export function containmentRoutes(deps: {
  db: Db;
  now?: () => Date;
  /** The Virtual patch catalog: the Actors of an exploit-attempt Incident come from its advisory's patches. */
  patches?: PatchCatalog | undefined;
}): Hono<AppEnv> {
  const { db } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");

  // Blocks one Actor of the Incident, or the Incident's own network prefix, in the Incident's App and
  // Environment for `ttl_s`. The App, Environment and prefix come from the Incident, never from the body.
  routes.post(
    "/v1/incidents/:incidentId/containments",
    admin,
    limitBody(),
    validateJson(CreateContainmentRequestSchema),
    async (c) => {
      const { organizationId, keyId } = c.var.principal;
      const incidentId = c.req.param("incidentId");
      const request = c.req.valid("json");
      if (!ID_PATTERNS.inc.test(incidentId)) return problem(c, "not-found");
      // Slice 18a: a block needs a reason.
      const missing = reasonMissing(c);
      if (missing !== null) return missing;
      const actor = auditActor(c);

      const at = now();
      const outcome = await db.tx<Outcome>({ organizationId }, async (q) => {
        // Serialises creations per Organization, so that the limit and the one-active-block-per-target rule hold
        // under concurrent requests. Then the Incident, locked: a status change does not interleave.
        await lockOrganization(q, organizationId);
        // Another Organization's Incident is invisible to this transaction: "not found" like any other.
        const incident = await findIncident(q, incidentId, true);
        if (incident === null) return { kind: "not-found" };
        // A clone Incident has no network prefix and no Actors: containment does not apply to it (take the copy
        // down at its host).
        // An exploit-attempt Incident (slice 20) is grouped by advisory, not network: its Actors can be blocked, a
        // network cannot (it has no prefix of its own).
        const ipPrefix = incident.ip_prefix;
        const actorsOnly = incident.rule === "exploit-attempt";
        if (incident.rule === "clone-origin" || (ipPrefix === null && !actorsOnly)) {
          return { kind: "conflict", reason: "containment-not-applicable" };
        }
        if (incident.status === "resolved") return { kind: "conflict", reason: "incident-resolved" };

        let target: ContainmentTarget;
        if (request.target.kind === "actor") {
          // Only an Actor of this Incident: its App, Environment, prefix (or patches), time span and rule.
          if (!(await hasActor(q, incident, request.target.ip_hash, deps.patches))) {
            return { kind: "conflict", reason: "actor-unknown" };
          }
          target = { kind: "actor", ip_hash: request.target.ip_hash };
        } else if (ipPrefix === null) {
          return { kind: "conflict", reason: "containment-not-applicable" };
        } else {
          if (request.confirm_prefix !== ipPrefix) return { kind: "confirm-mismatch" };
          // The allowlist always wins: a network that shares any address with an allowlisted range is refused.
          const allowlist = await allowlistCidrs(q);
          if (allowlist.some((cidr) => cidrOverlapsPrefix(cidr, ipPrefix))) {
            return { kind: "conflict", reason: "prefix-allowlisted" };
          }
          target = { kind: "prefix", ip_prefix: ipPrefix };
        }

        const scope = { organizationId, appId: incident.app_id, environment: incident.environment };
        const existing = await findActiveContainment(q, scope, target, at);
        if (existing !== null) return { kind: "existing", containment: existing };
        if ((await countActiveContainments(q, scope, at)) >= CONTAINMENT_LIMITS.activePerAppEnv) {
          return { kind: "conflict", reason: "containment-limit" };
        }
        const containment = await insertContainment(q, {
          ...scope,
          id: newId("cnt"),
          incidentId: incident.id,
          target,
          createdAt: at,
          expiresAt: new Date(at.getTime() + request.ttl_s * 1_000),
          createdBy: keyId,
        });
        await audit(q, actor, {
          action: "containment.create",
          appId: incident.app_id,
          target: { kind: "containment", id: containment.id },
          summary: `Blocked ${
            target.kind === "actor" ? `the Actor ${target.ip_hash}` : `the network ${target.ip_prefix}`
          } in ${incident.environment} for ${request.ttl_s} s, from the Incident ${incident.id}.`,
          at,
        });
        return { kind: "created", containment };
      });

      switch (outcome.kind) {
        case "not-found":
          return problem(c, "not-found");
        case "confirm-mismatch":
          return problem(c, "validation", CONFIRM_MISMATCH);
        case "conflict":
          return problem(c, "conflict", undefined, outcome.reason);
        default:
          return c.json(
            { containment: outcome.containment } satisfies ContainmentResponse,
            outcome.kind === "created" ? 201 : 200,
          );
      }
    },
  );

  // Ends an active block now. An expired or already lifted block is a conflict; blocks are never deleted.
  routes.post("/v1/containments/:containmentId/lift", admin, limitBody(), async (c) => {
    const { organizationId, keyId } = c.var.principal;
    const containmentId = c.req.param("containmentId");
    if (!ID_PATTERNS.cnt.test(containmentId)) return problem(c, "not-found");
    const actor = auditActor(c);
    const at = now();
    const result = await db.tx<Containment | "not-found" | "ended">({ organizationId }, async (q) => {
      const found = await findContainment(q, containmentId, at, true);
      if (found === null) return "not-found";
      if (found.status !== "active") return "ended";
      const lifted = await liftContainment(q, containmentId, keyId, at);
      if (lifted === null) return "ended";
      await audit(q, actor, {
        action: "containment.lift",
        appId: lifted.app_id,
        target: { kind: "containment", id: containmentId },
        summary: `Lifted the block ${containmentId} in ${lifted.environment} before its expiry.`,
        at,
      });
      return lifted;
    });
    if (result === "not-found") return problem(c, "not-found");
    if (result === "ended") return problem(c, "conflict", undefined, "containment-ended");
    return c.json({ containment: result } satisfies ContainmentResponse);
  });

  // Newest first, at most CONTAINMENTS_LISTED. The active blocks of one App and Environment (at most
  // CONTAINMENT_LIMITS.activePerAppEnv) always fit.
  routes.get("/v1/containments", admin, validateQuery(ListContainmentsQuerySchema), async (c) => {
    const { organizationId } = c.var.principal;
    const { app_id: appId, environment, status } = c.req.valid("query");
    const at = now();
    const containments = await db.tx({ organizationId }, (q) =>
      listContainments(
        q,
        {
          ...(appId === undefined ? {} : { appId }),
          ...(environment === undefined ? {} : { environment }),
          ...(status === undefined ? {} : { status }),
          limit: CONTAINMENTS_LISTED,
        },
        at,
      ),
    );
    return c.json({ containments } satisfies ListContainmentsResponse);
  });

  return routes;
}
