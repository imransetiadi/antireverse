import {
  AdvisoryIdSchema,
  ENVIRONMENTS,
  EXPOSURE_LIMITS,
  FINDING_SEVERITIES,
  FINDING_SOURCES,
  FINDING_STATUSES,
  type FindingDetailResponse,
  type FindingResponse,
  ID_PATTERNS,
  IgnoreFindingRequestSchema,
  type ListFindingsResponse,
} from "@antireverse/protocol";
import { Hono } from "hono";
import { z } from "zod";
import { audit, auditActor } from "../audit.ts";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import { findAdvisory } from "../stores/advisories.ts";
import { findFinding, ignoreFinding, listFindings, reopenFinding, reviveExpired } from "../stores/findings.ts";
import { validateJson, validateQuery } from "../validate.ts";

const DAY_MS = 86_400_000;

/** The filters of `GET /v1/findings`; each optional, unknown parameters ignored. */
const ListFindingsQuerySchema = z.object({
  app_id: z.string().regex(ID_PATTERNS.app).optional(),
  environment: z.enum(ENVIRONMENTS).optional(),
  status: z.enum(FINDING_STATUSES).optional(),
  severity: z.enum(FINDING_SEVERITIES).optional(),
  source: z.enum(FINDING_SOURCES).optional(),
  build_id: z.string().regex(ID_PATTERNS.bld).optional(),
  /** An advisory id or any of its aliases (GHSA-…, CVE-…), matched exactly. */
  advisory_id: AdvisoryIdSchema.optional(),
});

/**
 * The Findings of the caller's Organization (admin key). Another Organization's Finding is "not found" like any
 * other. Every read first returns ignored Findings whose expiry passed to open.
 */
export function findingRoutes(deps: { db: Db; now?: (() => Date) | undefined }): Hono<AppEnv> {
  const { db } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");

  routes.get("/v1/findings", admin, validateQuery(ListFindingsQuerySchema), async (c) => {
    const { organizationId } = c.var.principal;
    const query = c.req.valid("query");
    const findings = await db.tx({ organizationId }, async (q) => {
      await reviveExpired(q, now());
      return listFindings(q, {
        appId: query.app_id,
        environment: query.environment,
        status: query.status,
        severity: query.severity,
        source: query.source,
        buildId: query.build_id,
        advisoryId: query.advisory_id,
        limit: EXPOSURE_LIMITS.findingsListed,
      });
    });
    return c.json({ findings } satisfies ListFindingsResponse);
  });

  routes.get("/v1/findings/:findingId", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const id = c.req.param("findingId");
    if (!ID_PATTERNS.fnd.test(id)) return problem(c, "not-found");
    const detail = await db.tx({ organizationId }, async (q) => {
      await reviveExpired(q, now());
      const finding = await findFinding(q, id);
      if (finding === null) return null;
      const stored = await findAdvisory(q, finding.advisory_id);
      return stored === null ? null : { finding, advisory: stored.advisory };
    });
    if (detail === null) return problem(c, "not-found");
    return c.json(detail satisfies FindingDetailResponse);
  });

  routes.post(
    "/v1/findings/:findingId/ignore",
    admin,
    limitBody(),
    validateJson(IgnoreFindingRequestSchema),
    async (c) => {
      const { organizationId, keyId } = c.var.principal;
      const id = c.req.param("findingId");
      const { reason, until } = c.req.valid("json");
      const actor = auditActor(c);
      if (!ID_PATTERNS.fnd.test(id)) return problem(c, "not-found");
      const at = now();
      const expiry = Date.parse(until);
      if (!(expiry > at.getTime())) {
        return problem(c, "validation", [{ path: "until", message: "Must lie in the future." }]);
      }
      if (expiry > at.getTime() + EXPOSURE_LIMITS.ignoreDaysMax * DAY_MS) {
        return problem(c, "validation", [
          { path: "until", message: `Must be at most ${EXPOSURE_LIMITS.ignoreDaysMax} days ahead.` },
        ]);
      }
      const result = await db.tx({ organizationId }, async (q) => {
        await reviveExpired(q, at);
        const finding = await findFinding(q, id, true);
        if (finding === null) return null;
        if (finding.status === "fixed" || finding.status === "withdrawn") return "closed" as const;
        await ignoreFinding(q, id, { reason, until: new Date(expiry), by: keyId }, at);
        await audit(q, actor, {
          action: "finding.ignore",
          appId: finding.app_id,
          target: { kind: "finding", id },
          summary: `Ignored the Finding ${id} (${finding.advisory_id} in ${finding.package}) until ${new Date(expiry).toISOString()}.`,
          at,
        });
        return findFinding(q, id);
      });
      if (result === null) return problem(c, "not-found");
      if (result === "closed") return problem(c, "conflict"); // fixed or withdrawn (D-060)
      return c.json({ finding: result } satisfies FindingResponse);
    },
  );

  routes.post("/v1/findings/:findingId/reopen", admin, limitBody(), async (c) => {
    const { organizationId } = c.var.principal;
    const actor = auditActor(c);
    const id = c.req.param("findingId");
    if (!ID_PATTERNS.fnd.test(id)) return problem(c, "not-found");
    const at = now();
    const result = await db.tx({ organizationId }, async (q) => {
      await reviveExpired(q, at);
      const finding = await findFinding(q, id, true);
      if (finding === null) return null;
      if (finding.status === "fixed" || finding.status === "withdrawn") return "closed" as const;
      // Reopening an open Finding changes nothing, and so writes no entry.
      if (finding.status === "ignored") {
        await reopenFinding(q, id, at);
        await audit(q, actor, {
          action: "finding.reopen",
          appId: finding.app_id,
          target: { kind: "finding", id },
          summary: `Reopened the ignored Finding ${id} (${finding.advisory_id} in ${finding.package}).`,
          at,
        });
      }
      return findFinding(q, id);
    });
    if (result === null) return problem(c, "not-found");
    if (result === "closed") return problem(c, "conflict"); // fixed or withdrawn (D-060)
    return c.json({ finding: result } satisfies FindingResponse);
  });

  return routes;
}
