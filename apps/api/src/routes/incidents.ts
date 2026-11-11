import {
  CONTAINMENT_LIMITS,
  ID_PATTERNS,
  INCIDENT_LIMITS,
  INCIDENT_STATUSES,
  type Incident,
  type IncidentDetailResponse,
  type IncidentStatus,
  type ListIncidentsResponse,
  UpdateIncidentRequestSchema,
} from "@antireverse/protocol";
import { Hono } from "hono";
import { z } from "zod";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import { CONTAINMENTS_LISTED, listIncidentContainments } from "../stores/containments.ts";
import {
  findIncident,
  listActors,
  listDetections,
  listEvidence,
  listIncidents,
  setIncidentStatus,
} from "../stores/incidents.ts";
import { validateJson, validateQuery } from "../validate.ts";

/** Query of `GET /v1/incidents`: both filters optional. */
const ListIncidentsQuerySchema = z.object({
  app_id: z.string().regex(ID_PATTERNS.app, "Expected an App id.").optional(),
  status: z.enum(INCIDENT_STATUSES).optional(),
});

/** The allowed status transitions. Anything else, including a repeat of the current status, is a conflict. */
const TRANSITIONS: Record<IncidentStatus, readonly IncidentStatus[]> = {
  open: ["acknowledged", "resolved"],
  acknowledged: ["resolved"],
  resolved: [],
};

export function incidentRoutes(deps: { db: Db; now?: () => Date }): Hono<AppEnv> {
  const { db } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");

  routes.get("/v1/incidents", admin, validateQuery(ListIncidentsQuerySchema), async (c) => {
    const { organizationId } = c.var.principal;
    const { app_id: appId, status } = c.req.valid("query");
    const incidents = await db.tx({ organizationId }, (q) =>
      listIncidents(q, {
        ...(appId === undefined ? {} : { appId }),
        ...(status === undefined ? {} : { status }),
        limit: INCIDENT_LIMITS.listed,
      }),
    );
    return c.json({ incidents } satisfies ListIncidentsResponse);
  });

  routes.get("/v1/incidents/:incidentId", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const incidentId = c.req.param("incidentId");
    // A malformed id is an Incident that does not exist; another Organization's is invisible to the transaction.
    const detail = ID_PATTERNS.inc.test(incidentId)
      ? await db.tx({ organizationId }, async (q) => {
          const incident = await findIncident(q, incidentId);
          if (incident === null) return null;
          return {
            incident,
            detections: await listDetections(q, incident.id, INCIDENT_LIMITS.detectionsListed),
            evidence: await listEvidence(q, incident, INCIDENT_LIMITS.evidence),
            actors: await listActors(q, incident, CONTAINMENT_LIMITS.actorsListed),
            // Status from the clock: a block past its expiry is `expired`.
            containments: await listIncidentContainments(q, incident.id, now(), CONTAINMENTS_LISTED),
          };
        })
      : null;
    if (detail === null) return problem(c, "not-found");
    return c.json(detail satisfies IncidentDetailResponse);
  });

  routes.patch(
    "/v1/incidents/:incidentId",
    admin,
    limitBody(),
    validateJson(UpdateIncidentRequestSchema),
    async (c) => {
      const { organizationId } = c.var.principal;
      const incidentId = c.req.param("incidentId");
      const { status } = c.req.valid("json");
      if (!ID_PATTERNS.inc.test(incidentId)) return problem(c, "not-found");
      const result = await db.tx<{ incident: Incident } | "not-found" | "conflict">({ organizationId }, async (q) => {
        // Locked: a Detection joining the Incident and this change never interleave.
        const incident = await findIncident(q, incidentId, true);
        if (incident === null) return "not-found";
        if (!TRANSITIONS[incident.status].includes(status)) return "conflict";
        const updated = await setIncidentStatus(q, incidentId, status, now());
        return updated === null ? "not-found" : { incident: updated };
      });
      if (result === "not-found" || result === "conflict") return problem(c, result);
      return c.json(result);
    },
  );

  return routes;
}
