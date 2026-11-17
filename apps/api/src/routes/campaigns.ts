import {
  CAMPAIGN_LIMITS,
  CAMPAIGN_REPORT_LIMITS,
  CAMPAIGN_STAND_IN_NOTICE,
  type CampaignReportResponse,
  type CampaignResponse,
  type ConflictReason,
  CreateCampaignRequestSchema,
  campaignAuthorisationPhrase,
  campaignChecksSentence,
  ID_PATTERNS,
  intensityRank,
  isPathExcluded,
  type ListCampaignFindingsResponse,
  type ListCampaignRequestsResponse,
  type ListCampaignsResponse,
  STAND_IN_ENGINE,
  VERIFICATION_FILE_PATH,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import { Hono } from "hono";
import { audit, auditActor, reasonMissing, systemActor } from "../audit.ts";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import type { CampaignService } from "../campaign/runner.ts";
import type { Db } from "../db/db.ts";
import { problem } from "../problem.ts";
import { freshlyVerified } from "../prove/authorize.ts";
import {
  campaignControl,
  createdInLastDay,
  endCampaign,
  findCampaign,
  hasActiveCampaign,
  insertCampaign,
  listCampaignFindings,
  listCampaignRequests,
  listCampaigns,
  requestStop,
} from "../stores/campaigns.ts";
import { currentVersion } from "../stores/rules-of-engagement.ts";
import { findTarget } from "../stores/targets.ts";
import { validateJson } from "../validate.ts";

// Pentest Campaigns (slice 15a, D-105), admin key only. A Campaign is launched against a Verified Target of the
// caller's Organization under the current signed Rules of Engagement, with a typed phrase, a staging declaration and
// a reason; it is queued, and the runner starts it once every start check passed again. Stopping one needs a reason
// and is final. The engine is the scripted stand-in: every answer that shows a result carries the engine tag and the
// sentence that says what it is not.

const DAY_MS = 86_400_000;
/** How long a stop waits for the run to write its end before it answers anyway (the stop itself is already durable). */
const STOP_WAIT_MS = 10_000;

export function campaignRoutes(deps: {
  db: Db;
  campaigns: CampaignService;
  now?: (() => Date) | undefined;
}): Hono<AppEnv> {
  const { db, campaigns } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");

  routes.post("/v1/campaigns", admin, validateJson(CreateCampaignRequestSchema), async (c) => {
    const missing = reasonMissing(c);
    if (missing !== null) return missing;
    const { organizationId } = c.var.principal;
    const body = c.req.valid("json");
    // Off unless the operator turned Campaigns on: nothing is read or written.
    if (!campaigns.enabled) return problem(c, "campaigns-disabled");
    const actor = auditActor(c);

    const result = await db.tx({ organizationId }, async (q) => {
      const at = now();
      const control = await campaignControl(q, "");
      if (control.killed) return { refused: "campaigns-stopped" as const };
      if (control.suspended) return { refused: "campaigns-suspended" as const };
      const found = await findTarget(q, body.target_id);
      if (found === null) return { invalid: { path: "target_id", message: "Must be a target of the Organization." } };
      const { target } = found;
      if (body.confirm !== campaignAuthorisationPhrase(target.host)) {
        return {
          invalid: { path: "confirm", message: "Type the exact phrase: I authorise a test of <the target's host>." },
        };
      }
      const conflict = (reason: ConflictReason) => ({ conflict: reason });
      if (!freshlyVerified(target, at)) return conflict("campaign-target-not-verified");
      const current = await currentVersion(q);
      if (current === null) return conflict("campaign-no-rules");
      if (!current.scope.includes(target.id)) return conflict("campaign-target-out-of-scope");
      if (!(at.getTime() - Date.parse(current.signed_at) <= CAMPAIGN_LIMITS.roeMaxAgeDays * DAY_MS)) {
        return conflict("campaign-rules-too-old");
      }
      if (intensityRank(body.intensity) > intensityRank(current.intensity))
        return conflict("campaign-intensity-exceeds");
      // Every Campaign starts by fetching the ownership file: Rules that exclude its path can never be met.
      if (isPathExcluded(VERIFICATION_FILE_PATH, current.exclusions)) {
        return conflict("campaign-verification-path-excluded");
      }
      if (await hasActiveCampaign(q)) return conflict("campaign-active");
      const created = await createdInLastDay(q, target.id, at);
      const waits: number[] = [];
      if (created.organization >= CAMPAIGN_LIMITS.createdPerOrganizationPerDay && created.oldestOrganization !== null) {
        waits.push(created.oldestOrganization.getTime() + DAY_MS - at.getTime());
      }
      if (created.target >= CAMPAIGN_LIMITS.createdPerTargetPerDay && created.oldestTarget !== null) {
        waits.push(created.oldestTarget.getTime() + DAY_MS - at.getTime());
      }
      if (waits.length > 0) return { retryAfterS: Math.max(1, Math.ceil(Math.max(...waits) / 1000)) };
      const campaign = await insertCampaign(q, {
        organizationId,
        id: newId("cmp"),
        targetId: target.id,
        host: target.host,
        roeId: current.id,
        roeSha256: current.content_sha256,
        intensity: body.intensity,
        engine: STAND_IN_ENGINE,
        createdBy: c.var.principal.keyId,
        createdAt: at,
      });
      await audit(q, actor, {
        action: "campaign.create",
        target: { kind: "campaign", id: campaign.id },
        summary: `Queued a ${body.intensity} Campaign against the target ${target.id} under the Rules of Engagement ${current.id}. The creator declared the target a staging system and typed the authorisation phrase. Engine: ${STAND_IN_ENGINE.name} ${STAND_IN_ENGINE.version}.`,
        at,
      });
      return { campaign };
    });
    if ("refused" in result) return problem(c, result.refused);
    if ("invalid" in result) return problem(c, "validation", [result.invalid]);
    if ("conflict" in result) return problem(c, "conflict", undefined, result.conflict);
    if ("retryAfterS" in result) {
      c.header("Retry-After", String(result.retryAfterS));
      return problem(c, "too-many-campaigns");
    }
    campaigns.wake();
    return c.json({ campaign: result.campaign } satisfies CampaignResponse, 202);
  });

  routes.get("/v1/campaigns", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const { list, control } = await db.tx({ organizationId }, async (q) => ({
      list: await listCampaigns(q, CAMPAIGN_LIMITS.listed),
      control: await campaignControl(q, ""),
    }));
    return c.json({
      campaigns: list,
      enabled: campaigns.enabled,
      blocked: control.killed ? "operator_kill" : control.suspended ? "organization_suspended" : null,
      notice: CAMPAIGN_STAND_IN_NOTICE,
    } satisfies ListCampaignsResponse);
  });

  routes.get("/v1/campaigns/:id", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const id = c.req.param("id");
    const campaign = ID_PATTERNS.cmp.test(id) ? await db.tx({ organizationId }, (q) => findCampaign(q, id)) : null;
    if (campaign === null) return problem(c, "not-found");
    return c.json({ campaign } satisfies CampaignResponse);
  });

  routes.get("/v1/campaigns/:id/requests", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const id = c.req.param("id");
    const requests = ID_PATTERNS.cmp.test(id)
      ? await db.tx({ organizationId }, async (q) =>
          (await findCampaign(q, id)) === null ? null : listCampaignRequests(q, id),
        )
      : null;
    if (requests === null) return problem(c, "not-found");
    return c.json({ requests } satisfies ListCampaignRequestsResponse);
  });

  routes.get("/v1/campaigns/:id/findings", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const id = c.req.param("id");
    const found = ID_PATTERNS.cmp.test(id)
      ? await db.tx({ organizationId }, async (q) => {
          const campaign = await findCampaign(q, id);
          return campaign === null ? null : { campaign, findings: await listCampaignFindings(q, id) };
        })
      : null;
    if (found === null) return problem(c, "not-found");
    return c.json({
      findings: found.findings,
      engine: found.campaign.engine,
      notice: found.campaign.notice,
    } satisfies ListCampaignFindingsResponse);
  });

  // The report: what ran, what it reported and what it did not run — never a statement that nothing is wrong.
  routes.get("/v1/campaigns/:id/report", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const id = c.req.param("id");
    const found = ID_PATTERNS.cmp.test(id)
      ? await db.tx({ organizationId }, async (q) => {
          const campaign = await findCampaign(q, id);
          return campaign === null ? null : { campaign, findings: await listCampaignFindings(q, id) };
        })
      : null;
    if (found === null) return problem(c, "not-found");
    const { campaign, findings } = found;
    return c.json({
      report: {
        campaign,
        engine: campaign.engine,
        notice: campaign.notice,
        summary: campaign.checks === null ? null : campaignChecksSentence(campaign.checks),
        checks: campaign.checks,
        findings,
        findings_dropped: campaign.findings_dropped,
        limits: [...CAMPAIGN_REPORT_LIMITS],
      },
    } satisfies CampaignReportResponse);
  });

  // The owner's kill switch for one Campaign. The stop is written first (the gate reads it before every request), then
  // the run in this process is aborted: its request in flight is cut and its engine terminated. A stop is final.
  routes.post("/v1/campaigns/:id/stop", admin, async (c) => {
    const { organizationId, keyId } = c.var.principal;
    const id = c.req.param("id");
    if (!ID_PATTERNS.cmp.test(id)) return problem(c, "not-found");
    const known = await db.tx({ organizationId }, (q) => findCampaign(q, id));
    if (known === null) return problem(c, "not-found");
    const missing = reasonMissing(c);
    if (missing !== null) return missing;
    const actor = auditActor(c);

    const outcome = await db.tx({ organizationId }, async (q) => {
      const at = now();
      const campaign = await findCampaign(q, id);
      if (campaign === null) return "not-found" as const;
      if (campaign.status !== "queued" && campaign.status !== "running") return "ended" as const;
      // The durable request and its entry, once. A second stop of a Campaign that is still going writes neither
      // again; it cuts the run again, below.
      if (await requestStop(q, id, { keyId, reason: actor.reason ?? "", at })) {
        await audit(q, actor, {
          action: "campaign.stop",
          target: { kind: "campaign", id },
          summary: `Stopped the Campaign while it was ${campaign.status}. A stop is final.`,
          at,
        });
      }
      // Not running yet: it ends here, and the runner will find it no longer queued.
      if (campaign.status === "queued") {
        await endCampaign(q, id, { reason: "owner_stop", started: false, checks: null, at });
      }
      return campaign.status;
    });
    if (outcome === "not-found") return problem(c, "not-found");
    if (outcome === "ended") return problem(c, "conflict", undefined, "campaign-ended");
    // The run in this process, whether it is still in its start checks or sending: cut now (again, if asked again).
    await Promise.race([
      campaigns.abort(id, "owner_stop"),
      new Promise<void>((resolve) => setTimeout(resolve, STOP_WAIT_MS).unref()),
    ]);
    // Still running in the database, and no run in this process that could end it (its end could not be written, or
    // another process left it): the stop writes the end itself.
    const campaign = await db.tx({ organizationId }, async (q) => {
      const current = await findCampaign(q, id);
      if (current === null || current.status !== "running" || campaigns.isActive(id)) return current;
      const at = now();
      if (await endCampaign(q, id, { reason: "owner_stop", started: true, checks: null, at })) {
        await audit(q, systemActor(organizationId), {
          action: "campaign.end",
          target: { kind: "campaign", id },
          summary: `The Campaign ended: stopped (owner_stop); ${current.requests_sent} ${
            current.requests_sent === 1 ? "request" : "requests"
          } sent (the ownership check included), ${current.requests_refused} refused. Its run was no longer active; the stop wrote its end.`,
          at,
        });
      }
      return findCampaign(q, id);
    });
    if (campaign === null) return problem(c, "not-found");
    return c.json({ campaign } satisfies CampaignResponse);
  });

  return routes;
}
