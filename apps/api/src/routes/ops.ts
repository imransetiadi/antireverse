import { createHash, randomUUID, timingSafeEqual } from "node:crypto";
import { ID_PATTERNS, ProveOperatorRequestSchema, type ProveOperatorState } from "@antireverse/protocol";
import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { audit, operatorActor } from "../audit.ts";
import type { AppEnv } from "../auth/authenticate.ts";
import type { CampaignService } from "../campaign/runner.ts";
import type { Db } from "../db/db.ts";
import type { Logger } from "../log.ts";
import { problem } from "../problem.ts";
import type { SloService } from "../slo/service.ts";
import { operatorState, setKillSwitch, setSuspension } from "../stores/campaigns.ts";
import { validateJson } from "../validate.ts";

// Slice 18d: the operator routes. `GET /v1/ops/slo` (JSON, `SloReportSchema`) and `GET /metrics` (Prometheus text) take
// the operator token of `AR_OPS_TOKEN` only, as `Authorization: Bearer <token>`, compared in constant time over
// SHA-256 digests (no length leak). Without the token configured they answer 404, as if they did not exist. Tenant keys
// are not tokens: they get the 401 of any wrong token. Not audited as tenant actions, not counted in SLO-07.
//
// Slice 15a: the operator's switches of Pentest Campaigns, behind the same token.
// - `GET /v1/ops/prove`: the state (`ProveOperatorStateSchema`).
// - `POST /v1/ops/prove/kill`: the global kill switch. Durable; every queued or running Campaign is ended at once
//   (the request in flight is cut, the engine terminated) and none can be created or started until re-enabled.
// - `POST /v1/ops/prove/enable`: lifts the kill switch. Nothing that was stopped runs again.
// - `POST /v1/ops/prove/organizations/:id/suspend` and `…/resume`: the same for one Organization.
// Each takes `{ reason }`. A kill or a suspension writes one operator entry into the audit chain of each Organization
// it affects; lifting the global switch affects no Organization and is recorded with the switch and in the log.

const BEARER = /^Bearer (\S+)$/i;

const digest = (text: string): Buffer => createHash("sha256").update(text, "utf8").digest();

export function opsRoutes(deps: {
  slo?: SloService | undefined;
  token?: string | undefined;
  /** Slice 15a: the database and the Campaign runner of the operator's switches. Without them those routes are 404. */
  prove?:
    | { db: Db; campaigns: CampaignService; now?: (() => Date) | undefined; logger?: Logger | undefined }
    | undefined;
}): Hono<AppEnv> {
  const routes = new Hono<AppEnv>();
  const { slo, prove } = deps;
  const expected = deps.token === undefined ? undefined : digest(deps.token);

  const guarded = (available: boolean) =>
    createMiddleware(async (c, next) => {
      if (expected === undefined || !available) return problem(c, "not-found");
      const presented = BEARER.exec(c.req.header("authorization") ?? "")?.[1];
      if (presented === undefined || !timingSafeEqual(digest(presented), expected)) return problem(c, "unauthorized");
      await next();
    });
  const guard = guarded(slo !== undefined);
  const proveGuard = guarded(prove !== undefined);

  if (prove !== undefined) {
    const { db, campaigns } = prove;
    const now = prove.now ?? (() => new Date());
    const state = async (stopped: number): Promise<ProveOperatorState> => ({
      enabled: campaigns.enabled,
      ...(await db.tx("none", (q) => operatorState(q))),
      active: await campaigns.activeCount(),
      stopped,
    });
    const body = validateJson(ProveOperatorRequestSchema);

    routes.get("/v1/ops/prove", proveGuard, async (c) => c.json(await state(0)));

    routes.post("/v1/ops/prove/kill", proveGuard, body, async (c) => {
      const { reason } = c.req.valid("json");
      // The durable switch first: from here on the gate refuses every probe and nothing new starts.
      await db.tx("none", (q) => setKillSwitch(q, true, now(), reason));
      const stopped = await campaigns.operatorStop({
        reason: "operator_kill",
        requestId: randomUUID(),
        operatorReason: reason,
      });
      prove.logger?.warn(`campaigns killed by the operator stopped=${stopped}`);
      return c.json(await state(stopped));
    });

    routes.post("/v1/ops/prove/enable", proveGuard, body, async (c) => {
      const { reason } = c.req.valid("json");
      await db.tx("none", (q) => setKillSwitch(q, false, now(), reason));
      prove.logger?.warn("campaigns re-enabled by the operator");
      campaigns.wake();
      return c.json(await state(0));
    });

    const suspension = (suspended: boolean) =>
      routes.post(
        `/v1/ops/prove/organizations/:id/${suspended ? "suspend" : "resume"}`,
        proveGuard,
        body,
        async (c) => {
          const organizationId = c.req.param("id");
          const { reason } = c.req.valid("json");
          if (!ID_PATTERNS.org.test(organizationId)) return problem(c, "not-found");
          const requestId = randomUUID();
          const at = now();
          const changed = await db.tx("none", (q) => setSuspension(q, organizationId, suspended, at, reason));
          let stopped = 0;
          if (changed) {
            // First, with nothing awaited since the suspension was committed: the runner aborts this Organization's
            // Campaigns (it does so before its own first await) — as the kill route does. Its entries and its count
            // are awaited below.
            const stopping = suspended
              ? campaigns.operatorStop({
                  reason: "organization_suspended",
                  organizationId,
                  requestId,
                  operatorReason: reason,
                })
              : null;
            // Awaited below; if the entry cannot be written first, the stop's own failure is not left unhandled.
            stopping?.catch(() => {});
            // One entry in the Organization's own chain, whether or not it has a Campaign now.
            await db.tx({ organizationId }, (q) =>
              audit(q, operatorActor(organizationId, requestId, reason), {
                action: suspended ? "campaign.operator_suspend" : "campaign.operator_resume",
                target: { kind: "organization", id: organizationId },
                summary: suspended
                  ? "The operator suspended this Organization's Campaigns: none can be created or started."
                  : "The operator lifted the suspension of this Organization's Campaigns.",
                at,
              }),
            );
            if (stopping !== null) stopped = await stopping;
            else campaigns.wake();
          } else {
            // Nothing changed: either it was so already, or there is no such Organization.
            const { suspended: list } = await db.tx("none", (q) => operatorState(q));
            if (suspended !== list.some((entry) => entry.organization_id === organizationId)) {
              return problem(c, "not-found");
            }
            // Suspended already, and asked for again: the stop is run again. If an earlier one failed half-way, a
            // Campaign may still be open or lack the operator's entry; a stop with nothing left to do answers 0.
            if (suspended) {
              stopped = await campaigns.operatorStop({
                reason: "organization_suspended",
                organizationId,
                requestId,
                operatorReason: reason,
              });
            }
          }
          return c.json(await state(stopped));
        },
      );
    suspension(true);
    suspension(false);
  }

  routes.get("/v1/ops/slo", guard, async (c) => c.json(await (slo as SloService).report()));
  routes.get("/metrics", guard, async (c) =>
    c.body(await (slo as SloService).metrics(), 200, { "Content-Type": "text/plain; version=0.0.4; charset=utf-8" }),
  );
  return routes;
}
