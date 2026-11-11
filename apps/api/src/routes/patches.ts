import {
  ENVIRONMENTS,
  type Environment,
  ID_PATTERNS,
  type ListPatchesResponse,
  PATCH_ID_PATTERN,
  type PatchModeResponse,
  type PatchSummary,
  SetPatchModeRequestSchema,
} from "@antireverse/protocol";
import { Hono } from "hono";
import { z } from "zod";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db, Queryable } from "../db/db.ts";
import { type PatchState, patchHits, patchStates, setPatchMode } from "../patches/activation.ts";
import type { PatchCatalog } from "../patches/catalog.ts";
import { problem } from "../problem.ts";
import { findApp } from "../stores/apps.ts";
import { validateJson, validateQuery } from "../validate.ts";

// Virtual patches of one App Environment (slice 20, D-061), for admins: every catalog patch with its activation,
// mode, Findings and hits, and the mode change. Monitor → enforce needs the patch id typed as confirmation; back to
// monitor needs none. A change is stored per (Organization, App, Environment, patch) and the next bundle poll
// carries it (the bundle's digest covers the patches and their modes).

const EnvironmentQuerySchema = z.object({ environment: z.enum(ENVIRONMENTS) });

/** The confirmation of enforce names the patch, by fixed text: it never echoes what was sent. */
const CONFIRM_MISMATCH = [{ path: "confirm", message: "Must equal the id of the patch." }];

async function items(
  q: Queryable,
  catalog: PatchCatalog,
  scope: { appId: string; environment: Environment },
  at: Date,
): Promise<PatchSummary[]> {
  const states = await patchStates(q, catalog, scope);
  const hits = await patchHits(
    q,
    scope,
    states.map((state) => state.patch.id),
    at,
  );
  return states.map((state: PatchState) => ({
    id: state.patch.id,
    title: state.patch.title,
    advisories: [...state.patch.advisories],
    package: state.patch.package,
    mode: state.mode,
    active: state.active,
    shipped: state.shipped,
    findings: state.findings,
    hits_24h: hits.get(state.patch.id)?.hits24h ?? 0,
    last_hit: hits.get(state.patch.id)?.lastHit ?? null,
  }));
}

export function patchRoutes(deps: { db: Db; patches: PatchCatalog; now?: (() => Date) | undefined }): Hono<AppEnv> {
  const { db, patches: catalog } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");

  routes.get("/v1/apps/:appId/patches", admin, validateQuery(EnvironmentQuerySchema), async (c) => {
    const { organizationId } = c.var.principal;
    const appId = c.req.param("appId");
    const { environment } = c.req.valid("query");
    if (!ID_PATTERNS.app.test(appId)) return problem(c, "not-found");
    const listed = await db.tx({ organizationId }, async (q) =>
      (await findApp(q, appId)) === null ? null : items(q, catalog, { appId, environment }, now()),
    );
    if (listed === null) return problem(c, "not-found");
    return c.json({ patches: listed } satisfies ListPatchesResponse);
  });

  routes.post(
    "/v1/apps/:appId/patches/:patchId/mode",
    admin,
    limitBody(),
    validateJson(SetPatchModeRequestSchema),
    async (c) => {
      const { organizationId, keyId } = c.var.principal;
      const appId = c.req.param("appId");
      const patchId = c.req.param("patchId");
      const { environment, mode, confirm } = c.req.valid("json");
      if (!ID_PATTERNS.app.test(appId) || !PATCH_ID_PATTERN.test(patchId) || catalog.get(patchId) === undefined) {
        return problem(c, "not-found");
      }
      if (mode === "enforce" && confirm !== patchId) return problem(c, "validation", CONFIRM_MISMATCH);
      const at = now();
      const item = await db.tx({ organizationId }, async (q) => {
        // Another Organization's App is invisible to this transaction: "not found" like any other.
        if ((await findApp(q, appId)) === null) return null;
        await setPatchMode(q, { organizationId, appId, environment, patchId, mode, by: keyId, at });
        return (await items(q, catalog, { appId, environment }, at)).find((candidate) => candidate.id === patchId);
      });
      if (item === null || item === undefined) return problem(c, "not-found");
      return c.json({ patch: item } satisfies PatchModeResponse);
    },
  );

  return routes;
}
