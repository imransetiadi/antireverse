import {
  BUILD_LIMITS,
  type Build,
  type BuildManifest,
  type BuildResponse,
  EXPOSURE_LIMITS,
  type FindingsSummary,
  ID_PATTERNS,
  type ListBuildsResponse,
  LOGIC_LIMITS,
  type ProblemError,
  RegisterBuildRequestSchema,
  ROUTE_LIMITS,
} from "@antireverse/protocol";
import { componentsDigest, logicDigest, routesDigest } from "@antireverse/protocol/server";
import { Hono, type MiddlewareHandler } from "hono";
import { audit, auditActor } from "../audit.ts";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db, Queryable } from "../db/db.ts";
import { type IncidentQueue, matchInventory, type OpenedFinding } from "../exposure/match.ts";
import { problem } from "../problem.ts";
import { findApp } from "../stores/apps.ts";
import { findBeaconBuild, insertBeacon } from "../stores/beacons.ts";
import {
  type BuildTarget,
  findBuild,
  insertBuild,
  insertBuildLogic,
  insertBuildRoutes,
  listBuilds,
} from "../stores/builds.ts";
import { insertCanaries } from "../stores/canaries.ts";
import { buildFindingsSummary } from "../stores/findings.ts";
import { validateJson } from "../validate.ts";

/**
 * Bytes of a serialised route inventory at most (slice 12a): 2,000 entries of the longest form, each quoted and
 * separated (`"METHOD /path",`), with backslash escapes impossible (the entry grammar has no quote or backslash).
 */
const ROUTES_BYTES_MAX = ROUTE_LIMITS.routesMax * (ROUTE_LIMITS.methodMax + 1 + ROUTE_LIMITS.pathMax + 3) + 2;

/**
 * Bytes of a Build registration body: the Manifest's own bound plus the component list's (slice 19) and the route
 * inventory's (slice 12a). The Manifest and the components are then held to their own bounds by `limitMembers`; the
 * routes by their schema.
 */
const REGISTER_BODY_BYTES_MAX =
  BUILD_LIMITS.manifestBytesMax +
  EXPOSURE_LIMITS.componentsBytesMax +
  ROUTES_BYTES_MAX +
  // Slice 12b: the logic file, at most 1 MB as UTF-8 JSON (held to that by its schema).
  LOGIC_LIMITS.fileBytesMax +
  1024;

/**
 * Holds the Manifest to `BUILD_LIMITS.manifestBytesMax` and the component list to `EXPOSURE_LIMITS.componentsBytesMax`
 * (serialised), with a 413, before the body is validated. A body that does not parse is left to the validator.
 */
const limitMembers: MiddlewareHandler = async (c, next) => {
  let body: unknown;
  try {
    body = await c.req.json();
  } catch {
    return next();
  }
  if (typeof body === "object" && body !== null) {
    const { manifest, components } = body as { manifest?: unknown; components?: unknown };
    const bytes = (value: unknown) => (value === undefined ? 0 : Buffer.byteLength(JSON.stringify(value), "utf8"));
    if (bytes(manifest) > BUILD_LIMITS.manifestBytesMax || bytes(components) > EXPOSURE_LIMITS.componentsBytesMax) {
      return problem(c, "build-payload-too-large");
    }
  }
  return next();
};

/**
 * SQL state of a unique conflict: a Build id or a beacon token registered for this App, or a Canary id for the
 * Organization, before.
 */
const UNIQUE_VIOLATION = "23505";

/** The unique constraint on a beacon token (0011_beacon_per_app.sql): a token registered before for the App. */
const BEACON_TOKEN_CONSTRAINT = "build_beacons_app_token_key";

export function buildRoutes(deps: {
  db: Db;
  now?: (() => Date) | undefined;
  /** Opens the `vulnerable-component` Incidents of the Build's new Findings, after the response. */
  incidents: IncidentQueue;
  /** Told each beacon token registered with its App, after the commit (the Clone Beacon's caches forget it). */
  onBeaconRegistered?: (appId: string, token: string) => void;
  /** Told each Build registered with its App, after the commit (slice 21a: the integrity recorder learns it without a lookup). */
  onBuildRegistered?: (organizationId: string, manifest: BuildManifest) => void;
}): Hono<AppEnv> {
  const { db } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");

  /**
   * Runs `read` for an App of the caller's Organization. Null when the path's App id is malformed or the App
   * is not the caller's (another Organization's App is invisible: it is "not found" like any other).
   */
  async function forApp<T>(
    organizationId: string,
    appId: string,
    read: (q: Queryable, target: BuildTarget) => Promise<T>,
  ): Promise<T | null> {
    if (!ID_PATTERNS.app.test(appId)) return null;
    return db.tx({ organizationId }, async (q) =>
      (await findApp(q, appId)) === null ? null : read(q, { organizationId, appId }),
    );
  }

  // Registers a Build from its Manifest. The server stamps `registered_at`. The Manifest's `app_id` must
  // name the App in the path; its `environment` is the Build's own and is not matched against the App.
  // From slice 19 the body may carry the lockfile's components beside the Manifest: they must match the Manifest's
  // `component_count` and `components_digest`, are stored as the Build's inventory and matched in the Build's own
  // transaction, and the 201 then carries the Build's open Findings as a summary. The list is never returned.
  // From slice 12a it may carry the route inventory for W1 Map: held to `route_count` and `routes_digest`, stored
  // with the Build in its transaction, never returned and never given to an Assessment's agent.
  routes.post(
    "/v1/apps/:appId/builds",
    admin,
    limitBody(REGISTER_BODY_BYTES_MAX, "build-payload-too-large"),
    limitMembers,
    validateJson(RegisterBuildRequestSchema),
    async (c) => {
      const { organizationId } = c.var.principal;
      const appId = c.req.param("appId");
      const { manifest, components, routes: inventory, logic } = c.req.valid("json");
      const actor = auditActor(c);
      // A malformed App id names no App: "not found", before the body is judged against it.
      if (!ID_PATTERNS.app.test(appId)) return problem(c, "not-found");
      if (manifest.app_id !== appId) {
        return problem(c, "validation", [{ path: "manifest.app_id", message: "Must equal the App in the path." }]);
      }
      if (components !== undefined) {
        const errors: ProblemError[] = [];
        if (manifest.component_count === undefined) {
          errors.push({ path: "manifest.component_count", message: "Required when components are sent." });
        }
        if (manifest.components_digest === undefined) {
          errors.push({ path: "manifest.components_digest", message: "Required when components are sent." });
        } else if (manifest.components_digest !== componentsDigest(components)) {
          errors.push({ path: "manifest.components_digest", message: "Must equal the digest of the components sent." });
        }
        if (errors.length > 0) return problem(c, "validation", errors);
      }
      // Slice 12a: the route inventory is held to the Manifest's count and digest in the same way.
      if (inventory !== undefined) {
        const errors: ProblemError[] = [];
        if (manifest.route_count === undefined) {
          errors.push({ path: "manifest.route_count", message: "Required when routes are sent." });
        }
        if (manifest.routes_digest === undefined) {
          errors.push({ path: "manifest.routes_digest", message: "Required when routes are sent." });
        } else if (manifest.routes_digest !== routesDigest(inventory)) {
          errors.push({ path: "manifest.routes_digest", message: "Must equal the digest of the routes sent." });
        }
        if (errors.length > 0) return problem(c, "validation", errors);
      }
      // Slice 12b: the logic file likewise, against `logic_count` and `logic_digest`.
      if (logic !== undefined) {
        const errors: ProblemError[] = [];
        if (manifest.logic_count === undefined) {
          errors.push({ path: "manifest.logic_count", message: "Required when logic is sent." });
        }
        if (manifest.logic_digest === undefined) {
          errors.push({ path: "manifest.logic_digest", message: "Required when logic is sent." });
        } else if (manifest.logic_digest !== logicDigest(logic)) {
          errors.push({ path: "manifest.logic_digest", message: "Must equal the digest of the logic sent." });
        }
        if (errors.length > 0) return problem(c, "validation", errors);
      }

      // A failed statement aborts the transaction, so the conflict is caught outside it (as a Policy publish
      // does): inside, a return after the error would commit an aborted transaction.
      let result: { build: Build; findings?: FindingsSummary; opened: OpenedFinding[] } | "token-taken" | null;
      try {
        result = await db.tx({ organizationId }, async (q) => {
          if ((await findApp(q, appId)) === null) return null;
          // A beacon token names one Build of its App: one registered before for this App is refused up front.
          if (manifest.beacon !== undefined && (await findBeaconBuild(q, appId, manifest.beacon.token)) !== null) {
            return "token-taken";
          }
          const registeredAt = now();
          const build = await insertBuild(q, { organizationId, manifest, registeredAt });
          // In the same transaction: a Canary id the Organization registered before rolls the Build back (409).
          await insertCanaries(q, {
            organizationId,
            appId,
            environment: manifest.environment,
            buildId: manifest.build_id,
            canaries: manifest.canaries ?? [],
            createdAt: registeredAt,
          });
          // Likewise its beacon: a token registered before for this App rolls the Build back (409).
          if (manifest.beacon !== undefined) {
            await insertBeacon(q, {
              organizationId,
              appId,
              environment: manifest.environment,
              buildId: manifest.build_id,
              beacon: manifest.beacon,
              createdAt: registeredAt,
            });
          }
          // Likewise its route inventory (slice 12a): stored for the W1 verifier only, never returned.
          if (inventory !== undefined) {
            await insertBuildRoutes(q, { organizationId, appId, buildId: manifest.build_id, routes: inventory });
          }
          // Likewise its logic file (slice 12b): stored for the W3 verifier only, never returned.
          if (logic !== undefined) {
            await insertBuildLogic(q, { organizationId, appId, buildId: manifest.build_id, logic });
          }
          const parts = [
            `version ${manifest.version}`,
            manifest.environment,
            `${manifest.artifacts.length} artifacts`,
            ...(manifest.canaries === undefined ? [] : [`${manifest.canaries.length} Canaries`]),
            ...(manifest.beacon === undefined ? [] : ["a Clone Beacon"]),
            ...(manifest.integrity === undefined || manifest.integrity.files.length === 0
              ? []
              : [`an integrity marker of ${manifest.integrity.files.length} files`]),
            ...(components === undefined ? [] : [`${components.length} components`]),
            ...(inventory === undefined ? [] : [`${inventory.length} routes`]),
            ...(logic === undefined ? [] : [`${logic.functions.length} logic functions`]),
          ];
          await audit(q, actor, {
            action: "build.register",
            appId,
            target: { kind: "build", id: manifest.build_id },
            summary: `Registered the Build ${manifest.build_id} (${parts.join(", ")}).`,
            at: registeredAt,
          });
          if (components === undefined) return { build, opened: [] };
          // Likewise its inventory and Findings: a refused registration leaves neither.
          const matched = await matchInventory(q, {
            organizationId,
            appId,
            environment: manifest.environment,
            source: "build",
            buildId: manifest.build_id,
            components,
            at: registeredAt,
          });
          return { build, findings: await buildFindingsSummary(q, appId, manifest.build_id), opened: matched.opened };
        });
      } catch (error) {
        const { code, constraint } = error as { code?: unknown; constraint?: unknown };
        if (code === UNIQUE_VIOLATION) {
          return constraint === BEACON_TOKEN_CONSTRAINT
            ? problem(c, "conflict", undefined, "beacon-token-taken")
            : problem(c, "conflict");
        }
        throw error;
      }
      if (result === null) return problem(c, "not-found");
      if (result === "token-taken") return problem(c, "conflict", undefined, "beacon-token-taken");
      if (manifest.beacon !== undefined) deps.onBeaconRegistered?.(appId, manifest.beacon.token);
      deps.onBuildRegistered?.(organizationId, manifest);
      deps.incidents.enqueue(organizationId, result.opened);
      const response: BuildResponse =
        result.findings === undefined ? { build: result.build } : { build: result.build, findings: result.findings };
      return c.json(response, 201);
    },
  );

  routes.get("/v1/apps/:appId/builds", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const builds = await forApp(organizationId, c.req.param("appId"), (q, target) =>
      listBuilds(q, target, BUILD_LIMITS.listed),
    );
    if (builds === null) return problem(c, "not-found");
    return c.json({ builds } satisfies ListBuildsResponse);
  });

  routes.get("/v1/apps/:appId/builds/:buildId", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const buildId = c.req.param("buildId");
    // A malformed Build id is a Build that does not exist, like an unknown one.
    const build = ID_PATTERNS.bld.test(buildId)
      ? await forApp(organizationId, c.req.param("appId"), (q, target) => findBuild(q, target, buildId))
      : null;
    if (build === null) return problem(c, "not-found");
    return c.json({ build } satisfies BuildResponse);
  });

  return routes;
}
