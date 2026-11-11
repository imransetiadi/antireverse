import { setMaxListeners } from "node:events";
import { getConnInfo } from "@hono/node-server/conninfo";
import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { matchedRoutes } from "hono/route";
import { type AttestationKeys, createAttestationKeys } from "./attestation/keys.ts";
import type { AppEnv, Principal } from "./auth/authenticate.ts";
import type { EventBus } from "./bus.ts";
import type { Db } from "./db/db.ts";
import { type BeaconRecorder, createBeaconRecorder } from "./detect/beacon.ts";
import type { PolicyPublished } from "./detect/detector.ts";
import { createIncidentQueue, type IncidentQueue } from "./exposure/match.ts";
import { consoleLogger, type Logger, redacting } from "./log.ts";
import { createNotifier, type Notifier } from "./notify/notifier.ts";
import { defaultResolve, type Resolve } from "./notify/ssrf.ts";
import { PATCH_CATALOG, type PatchCatalog } from "./patches/catalog.ts";
import { problem } from "./problem.ts";
import { alertChannelRoutes } from "./routes/alert-channels.ts";
import { allowlistRoutes } from "./routes/allowlist.ts";
import { appRoutes } from "./routes/apps.ts";
import { attestRoutes } from "./routes/attest.ts";
import { beaconRoutes, type ClientAddress } from "./routes/beacon.ts";
import { buildRoutes } from "./routes/builds.ts";
import { bundleRoutes } from "./routes/bundle.ts";
import { containmentRoutes } from "./routes/containments.ts";
import { eventRoutes } from "./routes/events.ts";
import { findingRoutes } from "./routes/findings.ts";
import { healthRoutes } from "./routes/health.ts";
import { incidentRoutes } from "./routes/incidents.ts";
import { ingestRoutes } from "./routes/ingest.ts";
import { inventoryRoutes } from "./routes/inventory.ts";
import { organizationRoutes } from "./routes/organizations.ts";
import { patchRoutes } from "./routes/patches.ts";
import { policyRoutes } from "./routes/policies.ts";
import type { Signer } from "./signer.ts";

export interface AppDeps {
  db: Db;
  bus: EventBus;
  /** Signs Policy Bundles. Its public key is what `GET /v1/signing-key` answers. */
  signer: Signer;
  /** The clock that stamps `received_at`, `published_at` and a bundle's `issued_at`. Default: the system clock. */
  now?: () => Date;
  /**
   * Told the App Environment's new latest Policy version after a publish or rollback committed. `startApi` passes
   * the Detector's `policyPublished`, so that Events naming the new version are judged by its Rules at once.
   * Default: nobody is told.
   */
  onPolicyPublished?: (policy: PolicyPublished) => void;
  /** Interval of the comment heartbeat on live streams, in milliseconds. Default: 15,000. */
  heartbeatMs?: number;
  /** Receives one line per request and one per unexpected error; never a key, a header or a body. */
  logger?: Logger;
  /** Aborted when the server shuts down: every open live stream then ends. */
  shutdown?: AbortSignal;
  /**
   * Sends alert-channel test alerts. Default: a notifier on `db` with the settings below (`startApi` passes the
   * one it drains on close).
   */
  notifier?: Notifier;
  /** Resolves a channel's host for the SSRF check at creation. Default: `dns.lookup(host, { all: true })`. */
  resolve?: Resolve;
  /** Allows `http:` and private addresses as alert channel URLs: development and tests only. Default false. */
  allowPrivateAlertUrls?: boolean;
  /** Bound of the host lookup when an alert channel is created. Default 5,000 ms. */
  alertLookupTimeoutMs?: number;
  /**
   * Judges Clone Beacon reports after their 204. Default: a recorder on `db` and the notifier (`startApi` passes
   * the one it flushes on close).
   */
  beacon?: BeaconRecorder;
  /** The client address of a request, for the prefix of a beacon reporter or an attestation caller. Default: the socket's peer address. */
  clientAddress?: ClientAddress;
  /**
   * The attestation key set: signs Attestation Tokens, and its public halves travel in the Policy Bundle. Default: a
   * new set in memory on `now` (`startApi` passes the one of `attestation-keys.json`).
   */
  attestation?: AttestationKeys;
  /**
   * Opens the Incidents of new Critical or High Findings after the response. Default: a queue on `db` and the
   * notifier (`startApi` passes the one it flushes on close; tests flush it themselves).
   */
  exposureIncidents?: IncidentQueue;
  /** The Virtual patch catalog (slice 20). Default: `PATCH_CATALOG`; tests pass a fixture catalog. */
  patches?: PatchCatalog;
}

/** The socket's peer address; undefined outside a Node server (e.g. `app.request` in tests). */
const socketAddress: ClientAddress = (c) => {
  try {
    return getConnInfo(c).remote.address;
  } catch {
    return undefined;
  }
};

const KNOWN_METHOD = /^[A-Z]{1,16}$/;

/** The template of the route that answered, never the concrete path: a path can carry anything a client typed. */
function routeTemplate(c: Parameters<typeof matchedRoutes>[0]): string {
  const path = matchedRoutes(c).at(-1)?.path;
  return path === undefined || path === "*" || path === "/*" ? "(unmatched)" : path;
}

/** Composes the routes of the API. It holds no state of its own: everything lives in `deps`. */
export function createApp(deps: AppDeps): Hono<AppEnv> {
  const logger = redacting(deps.logger ?? consoleLogger);
  const app = new Hono<AppEnv>();
  // Every open live stream listens on the shutdown signal: up to 20 per Organization is normal use.
  if (deps.shutdown !== undefined) setMaxListeners(0, deps.shutdown);

  app.use("*", async (c, next) => {
    const started = performance.now();
    await next();
    const principal = c.get("principal") as Principal | undefined;
    const method = KNOWN_METHOD.test(c.req.method) ? c.req.method : "OTHER";
    const elapsed = Math.round(performance.now() - started);
    const organization = principal === undefined ? "" : ` organization=${principal.organizationId}`;
    logger.info(
      `request method=${method} route=${routeTemplate(c)} status=${c.res.status} ms=${elapsed}${organization}`,
    );
  });
  app.use("*", async (c, next) => {
    // Responses carry keys and tenant data: no cache may keep them. The live stream sets its own value.
    c.header("Cache-Control", "no-store");
    await next();
  });

  const resolve = deps.resolve ?? defaultResolve;
  const allowPrivateAlertUrls = deps.allowPrivateAlertUrls ?? false;
  const notifier =
    deps.notifier ??
    createNotifier({ db: deps.db, now: deps.now, resolve, allowPrivate: allowPrivateAlertUrls, logger });
  const beacon = deps.beacon ?? createBeaconRecorder({ db: deps.db, notifier, now: deps.now, logger });
  const attestation = deps.attestation ?? createAttestationKeys({ now: deps.now, logger });
  const clientAddress = deps.clientAddress ?? socketAddress;
  const exposureIncidents = deps.exposureIncidents ?? createIncidentQueue({ db: deps.db, notifier, logger });
  const patches = deps.patches ?? PATCH_CATALOG;

  app.route("/", healthRoutes());
  app.route("/", organizationRoutes(deps));
  app.route("/", appRoutes(deps));
  app.route(
    "/",
    buildRoutes({
      ...deps,
      incidents: exposureIncidents,
      onBeaconRegistered: (appId, token) => beacon.tokenRegistered(appId, token),
    }),
  );
  app.route("/", inventoryRoutes({ db: deps.db, incidents: exposureIncidents, now: deps.now }));
  app.route("/", findingRoutes({ db: deps.db, now: deps.now }));
  app.route("/", eventRoutes(deps));
  app.route("/", ingestRoutes(deps));
  app.route("/", policyRoutes(deps));
  app.route("/", bundleRoutes({ ...deps, attestation, patches }));
  app.route("/", patchRoutes({ db: deps.db, patches, now: deps.now }));
  app.route("/", incidentRoutes({ ...deps, patches }));
  app.route("/", containmentRoutes({ ...deps, patches }));
  app.route("/", allowlistRoutes(deps));
  // Public: no key. Outside every key middleware (each route above requires its own).
  app.route("/", beaconRoutes({ recorder: beacon, clientAddress }));
  app.route("/", attestRoutes({ db: deps.db, attestation, clientAddress, now: deps.now }));
  app.route("/", alertChannelRoutes({ ...deps, notifier, resolve, allowPrivateAlertUrls }));

  app.notFound((c) => problem(c, "not-found"));
  app.onError((error, c) => {
    if (error instanceof HTTPException) {
      // hono's validator raises this for a JSON body that does not parse.
      if (error.status === 400) return problem(c, "malformed-json");
      if (error.status === 404) return problem(c, "not-found");
      if (error.status === 413) return problem(c, "payload-too-large");
    }
    // The kind of error goes to the operator's log; the client learns only that the request failed.
    // The message stays out of the log: a database error quotes the value it rejected, and that value
    // can come from a request body.
    const code = (error as { code?: unknown }).code;
    const sqlState = typeof code === "string" && /^[0-9A-Z]{5}$/.test(code) ? ` sqlstate=${code}` : "";
    logger.warn(`error route=${routeTemplate(c)} ${error.name}${sqlState}`);
    return problem(c, "internal");
  });

  return app;
}
