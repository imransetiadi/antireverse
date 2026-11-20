import { setMaxListeners } from "node:events";
import { getConnInfo } from "@hono/node-server/conninfo";
import { Hono } from "hono";
import { HTTPException } from "hono/http-exception";
import { matchedRoutes } from "hono/route";
import { type Assessor, unavailableAssessor } from "./assess/assessor.ts";
import { type AssessmentQueue, createAssessmentRunner } from "./assess/runner.ts";
import { type AttestationKeys, createAttestationKeys } from "./attestation/keys.ts";
import { auditRequest } from "./audit.ts";
import type { AppEnv, Principal } from "./auth/authenticate.ts";
import type { EventBus } from "./bus.ts";
import { type CampaignService, createCampaignRunner } from "./campaign/runner.ts";
import type { Db } from "./db/db.ts";
import { type BeaconRecorder, createBeaconRecorder } from "./detect/beacon.ts";
import type { PolicyPublished } from "./detect/detector.ts";
import { createIntegrityRecorder, type IntegrityRecorder } from "./detect/integrity.ts";
import { createIncidentQueue, type IncidentQueue } from "./exposure/match.ts";
import { consoleLogger, type Logger, redacting } from "./log.ts";
import { type AddressHasher, createAddressHasher } from "./mail/address-key.ts";
import { createNotifier, type EmailDeps, type Notifier } from "./notify/notifier.ts";
import { defaultResolve, type Resolve } from "./notify/ssrf.ts";
import { PATCH_CATALOG, type PatchCatalog } from "./patches/catalog.ts";
import { problem } from "./problem.ts";
import { createAuthorize } from "./prove/authorize.ts";
import { type ProveDeps, proveNetwork } from "./prove/deps.ts";
import { alertChannelRoutes } from "./routes/alert-channels.ts";
import { allowlistRoutes } from "./routes/allowlist.ts";
import { appRoutes } from "./routes/apps.ts";
import { assessmentRoutes } from "./routes/assessments.ts";
import { attestRoutes } from "./routes/attest.ts";
import { auditRoutes, createAuditReadLimiter } from "./routes/audit.ts";
import { beaconRoutes, type ClientAddress } from "./routes/beacon.ts";
import { buildRoutes } from "./routes/builds.ts";
import { bundleRoutes } from "./routes/bundle.ts";
import { campaignRoutes } from "./routes/campaigns.ts";
import { containmentRoutes } from "./routes/containments.ts";
import { dataControlRoutes } from "./routes/data-controls.ts";
import { eventRoutes } from "./routes/events.ts";
import { findingRoutes } from "./routes/findings.ts";
import { healthRoutes } from "./routes/health.ts";
import { incidentRoutes } from "./routes/incidents.ts";
import { ingestRoutes } from "./routes/ingest.ts";
import { inventoryRoutes } from "./routes/inventory.ts";
import { opsRoutes } from "./routes/ops.ts";
import { organizationRoutes } from "./routes/organizations.ts";
import { patchRoutes } from "./routes/patches.ts";
import { policyRoutes } from "./routes/policies.ts";
import { proveRoutes } from "./routes/prove.ts";
import { type SimulationOptions, simulateRoutes } from "./routes/simulate.ts";
import { usageRoutes } from "./routes/usage.ts";
import { createSigner, type Signer } from "./signer.ts";
import { sloRequests } from "./slo/middleware.ts";
import type { SloService } from "./slo/service.ts";
import { integrityBuildOf } from "./stores/integrity.ts";
import type { UsageSalts } from "./usage/salts.ts";

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
   * The service's SMTP account (slice 06b): the mailer and the From of every mail. Without it, email channels cannot
   * be created and the channel list says `smtp_configured: false`. Default: none (`startApi` passes the one of the
   * `AR_SMTP_*` settings).
   */
  email?: EmailDeps;
  /**
   * Keys the per-address count of confirmation mails. Default: a secret in memory (`startApi` passes the one of
   * `mail-hash-key.json` beside the data directory).
   */
  addressHasher?: AddressHasher;
  /**
   * Judges Clone Beacon reports after their 204. Default: a recorder on `db` and the notifier (`startApi` passes
   * the one it flushes on close).
   */
  beacon?: BeaconRecorder;
  /**
   * Judges the integrity report of an attestation after its response (slice 21a). Default: a recorder on `db` and the
   * notifier (`startApi` passes the one it flushes on close).
   */
  integrity?: IntegrityRecorder;
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
  /** The bounds of a Policy simulation (slice 11). Default: `SIMULATION_LIMITS` and the process clock; tests pass smaller ones. */
  simulation?: SimulationOptions;
  /**
   * The network seams of Prove (slice 14): the DNS resolver and the guarded HTTPS fetcher of the ownership checks.
   * Default: node:dns and the guarded fetcher without its test-only option; tests pass stand-ins.
   */
  prove?: ProveDeps;
  /**
   * The Reverse Assessment engine (slice 12a): states the scope of a queued Assessment and runs it. Default: an
   * Assessor without an engine, whose runs fail saying so (`startApi` passes the engine of `packages/prove`).
   */
  assessor?: Assessor;
  /**
   * Told each queued Assessment. Default: a runner on `db` and `assessor`, never started (no restart recovery and no
   * artifact expiry; `startApi` passes the one it starts and stops).
   */
  assessments?: AssessmentQueue;
  /**
   * The audit key (slice 18a review F3): signs the chain heads of verification and export. Never the Policy key.
   * Default: a new key in memory (`startApi` passes the one of `audit-key.json`).
   */
  auditSigner?: Signer;
  /**
   * Audit verifications and exports and Organization exports (slice 18b) per Organization per minute, together.
   * Default `AUDIT_READS_PER_MINUTE`. The audit key also signs the Organization export and the deletion reports.
   */
  auditReadsPerMinute?: number;
  /**
   * The month salts of the Guard device references (slice 17a, review M3). Default: salts in memory (`startApi` passes
   * those of `usage-salts.json` beside the data directory, which its retention job also forgets month by month).
   */
  usageSalts?: UsageSalts;
  /** New Guard device references per App and UTC day at most. Default `USAGE_DEVICE_DAILY_CAP`. */
  usageDeviceDailyCap?: number;
  /**
   * The SLO service (slice 18d): its recorder is fed by every request and by ingest, and it answers the operator
   * routes. Default: none (nothing is recorded; `startApi` passes the one it starts and flushes on close).
   */
  slo?: SloService;
  /**
   * The Organizations the API itself owns (slice 18g, D-116: the synthetic probes'). Their requests and Events feed no
   * request SLI and no in-process SLO-04 sample. Default: none.
   */
  systemOrganizations?: { has(organizationId: string): boolean };
  /** The operator token (`AR_OPS_TOKEN`) of `GET /v1/ops/slo` and `GET /metrics`. Default: none, and they answer 404. */
  opsToken?: string;
  /** The millisecond clock of request latency for the SLIs. Default `performance.now`; tests pass a fake. */
  monotonic?: () => number;
  /**
   * Pentest Campaigns (slice 15a): the runner the routes queue on and stop through. Default: a runner with Campaigns
   * off, never started — creation answers 403 `campaigns-disabled` (`startApi` passes the one it starts and stops,
   * on only when `AR_PROVE_CAMPAIGNS=1`).
   */
  campaigns?: CampaignService;
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
  // Slice 18d: the request SLIs (route class, status, server time), counted in memory.
  if (deps.slo !== undefined) {
    const system = deps.systemOrganizations;
    app.use(
      "*",
      sloRequests(deps.slo.recorder, deps.monotonic, (organizationId) => system?.has(organizationId) === true),
    );
  }
  // Slice 18a: a request id for every request, and the reason header of a mutating one checked before any route.
  app.use("*", auditRequest());

  const resolve = deps.resolve ?? defaultResolve;
  const allowPrivateAlertUrls = deps.allowPrivateAlertUrls ?? false;
  const notifier =
    deps.notifier ??
    createNotifier({
      db: deps.db,
      now: deps.now,
      resolve,
      allowPrivate: allowPrivateAlertUrls,
      logger,
      email: deps.email,
    });
  const beacon = deps.beacon ?? createBeaconRecorder({ db: deps.db, notifier, now: deps.now, logger });
  const integrity = deps.integrity ?? createIntegrityRecorder({ db: deps.db, notifier, now: deps.now, logger });
  const attestation = deps.attestation ?? createAttestationKeys({ now: deps.now, logger });
  const clientAddress = deps.clientAddress ?? socketAddress;
  const exposureIncidents = deps.exposureIncidents ?? createIncidentQueue({ db: deps.db, notifier, logger });
  const patches = deps.patches ?? PATCH_CATALOG;

  app.route("/", healthRoutes());
  const network = proveNetwork(deps.prove);
  const campaigns =
    deps.campaigns ??
    createCampaignRunner({
      db: deps.db,
      enabled: false,
      resolver: network.resolver,
      authorize: createAuthorize({ db: deps.db, now: deps.now }),
      now: deps.now,
      logger,
    });
  app.route(
    "/",
    opsRoutes({ slo: deps.slo, token: deps.opsToken, prove: { db: deps.db, campaigns, now: deps.now, logger } }),
  );
  app.route("/", organizationRoutes(deps));
  app.route("/", appRoutes(deps));
  app.route(
    "/",
    buildRoutes({
      ...deps,
      incidents: exposureIncidents,
      onBeaconRegistered: (appId, token) => beacon.tokenRegistered(appId, token),
      onBuildRegistered: (organizationId, manifest) =>
        integrity.buildRegistered(integrityBuildOf(organizationId, manifest)),
    }),
  );
  app.route("/", inventoryRoutes({ db: deps.db, incidents: exposureIncidents, now: deps.now }));
  app.route("/", findingRoutes({ db: deps.db, now: deps.now }));
  app.route("/", eventRoutes(deps));
  app.route("/", ingestRoutes({ ...deps, slo: deps.slo?.recorder }));
  app.route("/", policyRoutes(deps));
  app.route("/", simulateRoutes(deps));
  app.route("/", bundleRoutes({ ...deps, attestation, patches }));
  app.route("/", patchRoutes({ db: deps.db, patches, now: deps.now }));
  app.route("/", incidentRoutes({ ...deps, patches }));
  app.route("/", containmentRoutes({ ...deps, patches }));
  app.route("/", allowlistRoutes(deps));
  // Public: no key. Outside every key middleware (each route above requires its own).
  app.route("/", beaconRoutes({ recorder: beacon, clientAddress }));
  app.route(
    "/",
    attestRoutes({
      db: deps.db,
      attestation,
      clientAddress,
      now: deps.now,
      logger,
      usageSalts: deps.usageSalts,
      usageDeviceDailyCap: deps.usageDeviceDailyCap,
      integrity,
    }),
  );
  app.route(
    "/",
    alertChannelRoutes({
      ...deps,
      notifier,
      resolve,
      allowPrivateAlertUrls,
      smtpConfigured: deps.email !== undefined,
      addressHasher: deps.addressHasher ?? createAddressHasher(),
      ...(deps.email?.confirmationsPerDay === undefined ? {} : { confirmationsPerDay: deps.email.confirmationsPerDay }),
    }),
  );
  app.route("/", proveRoutes({ db: deps.db, network, now: deps.now }));
  app.route("/", campaignRoutes({ db: deps.db, campaigns, now: deps.now }));
  const assessor = deps.assessor ?? unavailableAssessor();
  const assessmentQueue = deps.assessments ?? createAssessmentRunner({ db: deps.db, assessor, now: deps.now, logger });
  app.route("/", assessmentRoutes({ db: deps.db, assessor, queue: assessmentQueue, now: deps.now }));
  const auditSigner = deps.auditSigner ?? createSigner();
  // Audit verifications and exports and the Organization export take from one budget per Organization.
  const auditReads = createAuditReadLimiter(deps.auditReadsPerMinute);
  app.route("/", auditRoutes({ db: deps.db, signer: auditSigner, now: deps.now, reads: auditReads }));
  app.route("/", dataControlRoutes({ db: deps.db, signer: auditSigner, reads: auditReads, now: deps.now, campaigns }));
  // Usage reads (slice 17a) take from the same budget.
  app.route("/", usageRoutes({ db: deps.db, reads: auditReads, now: deps.now }));

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
