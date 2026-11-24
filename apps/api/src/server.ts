import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { CAMPAIGNS_VARIABLE, type CampaignCatalogProbe } from "@antireverse/protocol";
import { serve } from "@hono/node-server";
import { type AppDeps, createApp } from "./app.ts";
import type { Assessor } from "./assess/assessor.ts";
import { proveAssessor } from "./assess/prove-assessor.ts";
import { type AssessmentRunner, type AssessmentRunnerOptions, createAssessmentRunner } from "./assess/runner.ts";
import { type AttestationKeys, createAttestationKeys } from "./attestation/keys.ts";
import { createEventBus, type EventBus } from "./bus.ts";
import {
  type CampaignEngineRunner,
  type CampaignRunner,
  type CampaignTesting,
  createCampaignRunner,
} from "./campaign/runner.ts";
import { DEFAULT_HOST } from "./config.ts";
import { createPurgeJob, type PurgeJob, type PurgeOptions } from "./data/purge.ts";
import { createRetentionJob, type RetentionJob, type RetentionOptions } from "./data/retention.ts";
import { type Db, openDb } from "./db/db.ts";
import { createBeaconRecorder } from "./detect/beacon.ts";
import { createDetector, type Detector } from "./detect/detector.ts";
import { createIntegrityRecorder } from "./detect/integrity.ts";
import { createIncidentQueue } from "./exposure/match.ts";
import {
  ADDRESS_KEY_FILE,
  ATTESTATION_KEY_FILE,
  AUDIT_KEY_FILE,
  SIGNING_KEY_FILE,
  USAGE_SALTS_FILE,
} from "./key-files.ts";
import { consoleLogger, type Logger } from "./log.ts";
import { type AddressHasher, createAddressHasher } from "./mail/address-key.ts";
import { readSmtpSettings, type SmtpSettings, smtpSummary } from "./mail/settings.ts";
import { createSmtpMailer } from "./mail/smtp.ts";
import { createNotifier, DEFAULT_CONSOLE_URL, type EmailDeps, type Notifier } from "./notify/notifier.ts";
import type { PatchCatalog } from "./patches/catalog.ts";
import { createProbeConnect, type ProbeConnectOptions } from "./probe/connect.ts";
import { createProber, type Prober } from "./probe/runner.ts";
import { readProbeSettings } from "./probe/settings.ts";
import { provisionProbeTenant } from "./probe/tenant.ts";
import { createHttpProbeTransport, type HttpProbeOptions } from "./probe/transport.ts";
import { type Authorize, createAuthorize } from "./prove/authorize.ts";
import { type ProveDeps, proveNetwork } from "./prove/deps.ts";
import { createRecheckJob, type RecheckOptions } from "./prove/recheck.ts";
import { createSigner, type Signer } from "./signer.ts";
import { createSloService, type SloService } from "./slo/service.ts";
import { type OpsSettings, readOpsSettings } from "./slo/settings.ts";
import {
  createSystemOrganizations,
  listSystemOrganizationIds,
  type SystemOrganizations,
} from "./stores/system-organizations.ts";
import { createUsageSalts, type UsageSalts } from "./usage/salts.ts";

export interface Listening {
  server: Server;
  host: string;
  port: number;
  /** `http://<host>:<port>`, with the port the operating system actually bound. */
  url: string;
}

/** Serves an app over HTTP. `port: 0` binds a free port; the result says which. */
export function listen(
  app: { fetch: (request: Request) => Response | Promise<Response> },
  options: { host?: string; port?: number } = {},
): Promise<Listening> {
  const host = options.host ?? DEFAULT_HOST;
  return new Promise((resolve, reject) => {
    const server = serve({ fetch: app.fetch, hostname: host, port: options.port ?? 0 }, (info: AddressInfo) => {
      const authority = info.family === "IPv6" ? `[${info.address}]` : info.address;
      resolve({ server, host, port: info.port, url: `http://${authority}:${info.port}` });
    }) as Server;
    server.once("error", reject);
  });
}

export interface StartApiOptions {
  /** Default 127.0.0.1. */
  host?: string;
  /** Default 0: a free port. */
  port?: number;
  /** The PGlite data directory. Without it the database lives in memory and is gone on close. */
  dataDir?: string;
  /**
   * Signs Policy Bundles. Default: the key of `signing-key.json` beside the data directory, created on
   * the first start; without a data directory, a key in memory that is gone on close.
   */
  signer?: Signer;
  /**
   * Signs Attestation Tokens. Default: the key set of `attestation-keys.json` beside the data directory, created on
   * the first start and rotated daily; without a data directory, a set in memory that is gone on close.
   */
  attestation?: AttestationKeys;
  /**
   * Signs the audit chain heads (slice 18a). Default: the key of `audit-key.json` beside the data directory, created
   * on the first start; without a data directory, a key in memory. A key of its own: never the Policy signing key.
   */
  auditSigner?: Signer;
  logger?: Logger;
  heartbeatMs?: number;
  now?: () => Date;
  /** How long `close()` waits for requests in flight before it cuts their connections. Default 2,000 ms. */
  shutdownGraceMs?: number;
  /**
   * Allows `http:` and loopback, private and link-local addresses as alert channel URLs: for local development
   * and tests only. Default: true when the environment variable `AR_ALLOW_PRIVATE_ALERT_URLS` is `1`.
   */
  allowPrivateAlertUrls?: boolean;
  /** The Console's base URL for links in alerts. Default: `AR_CONSOLE_URL`, else `http://127.0.0.1:3000`. */
  consoleUrl?: string;
  /** The wait after a failed first alert attempt; it doubles after each further one. Default 1,000 ms. */
  alertBackoffMs?: number;
  /**
   * The SMTP account of email alerts (slice 06b). Default: the `AR_SMTP_*` environment variables, all or none (a
   * partial set fails the start, naming the missing variable); `null`: no email. Never logged beyond host, port and
   * TLS mode.
   */
  smtp?: SmtpSettings | null;
  /** Tests: a mailer and sender used instead of an SMTP client built from `smtp`. */
  email?: EmailDeps;
  /** The Virtual patch catalog (slice 20). Default: `PATCH_CATALOG`; tests pass a fixture catalog. */
  patches?: PatchCatalog;
  /**
   * The network seams of Prove (slice 14). Default: node:dns and the guarded HTTPS fetcher without its test-only
   * option. Tests pass stand-ins, or the guarded fetcher pointed at a local TLS server.
   */
  prove?: ProveDeps;
  /** Settings of the daily re-check of Verified Targets (timer, jitter, concurrency). Default: `RECHECK_DEFAULTS`. */
  recheck?: Omit<RecheckOptions, "db" | "network" | "now" | "logger">;
  /** The Reverse Assessment engine (slice 12a). Default: `packages/prove` with its stand-in agent (D-067). */
  assessor?: Assessor;
  /** Settings of the Assessment runner (concurrency, tier budgets, grace, expiry interval). Default: `RUNNER_DEFAULTS`. */
  assessments?: Omit<AssessmentRunnerOptions, "db" | "assessor" | "now" | "logger">;
  /** Settings of the daily purge of deleted Organizations (slice 18b). Default: `PURGE_DEFAULTS`. */
  purge?: Omit<PurgeOptions, "db" | "signer" | "now" | "logger">;
  /** Settings of the daily retention job (slice 18c). Default: `RETENTION_DEFAULTS`. */
  retention?: Omit<RetentionOptions, "db" | "now" | "logger" | "usageSalts">;
  /**
   * The operator settings (slice 18d): the token of `GET /v1/ops/slo` and `GET /metrics`, and the burn alerts'
   * webhook. Default: `AR_OPS_TOKEN`, `AR_OPS_WEBHOOK_URL` and `AR_OPS_WEBHOOK_SECRET`; an invalid value fails the
   * start, naming the variable.
   */
  ops?: OpsSettings;
  /**
   * Pentest Campaigns (slice 15a). `enabled`: default true only when the environment variable `AR_PROVE_CAMPAIGNS` is
   * `1`; otherwise none can be created or started. `testing` and `engine` are for tests only: no environment variable
   * and no request field sets them (a local TLS target with a test CA; a scripted engine in place of the worker).
   */
  campaigns?: {
    enabled?: boolean;
    testing?: CampaignTesting;
    engine?: CampaignEngineRunner;
    /** With a scripted `engine` only (tests): the probes that script may send. Default: the stand-in's catalog. */
    probes?: readonly CampaignCatalogProbe[];
  };
  /**
   * The synthetic probes (slice 18g). `enabled`: default true only when the environment variable `AR_PROBES` is `1`
   * (any value but unset, empty, `0` or `1` fails the start). The rest is for tests only — no environment variable sets
   * it: the interval and the delay before the first cycle, and shorter timers for the probe's Shield.
   */
  probes?: {
    enabled?: boolean;
    everyMs?: number;
    startDelayMs?: number;
    shield?: HttpProbeOptions["shield"];
    /** In place of the real transport (HTTP to this API, a Shield, a loopback server). */
    open?: ProbeConnectOptions["open"];
  };
}

export interface RunningApi extends Listening {
  app: ReturnType<typeof createApp>;
  db: Db;
  bus: EventBus;
  signer: Signer;
  /** The attestation key set (public halves via `attestationKeys()`). */
  attestation: AttestationKeys;
  /** Delivers alerts of newly opened Incidents. */
  notifier: Notifier;
  /**
   * The authorization check every test must pass (slice 14; slice 15 calls it before any traffic): the
   * Organization's verified targets and current signed Rules of Engagement against the request.
   */
  authorize: Authorize;
  /** The Assessment runner (slice 12a): started with the server, stopped on close. */
  assessments: AssessmentRunner;
  /** The Campaign runner (slice 15a): started with the server, stopped on close. */
  campaigns: CampaignRunner;
  /** The daily purge of Organizations past their deletion grace (slice 18b): started with the server, flushed on close. */
  purge: PurgeJob;
  /** The daily retention job (slice 18c): started with the server, flushed on close. */
  retention: RetentionJob;
  /** The SLO recorder and its minute job (slice 18d): started with the server, flushed last on close. */
  slo: SloService;
  /** The synthetic probes (slice 18g): started with the server, stopped first on close. Null when they are off. */
  probes: Prober | null;
  /**
   * Ends live streams, stops accepting connections, waits for requests in flight, stops the Detector and the Prove re-check and waits
   * for their and the Clone Beacon's writes, drains the alert queue (bounded), then closes the database.
   */
  close(): Promise<void>;
}

// The names of the secret files beside the data directory live in key-files.ts (the backup tool reads them too).
export { ADDRESS_KEY_FILE, ATTESTATION_KEY_FILE, AUDIT_KEY_FILE, SIGNING_KEY_FILE, USAGE_SALTS_FILE };

/** Opens the database, builds the app and listens: the whole API in one call, for `main.ts` and for tests. */
export async function startApi(options: StartApiOptions = {}): Promise<RunningApi> {
  const { dataDir } = options;
  const logger = options.logger ?? consoleLogger;
  // Read before anything opens: a partial SMTP set fails the start with the name of the missing variable.
  const smtp = options.smtp === undefined ? readSmtpSettings(process.env) : options.smtp;
  // Likewise the operator settings: a short AR_OPS_TOKEN fails the start (slice 18d).
  const ops = options.ops ?? readOpsSettings(process.env);
  // And the probes' switch (slice 18g): a value that is neither on nor off fails the start.
  const probesEnabled = options.probes?.enabled ?? readProbeSettings(process.env).enabled;
  const email: EmailDeps | undefined =
    options.email ??
    (smtp === null
      ? undefined
      : {
          mailer: createSmtpMailer({ settings: smtp }),
          sender: smtp.from,
          ...(smtp.confirmationsPerDay === undefined ? {} : { confirmationsPerDay: smtp.confirmationsPerDay }),
        });
  if (smtp !== null && options.email === undefined) logger.info(`email alerts on: ${smtpSummary(smtp)}`);
  const db = await openDb(dataDir === undefined ? {} : { dataDir });
  let signer: Signer;
  let auditSigner: Signer;
  let attestation: AttestationKeys;
  let addressHasher: AddressHasher;
  let usageSalts: UsageSalts;
  try {
    // After the database: its lock makes this process the only one that can create or rewrite the key files.
    signer =
      options.signer ?? createSigner(dataDir === undefined ? {} : { file: join(dirname(dataDir), SIGNING_KEY_FILE) });
    auditSigner =
      options.auditSigner ??
      createSigner(dataDir === undefined ? {} : { file: join(dirname(dataDir), AUDIT_KEY_FILE) });
    attestation =
      options.attestation ??
      createAttestationKeys({
        ...(dataDir === undefined ? {} : { file: join(dirname(dataDir), ATTESTATION_KEY_FILE) }),
        ...(options.now === undefined ? {} : { now: options.now }),
        logger,
      });
    addressHasher = createAddressHasher(
      dataDir === undefined ? {} : { file: join(dirname(dataDir), ADDRESS_KEY_FILE) },
    );
    usageSalts = createUsageSalts(dataDir === undefined ? {} : { file: join(dirname(dataDir), USAGE_SALTS_FILE) });
  } catch (error) {
    await db.close();
    throw error;
  }
  // Slice 18g (D-116): the Organizations the API itself owns, in memory: their requests and Events feed no SLI but
  // the prober's own two measurements, and the Detector does not look at them.
  let systemOrganizations: SystemOrganizations;
  try {
    systemOrganizations = createSystemOrganizations(await db.owner((q) => listSystemOrganizationIds(q)));
  } catch (error) {
    await db.close();
    throw error;
  }
  const bus = createEventBus();
  const shutdown = new AbortController();
  // Slice 18d: every feed writes to one recorder; the job flushes it each minute and evaluates the burn alerts.
  const slo = createSloService({ db, now: options.now, logger, webhook: ops.webhook });
  const allowPrivateAlertUrls = options.allowPrivateAlertUrls ?? process.env.AR_ALLOW_PRIVATE_ALERT_URLS === "1";
  const notifier = createNotifier({
    db,
    now: options.now,
    allowPrivate: allowPrivateAlertUrls,
    consoleUrl: options.consoleUrl ?? (process.env.AR_CONSOLE_URL || DEFAULT_CONSOLE_URL),
    backoffMs: options.alertBackoffMs,
    logger,
    email,
    slo: slo.recorder,
  });
  const beacon = createBeaconRecorder({ db, notifier, now: options.now, logger });
  const integrity = createIntegrityRecorder({ db, notifier, now: options.now, logger });
  const exposureIncidents = createIncidentQueue({ db, notifier, logger });
  // The Detector is made once the server listens; until then a publish tells nobody.
  let detector: Detector | undefined;
  const deps: AppDeps = {
    db,
    bus,
    onPolicyPublished: (policy) => detector?.policyPublished(policy),
    signer,
    auditSigner,
    attestation,
    shutdown: shutdown.signal,
    notifier,
    beacon,
    integrity,
    exposureIncidents,
    allowPrivateAlertUrls,
    slo,
    systemOrganizations,
  };
  if (ops.token !== null) deps.opsToken = ops.token;
  if (email !== undefined) deps.email = email;
  deps.addressHasher = addressHasher;
  deps.usageSalts = usageSalts;
  const network = proveNetwork(options.prove);
  deps.prove = network;
  if (options.logger !== undefined) deps.logger = options.logger;
  if (options.heartbeatMs !== undefined) deps.heartbeatMs = options.heartbeatMs;
  if (options.now !== undefined) deps.now = options.now;
  if (options.patches !== undefined) deps.patches = options.patches;
  const assessor = options.assessor ?? proveAssessor();
  const assessments = createAssessmentRunner({
    ...options.assessments,
    db,
    assessor,
    now: options.now,
    logger,
    slo: slo.recorder,
  });
  deps.assessor = assessor;
  deps.assessments = assessments;
  // Slice 15a: off unless AR_PROVE_CAMPAIGNS=1. The test-only transport option comes from `options` alone.
  const authorize = createAuthorize({ db, now: options.now });
  const campaigns = createCampaignRunner({
    db,
    enabled: options.campaigns?.enabled ?? process.env[CAMPAIGNS_VARIABLE] === "1",
    resolver: network.resolver,
    authorize,
    now: options.now,
    logger,
    engine: options.campaigns?.engine,
    probes: options.campaigns?.probes,
    testing: options.campaigns?.testing,
  });
  deps.campaigns = campaigns;
  const app = createApp(deps);

  let listening: Listening;
  try {
    listening = await listen(app, { host: options.host ?? DEFAULT_HOST, port: options.port ?? 0 });
  } catch (error) {
    await db.close();
    throw error;
  }
  const { server } = listening;
  const graceMs = options.shutdownGraceMs ?? 2_000;
  // Started once the server listens: a failed start leaves nothing subscribed.
  const started = createDetector({
    db,
    bus,
    notifier,
    now: options.now,
    logger,
    patches: options.patches,
    slo: slo.recorder,
    isSystemOrganization: (organizationId) => systemOrganizations.has(organizationId),
  });
  detector = started;
  const stopDetector = started.start();
  const recheck = createRecheckJob({ ...options.recheck, db, network, now: options.now, logger });
  const stopRecheck = recheck.start();
  const purge = createPurgeJob({
    ...options.purge,
    db,
    signer: auditSigner,
    now: options.now,
    logger,
    // What the process still holds of a purged Organization in memory goes with it.
    onPurged: (organizationId) => {
      started.forget(organizationId);
      beacon.forget(organizationId);
      integrity.forget(organizationId);
      options.purge?.onPurged?.(organizationId);
    },
  });
  const stopPurge = purge.start();
  const retention = createRetentionJob({ ...options.retention, db, now: options.now, logger, usageSalts });
  const stopRetention = retention.start();
  const stopSlo = slo.start();
  // Fails the Assessments a previous process left running, then takes the queued ones.
  await assessments.start();
  // Campaigns a previous process left running become interrupted and are never resumed; queued ones are taken again.
  await campaigns.start();

  // Slice 18g: off unless AR_PROBES=1. The prober reaches this API through its own listening address only, with the
  // keys of its own Organization, which it finds or creates at its first cycle (a failure there is a failed cycle,
  // logged and tried again, not a failed start).
  let probes: Prober | null = null;
  if (probesEnabled) {
    // A wildcard bind is reached through the loopback address.
    const endpoint = ["0.0.0.0", "::", "[::]"].includes(listening.host)
      ? `http://127.0.0.1:${listening.port}`
      : listening.url;
    const prober = createProber({
      // The probe's Organization is provisioned once per process; after a failure only the transport is opened again
      // (review F1). It is known as a system Organization before its first request is sent (D-116).
      connect: createProbeConnect({
        provision: () => provisionProbeTenant({ db, now: options.now }),
        register: (organizationId) => systemOrganizations.add(organizationId),
        open:
          options.probes?.open ??
          ((tenant, signal) =>
            createHttpProbeTransport(
              { endpoint, tenant, policyPublicKey: signer.publicKey, logger, shield: options.probes?.shield },
              signal,
            )),
      }),
      slo: slo.recorder,
      logger,
      now: options.now,
      everyMs: options.probes?.everyMs,
      startDelayMs: options.probes?.startDelayMs,
    });
    slo.attachProbes(() => prober.status());
    prober.start();
    probes = prober;
    logger.info(
      `probes on: one cycle every ${prober.status().interval_s} s, inside this API instance against one Shield of its own`,
    );
  }

  let closing: Promise<void> | undefined;
  const stop = async (): Promise<void> => {
    // 0. The prober first: it is a client of this server. Its cycle in flight is cut (no sample), its Shield flushes
    // and closes, and its connections go, before the server stops accepting.
    await probes?.stop();
    // 1. Live streams return, so their responses end. 2. No new connections. 3. Idle keep-alive sockets
    // are swept while requests in flight finish; whatever is left after the grace period is cut.
    shutdown.abort();
    await new Promise<void>((resolve) => {
      const sweep = setInterval(() => server.closeIdleConnections(), 20);
      const force = setTimeout(() => server.closeAllConnections(), graceMs);
      server.close(() => {
        clearInterval(sweep);
        clearTimeout(force);
        resolve();
      });
      server.closeIdleConnections();
    });
    // 4. No Event or beacon report arrives any more: the Detector stops, and both finish their writes, which may
    // queue alerts. 5. The alert queue drains (bounded wait), then the database closes.
    stopDetector();
    stopRecheck();
    stopPurge();
    stopRetention();
    stopSlo();
    // Running Assessments are aborted and recorded as failed (interrupted) while the database is still open.
    await assessments.stop();
    // Running Campaigns are cut (request in flight, engine) and recorded as interrupted.
    await campaigns.stop();
    await recheck.flush();
    await purge.flush();
    await retention.flush();
    await started.flush();
    await beacon.flush();
    await integrity.flush();
    await exposureIncidents.flush();
    await notifier.drain();
    // Last before the database closes: the minute in progress, and every SLI the steps above recorded.
    await slo.flush();
    await db.close();
  };

  return {
    ...listening,
    app,
    db,
    bus,
    signer,
    attestation,
    notifier,
    authorize,
    assessments,
    campaigns,
    purge,
    retention,
    slo,
    probes,
    close() {
      closing ??= stop();
      return closing;
    },
  };
}
