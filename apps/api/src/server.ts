import type { Server } from "node:http";
import type { AddressInfo } from "node:net";
import { dirname, join } from "node:path";
import { serve } from "@hono/node-server";
import { type AppDeps, createApp } from "./app.ts";
import { type AttestationKeys, createAttestationKeys } from "./attestation/keys.ts";
import { createEventBus, type EventBus } from "./bus.ts";
import { DEFAULT_HOST } from "./config.ts";
import { type Db, openDb } from "./db/db.ts";
import { createBeaconRecorder } from "./detect/beacon.ts";
import { createDetector } from "./detect/detector.ts";
import { createIncidentQueue } from "./exposure/match.ts";
import { consoleLogger, type Logger } from "./log.ts";
import { createNotifier, DEFAULT_CONSOLE_URL, type Notifier } from "./notify/notifier.ts";
import type { PatchCatalog } from "./patches/catalog.ts";
import { createSigner, type Signer } from "./signer.ts";

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
  /** The Virtual patch catalog (slice 20). Default: `PATCH_CATALOG`; tests pass a fixture catalog. */
  patches?: PatchCatalog;
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
   * Ends live streams, stops accepting connections, waits for requests in flight, stops the Detector and waits
   * for its and the Clone Beacon's writes, drains the alert queue (bounded), then closes the database.
   */
  close(): Promise<void>;
}

/** The file name of the signing key. It lies beside the data directory, like the directory's lock. */
export const SIGNING_KEY_FILE = "signing-key.json";
/** The file name of the attestation key set: beside the data directory too, a separate file and key purpose. */
export const ATTESTATION_KEY_FILE = "attestation-keys.json";

/** Opens the database, builds the app and listens: the whole API in one call, for `main.ts` and for tests. */
export async function startApi(options: StartApiOptions = {}): Promise<RunningApi> {
  const { dataDir } = options;
  const db = await openDb(dataDir === undefined ? {} : { dataDir });
  const logger = options.logger ?? consoleLogger;
  let signer: Signer;
  let attestation: AttestationKeys;
  try {
    // After the database: its lock makes this process the only one that can create or rewrite the key files.
    signer =
      options.signer ?? createSigner(dataDir === undefined ? {} : { file: join(dirname(dataDir), SIGNING_KEY_FILE) });
    attestation =
      options.attestation ??
      createAttestationKeys({
        ...(dataDir === undefined ? {} : { file: join(dirname(dataDir), ATTESTATION_KEY_FILE) }),
        ...(options.now === undefined ? {} : { now: options.now }),
        logger,
      });
  } catch (error) {
    await db.close();
    throw error;
  }
  const bus = createEventBus();
  const shutdown = new AbortController();
  const allowPrivateAlertUrls = options.allowPrivateAlertUrls ?? process.env.AR_ALLOW_PRIVATE_ALERT_URLS === "1";
  const notifier = createNotifier({
    db,
    now: options.now,
    allowPrivate: allowPrivateAlertUrls,
    consoleUrl: options.consoleUrl ?? (process.env.AR_CONSOLE_URL || DEFAULT_CONSOLE_URL),
    backoffMs: options.alertBackoffMs,
    logger,
  });
  const beacon = createBeaconRecorder({ db, notifier, now: options.now, logger });
  const exposureIncidents = createIncidentQueue({ db, notifier, logger });
  const deps: AppDeps = {
    db,
    bus,
    signer,
    attestation,
    shutdown: shutdown.signal,
    notifier,
    beacon,
    exposureIncidents,
    allowPrivateAlertUrls,
  };
  if (options.logger !== undefined) deps.logger = options.logger;
  if (options.heartbeatMs !== undefined) deps.heartbeatMs = options.heartbeatMs;
  if (options.now !== undefined) deps.now = options.now;
  if (options.patches !== undefined) deps.patches = options.patches;
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
  const detector = createDetector({ db, bus, notifier, now: options.now, logger, patches: options.patches });
  const stopDetector = detector.start();

  let closing: Promise<void> | undefined;
  const stop = async (): Promise<void> => {
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
    await detector.flush();
    await beacon.flush();
    await exposureIncidents.flush();
    await notifier.drain();
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
    close() {
      closing ??= stop();
      return closing;
    },
  };
}
