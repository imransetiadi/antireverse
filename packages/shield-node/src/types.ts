// The public contract of Shield (plan contract C3). Types only, plus the constants the contract names.
import type { IncomingMessage, ServerResponse } from "node:http";

/** `sdk.name` of every batch Shield sends. */
export const SDK_NAME = "shield-node";
/** `sdk.version` of every batch Shield sends. Equal to the version in package.json (pinned by a test). */
export const SDK_VERSION = "0.0.0";

export const SHIELD_DEFAULTS = {
  /** Milliseconds between the first buffered Event and the flush that sends it. */
  flushIntervalMs: 1_000,
  /** Events per request. */
  maxBatchSize: 100,
  /** Events kept while they wait to be sent. When full, the oldest Event is overwritten and counted as dropped. */
  maxBufferSize: 10_000,
  /** Milliseconds one request to ingest may take. */
  requestTimeoutMs: 5_000,
} as const;

export const POLICY_DEFAULTS = {
  /** Milliseconds between two requests for the Policy Bundle, before jitter. */
  pollIntervalMs: 5_000,
  /** Bytes of a response body the default transport reads at most; a longer one fails the request. */
  responseBytesMax: 131_072,
} as const;

/**
 * Sends one request to the API. Resolves with the HTTP status; rejects on a transport error or after `timeoutMs`.
 *
 * Shield sends two kinds of request: a batch of Events (`method` absent or `"POST"`, with a `body`), for which only
 * the status matters, and the request for the Policy Bundle (`method: "GET"`, no `body`), for which the response
 * `body` and its `etag` header are read as well.
 */
export type Transport = (request: {
  /** Default: `"POST"`. */
  method?: "POST" | "GET";
  url: string;
  headers: Record<string, string>;
  body?: string;
  timeoutMs: number;
}) => Promise<{ status: number; body?: string; etag?: string; retryAfter?: string }>;

export interface ShieldLogger {
  warn(message: string): void;
}

export interface ShieldConfig {
  /** The Shield key of the App: `ark_<prod|stg|dev>_<43 characters>`. */
  key: string;
  /** Base URL of the Anti Reverse API, e.g. `http://127.0.0.1:8787`. */
  endpoint: string;
  flushIntervalMs?: number;
  maxBatchSize?: number;
  maxBufferSize?: number;
  requestTimeoutMs?: number;
  /** Default: `process.env.AR_SHIELD_DISABLED === "1"`. */
  disabled?: boolean;
  /** The address of the client. Default: the remote address of the socket. Only its network prefix is recorded. */
  clientAddress?: (req: unknown) => string | undefined;
  /** Default: `console`. Receives at most one line per distinct condition. */
  logger?: ShieldLogger;
  /** Default: `node:http` / `node:https` on an unref'd socket. Replaceable in tests. */
  transport?: Transport;
  /** The clock, in milliseconds since the epoch. Default: `Date.now`. */
  now?: () => number;
  /**
   * The public key of the API's signing key, as `GET /v1/signing-key` returns it: 43 base64url characters
   * (a raw Ed25519 key). Shield applies only Policy Bundles signed with it. Without it Shield observes only:
   * it fetches no Policy, records Events and blocks nothing.
   */
  policyPublicKey?: string;
  /** Milliseconds between two requests for the Policy Bundle. Default 5,000; never less than 100. */
  policyPollIntervalMs?: number;
  /**
   * The key of the actor hash: a secret the customer holds and Anti Reverse never sees (at least 32 characters,
   * no whitespace, not the Shield key). Default: `process.env.AR_ACTOR_KEY`. With it every Event carries
   * `actor.ip_hash`, a keyed hash of the client address, and actor blocks can match. Without a usable one
   * `ip_hash` is null and actor blocks never match; prefix blocks still apply. An unusable value is treated as
   * absent with one warning. It is never sent, logged or put into an Event or an error.
   */
  actorKey?: string;
  /**
   * The media types whose body parser carries `shield.verifyBody` as its verify hook on every route a requirement
   * Rule names, e.g. `{ types: ["application/json"] }` with `express.json({ verify: shield.verifyBody })`. Each
   * entry is `type/subtype`, compared without regard to case on the part before any `;`, trimmed. Default: none.
   * Anything else (`true` included, the form before review F1) makes `createShield` throw a TypeError at startup.
   *
   * Shield decides before the body is read. A request with a body on a route with an Enforce requirement is
   * therefore blocked at once, unless it is validly signed and its `content-type` (before `;`, trimmed, any case) is
   * listed here: then it proceeds and the decision is deferred to the hook. A body with the signed hash is
   * `checked`; any other body is refused with 403 before the handler (Enforce) or recorded (Monitor). A body the
   * hook never saw is recorded, when the response closes, as the requirement Rule's block: the response has already
   * gone out, so list only the types whose parser carries the hook on those routes.
   */
  bodyVerified?: { readonly types: readonly string[] };
  /**
   * Sends the runtime component inventory (slice 19): once, after the first successful Policy fetch (or shortly
   * after start when no Policy is fetched), Shield reads `node_modules/.package-lock.json`, else
   * `package-lock.json`, under `projectRoot` and posts the package names, versions and dev flags to
   * `POST /v1/inventory` with its key, then again every 6 h. Never on the request path; retried 3 times, then quiet. Nothing else is
   * read and no package name is ever logged. Default: true, unless `process.env.AR_SHIELD_INVENTORY === "0"`;
   * the option wins over the environment.
   */
  inventory?: boolean;
  /** The folder whose lockfile the inventory reads. Default: `process.cwd()` when Shield is created. */
  projectRoot?: string;
}

/**
 * What Shield decided for one request.
 *
 * - A Rule in Enforce mode matched: `{ action: "block", mode: "enforce", ruleId, policyVersion }`. The middleware
 *   answers 403 and the application does not see the request.
 * - Only a Rule in Monitor mode matched: `{ action: "block", mode: "monitor", ruleId, policyVersion }`. The
 *   request proceeds; the Event says what Enforce mode would have done.
 * - No Rule matched: `{ action: "allow", ruleId: null, policyVersion }`, in mode `"monitor"` under the built-in
 *   Policy (version 0) and `"enforce"` under a published one.
 */
export interface Decision {
  action: "allow" | "block";
  mode: "monitor" | "enforce";
  ruleId: string | null;
  policyVersion: number;
}

export interface DecideInput {
  /** HTTP method. Read in upper case. */
  method: string;
  /**
   * The path of the request as the client sent it, e.g. `/api/admin/reports`. A query string is ignored.
   * It is matched inside the process only: it is never recorded and never sent anywhere.
   */
  path: string;
  /**
   * Whether the request meets the signature requirement (slice 04): signature `valid` and body `checked` or `none`.
   * Requirement Rules (`signature_rules`) match only when this is not true. Left out: not met.
   */
  signed?: boolean;
  /**
   * The request is a CORS preflight: method `OPTIONS` with an `access-control-request-method` header (review F3).
   * A preflight is exempt from requirement Rules (a browser never signs one); plain Rules still apply. Ignored for
   * any other method. Left out: not a preflight.
   */
  preflight?: boolean;
}

export interface ShieldStats {
  /** Events waiting to be sent. */
  buffered: number;
  /** Events ingest accepted. */
  sent: number;
  /** Events lost because the buffer was full, or still unsent when `close()` gave up. */
  dropped: number;
  /** Batches given up: retries exhausted, or refused by ingest. */
  failedBatches: number;
  /** Errors inside Shield that were contained. The host application never sees them. */
  internalErrors: number;
  /** Why Shield does nothing, or null when it is active. */
  disabledReason: string | null;
  /** The most recent reason a batch was not accepted, or null. Never contains the key. */
  lastError: string | null;
  /** The version of the applied Policy. 0 is the built-in Policy: no Rules. */
  policyVersion: number;
  /** The applied Policy is past its `not_after`: the API was not reached for days. Its Rules still apply. */
  policyStale: boolean;
  /** Rules of the applied Policy. */
  policyRules: number;
  /**
   * Why the most recent request for the Policy Bundle changed nothing: the API was not reached, or its answer was
   * refused. Null after a bundle was applied or confirmed. Never contains the key or the public key.
   */
  lastPolicyError: string | null;
  /**
   * A usable actor key was accepted (`actorKey` or AR_ACTOR_KEY): Events carry an actor hash and actor blocks can
   * match. False without one, with an unusable one, and for a disabled Shield. Never the key itself.
   */
  actorHashing: boolean;
  /**
   * The runtime component inventory: `off` (turned off, or a disabled Shield), `pending` (not sent yet, or being
   * retried), `sent` (the API accepted it) or `failed` (no readable lockfile, refused, or retries exhausted).
   */
  inventory: "off" | "pending" | "sent" | "failed";
}

/** An Express-compatible middleware, typed against `node:http` so that Shield needs no Express types. */
export type ShieldMiddleware = (req: IncomingMessage, res: ServerResponse, next: (err?: unknown) => void) => void;

/** An Express error middleware (four arguments), typed against `node:http`. */
export type ShieldErrorHandler = (
  err: unknown,
  req: IncomingMessage,
  res: ServerResponse,
  next: (err?: unknown) => void,
) => void;

export interface Shield {
  /** Synchronous, no I/O: reads the applied Policy only. Never throws. */
  decide(input: DecideInput): Decision;
  /** The middleware for an Express application: `app.use(shield.express())`, before the routes. */
  express(): ShieldMiddleware;
  /** Sends what is buffered now. Never rejects. */
  flush(): Promise<void>;
  /**
   * Asks the API for the Policy Bundle now instead of at the next poll, and resolves once the answer was applied
   * or refused (see `stats()`). Never rejects. Does nothing without a `policyPublicKey` or after `close()`.
   */
  refreshPolicy(): Promise<void>;
  /** Flushes once and stops. Afterwards nothing is recorded and no Policy is fetched. Never rejects. */
  close(): Promise<void>;
  stats(): ShieldStats;
  /**
   * The body-parser `verify` hook that binds a signed request's body to its signature:
   * `app.use(express.json({ verify: shield.verifyBody }))` (also `express.raw`, `express.text`,
   * `express.urlencoded`), installed after `shield.express()`. For a signed request it compares the SHA-256 of
   * the body bytes with `ar-content-sha256` (timing-safe): equal → body `checked`; different → body `mismatch` and
   * signature `invalid`. Only where an Enforce requirement Rule applies (deferred under `bodyVerified`) does it then
   * throw an error with `status` 403 and `expose` false, so that the parser answers 403 before the handler;
   * otherwise the parser goes on and the handler runs. Does nothing for other requests. A plain function: no `this`
   * needed. The thrown error carries `expose: false`, `type: "entity.verify.failed"` and `body` = the block body;
   * add `shield.errorHandler()` to answer it with exactly the standard block response.
   */
  verifyBody(req: IncomingMessage, res: ServerResponse, buf: Buffer, encoding: string): void;
  /**
   * An Express error middleware for Shield's body refusal (review F6): `app.use(shield.errorHandler())` after the
   * routes and before the application's own error handlers. For the error `verifyBody` throws it answers 403 with
   * the standard block body and the same headers as any Shield block; every other error goes on to `next(err)`
   * unchanged, as does this one when the response has already started.
   */
  errorHandler(): ShieldErrorHandler;
}
