import type { KeyObject } from "node:crypto";
import { describeError } from "../emitter.ts";
import type { Transport } from "../types.ts";
import type { AppliedPolicy, PolicyStore } from "./store.ts";
import { type RefusalReason, verifyBody } from "./verify.ts";

/** The conditions the poller reports to the host's logger. Shield prints one line per condition. */
export type PollerCondition =
  | "policy-unauthorized"
  | "policy-unreachable"
  | "policy-rejected"
  | "policy-reset"
  | `policy-refused-${RefusalReason}`;

export interface PollerOptions {
  key: string;
  /** Base URL of the API. The bundle comes from `{endpoint}/v1/policy-bundle`. */
  endpoint: string;
  /** The configured public key: only bundles signed with it are applied. */
  publicKey: KeyObject;
  /** The audience of this Shield: only bundles issued for it are applied. */
  audience: string;
  intervalMs: number;
  requestTimeoutMs: number;
  transport: Transport;
  now: () => number;
  warn: (condition: PollerCondition, message: string) => void;
  /** Where a verified Policy is applied. */
  store: PolicyStore;
  /** Called after each fetch that applied or confirmed the Policy (200 applied, or 304). Must not throw. */
  onFetched?: () => void;
}

export interface Poller {
  /** Fetches now and resolves once the answer was applied or refused. Never rejects. Does nothing after `close()`. */
  refresh(): Promise<void>;
  /** Stops the timer. An answer that is still under way is not applied. */
  close(): void;
  /** Why the most recent fetch changed nothing, or null. Never contains the key or the public key. */
  lastError(): string | null;
}

/** Wait before the first fetch, so that creating a Shield does no I/O in the same turn. */
const FIRST_FETCH_MS = 100;
const DEFAULT_INTERVAL_MS = 5_000;
/** A shorter interval would be a request loop against the API. */
const MIN_INTERVAL_MS = 100;
const MAX_INTERVAL_MS = 3_600_000;
/** Up to this share of a wait is added to it at random, so that many Shields do not ask in step. */
const JITTER = 0.25;
/** After a failure the wait doubles with each further failure, up to this. */
const MAX_BACKOFF_MS = 60_000;
/** After the API refuses the key (401 or 403) nothing is asked for this long. */
const UNAUTHORIZED_PAUSE_MS = 60_000;
/** An ETag worth sending back: printable ASCII of a sane length. */
const ETAG = /^[\x20-\x7e]{1,256}$/;

type Outcome = "ok" | "failed" | "unauthorized";

/**
 * Fetches the Policy Bundle in the background and applies what verifies.
 *
 * - One timer at a time, armed after each fetch and unref'd: it never holds the process.
 * - Conditional: once a bundle with an ETag was applied, `If-None-Match` is sent and a 304 changes nothing.
 * - Whatever goes wrong — no answer, an error status, a bundle that is refused — the applied Policy stays, the
 *   cause is in `lastError()`, the host is told once per condition, and the wait grows.
 * - Contained: `refresh()` never rejects and nothing here throws.
 */
export function createPoller(options: PollerOptions): Poller {
  const intervalMs =
    Number.isFinite(options.intervalMs) && options.intervalMs >= 1
      ? Math.min(Math.max(Math.floor(options.intervalMs), MIN_INTERVAL_MS), MAX_INTERVAL_MS)
      : DEFAULT_INTERVAL_MS;
  const url = `${options.endpoint.replace(/\/+$/, "")}/v1/policy-bundle`;

  let timer: NodeJS.Timeout | undefined;
  let inFlight: Promise<void> | undefined;
  /** The one fetch that follows the fetch in flight, for callers of `refresh()` that arrived during it. */
  let queued: Promise<void> | undefined;
  let closed = false;
  let etag: string | undefined;
  /** Consecutive fetches that changed nothing because something was wrong. */
  let failures = 0;
  let lastError: string | null = null;

  function arm(delayMs: number): void {
    if (closed || timer !== undefined) return;
    // setTimeout, armed for one fetch and unref'd: a waiting Shield never holds the process.
    timer = setTimeout(() => {
      timer = undefined;
      if (inFlight === undefined) void run();
    }, delayMs);
    timer.unref();
  }

  function disarm(): void {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
  }

  function jittered(ms: number): number {
    return Math.round(ms * (1 + Math.random() * JITTER));
  }

  function warn(condition: PollerCondition, message: string): void {
    try {
      options.warn(condition, message);
    } catch {
      // a logger that throws must not end the polling
    }
  }

  function kept(): string {
    const version = options.store.current().version;
    return version === 0
      ? "Shield keeps observing without Rules"
      : `Shield keeps the last valid Policy (version ${version})`;
  }

  /** One request and what follows from its answer. Never throws. */
  async function fetchOnce(): Promise<Outcome> {
    let status: number;
    let body: string | undefined;
    let received: string | undefined;
    try {
      const headers: Record<string, string> = { authorization: `Bearer ${options.key}`, accept: "application/json" };
      if (etag !== undefined) headers["if-none-match"] = etag;
      const response = await options.transport({ method: "GET", url, headers, timeoutMs: options.requestTimeoutMs });
      status = response.status;
      if (typeof status !== "number") throw new TypeError("the transport returned no status");
      body = response.body;
      received = response.etag;
    } catch (error) {
      if (closed) return "ok"; // closing Shield drops its connections: that is not an outage
      lastError = `the Policy endpoint is unreachable (${describeError(error)})`;
      warn(
        "policy-unreachable",
        `the Policy of the App cannot be reached (${describeError(error)}). ${kept()} and asks again; your application is not affected.`,
      );
      return "failed";
    }
    if (closed) return "ok"; // stopped while the request was under way: nothing is applied any more

    if (status === 304) {
      lastError = null; // the applied Policy is the current one
      return "ok";
    }
    if (status === 401 || status === 403) {
      lastError = `the Policy endpoint responded ${status}`;
      warn(
        "policy-unauthorized",
        `the API refused the Shield key when asked for the Policy (HTTP ${status}). ${kept()} and asks again every ${UNAUTHORIZED_PAUSE_MS / 1000} s.`,
      );
      return "unauthorized";
    }
    if (status !== 200) {
      lastError = `the Policy endpoint responded ${status}`;
      warn(
        "policy-rejected",
        `the API answered the request for the Policy with HTTP ${status}. Check that "endpoint" is the base URL of the Anti Reverse API. ${kept()}.`,
      );
      return "failed";
    }

    let applied: AppliedPolicy;
    let now: number;
    try {
      applied = options.store.current();
      now = options.now();
    } catch (error) {
      lastError = `the Policy could not be checked (${describeError(error)})`;
      return "failed";
    }
    const result = verifyBody(body, {
      publicKey: options.publicKey,
      audience: options.audience,
      appliedVersion: applied.version,
      appliedEpoch: applied.epoch,
      appliedIssuedAt: applied.issuedAt,
      now,
    });
    if (!result.ok) {
      lastError = `Policy refused (${result.reason}): ${result.detail}`;
      const hint =
        result.reason === "signature"
          ? ' Check that "policyPublicKey" is the public key of GET /v1/signing-key of this API.'
          : "";
      warn(
        `policy-refused-${result.reason}`,
        `the Policy from the API was refused (${result.reason}): ${result.detail}.${hint} ${kept()}.`,
      );
      return "failed";
    }
    options.store.apply(result.policy);
    if (applied.epoch !== null && applied.epoch !== result.policy.epoch) {
      // Informational: the API's database was reset while its signing key was kept, so its versions restarted.
      warn(
        "policy-reset",
        `the Policy history of the API was reset (a new epoch): Shield applied version ${result.policy.version} of the new history in place of version ${applied.version}.`,
      );
    }
    // Only the ETag of what was applied is sent back: a refused answer is asked for again.
    etag = typeof received === "string" && ETAG.test(received) ? received : undefined;
    lastError = null;
    return "ok";
  }

  /** One fetch, then the timer for the next. Never rejects. */
  function run(): Promise<void> {
    const cycle = (async () => {
      let outcome: Outcome = "failed";
      try {
        outcome = await fetchOnce();
      } catch (error) {
        lastError = `the Policy could not be checked (${describeError(error)})`;
      }
      let delay: number;
      if (outcome === "ok") {
        failures = 0;
        delay = jittered(intervalMs);
        if (!closed) {
          try {
            options.onFetched?.();
          } catch {
            // contained: the polling goes on
          }
        }
      } else if (outcome === "unauthorized") {
        failures = 0;
        delay = Math.max(jittered(intervalMs), UNAUTHORIZED_PAUSE_MS);
      } else {
        failures += 1;
        // 2x, 4x, 8x the interval ... up to a minute, and never less than the interval itself.
        delay = jittered(Math.max(intervalMs, Math.min(intervalMs * 2 ** Math.min(failures, 16), MAX_BACKOFF_MS)));
      }
      inFlight = undefined;
      arm(delay);
    })();
    inFlight = cycle;
    return cycle;
  }

  arm(jittered(FIRST_FETCH_MS));

  return {
    refresh() {
      if (closed) return Promise.resolve();
      if (inFlight !== undefined) {
        // The fetch in flight was sent before this call: its answer may be older than what the caller waits for.
        queued ??= inFlight.then(() => {
          queued = undefined;
          if (closed) return;
          disarm();
          return run();
        });
        return queued;
      }
      disarm();
      return run();
    },
    close() {
      closed = true;
      disarm();
    },
    lastError: () => lastError,
  };
}
