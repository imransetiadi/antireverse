import type { ShieldEvent } from "@antireverse/protocol";
import { SDK_NAME, SDK_VERSION, type Transport } from "./types.ts";

/** The conditions the emitter reports to the host's logger. Shield prints one line per condition. */
export type EmitterCondition = "unauthorized" | "unreachable" | "rejected";

export interface EmitterOptions {
  key: string;
  /** Base URL of the API. Events go to `{endpoint}/v1/events`. */
  endpoint: string;
  flushIntervalMs: number;
  maxBatchSize: number;
  maxBufferSize: number;
  requestTimeoutMs: number;
  transport: Transport;
  now: () => number;
  warn: (condition: EmitterCondition, message: string) => void;
}

export interface EmitterStats {
  buffered: number;
  sent: number;
  dropped: number;
  failedBatches: number;
  lastError: string | null;
}

export interface Emitter {
  /** Buffers one Event. Synchronous, no I/O. Does nothing after `close()`. */
  record(event: ShieldEvent): void;
  /** Sends what is buffered. Never rejects. */
  flush(): Promise<void>;
  /** Flushes once without retries, then stops. Never rejects. */
  close(): Promise<void>;
  stats(): EmitterStats;
}

/** Attempts per batch. */
const MAX_ATTEMPTS = 3;
/** Wait after the first, second and third failed attempt of a batch; the last one delays the next batch. */
const BACKOFF_MS = [500, 1_000, 2_000] as const;
/** Up to this share of a wait is added to it at random, so that many Shields do not retry in step. */
const JITTER = 0.25;
/** After ingest refuses the key (401 or 403) nothing is sent for this long. */
const UNAUTHORIZED_PAUSE_MS = 60_000;
/** The protocol accepts at most 500 Events per batch. */
const PROTOCOL_BATCH_MAX = 500;
/** Bytes of one request body at most: well under the 262,144 bytes ingest accepts. */
const BODY_BYTES_BUDGET = 196_608;
const BODY_HEAD = `{"protocol":1,"sdk":{"name":${JSON.stringify(SDK_NAME)},"version":${JSON.stringify(SDK_VERSION)}},"events":[`;
const BODY_TAIL = "]}";

type Outcome = "sent" | "rejected" | "unauthorized" | "failed";

function positiveInteger(value: number, fallback: number, max: number): number {
  return Number.isFinite(value) && value >= 1 ? Math.min(Math.floor(value), max) : fallback;
}

/** A short description of a transport error that cannot contain a secret: the error code or name only. */
export function describeError(error: unknown): string {
  const candidate = error as { code?: unknown; name?: unknown } | null | undefined;
  const label = typeof candidate?.code === "string" ? candidate.code : candidate?.name;
  return typeof label === "string" && /^[\w.-]{1,40}$/.test(label) ? label : "error";
}

/**
 * Buffers Events in a bounded ring and sends them in the background.
 *
 * - Bounded: when the ring is full the oldest Event is overwritten and counted.
 * - Idle when empty: the flush timer exists only while Events wait, and it is unref'd.
 * - Contained: `flush()` and `close()` never reject, and nothing here throws into the caller of `record()`.
 */
export function createEmitter(options: EmitterOptions): Emitter {
  const capacity = positiveInteger(options.maxBufferSize, 10_000, 1_000_000);
  const batchMax = positiveInteger(options.maxBatchSize, 100, PROTOCOL_BATCH_MAX);
  const flushIntervalMs = positiveInteger(options.flushIntervalMs, 1_000, 3_600_000);
  const timeoutMs = positiveInteger(options.requestTimeoutMs, 5_000, 600_000);
  const url = `${options.endpoint.replace(/\/+$/, "")}/v1/events`;
  const headers = { authorization: `Bearer ${options.key}`, "content-type": "application/json" };

  const ring: (ShieldEvent | undefined)[] = [];
  let head = 0; // index of the next write
  let size = 0;

  let sent = 0;
  let dropped = 0;
  let failedBatches = 0;
  let lastError: string | null = null;

  let timer: NodeJS.Timeout | undefined;
  let draining: Promise<void> | undefined;
  let closing: Promise<void> | undefined;
  let closed = false;
  let pausedUntil = 0;
  /** Ends the backoff wait that is in progress, if any. */
  let wake: (() => void) | undefined;

  function arm(delayMs: number): void {
    if (closed || timer !== undefined) return;
    // setTimeout, armed lazily and unref'd: an idle Shield has no timer, and a waiting one never holds the process.
    timer = setTimeout(() => {
      timer = undefined;
      void flush();
    }, delayMs);
    timer.unref();
  }

  function disarm(): void {
    if (timer !== undefined) clearTimeout(timer);
    timer = undefined;
  }

  /** The delay until the next flush: the interval, or the rest of a pause when that is longer. */
  function safeDelay(): number {
    try {
      const delay = Math.max(flushIntervalMs, pausedUntil - options.now());
      return Number.isFinite(delay) ? delay : flushIntervalMs;
    } catch {
      return flushIntervalMs; // the host's clock threw
    }
  }

  function warn(condition: EmitterCondition, message: string): void {
    try {
      options.warn(condition, message);
    } catch {
      // a logger that throws must not end the flush cycle
    }
  }

  function wait(ms: number): Promise<void> {
    return new Promise((resolve) => {
      const pending = setTimeout(done, ms);
      pending.unref();
      function done(): void {
        clearTimeout(pending);
        wake = undefined;
        resolve();
      }
      wake = done;
    });
  }

  function backoff(attempt: number): number {
    const base = BACKOFF_MS[attempt] as number;
    return Math.round(base * (1 + Math.random() * JITTER));
  }

  /** Removes the oldest Events from the ring, up to the batch size and the byte budget, and serializes them. */
  function take(): { body: string; count: number } {
    const parts: string[] = [];
    let bytes = BODY_HEAD.length + BODY_TAIL.length;
    while (size > 0 && parts.length < batchMax) {
      const tail = (head - size + capacity) % capacity;
      const json = JSON.stringify(ring[tail]);
      const cost = Buffer.byteLength(json) + 1;
      if (parts.length > 0 && bytes + cost > BODY_BYTES_BUDGET) break;
      ring[tail] = undefined;
      size -= 1;
      parts.push(json);
      bytes += cost;
    }
    return { body: BODY_HEAD + parts.join(",") + BODY_TAIL, count: parts.length };
  }

  function discardBuffered(): void {
    dropped += size;
    ring.length = 0;
    head = 0;
    size = 0;
  }

  async function send(batch: { body: string; count: number }): Promise<Outcome> {
    for (let attempt = 0; attempt < MAX_ATTEMPTS; attempt++) {
      let status: number | undefined;
      try {
        const response = await options.transport({ url, headers, body: batch.body, timeoutMs });
        status = response.status;
        if (typeof status !== "number") throw new TypeError("the transport returned no status");
      } catch (error) {
        status = undefined;
        lastError = `ingest unreachable (${describeError(error)})`;
      }
      if (status !== undefined) {
        if (status >= 200 && status < 300) {
          sent += batch.count;
          return "sent";
        }
        lastError = `ingest responded ${status}`;
        if (status === 401 || status === 403) {
          failedBatches += 1;
          pausedUntil = options.now() + UNAUTHORIZED_PAUSE_MS;
          warn(
            "unauthorized",
            `ingest refused the Shield key (HTTP ${status}). Events are not sent; Shield tries again every ${UNAUTHORIZED_PAUSE_MS / 1000} s.`,
          );
          return "unauthorized";
        }
        if (status !== 429 && status < 500) {
          failedBatches += 1; // the batch itself is refused: sending it again cannot help
          dropped += batch.count;
          warn(
            "rejected",
            `ingest refused a batch (HTTP ${status}). Check that "endpoint" is the base URL of the Airverse API. The Events of that batch are dropped; your application is not affected.`,
          );
          return "rejected";
        }
      }
      if (closed) break; // shutting down: no further attempts
      if (attempt < MAX_ATTEMPTS - 1) await wait(backoff(attempt));
      if (closed) break;
    }
    failedBatches += 1;
    dropped += batch.count;
    warn(
      "unreachable",
      `ingest cannot be reached (${lastError ?? "unknown"}). Events are dropped after ${MAX_ATTEMPTS} attempts; your application is not affected.`,
    );
    return "failed";
  }

  /** One flush cycle: sends batch after batch until the ring is empty, sending is paused or a batch was given up. */
  async function drain(): Promise<void> {
    let delay: number | undefined;
    try {
      while (size > 0) {
        if (options.now() < pausedUntil) {
          if (closed) discardBuffered();
          break;
        }
        const outcome = await send(take());
        if (outcome === "sent") continue;
        if (closed) {
          discardBuffered(); // one failure while shutting down: do not spend a timeout on every remaining batch
          break;
        }
        if (outcome === "failed") {
          delay = backoff(MAX_ATTEMPTS - 1); // leave a failing ingest alone for a while
          break;
        }
      }
    } catch {
      // Only the host's clock can throw here. The cycle ends; the promise stays resolved.
    }
    draining = undefined;
    if (size > 0) arm(delay ?? safeDelay());
  }

  function flush(): Promise<void> {
    if (draining !== undefined) return draining; // the cycle in progress also sends what was buffered since
    disarm();
    if (size === 0) return Promise.resolve();
    let paused = true;
    try {
      paused = options.now() < pausedUntil;
    } catch {
      // a clock that throws: treat as paused and try again later
    }
    if (paused && !closed) {
      arm(safeDelay());
      return Promise.resolve();
    }
    draining = drain();
    return draining;
  }

  return {
    record(event) {
      if (closed) return;
      if (size === capacity) dropped += 1;
      else size += 1;
      ring[head] = event;
      head = (head + 1) % capacity;
      if (timer === undefined && draining === undefined) arm(pausedUntil === 0 ? flushIntervalMs : safeDelay());
    },
    flush,
    close() {
      if (closing !== undefined) return closing;
      closed = true;
      disarm();
      wake?.();
      closing = (draining ?? Promise.resolve()).then(flush).then(() => {
        if (size > 0) discardBuffered();
      });
      return closing;
    },
    stats() {
      return { buffered: size, sent, dropped, failedBatches, lastError };
    },
  };
}
