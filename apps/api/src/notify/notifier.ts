import type { LookupAddress, LookupOptions } from "node:dns";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { Readable } from "node:stream";
import type { AlertDelivery, Incident, Severity, WebhookAlertPayload } from "@antireverse/protocol";
import { newId, signWebhookBody } from "@antireverse/protocol/server";
import type { Db } from "../db/db.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import {
  type DeliverableChannel,
  findChannelForDelivery,
  insertDelivery,
  listActiveChannelIds,
} from "../stores/alert-channels.ts";
import { findApp } from "../stores/apps.ts";
import { checkDestination, defaultResolve, type Resolve, resolveWithin } from "./ssrf.ts";

// Delivers alerts to the alert channels of an Organization: asynchronously, in process, with retries, behind
// the SSRF guard, and with webhook bodies signed. Every attempt is recorded. A channel's URL, its signing
// secret and the bodies sent never appear in a log line or a delivery record.

/** The address the SSRF guard vetted: the connection goes there and nowhere else. */
export interface Pin {
  address: string;
  family: 4 | 6;
}

export interface AlertRequestInit {
  method: "POST";
  headers: Record<string, string>;
  body: string;
  redirect: "manual";
  signal: AbortSignal;
}

/**
 * Sends one request to `url`, connected to `pin`. The global `fetch` fits this type (it ignores the pin), which
 * is convenient in tests; the default, `pinnedFetch`, connects to the pinned address.
 */
export type AlertFetch = (
  url: string,
  init: AlertRequestInit,
  pin: Pin,
) => Promise<{ status: number; body: ReadableStream<Uint8Array> | null }>;

export interface NotifierDeps {
  db: Db;
  now?: (() => Date) | undefined;
  /** Default: `pinnedFetch`. */
  fetch?: AlertFetch | undefined;
  /** Default: `dns.lookup(host, { all: true })`. */
  resolve?: Resolve | undefined;
  /** Allows `http:` and private addresses (development and tests only). Default false. */
  allowPrivate?: boolean | undefined;
  /** The Console's base URL, for the link in an alert. Default `http://127.0.0.1:3000`. */
  consoleUrl?: string | undefined;
  /** The wait after a failed first attempt; it doubles after each further one. Default 1,000 ms. */
  backoffMs?: number | undefined;
  logger?: Logger | undefined;
  /** Timeout of one attempt: host lookup, connection and response. Default 5,000 ms. */
  timeoutMs?: number | undefined;
  /** How long `drain()` waits for deliveries in flight. Default 10,000 ms. */
  drainMs?: number | undefined;
  /** Waits between attempts. Injectable so that tests can see the backoff without waiting it. */
  sleep?: ((ms: number) => Promise<void>) | undefined;
  /** Alert jobs held at once, all Organizations together: a safety cap. Default 10,000. */
  maxPending?: number | undefined;
  /**
   * Alert jobs held at once for one Organization; beyond it that Organization's new alert is dropped (and
   * logged), so one Organization's slow channels never crowd out another's alerts. Default 100.
   */
  maxPendingPerOrg?: number | undefined;
}

export interface Notifier {
  /** Queues the alerts of a newly opened Incident to every active channel of its Organization. Never throws. */
  incidentOpened(incident: Incident, organizationId: string): void;
  /** Sends one `test` alert to the channel, one attempt, and returns its record. Null when no such channel. */
  test(channelId: string, organizationId: string): Promise<AlertDelivery | null>;
  /** Waits (bounded) for the deliveries in flight, then stops: later alerts are dropped. */
  drain(): Promise<void>;
}

export const MAX_ATTEMPTS = 3;
/** Bytes of a response read, at most. The rest is never read: the connection is dropped. */
export const RESPONSE_BYTES_MAX = 4_096;
export const DEFAULT_CONSOLE_URL = "http://127.0.0.1:3000";

const USER_AGENT = "Airverse-Alerts/1";

/**
 * The default transport: `node:http(s)` with the host name in the URL (Host header, TLS server name and
 * certificate check) but the connection made to the pinned address only. One connection per request, so a
 * kept-alive socket to another address is never reused. Redirects are never followed (node does not follow).
 */
export const pinnedFetch: AlertFetch = (url, init, pin) =>
  new Promise((resolve, reject) => {
    const target = new URL(url);
    const send = target.protocol === "https:" ? httpsRequest : httpRequest;
    const lookup = (
      _host: string,
      options: LookupOptions,
      callback: (error: Error | null, address: string | LookupAddress[], family?: number) => void,
    ) => {
      if (options.all === true) callback(null, [{ address: pin.address, family: pin.family }]);
      else callback(null, pin.address, pin.family);
    };
    const request = send(
      target,
      {
        method: init.method,
        headers: { ...init.headers, "content-length": String(Buffer.byteLength(init.body)) },
        signal: init.signal,
        agent: false,
        lookup: lookup as never,
      },
      (response) => {
        resolve({
          status: response.statusCode ?? 0,
          body: Readable.toWeb(response) as unknown as ReadableStream<Uint8Array>,
        });
      },
    );
    request.on("error", reject);
    request.end(init.body);
  });

/** Reads at most `RESPONSE_BYTES_MAX` bytes of a body, then drops the rest. Never throws. */
async function readBounded(body: ReadableStream<Uint8Array> | null): Promise<void> {
  if (body === null) return;
  const reader = body.getReader();
  let read = 0;
  try {
    while (read < RESPONSE_BYTES_MAX) {
      const { done, value } = await reader.read();
      if (done) return;
      read += value.byteLength;
    }
  } catch {
    // A body that fails after the status arrived does not change the outcome.
  } finally {
    void reader.cancel().catch(() => {});
  }
}

const SEVERITY_WORDS: Record<Severity, string> = {
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  info: "Info",
};

/** Slack's three control characters in message text (`<`, `>` and `&`), escaped as Slack documents. */
function slackEscape(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

type Alert = { type: "incident.opened"; incident: Incident; appName: string } | { type: "test" };

const sleepFor = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

export function createNotifier(deps: NotifierDeps): Notifier {
  const { db } = deps;
  const now = deps.now ?? (() => new Date());
  const fetch = deps.fetch ?? pinnedFetch;
  const resolve = deps.resolve ?? defaultResolve;
  const allowPrivate = deps.allowPrivate ?? false;
  const consoleBase = (deps.consoleUrl ?? DEFAULT_CONSOLE_URL).replace(/\/+$/, "");
  const backoffMs = deps.backoffMs ?? 1_000;
  const logger = redacting(deps.logger ?? consoleLogger);
  const timeoutMs = deps.timeoutMs ?? 5_000;
  const drainMs = deps.drainMs ?? 10_000;
  const sleep = deps.sleep ?? sleepFor;
  const maxPending = deps.maxPending ?? 10_000;
  const maxPendingPerOrg = deps.maxPendingPerOrg ?? 100;

  const pending = new Set<Promise<unknown>>();
  /** Aborted when a drain gives up waiting: every request in flight is cut. */
  const stop = new AbortController();
  let closed = false;

  /** Jobs held per Organization. */
  const pendingByOrg = new Map<string, number>();

  function track<T>(organizationId: string, promise: Promise<T>): Promise<T> {
    pending.add(promise);
    pendingByOrg.set(organizationId, (pendingByOrg.get(organizationId) ?? 0) + 1);
    void promise
      .finally(() => {
        pending.delete(promise);
        const left = (pendingByOrg.get(organizationId) ?? 1) - 1;
        if (left > 0) pendingByOrg.set(organizationId, left);
        else pendingByOrg.delete(organizationId);
      })
      .catch(() => {});
    return promise;
  }

  const consoleUrlOf = (incident: Incident) => `${consoleBase}/incidents/${incident.id}`;

  function bodyFor(target: DeliverableChannel, alert: Alert): string {
    if (target.channel.kind === "slack") {
      const text =
        alert.type === "test"
          ? "Test alert from Airverse: this channel is connected."
          : `${SEVERITY_WORDS[alert.incident.severity]} — ${slackEscape(alert.incident.title)} on ${slackEscape(alert.appName)} (${alert.incident.environment}): ${consoleUrlOf(alert.incident)}`;
      return JSON.stringify({ text });
    }
    const payload: WebhookAlertPayload =
      alert.type === "test"
        ? { type: "test", incident: null, console_url: null }
        : { type: "incident.opened", incident: alert.incident, console_url: consoleUrlOf(alert.incident) };
    return JSON.stringify(payload);
  }

  /** One request; the status code when a response arrived, else null. Never throws. */
  async function send(target: DeliverableChannel, body: string): Promise<number | null> {
    // One signal bounds the whole attempt: host lookup, connection and response.
    const signal = AbortSignal.any([AbortSignal.timeout(timeoutMs), stop.signal]);
    const check = await checkDestination(target.url, { resolve: resolveWithin(resolve, signal), allowPrivate });
    if (!check.ok) return null;
    const headers: Record<string, string> = { "content-type": "application/json", "user-agent": USER_AGENT };
    if (target.signingSecret !== null) {
      const t = Math.floor(now().getTime() / 1_000);
      headers["ar-signature"] = `t=${t},v1=${signWebhookBody(target.signingSecret, t, body)}`;
    }
    try {
      const response = await fetch(target.url, { method: "POST", headers, body, redirect: "manual", signal }, check);
      await readBounded(response.body);
      return Number.isInteger(response.status) && response.status >= 100 && response.status <= 599
        ? response.status
        : null;
    } catch {
      return null;
    }
  }

  /** One attempt, recorded. Null when the channel no longer exists (deleted or inactive) or the notifier stopped. */
  async function attempt(
    organizationId: string,
    channelId: string,
    alert: Alert,
    number: number,
  ): Promise<AlertDelivery | null> {
    if (closed) return null;
    // Read again on every attempt: a channel deleted meanwhile is not contacted again.
    const target = await db.tx({ organizationId }, (q) => findChannelForDelivery(q, channelId));
    if (target === null) return null;
    const status = await send(target, bodyFor(target, alert));
    if (closed) return null;
    const outcome = status !== null && status >= 200 && status < 300 ? "delivered" : "failed";
    const delivery = await db.tx({ organizationId }, (q) =>
      insertDelivery(q, {
        organizationId,
        id: newId("dlv"),
        channel_id: channelId,
        incident_id: alert.type === "test" ? null : alert.incident.id,
        attempt: number,
        outcome,
        status_code: status,
        at: now().toISOString(),
      }),
    );
    const incident = alert.type === "test" ? "test" : alert.incident.id;
    logger.info(
      `alert channel=${channelId} incident=${incident} attempt=${number} outcome=${outcome} status=${status ?? "none"}`,
    );
    return delivery;
  }

  async function deliver(organizationId: string, channelId: string, alert: Alert): Promise<void> {
    for (let number = 1; number <= MAX_ATTEMPTS; number++) {
      const delivery = await attempt(organizationId, channelId, alert, number);
      if (delivery === null || delivery.outcome === "delivered") return;
      if (number < MAX_ATTEMPTS && !closed) await sleep(backoffMs * 2 ** (number - 1));
    }
  }

  /** The kind of error only: its message could quote a value. */
  const failed = (error: unknown) => {
    logger.warn(`alert failed ${error instanceof Error ? error.name : "error"}`);
  };

  return {
    incidentOpened(incident, organizationId) {
      if (closed) {
        logger.warn(`alert dropped incident=${incident.id} reason=stopped`);
        return;
      }
      if (pending.size >= maxPending || (pendingByOrg.get(organizationId) ?? 0) >= maxPendingPerOrg) {
        logger.warn(`alert dropped incident=${incident.id} organization=${organizationId} reason=queue-full`);
        return;
      }
      const job = (async () => {
        const { channelIds, appName } = await db.tx({ organizationId }, async (q) => ({
          channelIds: await listActiveChannelIds(q),
          appName: (await findApp(q, incident.app_id))?.name ?? incident.app_id,
        }));
        const alert: Alert = { type: "incident.opened", incident, appName };
        // Each channel on its own: a failing or slow one never holds back another.
        await Promise.all(channelIds.map((channelId) => deliver(organizationId, channelId, alert).catch(failed)));
      })().catch(failed);
      track(organizationId, job);
    },

    test(channelId, organizationId) {
      return track(organizationId, attempt(organizationId, channelId, { type: "test" }, 1));
    },

    async drain() {
      if (pending.size > 0) {
        let timer: NodeJS.Timeout | undefined;
        const bound = new Promise<void>((resolve) => {
          timer = setTimeout(resolve, drainMs);
        });
        await Promise.race([Promise.allSettled([...pending]), bound]);
        clearTimeout(timer);
      }
      closed = true;
      stop.abort();
    },
  };
}
