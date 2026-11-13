import type { LookupAddress, LookupOptions } from "node:dns";
import { request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { Readable } from "node:stream";
import type { AlertDelivery, Incident, WebhookAlertPayload } from "@antireverse/protocol";
import { newId, signWebhookBody } from "@antireverse/protocol/server";
import type { Db } from "../db/db.ts";
import { consoleLogger, type Logger, redacting } from "../log.ts";
import {
  alertMail,
  buildMessage,
  confirmationMail,
  type MailText,
  newMessageId,
  SEVERITY_WORDS,
  type Sender,
  testAlertMail,
} from "../mail/message.ts";
import type { MailEnvelope, Mailer, MailResult } from "../mail/smtp.ts";
import {
  type DeliverableChannel,
  findChannelForDelivery,
  insertDelivery,
  listActiveChannelIds,
  type MailRecipient,
  markRecipientsSent,
} from "../stores/alert-channels.ts";
import { findApp } from "../stores/apps.ts";
import { checkDestination, defaultResolve, type Resolve, resolveWithin } from "./ssrf.ts";

// Delivers alerts to the alert channels of an Organization: asynchronously, in process, with retries, behind
// the SSRF guard, and with webhook bodies signed. Every attempt is recorded. A channel's URL, its signing
// secret and the bodies sent never appear in a log line or a delivery record.
// Email channels (slice 06b) go through the `Mailer`: one message per confirmed recipient, all of a channel's in one
// batch (one SMTP connection); a retry goes to the recipients that failed only. Confirmation mails go the same way.
// No address and no token appears in a log line: recipients are named by their ids.

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
  /** The service's SMTP account (slice 06b). Without it, email channels get a failed attempt and no retry. */
  email?: EmailDeps | undefined;
  /** Alert jobs held at once, all Organizations together: a safety cap. Default 10,000. */
  maxPending?: number | undefined;
  /**
   * Alert jobs held at once for one Organization; beyond it that Organization's new alert is dropped (and
   * logged), so one Organization's slow channels never crowd out another's alerts. Default 100.
   */
  maxPendingPerOrg?: number | undefined;
}

/** The mail side of the notifier: the SMTP client (or a fake in tests) and the From of every mail. */
export interface EmailDeps {
  mailer: Mailer;
  sender: Sender;
  /** Confirmation mails of the whole service per UTC day (`AR_SMTP_CONFIRMATIONS_PER_DAY`). Default 500. */
  confirmationsPerDay?: number;
}

/** A confirmation mail to send: the token is in the link, and never stored or logged. */
export interface ConfirmationMail {
  recipientId: string;
  address: string;
  token: string;
}

export interface Notifier {
  /** Queues the alerts of a newly opened Incident to every active channel of its Organization. Never throws. */
  incidentOpened(incident: Incident, organizationId: string): void;
  /** Sends one `test` alert to the channel, one attempt, and returns its record. Null when no such channel. */
  test(channelId: string, organizationId: string): Promise<AlertDelivery | null>;
  /**
   * Queues confirmation mails (slice 06b): one attempt plus retries on the alert schedule, each accepted mail stamped
   * on its recipient. Never throws. The caller has already counted them against the daily limit per address.
   */
  confirmations(organizationId: string, mails: readonly ConfirmationMail[]): void;
  /** Waits (bounded) for the deliveries in flight, then stops: later alerts are dropped. */
  drain(): Promise<void>;
}

export const MAX_ATTEMPTS = 3;
/** SMTP connections open at once, all mail together (review F2): a flood can hold no more. */
export const SMTP_CONNECTIONS_MAX = 4;
/** Of those, the most confirmation mails may hold: alerts always keep the rest, and go first when one frees. */
export const CONFIRMATION_CONNECTIONS_MAX = 2;

type MailKind = "alert" | "confirmation";

/**
 * The connection pool of the mailer: at most `size` sends at once, at most `confirmations` of them confirmation
 * mails; a waiting alert is served before a waiting confirmation. A wait ends with the notifier (`signal`).
 */
function createSendPool(size: number, confirmations: number) {
  let inUse = 0;
  let confirmationsInUse = 0;
  const waiting: Record<MailKind, (() => void)[]> = { alert: [], confirmation: [] };
  const grant = (kind: MailKind) => {
    inUse++;
    if (kind === "confirmation") confirmationsInUse++;
  };
  const next = () => {
    while (inUse < size) {
      const alert = waiting.alert.shift();
      if (alert !== undefined) {
        alert();
        continue;
      }
      if (confirmationsInUse >= confirmations) return;
      const confirmation = waiting.confirmation.shift();
      if (confirmation === undefined) return;
      confirmation();
    }
  };
  return {
    /** Waits for a connection slot; resolves to its release. Rejects when `signal` aborts first. */
    acquire(kind: MailKind, signal: AbortSignal): Promise<() => void> {
      return new Promise((resolve, reject) => {
        if (signal.aborted) return reject(new Error("stopped"));
        const release = () => {
          inUse--;
          if (kind === "confirmation") confirmationsInUse--;
          next();
        };
        const start = () => {
          signal.removeEventListener("abort", onAbort);
          grant(kind);
          resolve(release);
        };
        const onAbort = () => {
          const queue = waiting[kind];
          const at = queue.indexOf(start);
          if (at !== -1) queue.splice(at, 1);
          reject(new Error("stopped"));
        };
        signal.addEventListener("abort", onAbort, { once: true });
        waiting[kind].push(start);
        next();
      });
    },
  };
}
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

/** Slack's three control characters in message text (`<`, `>` and `&`), escaped as Slack documents. */
function slackEscape(value: string): string {
  return value.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

type Alert = { type: "incident.opened"; incident: Incident; appName: string } | { type: "test" };

/** What a further attempt of one alert to one channel still has to do: for email, the recipients not yet reached. */
interface Progress {
  /** Null until the first email attempt: every confirmed recipient. */
  remaining: Set<string> | null;
}

type UrlChannel = Extract<DeliverableChannel, { kind: "webhook" | "slack" }>;

/**
 * A mail worth another attempt: refused for now (4xx), or no reply at all (connection, TLS, timeout). A 5xx reply is
 * permanent (RFC 5321 §4.2.1): recorded as failed at once and never sent again.
 */
const retryable = (result: { ok: boolean; code: number | null } | undefined): boolean =>
  result === undefined || (!result.ok && (result.code === null || result.code < 500));

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
  const email = deps.email;
  const pool = createSendPool(SMTP_CONNECTIONS_MAX, CONFIRMATION_CONNECTIONS_MAX);

  /** One batch through the pool. Never throws: a failure is every message failed without a reply. */
  async function sendThroughPool(mail: EmailDeps, kind: MailKind, messages: MailEnvelope[]): Promise<MailResult[]> {
    let release: (() => void) | undefined;
    try {
      release = await pool.acquire(kind, stop.signal);
      return await mail.mailer.send(messages, stop.signal);
    } catch {
      return messages.map(() => ({ ok: false, code: null }));
    } finally {
      release?.();
    }
  }

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

  function bodyFor(target: UrlChannel, alert: Alert): string {
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
  async function send(target: UrlChannel, body: string): Promise<number | null> {
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

  /** One message per recipient: `To` names that recipient alone. */
  function messagesFor(sender: Sender, recipients: readonly { address: string }[], text: MailText): MailEnvelope[] {
    return recipients.map((recipient) => ({
      from: sender.address,
      to: recipient.address,
      data: buildMessage({
        from: sender,
        to: recipient.address,
        subject: text.subject,
        body: text.body,
        date: now(),
        messageId: newMessageId(sender.address),
      }),
    }));
  }

  /**
   * Mails the recipients over one connection. Returns the reply code to record (the first failing one, else the
   * last accepting one; null when none arrived), whether any failed, and the ids worth a retry (temporary failures
   * only). Stamps the recipients reached.
   */
  async function mailTo(
    organizationId: string,
    mail: EmailDeps,
    recipients: readonly MailRecipient[],
    text: MailText,
  ): Promise<{ status: number | null; anyFailed: boolean; retry: string[] }> {
    const results = await sendThroughPool(mail, "alert", messagesFor(mail.sender, recipients, text));
    const reached = recipients.filter((_, index) => results[index]?.ok === true).map((recipient) => recipient.id);
    const anyFailed = reached.length < recipients.length;
    const retry = recipients.filter((_, index) => retryable(results[index])).map((recipient) => recipient.id);
    const firstFailure = results.find((result) => !result.ok);
    const status = firstFailure !== undefined ? firstFailure.code : (results.at(-1)?.code ?? null);
    if (reached.length > 0 && !closed) {
      await db.tx({ organizationId }, (q) => markRecipientsSent(q, reached, now()));
    }
    return { status, anyFailed, retry };
  }

  /** The text of an alert mail. */
  const mailTextOf = (alert: Alert): MailText =>
    alert.type === "test"
      ? testAlertMail()
      : alertMail({ incident: alert.incident, appName: alert.appName, consoleUrl: consoleBase });

  /**
   * One attempt, recorded. Null when the channel no longer exists (deleted or inactive), when an email channel has
   * nobody left to mail, or when the notifier stopped. `retry` is false when a further attempt cannot help.
   */
  async function attempt(
    organizationId: string,
    channelId: string,
    alert: Alert,
    number: number,
    progress: Progress = { remaining: null },
  ): Promise<{ delivery: AlertDelivery; retry: boolean } | null> {
    if (closed) return null;
    // Read again on every attempt: a channel deleted meanwhile is not contacted again.
    const target = await db.tx({ organizationId }, (q) => findChannelForDelivery(q, channelId));
    if (target === null) return null;
    let status: number | null;
    let delivered: boolean;
    let retry = true;
    if (target.kind === "email") {
      // Only confirmed recipients, and on a retry only those not reached yet.
      const remaining = progress.remaining;
      const recipients = target.recipients.filter((recipient) => remaining === null || remaining.has(recipient.id));
      if (recipients.length === 0) return null;
      if (email === undefined) {
        // No SMTP settings: nothing can be sent, now or on a retry.
        status = null;
        delivered = false;
        retry = false;
      } else {
        const sent = await mailTo(organizationId, email, recipients, mailTextOf(alert));
        progress.remaining = new Set(sent.retry);
        status = sent.status;
        delivered = !sent.anyFailed;
        // Only temporary failures are tried again; permanent refusals are final.
        retry = sent.retry.length > 0;
      }
    } else {
      status = await send(target, bodyFor(target, alert));
      delivered = status !== null && status >= 200 && status < 300;
    }
    if (closed) return null;
    const outcome = delivered ? "delivered" : "failed";
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
    return { delivery, retry };
  }

  async function deliver(organizationId: string, channelId: string, alert: Alert): Promise<void> {
    const progress: Progress = { remaining: null };
    for (let number = 1; number <= MAX_ATTEMPTS; number++) {
      const result = await attempt(organizationId, channelId, alert, number, progress);
      if (result === null || result.delivery.outcome === "delivered" || !result.retry) return;
      if (number < MAX_ATTEMPTS && !closed) await sleep(backoffMs * 2 ** (number - 1));
    }
  }

  /** Confirmation mails with retries: each attempt goes to the recipients not reached yet. */
  async function confirm(organizationId: string, mails: readonly ConfirmationMail[]): Promise<void> {
    if (email === undefined) {
      logger.warn(`confirmation mails dropped count=${mails.length} reason=smtp-not-configured`);
      return;
    }
    let remaining = [...mails];
    for (let number = 1; number <= MAX_ATTEMPTS && remaining.length > 0 && !closed; number++) {
      // One connection for all of them; each mail has its own text (its own link).
      const messages = remaining.flatMap((mail) =>
        messagesFor(email.sender, [mail], confirmationMail({ token: mail.token, consoleUrl: consoleBase })),
      );
      const results = await sendThroughPool(email, "confirmation", messages);
      const reached = remaining.filter((_, index) => results[index]?.ok === true);
      if (reached.length > 0 && !closed) {
        await db.tx({ organizationId }, (q) =>
          markRecipientsSent(
            q,
            reached.map((mail) => mail.recipientId),
            now(),
          ),
        );
      }
      for (const [index, mail] of remaining.entries()) {
        const result = results[index];
        logger.info(
          `confirmation recipient=${mail.recipientId} attempt=${number} outcome=${outcomeOf(result)} status=${result?.code ?? "none"}`,
        );
      }
      // Temporary failures only: a 5xx refusal is final, and a mail whose data went out without a final reply counts
      // as sent (review F4): sending it again could exceed the address's mails of the day.
      remaining = remaining.filter((_, index) => {
        const result = results[index];
        return retryable(result) && !(result !== undefined && !result.ok && result.dataSent === true);
      });
      if (remaining.length > 0 && number < MAX_ATTEMPTS && !closed) await sleep(backoffMs * 2 ** (number - 1));
    }
  }

  const outcomeOf = (result: MailResult | undefined): string =>
    result?.ok === true ? "delivered" : result?.dataSent === true ? "unknown" : "failed";

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
      return track(
        organizationId,
        attempt(organizationId, channelId, { type: "test" }, 1).then((result) => result?.delivery ?? null),
      );
    },

    confirmations(organizationId, mails) {
      if (mails.length === 0) return;
      if (closed) {
        logger.warn(`confirmation mails dropped count=${mails.length} reason=stopped`);
        return;
      }
      // The same queue limits as alerts (review F2): one Organization's mails never crowd out another's alerts.
      if (pending.size >= maxPending || (pendingByOrg.get(organizationId) ?? 0) >= maxPendingPerOrg) {
        logger.warn(
          `confirmation mails dropped count=${mails.length} organization=${organizationId} reason=queue-full`,
        );
        return;
      }
      track(organizationId, confirm(organizationId, mails).catch(failed));
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
