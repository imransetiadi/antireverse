// Alert channels of the stand-in API (slices 06 and 06b), in memory, per Organization. The answers have the shape of
// the protocol's schemas (incidents.ts); a test checks them. Only node:crypto is imported, so that the test can load
// this module as it is.
//
// Seed of every Organization: a webhook, a Slack channel and an email channel whose first recipient has confirmed
// and whose second is pending (one confirmation mail sent today). `smtpConfigured: false` answers as an API without
// SMTP settings: `smtp_configured: false` and 409 smtp-not-configured for every email action.
//
// A test alert to a host under example.com fails with 503, to a host under .invalid gets no response, and is
// delivered anywhere else; to an email channel it is delivered (SMTP 250) once a recipient has confirmed, else 409
// no-confirmed-recipients. Confirmation mails: 3 per address per UTC day (429 with Retry-After until midnight UTC);
// a confirmed recipient answers 409 recipient-confirmed. The public confirmation takes 600 requests a minute, all
// callers together (429 with Retry-After 60), and 5 attempts per token; it answers `confirmed: false` alike for
// unknown, used, expired and exhausted tokens.
//
// No mail is sent and no token is logged: `confirmationToken(organizationId, recipientId)` hands the latest token of
// a pending recipient to the stub's own `/__stub/` endpoint, so that a person can open the link by hand.
import { randomBytes } from "node:crypto";

const DAY_MS = 86_400_000;
const MINUTE_MS = 60_000;
const CHANNELS_MAX = 10;
const RECIPIENTS_MAX = 5;
const MAILS_PER_DAY = 3;
const CONFIRM_PER_MINUTE = 600;
const ATTEMPTS_PER_TOKEN = 5;
const TOKEN_TTL_MS = 72 * 3_600_000;
const TOKEN_PATTERN = /^[A-Za-z0-9_-]{43}$/;
// Roughly the protocol's address rule: lower-case ASCII, a dot-atom local part, a dotted domain.
const ADDRESS_PATTERN =
  /^[a-z0-9!#$%&'*+/=?^_`{|}~-]+(?:\.[a-z0-9!#$%&'*+/=?^_`{|}~-]+)*@(?:[a-z0-9](?:[a-z0-9-]*[a-z0-9])?\.)+[a-z](?:[a-z0-9-]*[a-z0-9])?$/;

const newId = (prefix) => `${prefix}_${randomBytes(12).toString("hex")}`;

/** Like the API's SSRF guard, roughly: no loopback, private or link-local literal and no localhost. */
function refusedHost(hostname) {
  const host = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    /^(?:127|10|0)\./.test(host) ||
    /^192\.168\./.test(host) ||
    /^172\.(?:1[6-9]|2[0-9]|3[01])\./.test(host) ||
    /^169\.254\./.test(host) ||
    /^100\.(?:6[4-9]|[7-9][0-9]|1[01][0-9]|12[0-7])\./.test(host) ||
    host === "::1" ||
    host.startsWith("::ffff:") ||
    /^f[cd]|^fe[89ab]/.test(host)
  );
}

const problem = (status, title, extra = {}, headers = undefined) => ({
  status,
  body: { type: "about:blank", title, status, ...extra },
  ...(headers ? { headers } : {}),
});
const invalid = (path, message) => problem(400, "Bad Request", { errors: [{ path, message }] });
const conflict = (reason) => problem(409, "Conflict", { reason });

function validName(body) {
  const name = typeof body?.name === "string" ? body.name.trim() : "";
  return name.length >= 1 && name.length <= 80 ? name : null;
}

/**
 * @param {{ smtpConfigured?: boolean, now?: () => number }} [options]
 */
export function createAlertStore({ smtpConfigured = true, now = () => Date.now() } = {}) {
  /** @type {Map<string, Array<{ channel: any, url: string | null, secret: string | null }>>} */
  const channels = new Map();
  /** token → { organizationId, channelId, recipientId, expiresAt, used } */
  const tokens = new Map();
  /** "<address>/<UTC day>" → confirmation mails sent */
  const mails = new Map();
  /** token → attempts, counted whether or not a recipient holds the token */
  const attempts = new Map();
  let window = { start: 0, count: 0 };

  const iso = () => new Date(now()).toISOString();
  const day = () => Math.floor(now() / DAY_MS);

  /** A new confirmation mail: the previous link of the recipient stops working. Null once the day's mails are spent. */
  function issueToken(organizationId, channelId, recipient) {
    const counted = `${recipient.address}/${day()}`;
    const sent = mails.get(counted) ?? 0;
    if (sent >= MAILS_PER_DAY) return null;
    mails.set(counted, sent + 1);
    for (const [token, entry] of tokens) if (entry.recipientId === recipient.id) tokens.delete(token);
    const token = randomBytes(32).toString("base64url");
    tokens.set(token, {
      organizationId,
      channelId,
      recipientId: recipient.id,
      expiresAt: now() + TOKEN_TTL_MS,
      used: false,
    });
    recipient.last_sent_at = iso();
    return token;
  }

  function urlChannel(kind, name, url) {
    const parsed = new URL(url);
    const channel = {
      id: newId("chn"),
      kind,
      name,
      host: parsed.hostname,
      url_last4: url.slice(-4),
      active: true,
      created_at: iso(),
    };
    const secret = kind === "webhook" ? `whsec_${randomBytes(32).toString("base64url")}` : null;
    return { channel, url, secret };
  }

  function emailChannel(organizationId, name, addresses) {
    const channel = {
      id: newId("chn"),
      kind: "email",
      name,
      recipients: addresses.map((address) => ({
        id: newId("rcp"),
        address,
        status: "pending",
        confirmed_at: null,
        last_sent_at: null,
      })),
      active: true,
      created_at: iso(),
    };
    for (const recipient of channel.recipients) issueToken(organizationId, channel.id, recipient);
    return { channel, url: null, secret: null };
  }

  function seed(organizationId) {
    const hook = urlChannel("webhook", "Ops webhook", "https://hooks.example.com/anti-reverse/alerts");
    hook.channel.created_at = new Date(now() - 2 * DAY_MS).toISOString();
    const slack = urlChannel(
      "slack",
      "#security-alerts",
      `https://hooks.slack.com/services/T0000/B0000/${randomBytes(18).toString("base64url")}`,
    );
    const mail = emailChannel(organizationId, "On-call email", ["oncall@acme-shop.io", "lead@acme-shop.io"]);
    const [first] = mail.channel.recipients;
    first.status = "confirmed";
    first.confirmed_at = iso();
    for (const [token, entry] of tokens) if (entry.recipientId === first.id) tokens.delete(token);
    channels.set(organizationId, [hook, slack, mail]);
  }

  /** The recipients of a new email channel, or the problem that refuses them. */
  function recipientsOf(body) {
    if (!Array.isArray(body?.recipients)) return invalid("recipients", "Expected an array");
    const addresses = body.recipients.map((value) => (typeof value === "string" ? value.trim().toLowerCase() : ""));
    if (addresses.length < 1 || addresses.length > RECIPIENTS_MAX) {
      return invalid("recipients", `Between 1 and ${RECIPIENTS_MAX} addresses`);
    }
    for (const [index, address] of addresses.entries()) {
      if (address.length > 254 || address.split("@")[0].length > 64 || !ADDRESS_PATTERN.test(address)) {
        return invalid(`recipients.${index}`, "Must be a valid email address.");
      }
      if (addresses.indexOf(address) !== index)
        return invalid(`recipients.${index}`, "Each address may be given once.");
    }
    return addresses;
  }

  function testDelivery(channel) {
    const base = { id: newId("dlv"), channel_id: channel.id, incident_id: null, attempt: 1, at: iso() };
    if (channel.kind === "email") return { ...base, outcome: "delivered", status_code: 250 };
    const host = channel.host;
    const failedNoResponse = host.endsWith(".invalid");
    const failed = failedNoResponse || host === "example.com" || host.endsWith(".example.com");
    return {
      ...base,
      outcome: failed ? "failed" : "delivered",
      status_code: failedNoResponse ? null : failed ? 503 : 200,
    };
  }

  /** Answers a request under `/v1/alert-channels` of an Organization, or null for any other path. */
  function handle(organizationId, method, path, body) {
    const own = channels.get(organizationId) ?? [];
    channels.set(organizationId, own);
    if (path === "/v1/alert-channels") {
      if (method === "GET") {
        return { status: 200, body: { channels: own.map((entry) => entry.channel), smtp_configured: smtpConfigured } };
      }
      if (method !== "POST") return problem(405, "Method Not Allowed");
      const name = validName(body);
      if (body?.kind === "email") {
        if (!name) return invalid("name", "Invalid name");
        const addresses = recipientsOf(body);
        if (!Array.isArray(addresses)) return addresses;
        if (!smtpConfigured) return conflict("smtp-not-configured");
        if (own.length >= CHANNELS_MAX) return problem(409, "Too many alert channels");
        const entry = emailChannel(organizationId, name, addresses);
        own.push(entry);
        return { status: 201, body: { channel: entry.channel } };
      }
      const errors = [];
      if (body?.kind !== "webhook" && body?.kind !== "slack") errors.push({ path: "kind", message: "Invalid option" });
      if (!name) errors.push({ path: "name", message: "Invalid name" });
      let parsed = null;
      try {
        parsed = typeof body?.url === "string" && body.url.length <= 2048 ? new URL(body.url) : null;
      } catch {
        parsed = null;
      }
      // Refused without repeating the URL.
      if (parsed?.protocol !== "https:" || refusedHost(parsed.hostname)) {
        errors.push({ path: "url", message: "This destination is not allowed" });
      }
      if (errors.length > 0) return problem(400, "Bad Request", { errors });
      if (own.length >= CHANNELS_MAX) return problem(409, "Too many alert channels");
      const entry = urlChannel(body.kind, name, body.url);
      own.push(entry);
      return {
        status: 201,
        body: entry.secret ? { channel: entry.channel, signing_secret: entry.secret } : { channel: entry.channel },
      };
    }

    const match = /^\/v1\/alert-channels\/([^/]+)(?:\/(test)|\/recipients\/([^/]+)\/(resend))?$/.exec(path);
    if (!match) return null;
    const [, channelId, test, recipientId, resend] = match;
    const index = own.findIndex((entry) => entry.channel.id === channelId);
    if (index === -1) return problem(404, "Not Found");
    const { channel } = own[index];

    if (!test && !resend) {
      if (method !== "DELETE") return problem(405, "Method Not Allowed");
      own.splice(index, 1);
      for (const [token, entry] of tokens) if (entry.channelId === channelId) tokens.delete(token);
      return { status: 204, body: undefined };
    }
    if (method !== "POST") return problem(405, "Method Not Allowed");
    if (test) {
      if (channel.kind === "email") {
        if (!smtpConfigured) return conflict("smtp-not-configured");
        if (!channel.recipients.some((one) => one.status === "confirmed")) return conflict("no-confirmed-recipients");
      }
      return { status: 200, body: { delivery: testDelivery(channel) } };
    }
    const recipient = channel.kind === "email" ? channel.recipients.find((one) => one.id === recipientId) : undefined;
    if (!recipient) return problem(404, "Not Found");
    if (recipient.status === "confirmed") return conflict("recipient-confirmed");
    if (!smtpConfigured) return conflict("smtp-not-configured");
    if (issueToken(organizationId, channel.id, recipient) === null) {
      const untilMidnight = Math.ceil(((day() + 1) * DAY_MS - now()) / 1000);
      return problem(429, "Too many requests", {}, { "retry-after": String(untilMidnight) });
    }
    return { status: 202, body: { recipient } };
  }

  /** Answers the public `POST /v1/alert-recipients/confirm` (no key). */
  function confirm(body) {
    if (now() - window.start >= MINUTE_MS) window = { start: now(), count: 0 };
    window.count += 1;
    if (window.count > CONFIRM_PER_MINUTE) return problem(429, "Too many requests", {}, { "retry-after": "60" });
    const token = body?.token;
    if (typeof token !== "string" || !TOKEN_PATTERN.test(token)) return invalid("token", "Invalid token");
    const tries = (attempts.get(token) ?? 0) + 1;
    attempts.set(token, tries);
    const entry = tokens.get(token);
    if (tries > ATTEMPTS_PER_TOKEN || !entry || entry.used || entry.expiresAt < now())
      return { status: 200, body: { confirmed: false } };
    entry.used = true;
    const channel = (channels.get(entry.organizationId) ?? []).find(
      (one) => one.channel.id === entry.channelId,
    )?.channel;
    const recipient = channel?.recipients?.find((one) => one.id === entry.recipientId);
    if (!recipient) return { status: 200, body: { confirmed: false } };
    recipient.status = "confirmed";
    recipient.confirmed_at = iso();
    return { status: 200, body: { confirmed: true } };
  }

  /** The latest unused token of a pending recipient of the Organization, or null. For the stub's own link endpoint. */
  function confirmationToken(organizationId, recipientId) {
    for (const [token, entry] of tokens) {
      if (entry.organizationId === organizationId && entry.recipientId === recipientId && !entry.used) return token;
    }
    return null;
  }

  return { seed, handle, confirm, confirmationToken };
}
