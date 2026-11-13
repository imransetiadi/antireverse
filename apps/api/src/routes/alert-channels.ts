import { createHash, randomBytes } from "node:crypto";
import {
  ALERT_EMAIL_LIMITS,
  type AlertChannel,
  type AlertRecipient,
  ConfirmAlertRecipientRequestSchema,
  type ConfirmAlertRecipientResponse,
  CreateAlertChannelRequestSchema,
  type CreateAlertChannelResponse,
  ID_PATTERNS,
  INCIDENT_LIMITS,
  type ListAlertChannelsResponse,
  type ResendConfirmationResponse,
  type TestAlertChannelResponse,
} from "@antireverse/protocol";
import { generateSigningSecret, newId } from "@antireverse/protocol/server";
import { Hono } from "hono";
import { createWindowLimiter } from "../attestation/limiter.ts";
import { type AppEnv, requireKey } from "../auth/authenticate.ts";
import { limitBody } from "../body.ts";
import type { Db, Queryable } from "../db/db.ts";
import type { AddressHasher } from "../mail/address-key.ts";
import { capAddress } from "../mail/caps.ts";
import type { ConfirmationMail, Notifier } from "../notify/notifier.ts";
import { checkDestination, LOOKUP_TIMEOUT_MS, type Resolve, resolveWithin } from "../notify/ssrf.ts";
import { problem } from "../problem.ts";
import {
  confirmRecipient,
  countChannels,
  deleteChannel,
  findChannel,
  findRecipient,
  insertChannel,
  insertRecipients,
  listChannels,
  lockOrganization,
  setRecipientToken,
  takeMailCaps,
} from "../stores/alert-channels.ts";
import { validateJson } from "../validate.ts";

/**
 * Token hashes whose confirmation attempts are counted at once. Beyond it the oldest is forgotten: a 256-bit token
 * cannot be guessed, so the per-token count guards against replaying one link, not against search.
 */
export const CONFIRM_TOKENS_TRACKED = 100_000;

/** SHA-256 hex of a value: how tokens are kept. */
const sha256 = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");

/** Seconds until the next UTC midnight, when an address's confirmation mails start again. At least 1. */
function untilNextUtcDay(at: Date): number {
  const next = Date.UTC(at.getUTCFullYear(), at.getUTCMonth(), at.getUTCDate() + 1);
  return Math.max(1, Math.ceil((next - at.getTime()) / 1_000));
}

export function alertChannelRoutes(deps: {
  db: Db;
  notifier: Notifier;
  resolve: Resolve;
  allowPrivateAlertUrls: boolean;
  /** Whether the service has SMTP settings (slice 06b): without them, no email channel can be created or tested. */
  smtpConfigured: boolean;
  /** Keys the daily counters of confirmation mails and channel creations (HMAC under the server secret). */
  addressHasher: AddressHasher;
  /** Confirmation mails of the whole service per UTC day. Default `ALERT_EMAIL_LIMITS.confirmationMailsPerDay`. */
  confirmationsPerDay?: number;
  /** Bound of the host lookup at creation. Default 5,000 ms. */
  alertLookupTimeoutMs?: number;
  now?: () => Date;
}): Hono<AppEnv> {
  const { db, notifier, resolve, smtpConfigured, addressHasher } = deps;
  const now = deps.now ?? (() => new Date());
  const routes = new Hono<AppEnv>();
  const admin = requireKey(db, "admin");
  // The public confirmation endpoint: one global minute window (the Console calls it from its server, so every
  // caller shares one address), and at most `confirmAttemptsPerToken` attempts per token hash.
  const confirmGlobal = createWindowLimiter({
    limit: ALERT_EMAIL_LIMITS.confirmPerMinute,
    windowMs: 60_000,
    maxKeys: 1,
  });
  const attemptsByToken = new Map<string, number>();
  /** Counts one attempt of the token; false once its attempts are spent. */
  function takeAttempt(tokenHash: string): boolean {
    const used = attemptsByToken.get(tokenHash) ?? 0;
    attemptsByToken.delete(tokenHash);
    attemptsByToken.set(tokenHash, used + 1);
    while (attemptsByToken.size > CONFIRM_TOKENS_TRACKED) {
      const oldest = attemptsByToken.keys().next();
      if (oldest.done) break;
      attemptsByToken.delete(oldest.value);
    }
    return used < ALERT_EMAIL_LIMITS.confirmAttemptsPerToken;
  }

  const confirmationsPerDay = deps.confirmationsPerDay ?? ALERT_EMAIL_LIMITS.confirmationMailsPerDay;

  /**
   * Takes a confirmation mail of the day and, when one was left, gives the recipient a new token (stored as its
   * SHA-256, valid 72 hours). Two groups of daily counters (review F1, F6), keyed with the server secret:
   * - the ones a tenant is told about (`refused`, a 429 on resend): per Organization and address, and per Organization;
   *   they count only this Organization's own use, so the answer reveals nothing of other Organizations;
   * - the silent ones (`silent`: no mail, and the answer is as if sent): per address for all Organizations together,
   *   the address normalised (`capAddress`), and the whole service's mails of the day.
   * The first group is charged even when the second refuses, so that the tenant's count runs the same either way.
   */
  async function issueToken(
    q: Queryable,
    organizationId: string,
    recipient: Pick<AlertRecipient, "id" | "address">,
  ): Promise<{ kind: "sent"; mail: ConfirmationMail } | { kind: "refused" } | { kind: "silent" }> {
    const at = now();
    const address = capAddress(recipient.address);
    const visible = await takeMailCaps(q, {
      at,
      counters: [
        {
          hash: addressHasher.hash(`org:${organizationId}:${address}`),
          max: ALERT_EMAIL_LIMITS.confirmationMailsPerAddressPerDay,
        },
        {
          hash: addressHasher.hash(`org-mails:${organizationId}`),
          max: ALERT_EMAIL_LIMITS.confirmationMailsPerOrganizationPerDay,
        },
      ],
    });
    if (visible !== 0) return { kind: "refused" };
    const silent = await takeMailCaps(q, {
      at,
      counters: [
        { hash: addressHasher.hash("service-mails"), max: confirmationsPerDay },
        { hash: addressHasher.hash(address), max: ALERT_EMAIL_LIMITS.confirmationMailsPerAddressPerDay },
      ],
    });
    if (silent !== 0) return { kind: "silent" };
    const token = randomBytes(32).toString("base64url");
    await setRecipientToken(q, {
      recipientId: recipient.id,
      tokenHash: sha256(token),
      expiresAt: new Date(at.getTime() + ALERT_EMAIL_LIMITS.confirmationTtlS * 1_000),
    });
    return { kind: "sent", mail: { recipientId: recipient.id, address: recipient.address, token } };
  }

  routes.get("/v1/alert-channels", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const channels = await db.tx({ organizationId }, (q) => listChannels(q));
    return c.json({ channels, smtp_configured: smtpConfigured } satisfies ListAlertChannelsResponse);
  });

  // The URL and a webhook's signing secret go in here; only the secret comes back, in this response only. An email
  // channel's recipients each get a confirmation mail (after the commit), within the daily limit per address.
  routes.post("/v1/alert-channels", admin, limitBody(), validateJson(CreateAlertChannelRequestSchema), async (c) => {
    const { organizationId } = c.var.principal;
    const request = c.req.valid("json");

    if (request.kind === "email") {
      if (!smtpConfigured) return problem(c, "conflict", undefined, "smtp-not-configured");
      const created = await db.tx<
        { channel: AlertChannel; mails: ConfirmationMail[] } | "conflict" | "too-many-email-channels"
      >({ organizationId }, async (q) => {
        await lockOrganization(q, organizationId);
        if ((await countChannels(q)) >= INCIDENT_LIMITS.channelsMax) return "conflict";
        // At most 20 email channels a day, deletions notwithstanding: each brings confirmation mails.
        const createdToday = await takeMailCaps(q, {
          at: now(),
          counters: [
            {
              hash: addressHasher.hash(`org-email-channels:${organizationId}`),
              max: ALERT_EMAIL_LIMITS.emailChannelsPerOrganizationPerDay,
            },
          ],
        });
        if (createdToday !== 0) return "too-many-email-channels";
        const id = newId("chn");
        await insertChannel(q, {
          id,
          organizationId,
          kind: "email",
          name: request.name,
          url: null,
          signingSecret: null,
          createdAt: now(),
        });
        const recipients = await insertRecipients(q, {
          organizationId,
          channelId: id,
          addresses: request.recipients,
        });
        const mails: ConfirmationMail[] = [];
        for (const recipient of recipients) {
          // A recipient over any cap stays pending without a link; a resend later may send one.
          const issued = await issueToken(q, organizationId, recipient);
          if (issued.kind === "sent") mails.push(issued.mail);
        }
        const channel = await findChannel(q, id);
        return channel === null ? "conflict" : { channel, mails };
      });
      if (created === "conflict") return problem(c, "conflict");
      if (created === "too-many-email-channels") {
        c.header("Retry-After", String(untilNextUtcDay(now())));
        return problem(c, "too-many-email-channels");
      }
      notifier.confirmations(organizationId, created.mails);
      return c.json({ channel: created.channel } satisfies CreateAlertChannelResponse, 201);
    }

    const { kind, name, url } = request;
    // Fast feedback: the same check runs again before every delivery (DNS can change). The message is fixed
    // text: it never echoes the URL, which may itself be a secret.
    // The lookup is bounded: a host that does not answer in time is "could not be resolved".
    const lookupBound = AbortSignal.timeout(deps.alertLookupTimeoutMs ?? LOOKUP_TIMEOUT_MS);
    const destination = await checkDestination(url, {
      resolve: resolveWithin(resolve, lookupBound),
      allowPrivate: deps.allowPrivateAlertUrls,
    });
    if (!destination.ok) return problem(c, "validation", [{ path: "url", message: destination.reason }]);

    const signingSecret = kind === "webhook" ? generateSigningSecret() : null;
    const channel = await db.tx<AlertChannel | null>({ organizationId }, async (q) => {
      // Serialises creations per Organization, so that the limit holds under concurrent requests.
      await lockOrganization(q, organizationId);
      if ((await countChannels(q)) >= INCIDENT_LIMITS.channelsMax) return null;
      return insertChannel(q, { id: newId("chn"), organizationId, kind, name, url, signingSecret, createdAt: now() });
    });
    if (channel === null) return problem(c, "conflict");
    const body: CreateAlertChannelResponse =
      signingSecret === null ? { channel } : { channel, signing_secret: signingSecret };
    return c.json(body, 201);
  });

  routes.delete("/v1/alert-channels/:channelId", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const channelId = c.req.param("channelId");
    const deleted = ID_PATTERNS.chn.test(channelId)
      ? await db.tx({ organizationId }, (q) => deleteChannel(q, channelId))
      : false;
    if (!deleted) return problem(c, "not-found");
    return c.body(null, 204);
  });

  // Sends one test alert, synchronously, one attempt. Needs no body. An email channel's goes to its confirmed
  // recipients only, so it needs SMTP settings and at least one of them.
  routes.post("/v1/alert-channels/:channelId/test", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const channelId = c.req.param("channelId");
    const channel = ID_PATTERNS.chn.test(channelId)
      ? await db.tx({ organizationId }, (q) => findChannel(q, channelId))
      : null;
    if (channel === null) return problem(c, "not-found");
    if (channel.kind === "email") {
      if (!smtpConfigured) return problem(c, "conflict", undefined, "smtp-not-configured");
      if (!channel.recipients.some((recipient) => recipient.status === "confirmed")) {
        return problem(c, "conflict", undefined, "no-confirmed-recipients");
      }
    }
    const delivery = await notifier.test(channelId, organizationId);
    // Deleted in the meantime.
    if (delivery === null) return problem(c, "not-found");
    return c.json({ delivery } satisfies TestAlertChannelResponse);
  });

  // A new confirmation mail for a pending recipient: a new token replaces the old one, and it counts toward the
  // address's mails of the day. By recipient id, so that no address travels in a URL.
  routes.post("/v1/alert-channels/:channelId/recipients/:recipientId/resend", admin, async (c) => {
    const { organizationId } = c.var.principal;
    const channelId = c.req.param("channelId");
    const recipientId = c.req.param("recipientId");
    if (!ID_PATTERNS.chn.test(channelId) || !ID_PATTERNS.rcp.test(recipientId)) return problem(c, "not-found");
    const result = await db.tx({ organizationId }, async (q) => {
      const recipient = await findRecipient(q, channelId, recipientId);
      if (recipient === null) return { kind: "not-found" as const };
      if (recipient.status === "confirmed") return { kind: "confirmed" as const };
      if (!smtpConfigured) return { kind: "no-smtp" as const };
      const issued = await issueToken(q, organizationId, recipient);
      if (issued.kind === "refused") return { kind: "limited" as const };
      // Silent: answered as sent, nothing goes out, the recipient stays pending with its earlier link (review F6).
      return { kind: "sent" as const, recipient, mail: issued.kind === "sent" ? issued.mail : null };
    });
    switch (result.kind) {
      case "not-found":
        return problem(c, "not-found");
      case "confirmed":
        return problem(c, "conflict", undefined, "recipient-confirmed");
      case "no-smtp":
        return problem(c, "conflict", undefined, "smtp-not-configured");
      case "limited":
        c.header("Retry-After", String(untilNextUtcDay(now())));
        return problem(c, "too-many-confirmations");
      case "sent":
        if (result.mail !== null) notifier.confirmations(organizationId, [result.mail]);
        return c.json({ recipient: result.recipient } satisfies ResendConfirmationResponse, 202);
    }
  });

  // Public: no key. The link of a confirmation mail leads to the Console, which posts the token here. At most 600
  // requests a minute in all, and 5 attempts per token. Unknown, used, expired and spent tokens get the same 200
  // answer: nothing tells them apart, and nothing about an address, a channel or an Organization comes back. The
  // token is never logged.
  routes.post(
    "/v1/alert-recipients/confirm",
    // The body is checked first (review F3): a malformed request costs nothing of the global minute.
    limitBody(),
    validateJson(ConfirmAlertRecipientRequestSchema),
    async (c) => {
      const { allowed, retryAfterS } = confirmGlobal.take("all", now().getTime());
      if (!allowed) {
        c.header("Retry-After", String(retryAfterS));
        return problem(c, "too-many-confirm-requests");
      }
      const tokenHash = sha256(c.req.valid("json").token);
      // Counted before the lookup, whether or not any recipient holds the token.
      const confirmed = takeAttempt(tokenHash) && (await db.tx("none", (q) => confirmRecipient(q, tokenHash, now())));
      return c.json({ confirmed } satisfies ConfirmAlertRecipientResponse, 200);
    },
  );

  return routes;
}
