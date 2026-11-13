import type { AlertChannel, AlertChannelKind, AlertDelivery, AlertRecipient } from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import type { Queryable } from "../db/db.ts";

// Alert channels, the recipients of email channels (slice 06b), and their delivery records. The URL and the signing
// secret are read only by `findChannelForDelivery` (the notifier); every other function returns the public form,
// `AlertChannel`, which carries the URL's host and last 4 characters and nothing else of it. A recipient's token hash
// never leaves this module.

interface ChannelRow {
  id: string;
  kind: AlertChannelKind;
  name: string;
  /** Null for an email channel. */
  url: string | null;
  active: boolean;
  created_at: Date;
}

interface RecipientRow {
  id: string;
  channel_id: string;
  address: string;
  status: AlertRecipient["status"];
  confirmed_at: Date | null;
  last_sent_at: Date | null;
}

/** A confirmed recipient the notifier mails. */
export interface MailRecipient {
  id: string;
  address: string;
}

/** Everything the notifier needs to deliver. Never leaves the API. */
export type DeliverableChannel =
  | {
      channel: AlertChannel;
      kind: "webhook" | "slack";
      url: string;
      /** Null for a Slack channel. */
      signingSecret: string | null;
    }
  | {
      channel: AlertChannel;
      kind: "email";
      /** The confirmed recipients, in creation order. */
      recipients: MailRecipient[];
    };

/** The host of a URL as the URL parser has it (an IPv6 host keeps its brackets). */
function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

function toRecipient(row: RecipientRow): AlertRecipient {
  return {
    id: row.id,
    address: row.address,
    status: row.status,
    confirmed_at: row.confirmed_at?.toISOString() ?? null,
    last_sent_at: row.last_sent_at?.toISOString() ?? null,
  };
}

/**
 * The public form: the URL is reduced to its host and its last 4 characters here, and only here. An email channel
 * carries its recipients instead.
 */
function toChannel(row: ChannelRow, recipients: RecipientRow[] = []): AlertChannel {
  const common = { id: row.id, name: row.name, active: row.active, created_at: row.created_at.toISOString() };
  if (row.kind === "email") {
    return {
      ...common,
      kind: "email",
      recipients: recipients.filter((recipient) => recipient.channel_id === row.id).map(toRecipient),
    };
  }
  const url = row.url ?? "";
  return { ...common, kind: row.kind, host: hostOf(url), url_last4: url.slice(-4) };
}

const COLUMNS = "id, kind, name, url, active, created_at";
const RECIPIENT_COLUMNS = "id, channel_id, address, status, confirmed_at, last_sent_at";

/** The recipients of the given channels, in creation order. */
async function recipientsOf(q: Queryable, channelIds: string[]): Promise<RecipientRow[]> {
  if (channelIds.length === 0) return [];
  const { rows } = await q.query<RecipientRow>(
    `SELECT ${RECIPIENT_COLUMNS} FROM alert_recipients WHERE channel_id = ANY($1::text[]) ORDER BY seq`,
    [channelIds],
  );
  return rows;
}

async function withRecipients(q: Queryable, rows: ChannelRow[]): Promise<AlertChannel[]> {
  const emailIds = rows.filter((row) => row.kind === "email").map((row) => row.id);
  const recipients = await recipientsOf(q, emailIds);
  return rows.map((row) => toChannel(row, recipients));
}

export async function insertChannel(
  q: Queryable,
  input: {
    id: string;
    organizationId: string;
    kind: AlertChannelKind;
    name: string;
    /** Null for an email channel, whose recipients `insertRecipients` adds in the same transaction. */
    url: string | null;
    signingSecret: string | null;
    createdAt?: Date;
  },
): Promise<AlertChannel> {
  const { rows } = await q.query<ChannelRow>(
    `INSERT INTO alert_channels (id, organization_id, kind, name, url, signing_secret, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7::timestamptz)
     RETURNING ${COLUMNS}`,
    [
      input.id,
      input.organizationId,
      input.kind,
      input.name,
      input.url,
      input.signingSecret,
      (input.createdAt ?? new Date()).toISOString(),
    ],
  );
  const row = rows[0];
  if (row === undefined) throw new Error("The alert channel was not stored.");
  return (await withRecipients(q, [row]))[0] as AlertChannel;
}

/** Adds the recipients of a new email channel, pending, in the order given. Returns them with their ids. */
export async function insertRecipients(
  q: Queryable,
  input: { organizationId: string; channelId: string; addresses: readonly string[] },
): Promise<AlertRecipient[]> {
  const out: AlertRecipient[] = [];
  for (const address of input.addresses) {
    const { rows } = await q.query<RecipientRow>(
      `INSERT INTO alert_recipients (id, organization_id, channel_id, address) VALUES ($1, $2, $3, $4)
       RETURNING ${RECIPIENT_COLUMNS}`,
      [newId("rcp"), input.organizationId, input.channelId, address],
    );
    const row = rows[0];
    if (row === undefined) throw new Error("The recipient was not stored.");
    out.push(toRecipient(row));
  }
  return out;
}

/** One recipient of one channel of the transaction's Organization; null when either does not exist. */
export async function findRecipient(
  q: Queryable,
  channelId: string,
  recipientId: string,
): Promise<AlertRecipient | null> {
  const { rows } = await q.query<RecipientRow>(
    `SELECT ${RECIPIENT_COLUMNS} FROM alert_recipients WHERE channel_id = $1 AND id = $2`,
    [channelId, recipientId],
  );
  return rows[0] === undefined ? null : toRecipient(rows[0]);
}

/**
 * Gives a pending recipient a new confirmation token: its SHA-256 and expiry replace any earlier one, so an earlier
 * link stops working. False when the recipient is gone or no longer pending.
 */
export async function setRecipientToken(
  q: Queryable,
  input: { recipientId: string; tokenHash: string; expiresAt: Date },
): Promise<boolean> {
  const { rows } = await q.query(
    `UPDATE alert_recipients SET token_hash = $2, token_expires_at = $3::timestamptz
     WHERE id = $1 AND status = 'pending' RETURNING id`,
    [input.recipientId, input.tokenHash, input.expiresAt.toISOString()],
  );
  return rows.length === 1;
}

/** Stamps `last_sent_at` on recipients whose mail the SMTP server accepted. */
export async function markRecipientsSent(q: Queryable, recipientIds: readonly string[], at: Date): Promise<void> {
  if (recipientIds.length === 0) return;
  await q.query("UPDATE alert_recipients SET last_sent_at = $2::timestamptz WHERE id = ANY($1::text[])", [
    [...recipientIds],
    at.toISOString(),
  ]);
}

/**
 * Takes one of each daily counter (keyed hashes, see migration 0025), all or none, for the UTC day of `at`. 0 when
 * taken, else the 1-based position of the first full counter. Any scope: the counter table has no tenant.
 */
export async function takeMailCaps(
  q: Queryable,
  input: { counters: readonly { hash: string; max: number }[]; at: Date },
): Promise<number> {
  const { rows } = await q.query<{ full: number }>(
    "SELECT take_mail_caps($1::text[], $2::integer[], $3::date) AS full",
    [input.counters.map((c) => c.hash), input.counters.map((c) => c.max), input.at.toISOString().slice(0, 10)],
  );
  return rows[0]?.full ?? 1;
}

/**
 * Confirms the pending recipient whose current, unexpired token hashes to `tokenHash`, and spends the token. Any
 * scope: the definer function finds the recipient across Organizations and says only whether it confirmed one.
 */
export async function confirmRecipient(q: Queryable, tokenHash: string, at: Date): Promise<boolean> {
  const { rows } = await q.query<{ confirmed: boolean }>(
    "SELECT confirm_alert_recipient($1::text, $2::timestamptz) AS confirmed",
    [tokenHash, at.toISOString()],
  );
  return rows[0]?.confirmed === true;
}

/**
 * Locks the transaction's Organization until commit, so that two channel creations at once cannot both pass
 * the per-Organization limit. False when the Organization is not visible.
 */
export async function lockOrganization(q: Queryable, organizationId: string): Promise<boolean> {
  const { rows } = await q.query("SELECT id FROM organizations WHERE id = $1 FOR NO KEY UPDATE", [organizationId]);
  return rows.length === 1;
}

export async function countChannels(q: Queryable): Promise<number> {
  const { rows } = await q.query<{ n: number }>("SELECT count(*)::int AS n FROM alert_channels");
  return rows[0]?.n ?? 0;
}

/** The channels of the transaction's Organization in creation order. */
export async function listChannels(q: Queryable): Promise<AlertChannel[]> {
  const { rows } = await q.query<ChannelRow>(`SELECT ${COLUMNS} FROM alert_channels ORDER BY seq`);
  return withRecipients(q, rows);
}

export async function findChannel(q: Queryable, id: string): Promise<AlertChannel | null> {
  const { rows } = await q.query<ChannelRow>(`SELECT ${COLUMNS} FROM alert_channels WHERE id = $1`, [id]);
  return rows[0] === undefined ? null : ((await withRecipients(q, rows))[0] ?? null);
}

/** True when the channel existed in the transaction's Organization and is now deleted. */
export async function deleteChannel(q: Queryable, id: string): Promise<boolean> {
  const { rows } = await q.query("DELETE FROM alert_channels WHERE id = $1 RETURNING id", [id]);
  return rows.length === 1;
}

/**
 * One channel with its URL and signing secret, or for an email channel its confirmed recipients, for the notifier
 * only. Null when deleted or inactive.
 */
export async function findChannelForDelivery(q: Queryable, id: string): Promise<DeliverableChannel | null> {
  const { rows } = await q.query<ChannelRow & { signing_secret: string | null }>(
    `SELECT ${COLUMNS}, signing_secret FROM alert_channels WHERE id = $1 AND active`,
    [id],
  );
  const row = rows[0];
  if (row === undefined) return null;
  if (row.kind === "email") {
    const recipients = await recipientsOf(q, [row.id]);
    return {
      channel: toChannel(row, recipients),
      kind: "email",
      recipients: recipients
        .filter((recipient) => recipient.status === "confirmed")
        .map((recipient) => ({ id: recipient.id, address: recipient.address })),
    };
  }
  return { channel: toChannel(row), kind: row.kind, url: row.url ?? "", signingSecret: row.signing_secret };
}

/** The ids of the active channels of the transaction's Organization, in creation order. */
export async function listActiveChannelIds(q: Queryable): Promise<string[]> {
  const { rows } = await q.query<{ id: string }>("SELECT id FROM alert_channels WHERE active ORDER BY seq");
  return rows.map((row) => row.id);
}

/** Records one delivery attempt. It holds no URL, no secret and no response body. */
export async function insertDelivery(
  q: Queryable,
  input: AlertDelivery & { organizationId: string },
): Promise<AlertDelivery> {
  const { rows } = await q.query<Omit<AlertDelivery, "at"> & { at: Date }>(
    `INSERT INTO alert_deliveries (id, organization_id, channel_id, incident_id, attempt, outcome, status_code, at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8::timestamptz)
     RETURNING id, channel_id, incident_id, attempt, outcome, status_code, at`,
    [
      input.id,
      input.organizationId,
      input.channel_id,
      input.incident_id,
      input.attempt,
      input.outcome,
      input.status_code,
      input.at,
    ],
  );
  const row = rows[0];
  if (row === undefined) throw new Error("The delivery was not stored.");
  return { ...row, at: row.at.toISOString() };
}
