import type { AlertChannel, AlertChannelKind, AlertDelivery } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

// Alert channels and their delivery records. The URL and the signing secret are read only by
// `findChannelForDelivery` (the notifier); every other function returns the public form, `AlertChannel`,
// which carries the URL's host and last 4 characters and nothing else of it.

interface ChannelRow {
  id: string;
  kind: AlertChannelKind;
  name: string;
  url: string;
  active: boolean;
  created_at: Date;
}

/** Everything the notifier needs to deliver. Never leaves the API. */
export interface DeliverableChannel {
  channel: AlertChannel;
  url: string;
  /** Null for a Slack channel. */
  signingSecret: string | null;
}

/** The host of a URL as the URL parser has it (an IPv6 host keeps its brackets). */
function hostOf(url: string): string {
  try {
    return new URL(url).hostname;
  } catch {
    return "";
  }
}

/** The public form: the URL is reduced to its host and its last 4 characters here, and only here. */
function toChannel(row: ChannelRow): AlertChannel {
  return {
    id: row.id,
    kind: row.kind,
    name: row.name,
    host: hostOf(row.url),
    url_last4: row.url.slice(-4),
    active: row.active,
    created_at: row.created_at.toISOString(),
  };
}

const COLUMNS = "id, kind, name, url, active, created_at";

export async function insertChannel(
  q: Queryable,
  input: {
    id: string;
    organizationId: string;
    kind: AlertChannelKind;
    name: string;
    url: string;
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
  return toChannel(row);
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
  return rows.map(toChannel);
}

export async function findChannel(q: Queryable, id: string): Promise<AlertChannel | null> {
  const { rows } = await q.query<ChannelRow>(`SELECT ${COLUMNS} FROM alert_channels WHERE id = $1`, [id]);
  return rows[0] === undefined ? null : toChannel(rows[0]);
}

/** True when the channel existed in the transaction's Organization and is now deleted. */
export async function deleteChannel(q: Queryable, id: string): Promise<boolean> {
  const { rows } = await q.query("DELETE FROM alert_channels WHERE id = $1 RETURNING id", [id]);
  return rows.length === 1;
}

/** One channel with its URL and signing secret, for the notifier only. Null when deleted or inactive. */
export async function findChannelForDelivery(q: Queryable, id: string): Promise<DeliverableChannel | null> {
  const { rows } = await q.query<ChannelRow & { signing_secret: string | null }>(
    `SELECT ${COLUMNS}, signing_secret FROM alert_channels WHERE id = $1 AND active`,
    [id],
  );
  const row = rows[0];
  return row === undefined ? null : { channel: toChannel(row), url: row.url, signingSecret: row.signing_secret };
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
