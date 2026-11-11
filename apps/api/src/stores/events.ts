import type { Environment, ShieldEvent, StoredEvent } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";

/** Where a batch comes from and when it arrived. Every member is taken from the Shield key or the clock. */
export interface EventOrigin {
  organizationId: string;
  appId: string;
  environment: Environment;
  receivedAt: Date;
}

/**
 * Stores a batch in one statement. An Event whose `(organization, event_id)` is already stored, or that
 * repeats inside the batch, is skipped. Returns the identifiers that were newly stored.
 * `events` must be validated Events: each one is stored whole as the payload, and nothing else is.
 */
export async function insertEvents(q: Queryable, origin: EventOrigin, events: ShieldEvent[]): Promise<Set<string>> {
  const records = events.map((event) => ({ event_id: event.event_id, ts: event.ts, type: event.type, payload: event }));
  const { rows } = await q.query<{ event_id: string }>(
    `INSERT INTO events (organization_id, event_id, app_id, environment, ts, received_at, type, payload)
     SELECT $1::text, r.event_id, $2::text, $3::text, r.ts, $4::timestamptz, r.type, r.payload
     FROM jsonb_to_recordset($5::jsonb) AS r(event_id uuid, ts timestamptz, type text, payload jsonb)
     ON CONFLICT (organization_id, event_id) DO NOTHING
     RETURNING event_id`,
    [origin.organizationId, origin.appId, origin.environment, origin.receivedAt.toISOString(), JSON.stringify(records)],
  );
  return new Set(rows.map((row) => row.event_id));
}

interface EventRow {
  organization_id: string;
  app_id: string;
  environment: Environment;
  received_at: Date;
  payload: ShieldEvent;
}

/** The newest Events of one App of the transaction's Organization: by time of receipt, then by identifier. */
export async function listEvents(
  q: Queryable,
  filter: { organizationId: string; appId: string; limit: number },
): Promise<StoredEvent[]> {
  const { rows } = await q.query<EventRow>(
    `SELECT organization_id, app_id, environment, received_at, payload
     FROM events
     WHERE organization_id = $1 AND app_id = $2
     ORDER BY received_at DESC, event_id DESC
     LIMIT $3`,
    [filter.organizationId, filter.appId, filter.limit],
  );
  return rows.map((row) => ({
    ...row.payload,
    organization_id: row.organization_id,
    app_id: row.app_id,
    environment: row.environment,
    received_at: row.received_at.toISOString(),
  }));
}
