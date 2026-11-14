import type { Environment, ShieldEvent, StoredEvent } from "@antireverse/protocol";
import type { Queryable } from "../db/db.ts";
import type { ReplayEvent } from "../simulate/replay.ts";
import { addRequests } from "./usage.ts";

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
 * The newly stored Events are metered as protected requests (slice 17a) in the same transaction, from the insert's
 * RETURNING count: a batch sent again adds nothing. Tenant transaction (the origin's Organization).
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
  await addRequests(q, origin, rows.length);
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

interface ReplayRow {
  ts: Date;
  method: string;
  route: string;
  status: number;
  latency_ms: number | null;
  instance_id: string | null;
  action: string;
  mode: string;
  ip_hash: string | null;
  ip_prefix: string | null;
  signature_status: string | null;
  signature_body: string | null;
  attestation_status: string | null;
}

/**
 * The read of `listReplayEvents`: Organization, App, Environment, from, to, limit. Served in order by the index
 * `events_replay` (migration 0020), which a test checks.
 */
export const REPLAY_EVENTS_SQL = `SELECT ts,
            payload->'request'->>'method' AS method,
            payload->'request'->>'route' AS route,
            (payload->'request'->>'status')::int AS status,
            (payload->'request'->>'latency_ms')::float8 AS latency_ms,
            payload->>'instance_id' AS instance_id,
            payload->'decision'->>'action' AS action,
            payload->'decision'->>'mode' AS mode,
            payload->'actor'->>'ip_hash' AS ip_hash,
            payload->'actor'->>'ip_prefix' AS ip_prefix,
            payload->'signature'->>'status' AS signature_status,
            payload->'signature'->>'body' AS signature_body,
            payload->'attestation'->>'status' AS attestation_status
     FROM events
     WHERE organization_id = $1 AND app_id = $2 AND environment = $3 AND type = 'request.decision'
       AND ts >= $4 AND ts <= $5
     ORDER BY ts DESC, event_id DESC
     LIMIT $6`;
/** `REPLAY_EVENTS_SQL` with `to` left out: the seed of a simulation ends where its period begins (plan 11 A11). */
export const REPLAY_EVENTS_BEFORE_SQL = REPLAY_EVENTS_SQL.replace("AND ts <= $5", "AND ts < $5");

/**
 * What a Policy simulation replays (slice 11): the `request.decision` Events of one App and Environment of the
 * transaction's Organization with `ts` from `from` to `to` — before `to` with `before` — newest first by `ts` (then
 * by identifier), at most `limit`. Only the members the replay reads leave the database. Read only.
 */
export async function listReplayEvents(
  q: Queryable,
  filter: {
    organizationId: string;
    appId: string;
    environment: Environment;
    from: Date;
    to: Date;
    limit: number;
    /** `to` itself left out: whatever fraction of a millisecond an Event carries, it is in one read or the other. */
    before?: boolean;
  },
): Promise<ReplayEvent[]> {
  const sql = filter.before === true ? REPLAY_EVENTS_BEFORE_SQL : REPLAY_EVENTS_SQL;
  const { rows } = await q.query<ReplayRow>(sql, [
    filter.organizationId,
    filter.appId,
    filter.environment,
    filter.from.toISOString(),
    filter.to.toISOString(),
    filter.limit,
  ]);
  return rows.map((row) => ({
    ts: row.ts.toISOString(),
    // The Shield process and the response time (plan 11 amendment A9); absent when not recorded.
    ...(row.instance_id === null ? {} : { instance_id: row.instance_id }),
    request: {
      method: row.method,
      route: row.route,
      status: row.status,
      ...(row.latency_ms === null ? {} : { latency_ms: row.latency_ms }),
    },
    decision: { action: row.action, mode: row.mode },
    actor: { ip_hash: row.ip_hash, ip_prefix: row.ip_prefix },
    signature: row.signature_status === null ? null : { status: row.signature_status, body: row.signature_body },
    attestation: row.attestation_status === null ? null : { status: row.attestation_status },
  }));
}
