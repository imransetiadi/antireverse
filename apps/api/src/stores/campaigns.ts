import {
  CAMPAIGN_LIMITS,
  CAMPAIGN_STAND_IN_NOTICE,
  type Campaign,
  type CampaignChecks,
  type CampaignEndReason,
  type CampaignEngine,
  type CampaignEvidence,
  type CampaignFinding,
  type CampaignFindingState,
  type CampaignIntensity,
  type CampaignRequest,
  type CampaignSeverity,
  type CampaignStatus,
  type ProveOperatorState,
  statusOfEndReason,
} from "@antireverse/protocol";
import type { GateControl, GateRecord } from "../campaign/gate.ts";
import type { Queryable } from "../db/db.ts";

// Pentest Campaigns of the transaction's Organization (slice 15a, migration 0039), their request log and Findings,
// and the operator's switch. The counters of a Campaign are read from its request log (at most 200 rows), so they are
// current while it runs.

interface CampaignRow {
  id: string;
  target_id: string;
  host: string;
  roe_id: string;
  roe_sha256: string;
  intensity: CampaignIntensity;
  engine: CampaignEngine;
  status: CampaignStatus;
  end_reason: CampaignEndReason | null;
  created_by: string;
  pinned_address: string | null;
  checks_ran: number | null;
  checks_reported: number | null;
  checks_skipped: number | null;
  checks_inconclusive: number | null;
  findings_dropped: number;
  stop_requested_at: Date | null;
  stop_requested_by: string | null;
  stop_reason: string | null;
  created_at: Date;
  started_at: Date | null;
  finished_at: Date | null;
  requests_sent: number;
  requests_refused: number;
  response_bytes: string | number;
}

const COLUMNS = `c.id, c.target_id, c.host, c.roe_id, c.roe_sha256, c.intensity, c.engine, c.status, c.end_reason,
  c.created_by, c.pinned_address, c.checks_ran, c.checks_reported, c.checks_skipped, c.checks_inconclusive,
  c.findings_dropped, c.stop_requested_at,
  c.stop_requested_by, c.stop_reason, c.created_at, c.started_at, c.finished_at,
  (SELECT count(*)::int FROM campaign_requests r WHERE r.campaign_id = c.id AND r.outcome IN ('sending', 'sent'))
    AS requests_sent,
  (SELECT count(*)::int FROM campaign_requests r WHERE r.campaign_id = c.id AND r.outcome = 'refused')
    AS requests_refused,
  (SELECT COALESCE(sum(r.bytes), 0) FROM campaign_requests r WHERE r.campaign_id = c.id) AS response_bytes`;

const iso = (value: Date | null): string | null => (value === null ? null : value.toISOString());

function toCampaign(row: CampaignRow): Campaign {
  return {
    id: row.id,
    target_id: row.target_id,
    host: row.host,
    roe_id: row.roe_id,
    roe_sha256: row.roe_sha256,
    intensity: row.intensity,
    engine: row.engine,
    notice: CAMPAIGN_STAND_IN_NOTICE,
    status: row.status,
    end_reason: row.end_reason,
    staging_declared: true,
    created_by: row.created_by,
    requests_sent: row.requests_sent,
    requests_refused: row.requests_refused,
    response_bytes: Number(row.response_bytes),
    checks:
      row.checks_ran === null
        ? null
        : {
            ran: row.checks_ran,
            reported: row.checks_reported ?? 0,
            inconclusive: row.checks_inconclusive ?? 0,
            skipped: row.checks_skipped ?? 0,
          },
    findings_dropped: row.findings_dropped,
    stop:
      row.stop_requested_at === null || row.stop_requested_by === null || row.stop_reason === null
        ? null
        : {
            requested_at: row.stop_requested_at.toISOString(),
            requested_by: row.stop_requested_by,
            reason: row.stop_reason,
          },
    created_at: row.created_at.toISOString(),
    started_at: iso(row.started_at),
    finished_at: iso(row.finished_at),
  };
}

export interface NewCampaign {
  organizationId: string;
  id: string;
  targetId: string;
  host: string;
  roeId: string;
  roeSha256: string;
  intensity: CampaignIntensity;
  engine: CampaignEngine;
  createdBy: string;
  createdAt: Date;
}

/** Stores a queued Campaign. A second queued or running one of the Organization raises a unique violation (23505). */
export async function insertCampaign(q: Queryable, input: NewCampaign): Promise<Campaign> {
  await q.query(
    `INSERT INTO campaigns (organization_id, id, target_id, host, roe_id, roe_sha256, intensity, engine, status,
       staging_declared, created_by, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb, 'queued', true, $9, $10::timestamptz)`,
    [
      input.organizationId,
      input.id,
      input.targetId,
      input.host,
      input.roeId,
      input.roeSha256,
      input.intensity,
      JSON.stringify(input.engine),
      input.createdBy,
      input.createdAt.toISOString(),
    ],
  );
  const stored = await findCampaign(q, input.id);
  if (stored === null) throw new Error("The Campaign was not stored.");
  return stored;
}

export async function findCampaign(q: Queryable, id: string): Promise<Campaign | null> {
  const { rows } = await q.query<CampaignRow>(`SELECT ${COLUMNS} FROM campaigns c WHERE c.id = $1`, [id]);
  return rows[0] === undefined ? null : toCampaign(rows[0]);
}

/** The newest Campaigns of the Organization. */
export async function listCampaigns(q: Queryable, limit: number): Promise<Campaign[]> {
  const { rows } = await q.query<CampaignRow>(
    `SELECT ${COLUMNS} FROM campaigns c ORDER BY c.created_at DESC, c.id DESC LIMIT $1`,
    [limit],
  );
  return rows.map(toCampaign);
}

/** Whether the Organization has a queued or running Campaign. */
export async function hasActiveCampaign(q: Queryable): Promise<boolean> {
  const { rows } = await q.query("SELECT 1 FROM campaigns WHERE status IN ('queued', 'running') LIMIT 1");
  return rows.length > 0;
}

/**
 * Campaigns created in the 24 hours before `at`, by the Organization and for one Target, and when the oldest of each
 * leaves the window (for Retry-After).
 */
export async function createdInLastDay(
  q: Queryable,
  targetId: string,
  at: Date,
): Promise<{ organization: number; target: number; oldestOrganization: Date | null; oldestTarget: Date | null }> {
  const since = new Date(at.getTime() - 86_400_000).toISOString();
  const { rows } = await q.query<{ n: number; t: number; oldest: Date | null; oldest_target: Date | null }>(
    `SELECT count(*)::int AS n, (count(*) FILTER (WHERE target_id = $2))::int AS t, min(created_at) AS oldest,
       min(created_at) FILTER (WHERE target_id = $2) AS oldest_target
     FROM campaigns WHERE created_at > $1::timestamptz`,
    [since, targetId],
  );
  const row = rows[0];
  return {
    organization: row?.n ?? 0,
    target: row?.t ?? 0,
    oldestOrganization: row?.oldest ?? null,
    oldestTarget: row?.oldest_target ?? null,
  };
}

/**
 * Marks a queued Campaign running, with the address resolved and pinned for the whole run. False when it is no longer
 * queued (stopped meanwhile).
 */
export async function claimCampaign(q: Queryable, id: string, at: Date, address: string): Promise<boolean> {
  const { rows } = await q.query(
    `UPDATE campaigns SET status = 'running', started_at = GREATEST($2::timestamptz, created_at), pinned_address = $3
     WHERE id = $1 AND status = 'queued' RETURNING id`,
    [id, at.toISOString(), address],
  );
  return rows.length === 1;
}

/**
 * Ends a queued or running Campaign: its status is the end reason's (`statusOfEndReason`; `started` says whether it
 * passed its start checks). False when it had already ended: an end is written once.
 */
export async function endCampaign(
  q: Queryable,
  id: string,
  end: {
    reason: CampaignEndReason;
    started: boolean;
    checks: CampaignChecks | null;
    at: Date;
    findingsDropped?: number;
  },
): Promise<boolean> {
  const { rows } = await q.query(
    `UPDATE campaigns SET status = $2, end_reason = $3, checks_ran = $4, checks_reported = $5, checks_skipped = $6,
       checks_inconclusive = $9, findings_dropped = $8, finished_at = GREATEST($7::timestamptz, COALESCE(started_at, created_at))
     WHERE id = $1 AND status IN ('queued', 'running') RETURNING id`,
    [
      id,
      statusOfEndReason(end.reason, end.started),
      end.reason,
      end.checks?.ran ?? null,
      end.checks?.reported ?? null,
      end.checks?.skipped ?? null,
      end.at.toISOString(),
      end.findingsDropped ?? 0,
      end.checks?.inconclusive ?? null,
    ],
  );
  return rows.length === 1;
}

/** Records the owner's stop request on a queued or running Campaign. False when it had ended or was already asked. */
export async function requestStop(
  q: Queryable,
  id: string,
  input: { keyId: string; reason: string; at: Date },
): Promise<boolean> {
  const { rows } = await q.query(
    `UPDATE campaigns SET stop_requested_at = $2::timestamptz, stop_requested_by = $3, stop_reason = $4
     WHERE id = $1 AND status IN ('queued', 'running') AND stop_requested_at IS NULL RETURNING id`,
    [id, input.at.toISOString(), input.keyId, input.reason],
  );
  return rows.length === 1;
}

/** What the gate reads before every request (`campaign_control`). Without an answer everything counts as stopped. */
export async function campaignControl(q: Queryable, id: string): Promise<GateControl> {
  const { rows } = await q.query<{
    killed: boolean;
    suspended: boolean;
    stop_requested: boolean;
    deletion_pending: boolean;
  }>("SELECT killed, suspended, stop_requested, deletion_pending FROM campaign_control($1)", [id]);
  const row = rows[0];
  if (row === undefined) return { killed: true, suspended: true, stopRequested: true, deletionPending: true };
  return {
    killed: row.killed,
    suspended: row.suspended,
    stopRequested: row.stop_requested,
    deletionPending: row.deletion_pending,
  };
}

/** One row of the request log. */
export async function insertCampaignRequest(
  q: Queryable,
  organizationId: string,
  id: string,
  entry: GateRecord,
  at: Date,
): Promise<void> {
  await q.query(
    `INSERT INTO campaign_requests (organization_id, campaign_id, seq, at, method, target, outcome, reason, status,
       failure, bytes, ms)
     VALUES ($1, $2, $3, $4::timestamptz, $5, $6, $7, $8, $9, $10, $11, $12)`,
    [
      organizationId,
      id,
      entry.seq,
      at.toISOString(),
      entry.method,
      entry.target,
      entry.outcome,
      entry.reason,
      entry.status,
      entry.failure,
      entry.bytes,
      Math.min(Math.round(entry.ms), 2_000_000_000),
    ],
  );
}

/**
 * Settles a row written as `sending` with its request's result. False when there is no such row still `sending` (the
 * database refuses to settle a row twice).
 */
export async function settleCampaignRequest(q: Queryable, id: string, entry: GateRecord): Promise<boolean> {
  const { rows } = await q.query(
    `UPDATE campaign_requests SET outcome = $7, status = $3, failure = $4, bytes = $5, ms = $6
     WHERE campaign_id = $1 AND seq = $2 AND outcome = 'sending' RETURNING seq`,
    [
      id,
      entry.seq,
      entry.status,
      entry.failure,
      Math.min(entry.bytes, 1_048_576),
      Math.min(Math.round(entry.ms), 2_000_000_000),
      entry.outcome === "not_sent" ? "not_sent" : "sent",
    ],
  );
  return rows.length === 1;
}

/** The number of the last row of a Campaign's request log; 0 when it has none. */
export async function lastRequestSeq(q: Queryable, id: string): Promise<number> {
  const { rows } = await q.query<{ seq: number }>(
    "SELECT COALESCE(max(seq), 0)::int AS seq FROM campaign_requests WHERE campaign_id = $1",
    [id],
  );
  return rows[0]?.seq ?? 0;
}

interface RequestRow {
  seq: number;
  at: Date;
  method: string | null;
  target: string | null;
  outcome: CampaignRequest["outcome"];
  reason: CampaignRequest["reason"];
  status: number | null;
  failure: CampaignRequest["failure"];
  bytes: number;
  ms: number;
}

export async function listCampaignRequests(q: Queryable, id: string): Promise<CampaignRequest[]> {
  const { rows } = await q.query<RequestRow>(
    `SELECT seq, at, method, target, outcome, reason, status, failure, bytes, ms FROM campaign_requests
     WHERE campaign_id = $1 ORDER BY seq LIMIT $2`,
    [id, CAMPAIGN_LIMITS.storedRequestsMax],
  );
  return rows.map((row) => ({ ...row, at: row.at.toISOString() }));
}

export interface ReportedFinding {
  checkId: string;
  path: string;
  title: string;
  severity: CampaignSeverity;
  evidence: CampaignEvidence;
  at: Date;
}

/**
 * Stores what the engine reported, one Finding per check and path: the first report is `unverified`; a later report
 * of the same check and path (the automatic repeat) makes it `confirmed` and keeps the newer evidence. At most
 * `findingsMax` Findings per Campaign; a report beyond them is dropped (null).
 */
export async function reportFinding(
  q: Queryable,
  organizationId: string,
  campaignId: string,
  finding: ReportedFinding,
): Promise<CampaignFindingState | null> {
  const updated = await q.query<{ state: CampaignFindingState }>(
    `UPDATE campaign_findings SET state = 'confirmed', evidence = $4::jsonb, last_seen_at = $5::timestamptz
     WHERE campaign_id = $1 AND check_id = $2 AND path = $3 RETURNING state`,
    [campaignId, finding.checkId, finding.path, JSON.stringify(finding.evidence), finding.at.toISOString()],
  );
  if (updated.rows[0] !== undefined) return updated.rows[0].state;
  const { rows } = await q.query<{ n: number }>(
    "SELECT count(*)::int AS n FROM campaign_findings WHERE campaign_id = $1",
    [campaignId],
  );
  if ((rows[0]?.n ?? 0) >= CAMPAIGN_LIMITS.findingsMax) return null;
  await q.query(
    `INSERT INTO campaign_findings (organization_id, campaign_id, check_id, path, title, severity, state, evidence,
       first_seen_at, last_seen_at)
     VALUES ($1, $2, $3, $4, $5, $6, 'unverified', $7::jsonb, $8::timestamptz, $8::timestamptz)`,
    [
      organizationId,
      campaignId,
      finding.checkId,
      finding.path,
      finding.title,
      finding.severity,
      JSON.stringify(finding.evidence),
      finding.at.toISOString(),
    ],
  );
  return "unverified";
}

interface FindingRow {
  check_id: string;
  path: string;
  title: string;
  severity: CampaignSeverity;
  state: CampaignFindingState;
  evidence: CampaignEvidence;
  first_seen_at: Date;
  last_seen_at: Date;
}

export async function listCampaignFindings(q: Queryable, id: string): Promise<CampaignFinding[]> {
  const { rows } = await q.query<FindingRow>(
    `SELECT check_id, path, title, severity, state, evidence, first_seen_at, last_seen_at FROM campaign_findings
     WHERE campaign_id = $1 ORDER BY check_id, path LIMIT $2`,
    [id, CAMPAIGN_LIMITS.findingsMax],
  );
  return rows.map((row) => ({
    ...row,
    first_seen_at: row.first_seen_at.toISOString(),
    last_seen_at: row.last_seen_at.toISOString(),
  }));
}

// --- Without a tenant: the runner's queue and the operator -------------------------------------------------------

export interface QueuedCampaign {
  organizationId: string;
  campaignId: string;
  host: string;
  status: "queued" | "running";
  deletionPending: boolean;
}

/** Queued and running Campaigns across Organizations, oldest first: identifiers and hosts only. */
export async function campaignQueue(q: Queryable, limit: number, offset = 0): Promise<QueuedCampaign[]> {
  const { rows } = await q.query<{
    organization_id: string;
    campaign_id: string;
    host: string;
    status: "queued" | "running";
    deletion_pending: boolean;
  }>("SELECT organization_id, campaign_id, host, status, deletion_pending FROM campaign_queue($1, $2)", [
    limit,
    offset,
  ]);
  return rows.map((row) => ({
    organizationId: row.organization_id,
    campaignId: row.campaign_id,
    host: row.host,
    status: row.status,
    deletionPending: row.deletion_pending,
  }));
}

/** On start: every running Campaign becomes interrupted (`api_restart`). Answers which. */
export async function interruptRunningCampaigns(
  q: Queryable,
  at: Date,
): Promise<{ organizationId: string; campaignId: string }[]> {
  const { rows } = await q.query<{ organization_id: string; campaign_id: string }>(
    "SELECT organization_id, campaign_id FROM campaigns_interrupt($1)",
    [at.toISOString()],
  );
  return rows.map((row) => ({ organizationId: row.organization_id, campaignId: row.campaign_id }));
}

/** The operator's switch and suspensions. */
export async function operatorState(
  q: Queryable,
): Promise<Pick<ProveOperatorState, "killed" | "killed_at" | "suspended">> {
  const { rows } = await q.query<{
    killed: boolean;
    killed_at: Date | null;
    suspended: { organization_id: string; suspended_at: string }[];
  }>("SELECT killed, killed_at, suspended FROM prove_operator_state()");
  const row = rows[0];
  if (row === undefined) throw new Error("The operator state is not readable.");
  return {
    killed: row.killed,
    killed_at: iso(row.killed_at),
    suspended: row.suspended.map((entry) => ({
      organization_id: entry.organization_id,
      suspended_at: new Date(entry.suspended_at).toISOString(),
    })),
  };
}

export async function setKillSwitch(q: Queryable, killed: boolean, at: Date, reason: string): Promise<void> {
  await q.query("SELECT prove_switch_set($1, $2, $3)", [killed, at.toISOString(), reason]);
}

/** Suspends or resumes one Organization. False when nothing changed (already so, or no such Organization). */
export async function setSuspension(
  q: Queryable,
  organizationId: string,
  suspended: boolean,
  at: Date,
  reason: string,
): Promise<boolean> {
  const { rows } = await q.query<{ changed: boolean }>("SELECT prove_suspension_set($1, $2, $3, $4) AS changed", [
    organizationId,
    suspended,
    at.toISOString(),
    reason,
  ]);
  return rows[0]?.changed === true;
}

/** The owner's retention sweep of Campaigns that ended more than 395 days ago: Campaigns removed per Organization. */
export async function sweepCampaigns(q: Queryable, at: Date, batch: number): Promise<Record<string, number>> {
  const { rows } = await q.query<{ organization_id: string; removed: number }>(
    "SELECT organization_id, removed FROM campaigns_retention_sweep($1, $2)",
    [at.toISOString(), batch],
  );
  return Object.fromEntries(rows.map((row) => [row.organization_id, Number(row.removed)]));
}
