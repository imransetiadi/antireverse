import {
  canarySignalId,
  type Detection,
  type DetectionRule,
  type DetectionRuleKey,
  type Environment,
  type Incident,
  type IncidentStatus,
  type Severity,
  type ShieldEvent,
  type StoredEvent,
} from "@antireverse/protocol";
import { newId } from "@antireverse/protocol/server";
import type { Queryable } from "../db/db.ts";
import { ruleConditionSql } from "../detect/rules.ts";

interface IncidentRow {
  id: string;
  app_id: string;
  environment: Environment;
  rule: DetectionRuleKey;
  severity: Severity;
  title: string;
  status: IncidentStatus;
  ip_prefix: string | null;
  first_seen: Date;
  last_seen: Date;
  detection_count: number;
  created_at: Date;
  updated_at: Date;
  canary_id: string | null;
  build_id: string | null;
  origin: string | null;
  advisory_id: string | null;
}

interface DetectionRow {
  id: string;
  rule: DetectionRuleKey;
  app_id: string;
  environment: Environment;
  ip_prefix: string | null;
  count: number;
  window_start: Date;
  window_end: Date;
  detected_at: Date;
  canary_id: string | null;
  origin: string | null;
}

const INCIDENT_COLUMNS =
  "id, app_id, environment, rule, severity, title, status, ip_prefix, first_seen, last_seen, detection_count, created_at, updated_at, canary_id, build_id, origin, advisory_id";
const DETECTION_COLUMNS =
  "id, rule, app_id, environment, ip_prefix, count, window_start, window_end, detected_at, canary_id, origin";

function toIncident(row: IncidentRow): Incident {
  return {
    id: row.id,
    app_id: row.app_id,
    environment: row.environment,
    rule: row.rule,
    severity: row.severity,
    title: row.title,
    status: row.status,
    ip_prefix: row.ip_prefix,
    first_seen: row.first_seen.toISOString(),
    last_seen: row.last_seen.toISOString(),
    detection_count: row.detection_count,
    created_at: row.created_at.toISOString(),
    updated_at: row.updated_at.toISOString(),
    canary_id: row.canary_id,
    build_id: row.build_id,
    origin: row.origin,
    advisory_id: row.advisory_id,
  };
}

function toDetection(row: DetectionRow): Detection {
  return {
    id: row.id,
    rule: row.rule,
    app_id: row.app_id,
    environment: row.environment,
    ip_prefix: row.ip_prefix,
    count: row.count,
    window_start: row.window_start.toISOString(),
    window_end: row.window_end.toISOString(),
    detected_at: row.detected_at.toISOString(),
    canary_id: row.canary_id,
    origin: row.origin,
  };
}

export interface DetectionInput {
  organizationId: string;
  appId: string;
  environment: Environment;
  rule: DetectionRule;
  /**
   * The network prefix counted; for `clone-origin` the reporter's prefix, or null when unknown. A clone
   * Incident has no prefix: only its Detections carry the reporter's.
   */
  ipPrefix: string | null;
  count: number;
  /** `ts` of the oldest and newest counted Event (ISO-8601); for `clone-origin`, the time of the report. */
  windowStart: string;
  windowEnd: string;
  detectedAt: Date;
  /**
   * For `canary-touched` only: the Canary, checked to be the App Environment's own, and its Build. It is part
   * of the group: one Incident per Canary and prefix.
   */
  canary?: { id: string; buildId: string } | undefined;
  /**
   * For `clone-origin` only: the foreign origin and the Build whose beacon reported it. The origin is the group:
   * one Incident per (App, Environment, origin), whichever Build reported it; the Incident names the first Build.
   */
  clone?: { origin: string; buildId: string } | undefined;
  /**
   * For `vulnerable-component` only: the advisory a new Critical or High Finding matched, the Finding's severity
   * (the Incident's) and its Build (null for a runtime Finding). The advisory is the group: one Incident per (App,
   * Environment, advisory); the Incident names the first Finding's Build.
   */
  vulnerability?: { advisoryId: string; severity: "critical" | "high"; buildId: string | null } | undefined;
}

/**
 * Records one Detection and groups it: it joins the open or acknowledged Incident of the same (App,
 * Environment, rule, Canary, origin, prefix), else a new Incident opens. `opened` says which, so that only a new
 * Incident alerts. Run in one transaction of the Detection's Organization.
 */
export async function recordDetection(
  q: Queryable,
  input: DetectionInput,
): Promise<{ incident: Incident; detection: Detection; opened: boolean }> {
  const at = input.detectedAt.toISOString();
  const canaryId = input.canary?.id ?? null;
  const origin = input.clone?.origin ?? null;
  const advisoryId = input.vulnerability?.advisoryId ?? null;
  const buildId = input.canary?.buildId ?? input.clone?.buildId ?? input.vulnerability?.buildId ?? null;
  // A clone Incident is grouped by origin and has no prefix of its own; a vulnerable-component Incident by advisory.
  const incidentPrefix = input.clone === undefined && input.vulnerability === undefined ? input.ipPrefix : null;
  const severity = input.vulnerability?.severity ?? input.rule.severity;
  // The row is locked, so that a status change and a Detection never interleave.
  const found = await q.query<IncidentRow>(
    `SELECT ${INCIDENT_COLUMNS} FROM incidents
     WHERE organization_id = $1 AND app_id = $2 AND environment = $3 AND rule = $4
       AND ip_prefix IS NOT DISTINCT FROM $5::text
       AND canary_id IS NOT DISTINCT FROM $6::text
       AND origin IS NOT DISTINCT FROM $7::text
       AND advisory_id IS NOT DISTINCT FROM $8::text
       AND status IN ('open', 'acknowledged')
     FOR UPDATE`,
    [
      input.organizationId,
      input.appId,
      input.environment,
      input.rule.key,
      incidentPrefix,
      canaryId,
      origin,
      advisoryId,
    ],
  );
  let row: IncidentRow | undefined;
  let opened: boolean;
  const current = found.rows[0];
  if (current !== undefined) {
    const updated = await q.query<IncidentRow>(
      `UPDATE incidents SET
         first_seen = LEAST(first_seen, $2::timestamptz),
         last_seen = GREATEST(last_seen, $3::timestamptz),
         detection_count = detection_count + 1,
         updated_at = $4::timestamptz
       WHERE id = $1
       RETURNING ${INCIDENT_COLUMNS}`,
      [current.id, input.windowStart, input.windowEnd, at],
    );
    row = updated.rows[0];
    opened = false;
  } else {
    const inserted = await q.query<IncidentRow>(
      `INSERT INTO incidents (id, organization_id, app_id, environment, rule, severity, title, status, ip_prefix,
         first_seen, last_seen, detection_count, created_at, updated_at, canary_id, build_id, origin, advisory_id)
       VALUES ($1, $2, $3, $4, $5, $6, $7, 'open', $8::text, $9::timestamptz, $10::timestamptz, 1, $11::timestamptz,
         $11::timestamptz, $12::text, $13::text, $14::text, $15::text)
       RETURNING ${INCIDENT_COLUMNS}`,
      [
        newId("inc"),
        input.organizationId,
        input.appId,
        input.environment,
        input.rule.key,
        severity,
        input.rule.title,
        incidentPrefix,
        input.windowStart,
        input.windowEnd,
        at,
        canaryId,
        buildId,
        origin,
        advisoryId,
      ],
    );
    row = inserted.rows[0];
    opened = true;
  }
  if (row === undefined) throw new Error("The Incident was not stored.");

  const detection = await q.query<DetectionRow>(
    `INSERT INTO detections (id, organization_id, incident_id, app_id, environment, rule, ip_prefix, count,
       window_start, window_end, detected_at, canary_id, origin, advisory_id)
     VALUES ($1, $2, $3, $4, $5, $6, $7::text, $8, $9::timestamptz, $10::timestamptz, $11::timestamptz, $12::text,
       $13::text, $14::text)
     RETURNING ${DETECTION_COLUMNS}`,
    [
      newId("dtc"),
      input.organizationId,
      row.id,
      input.appId,
      input.environment,
      input.rule.key,
      input.ipPrefix,
      input.count,
      input.windowStart,
      input.windowEnd,
      at,
      canaryId,
      origin,
      advisoryId,
    ],
  );
  const detectionRow = detection.rows[0];
  if (detectionRow === undefined) throw new Error("The Detection was not stored.");
  return { incident: toIncident(row), detection: toDetection(detectionRow), opened };
}

/** The Incidents of the transaction's Organization, newest first by `last_seen`, then by id; optionally filtered. */
export async function listIncidents(
  q: Queryable,
  filter: { appId?: string; status?: IncidentStatus; limit: number },
): Promise<Incident[]> {
  const { rows } = await q.query<IncidentRow>(
    `SELECT ${INCIDENT_COLUMNS} FROM incidents
     WHERE ($1::text IS NULL OR app_id = $1::text) AND ($2::text IS NULL OR status = $2::text)
     ORDER BY last_seen DESC, id DESC
     LIMIT $3`,
    [filter.appId ?? null, filter.status ?? null, filter.limit],
  );
  return rows.map(toIncident);
}

/** One Incident of the transaction's Organization, or null. With `lock`, the row stays locked until commit. */
export async function findIncident(q: Queryable, id: string, lock = false): Promise<Incident | null> {
  const { rows } = await q.query<IncidentRow>(
    `SELECT ${INCIDENT_COLUMNS} FROM incidents WHERE id = $1${lock ? " FOR UPDATE" : ""}`,
    [id],
  );
  return rows[0] === undefined ? null : toIncident(rows[0]);
}

/** Sets the status of an Incident and stamps `updated_at`. The caller decides whether the transition is allowed. */
export async function setIncidentStatus(
  q: Queryable,
  id: string,
  status: IncidentStatus,
  at: Date,
): Promise<Incident | null> {
  const { rows } = await q.query<IncidentRow>(
    `UPDATE incidents SET status = $2, updated_at = $3::timestamptz WHERE id = $1 RETURNING ${INCIDENT_COLUMNS}`,
    [id, status, at.toISOString()],
  );
  return rows[0] === undefined ? null : toIncident(rows[0]);
}

/** The newest `limit` Detections of an Incident: by `detected_at`, then id, both descending. */
export async function listDetections(q: Queryable, incidentId: string, limit: number): Promise<Detection[]> {
  const { rows } = await q.query<DetectionRow>(
    `SELECT ${DETECTION_COLUMNS} FROM detections WHERE incident_id = $1 ORDER BY detected_at DESC, id DESC LIMIT $2`,
    [incidentId, limit],
  );
  return rows.map(toDetection);
}

interface EvidenceRow {
  organization_id: string;
  app_id: string;
  environment: Environment;
  received_at: Date;
  payload: ShieldEvent;
}

/**
 * The Events behind an Incident, as an SQL condition over `events` with its parameters: its App, Environment
 * and network prefix, with `ts` within `first_seen..last_seen`, that the Incident's rule counts (for a Canary
 * Incident: the Events carrying that Canary's signal). A caller appends its own parameters after these. Null
 * for a Canary Incident without its Canary (the table's check rules it out): it has no evidence. Null for a clone
 * Incident too: it counts Clone Beacon reports, not Events, so it has no evidence and no Actors.
 */
function evidenceScope(incident: Incident): { where: string; params: unknown[] } | null {
  if (incident.rule === "clone-origin" || incident.rule === "vulnerable-component" || incident.ip_prefix === null) {
    return null;
  }
  const params: unknown[] = [
    incident.app_id,
    incident.environment,
    incident.ip_prefix,
    incident.first_seen,
    incident.last_seen,
  ];
  let condition: string;
  if (incident.rule === "canary-touched") {
    if (incident.canary_id === null) return null;
    params.push(canarySignalId(incident.canary_id));
    condition = ruleConditionSql(incident.rule, "$6");
  } else {
    condition = ruleConditionSql(incident.rule);
  }
  return {
    where: `app_id = $1 AND environment = $2 AND payload->'actor'->>'ip_prefix' = $3
       AND ts BETWEEN $4::timestamptz AND $5::timestamptz
       AND ${condition}`,
    params,
  };
}

/** `$n` of the parameter that follows `params`. */
const nextParam = (params: unknown[]): `$${number}` => `$${params.length + 1}`;

/**
 * The Actors of an Incident: the distinct actor hashes of its evidence (`evidenceScope`) with their Event
 * counts, by count descending, then hash; at most `limit`. Events without a hash are left out.
 */
export async function listActors(
  q: Queryable,
  incident: Incident,
  limit: number,
): Promise<{ ip_hash: string; events: number }[]> {
  const scope = evidenceScope(incident);
  if (scope === null) return [];
  const { rows } = await q.query<{ ip_hash: string; events: number }>(
    `SELECT payload->'actor'->>'ip_hash' AS ip_hash, count(*)::int AS events FROM events
     WHERE ${scope.where} AND payload->'actor'->>'ip_hash' IS NOT NULL
     GROUP BY 1
     ORDER BY 2 DESC, 1
     LIMIT ${nextParam(scope.params)}`,
    [...scope.params, limit],
  );
  return rows.map((row) => ({ ip_hash: row.ip_hash, events: row.events }));
}

/** Whether the actor hash occurs in the Incident's evidence (`evidenceScope`): an Actor of the Incident. */
export async function hasActor(q: Queryable, incident: Incident, ipHash: string): Promise<boolean> {
  const scope = evidenceScope(incident);
  if (scope === null) return false;
  const { rows } = await q.query(
    `SELECT 1 FROM events WHERE ${scope.where} AND payload->'actor'->>'ip_hash' = ${nextParam(scope.params)} LIMIT 1`,
    [...scope.params, ipHash],
  );
  return rows.length > 0;
}

/**
 * The stored Events behind an Incident (`evidenceScope`), newest first (by `ts`, then id), at most `limit`.
 * As stored: the Event allowlist.
 */
export async function listEvidence(q: Queryable, incident: Incident, limit: number): Promise<StoredEvent[]> {
  const scope = evidenceScope(incident);
  if (scope === null) return [];
  const { rows } = await q.query<EvidenceRow>(
    `SELECT organization_id, app_id, environment, received_at, payload FROM events
     WHERE ${scope.where}
     ORDER BY ts DESC, event_id DESC
     LIMIT ${nextParam(scope.params)}`,
    [...scope.params, limit],
  );
  return rows.map((row) => ({
    ...row.payload,
    organization_id: row.organization_id,
    app_id: row.app_id,
    environment: row.environment,
    received_at: row.received_at.toISOString(),
  }));
}
