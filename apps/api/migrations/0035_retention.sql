-- Slice 18c: retention (FR-CON-11, SECURITY §8, OPERATION §17). Runs once, as the owner of the database, inside one
-- transaction.
--
-- - `organizations.event_retention_days`: how long the Organization's Events are kept, one of 7, 30, 90, 180 or 395
--   days. New Organizations get 30 (D-086); the Organizations that exist when this runs get 395, so that the first
--   sweep removes nothing they did not expect. The request role changes it through its existing UPDATE grant on
--   `organizations`, under row-level security: only its own Organization's row (0001).
-- - `retention_runs`: one row per Organization per run of the daily job (when, rows removed per table, whether the
--   run finished). The request role reads its own Organization's rows only; the job writes them as the owner and keeps
--   the 30 most recent per Organization. Purged with the Organization (it has an `organization_id`).
-- - `setup_milestones`: when each App Environment's Shield and Guard set-up steps were first done (slice 16), so that
--   removing old Events does not undo them. Backfilled here from the Events there are; afterwards the sweep records,
--   before it deletes Events, the earliest instants it removes (keeping the earlier value). The Set up read takes the
--   earlier of this and the Events that remain. The request role reads its own Organization's rows only.
-- - `retention_sweep_state`: where the sweep's rotation over Organizations stands (a position, no identifier).
-- - `retention_sweep(at, batch)`: the sweep. Owner only (no grant to the request role), like `organization_purge`.
--   Skips Organizations whose deletion is pending (their data goes with the purge). Removes, per Organization:
--     events        received before `at` less the Event retention; those carrying a Guard report (a verified
--                   Attestation Token: `payload.attestation.status = 'valid'`, the Guard step of 0030) before `at`
--                   less 30 days, if the Event retention is longer;
--     containments  ended (`coalesce(lifted_at, expires_at)`) before `at` less the Event retention: they hold the
--                   actor hash, the account reference of SECURITY §8;
--     detections, alert_deliveries, then incidents
--                   of Incidents whose `last_seen` is older than 395 days, children first. An Incident that any
--                   containment still names is skipped, ended or not: the foreign key from containments has no
--                   action and a containment cannot change (0009), so such an Incident goes at a later run, once its
--                   containments have aged out under their own rule (at most 395 days after they ended);
--     alert_deliveries
--                   older than 395 days (`at`);
--     assessments   finished (scored, inconclusive or failed) more than 395 days ago. Their artifacts go by the
--                   artifact expiry, which the job also calls.
--   Fairness and bounds: a call serves a window of at most `batch` Organizations, taken in id order from where the
--   last call stopped (wrapping), and each step gives each Organization of the window an equal share of `batch` rows
--   (at least one). So each step deletes at most `batch` rows per call, and one Organization's backlog never holds the
--   others back: every Organization is served within ceil(Organizations / batch) calls. Each step has its own
--   budget. The answer says whether any Organization used its whole share in any step (`saturated`), how many
--   Organizations the window held and how many there are; the job calls again until a series of unsaturated calls has
--   covered every Organization. Builds and the audit tables are not touched.
-- - `retention_record(at, counts, complete)`: writes one run row per Organization the sweep covered and keeps the 30
--   most recent per Organization. Owner only.
-- - `subject_erase(hash, at)` (0033) is redefined: before it deletes the subject's Events it records their earliest
--   Shield and Guard instants in `setup_milestones`, as the sweep does, so that an erasure does not undo Set up.
-- - `assessment_artifacts_expire_by_organization(now)`: the artifact expiry of 0026/0028 (same candidates, same
--   `SKIP LOCKED`), answering the artifacts removed per Organization. Owner only; the job calls it.
--   `assessment_artifacts_expire` stays as it is for the Assessment runner.

ALTER TABLE organizations ADD COLUMN event_retention_days integer NOT NULL DEFAULT 30
  CHECK (event_retention_days IN (7, 30, 90, 180, 395));
UPDATE organizations SET event_retention_days = 395;

CREATE TABLE retention_runs (
  organization_id text NOT NULL REFERENCES organizations(id),
  seq bigint GENERATED ALWAYS AS IDENTITY,
  ran_at timestamptz NOT NULL,
  complete boolean NOT NULL,
  -- Rows removed per table; a table with none is left out.
  counts jsonb NOT NULL CHECK (jsonb_typeof(counts) = 'object'),
  PRIMARY KEY (organization_id, seq)
);
CREATE INDEX retention_runs_recent ON retention_runs (organization_id, ran_at DESC, seq DESC);
GRANT SELECT ON retention_runs TO ar_app;
ALTER TABLE retention_runs ENABLE ROW LEVEL SECURITY;
ALTER TABLE retention_runs FORCE ROW LEVEL SECURITY;
CREATE POLICY retention_runs_tenant ON retention_runs
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

CREATE TABLE setup_milestones (
  organization_id text NOT NULL REFERENCES organizations(id),
  app_id text NOT NULL REFERENCES apps(id),
  environment text NOT NULL CHECK (environment IN ('production', 'staging', 'development')),
  shield_first_at timestamptz,
  guard_first_at timestamptz,
  PRIMARY KEY (organization_id, app_id, environment)
);
GRANT SELECT ON setup_milestones TO ar_app;
ALTER TABLE setup_milestones ENABLE ROW LEVEL SECURITY;
ALTER TABLE setup_milestones FORCE ROW LEVEL SECURITY;
CREATE POLICY setup_milestones_tenant ON setup_milestones
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));
INSERT INTO setup_milestones (organization_id, app_id, environment, shield_first_at, guard_first_at)
SELECT e.organization_id, e.app_id, e.environment, min(e.received_at),
  min(e.received_at) FILTER (WHERE e.payload->'attestation'->>'status' = 'valid')
FROM events e
JOIN apps a ON a.id = e.app_id AND a.organization_id = e.organization_id
GROUP BY e.organization_id, e.app_id, e.environment;

CREATE TABLE retention_sweep_state (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  next_offset bigint NOT NULL DEFAULT 0 CHECK (next_offset >= 0)
);
INSERT INTO retention_sweep_state DEFAULT VALUES;
REVOKE ALL ON retention_sweep_state FROM PUBLIC;

-- What the sweep reads: alert deliveries by time, finished Assessments by finish, old Incidents per Organization
-- (`incidents_recent`, 0006). And what deleting an Incident checks: every foreign key that names it; the sweep's own
-- "named by a containment" check uses the containments one. Events need no new index: the sweep reads them per App through
-- `events_recent` (0001), and those carrying a Guard report per App and Environment through `events_first_attested`
-- (0030), so that ingest pays for no further index.
CREATE INDEX alert_deliveries_by_time ON alert_deliveries (organization_id, at);
CREATE INDEX alert_deliveries_of_incident_fk ON alert_deliveries (incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX detections_of_incident_fk ON detections (incident_id);
CREATE INDEX containments_of_incident_fk ON containments (incident_id) WHERE incident_id IS NOT NULL;
CREATE INDEX assessments_finished ON assessments (organization_id, finished_at)
  WHERE status IN ('scored', 'inconclusive', 'failed');

-- `counts` with `n` more rows of `tbl` for `org`.
CREATE FUNCTION retention_add(p_counts jsonb, p_org text, p_table text, p_n bigint)
RETURNS jsonb
LANGUAGE sql IMMUTABLE
AS $$
  SELECT p_counts || jsonb_build_object(p_org,
    COALESCE(p_counts->p_org, '{}'::jsonb)
      || jsonb_build_object(p_table, COALESCE((p_counts->p_org->>p_table)::bigint, 0) + p_n))
$$;
REVOKE ALL ON FUNCTION retention_add(jsonb, text, text, bigint) FROM PUBLIC;

CREATE FUNCTION retention_sweep(p_at timestamptz, p_batch integer)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  lim integer := LEAST(GREATEST(COALESCE(p_batch, 1), 1), 100000);
  evidence timestamptz := p_at - interval '395 days';
  guard timestamptz := p_at - interval '30 days';
  counts jsonb := '{}'::jsonb;
  saturated boolean := false;
  total integer;
  start_at bigint;
  k integer;
  share integer;
  win text[];
  r record;
BEGIN
  IF p_at IS NULL THEN
    RAISE EXCEPTION 'retention sweep: no time' USING ERRCODE = '22023';
  END IF;

  -- The window: up to `lim` Organizations (deletion not pending), in id order from where the last call stopped.
  SELECT count(*)::integer INTO total FROM public.organizations o
  WHERE NOT public.organization_deletion_is_pending(o.id);
  IF total = 0 THEN
    RETURN jsonb_build_object('rows', counts, 'saturated', false, 'window', 0, 'organizations', 0);
  END IF;
  SELECT s.next_offset % total INTO start_at FROM public.retention_sweep_state s FOR UPDATE;
  start_at := COALESCE(start_at, 0);
  k := LEAST(total, lim);
  share := GREATEST(lim / k, 1);
  SELECT array_agg(ranked.id) INTO win FROM (
    SELECT o.id, row_number() OVER (ORDER BY o.id) - 1 AS pos
    FROM public.organizations o
    WHERE NOT public.organization_deletion_is_pending(o.id)
  ) ranked
  WHERE (ranked.pos - start_at + total) % total < k;
  UPDATE public.retention_sweep_state SET next_offset = (start_at + k) % total;

  -- Events past the Organization's retention, oldest first per App. The earliest instants removed are kept in the
  -- set-up record first.
  FOR r IN
    WITH victims AS (
      SELECT v.*
      FROM public.organizations o
      CROSS JOIN LATERAL (
        SELECT x.* FROM public.apps a
        CROSS JOIN LATERAL (
          SELECT e.organization_id, e.event_id, e.app_id, e.environment, e.received_at,
            COALESCE(e.payload->'attestation'->>'status' = 'valid', false) AS guarded
          FROM public.events e
          WHERE e.organization_id = o.id AND e.app_id = a.id
            AND e.received_at < p_at - make_interval(days => o.event_retention_days)
          ORDER BY e.received_at LIMIT share
        ) x
        WHERE a.organization_id = o.id
        LIMIT share
      ) v
      WHERE o.id = ANY (win)
    ), marked AS (
      INSERT INTO public.setup_milestones AS m (organization_id, app_id, environment, shield_first_at, guard_first_at)
      SELECT v.organization_id, v.app_id, v.environment, min(v.received_at),
        min(v.received_at) FILTER (WHERE v.guarded)
      FROM victims v GROUP BY v.organization_id, v.app_id, v.environment
      ON CONFLICT (organization_id, app_id, environment) DO UPDATE
      SET shield_first_at = LEAST(m.shield_first_at, EXCLUDED.shield_first_at),
        guard_first_at = LEAST(m.guard_first_at, EXCLUDED.guard_first_at)
      RETURNING 1
    ), gone AS (
      DELETE FROM public.events e USING victims v
      WHERE e.organization_id = v.organization_id AND e.event_id = v.event_id
      RETURNING e.organization_id
    )
    SELECT organization_id, count(*)::integer AS n FROM gone GROUP BY organization_id
  LOOP
    counts := public.retention_add(counts, r.organization_id, 'events', r.n);
    saturated := saturated OR r.n >= share;
  END LOOP;

  -- Events carrying a Guard report, after 30 days, where the Event retention is longer: a budget of their own.
  FOR r IN
    WITH victims AS (
      SELECT v.*
      FROM public.organizations o
      CROSS JOIN LATERAL (
        SELECT x.* FROM public.apps a
        CROSS JOIN unnest(ARRAY['production', 'staging', 'development']) AS env (name)
        CROSS JOIN LATERAL (
          SELECT e.organization_id, e.event_id, e.app_id, e.environment, e.received_at
          FROM public.events e
          WHERE e.organization_id = o.id AND e.app_id = a.id AND e.environment = env.name
            AND e.received_at < guard AND e.payload->'attestation'->>'status' = 'valid'
          ORDER BY e.received_at LIMIT share
        ) x
        WHERE a.organization_id = o.id
        LIMIT share
      ) v
      WHERE o.id = ANY (win) AND o.event_retention_days > 30
    ), marked AS (
      INSERT INTO public.setup_milestones AS m (organization_id, app_id, environment, shield_first_at, guard_first_at)
      SELECT v.organization_id, v.app_id, v.environment, min(v.received_at), min(v.received_at)
      FROM victims v GROUP BY v.organization_id, v.app_id, v.environment
      ON CONFLICT (organization_id, app_id, environment) DO UPDATE
      SET shield_first_at = LEAST(m.shield_first_at, EXCLUDED.shield_first_at),
        guard_first_at = LEAST(m.guard_first_at, EXCLUDED.guard_first_at)
      RETURNING 1
    ), gone AS (
      DELETE FROM public.events e USING victims v
      WHERE e.organization_id = v.organization_id AND e.event_id = v.event_id
      RETURNING e.organization_id
    )
    SELECT organization_id, count(*)::integer AS n FROM gone GROUP BY organization_id
  LOOP
    counts := public.retention_add(counts, r.organization_id, 'events', r.n);
    saturated := saturated OR r.n >= share;
  END LOOP;

  -- Containments that ended before the Organization's Event retention. A containment ends after it was created, so
  -- `created_at` bounds the scan.
  FOR r IN
    WITH victims AS (
      SELECT v.organization_id, v.id
      FROM public.organizations o
      CROSS JOIN LATERAL (
        SELECT c.organization_id, c.id FROM public.containments c
        WHERE c.organization_id = o.id
          AND c.created_at < p_at - make_interval(days => o.event_retention_days)
          AND COALESCE(c.lifted_at, c.expires_at) < p_at - make_interval(days => o.event_retention_days)
        LIMIT share
      ) v
      WHERE o.id = ANY (win)
    ), gone AS (
      DELETE FROM public.containments c USING victims v
      WHERE c.organization_id = v.organization_id AND c.id = v.id
      RETURNING c.organization_id
    )
    SELECT organization_id, count(*)::integer AS n FROM gone GROUP BY organization_id
  LOOP
    counts := public.retention_add(counts, r.organization_id, 'containments', r.n);
    saturated := saturated OR r.n >= share;
  END LOOP;

  -- The Detections of Incidents past the evidence period that no containment names.
  FOR r IN
    WITH victims AS (
      SELECT v.id
      FROM public.organizations o
      CROSS JOIN LATERAL (
        SELECT d.id
        FROM public.incidents i
        JOIN public.detections d ON d.organization_id = i.organization_id AND d.incident_id = i.id
        WHERE i.organization_id = o.id AND i.last_seen < evidence
          AND NOT EXISTS (SELECT 1 FROM public.containments c WHERE c.incident_id = i.id)
        LIMIT share
      ) v
      WHERE o.id = ANY (win)
    ), gone AS (
      DELETE FROM public.detections d USING victims v WHERE d.id = v.id
      RETURNING d.organization_id
    )
    SELECT organization_id, count(*)::integer AS n FROM gone GROUP BY organization_id
  LOOP
    counts := public.retention_add(counts, r.organization_id, 'detections', r.n);
    saturated := saturated OR r.n >= share;
  END LOOP;

  -- The alert deliveries of the same Incidents.
  FOR r IN
    WITH victims AS (
      SELECT v.id
      FROM public.organizations o
      CROSS JOIN LATERAL (
        SELECT a.id
        FROM public.incidents i
        JOIN public.alert_deliveries a ON a.incident_id = i.id
        WHERE i.organization_id = o.id AND i.last_seen < evidence
          AND NOT EXISTS (SELECT 1 FROM public.containments c WHERE c.incident_id = i.id)
        LIMIT share
      ) v
      WHERE o.id = ANY (win)
    ), gone AS (
      DELETE FROM public.alert_deliveries a USING victims v WHERE a.id = v.id
      RETURNING a.organization_id
    )
    SELECT organization_id, count(*)::integer AS n FROM gone GROUP BY organization_id
  LOOP
    counts := public.retention_add(counts, r.organization_id, 'alert_deliveries', r.n);
    saturated := saturated OR r.n >= share;
  END LOOP;

  -- Alert deliveries older than the evidence period: a budget of their own.
  FOR r IN
    WITH victims AS (
      SELECT v.id
      FROM public.organizations o
      CROSS JOIN LATERAL (
        SELECT a.id FROM public.alert_deliveries a
        WHERE a.organization_id = o.id AND a.at < evidence
        LIMIT share
      ) v
      WHERE o.id = ANY (win)
    ), gone AS (
      DELETE FROM public.alert_deliveries a USING victims v WHERE a.id = v.id
      RETURNING a.organization_id
    )
    SELECT organization_id, count(*)::integer AS n FROM gone GROUP BY organization_id
  LOOP
    counts := public.retention_add(counts, r.organization_id, 'alert_deliveries', r.n);
    saturated := saturated OR r.n >= share;
  END LOOP;

  -- The Incidents themselves, once nothing names them any more.
  FOR r IN
    WITH victims AS (
      SELECT v.id
      FROM public.organizations o
      CROSS JOIN LATERAL (
        SELECT i.id
        FROM public.incidents i
        WHERE i.organization_id = o.id AND i.last_seen < evidence
          AND NOT EXISTS (SELECT 1 FROM public.containments c WHERE c.incident_id = i.id)
          AND NOT EXISTS (SELECT 1 FROM public.detections d WHERE d.incident_id = i.id)
          AND NOT EXISTS (SELECT 1 FROM public.alert_deliveries a WHERE a.incident_id = i.id)
        LIMIT share
      ) v
      WHERE o.id = ANY (win)
    ), gone AS (
      DELETE FROM public.incidents i USING victims v WHERE i.id = v.id
      RETURNING i.organization_id
    )
    SELECT organization_id, count(*)::integer AS n FROM gone GROUP BY organization_id
  LOOP
    counts := public.retention_add(counts, r.organization_id, 'incidents', r.n);
    saturated := saturated OR r.n >= share;
  END LOOP;

  -- Assessments that finished before the evidence period.
  FOR r IN
    WITH victims AS (
      SELECT v.organization_id, v.id
      FROM public.organizations o
      CROSS JOIN LATERAL (
        SELECT a.organization_id, a.id FROM public.assessments a
        WHERE a.organization_id = o.id AND a.status IN ('scored', 'inconclusive', 'failed')
          AND a.finished_at < evidence
        LIMIT share
      ) v
      WHERE o.id = ANY (win)
    ), gone AS (
      DELETE FROM public.assessments a USING victims v
      WHERE a.organization_id = v.organization_id AND a.id = v.id
      RETURNING a.organization_id
    )
    SELECT organization_id, count(*)::integer AS n FROM gone GROUP BY organization_id
  LOOP
    counts := public.retention_add(counts, r.organization_id, 'assessments', r.n);
    saturated := saturated OR r.n >= share;
  END LOOP;

  RETURN jsonb_build_object('rows', counts, 'saturated', saturated, 'window', k, 'organizations', total);
END
$$;
REVOKE ALL ON FUNCTION retention_sweep(timestamptz, integer) FROM PUBLIC;

-- One run row per Organization the sweep covered (every Organization whose deletion is not pending), with its counts
-- (`p_counts` by Organization id; none: `{}`), then the 30 most recent kept per Organization. Answers the rows written.
CREATE FUNCTION retention_record(p_at timestamptz, p_counts jsonb, p_complete boolean)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  n integer;
BEGIN
  INSERT INTO public.retention_runs (organization_id, ran_at, complete, counts)
  SELECT o.id, p_at, p_complete, COALESCE(p_counts->o.id, '{}'::jsonb)
  FROM public.organizations o
  WHERE NOT public.organization_deletion_is_pending(o.id);
  GET DIAGNOSTICS n = ROW_COUNT;
  DELETE FROM public.retention_runs r
  USING (
    SELECT organization_id, seq,
      row_number() OVER (PARTITION BY organization_id ORDER BY ran_at DESC, seq DESC) AS rank
    FROM public.retention_runs
  ) old
  WHERE r.organization_id = old.organization_id AND r.seq = old.seq AND old.rank > 30;
  RETURN n;
END
$$;
REVOKE ALL ON FUNCTION retention_record(timestamptz, jsonb, boolean) FROM PUBLIC;

-- The artifact expiry of 0028 (same candidates, same `SKIP LOCKED`), answering the artifacts removed per Organization.
CREATE FUNCTION assessment_artifacts_expire_by_organization(p_now timestamptz)
RETURNS TABLE (organization_id text, removed integer)
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
#variable_conflict use_column
BEGIN
  RETURN QUERY
  WITH candidates AS (
    SELECT ar.organization_id, ar.id
    FROM public.artifacts ar
    WHERE ar.kept_until <= p_now
      AND NOT EXISTS (
        SELECT 1 FROM public.assessments a
        WHERE a.organization_id = ar.organization_id AND a.artifact_id = ar.id AND a.status IN ('queued', 'running')
      )
    FOR UPDATE SKIP LOCKED
  ), gone AS (
    DELETE FROM public.artifacts ar
    USING candidates c
    WHERE ar.organization_id = c.organization_id AND ar.id = c.id
    RETURNING ar.organization_id
  )
  SELECT g.organization_id, count(*)::integer FROM gone g GROUP BY g.organization_id;
END
$$;
REVOKE ALL ON FUNCTION assessment_artifacts_expire_by_organization(timestamptz) FROM PUBLIC;


-- Subject erasure (0033), unchanged but for the set-up record: the earliest Shield and Guard instants of the Events it
-- removes are kept first (the earlier value wins), so that erasing a subject does not undo an App's Set up.
CREATE OR REPLACE FUNCTION subject_erase(p_ip_hash text, p_at timestamptz)
RETURNS TABLE (events_erased integer, containments_erased integer)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  tenant text := NULLIF(current_setting('app.tenant_id', true), '');
  e integer;
  k integer;
BEGIN
  IF tenant IS NULL THEN
    RAISE EXCEPTION 'subject erase: no tenant' USING ERRCODE = '42501';
  END IF;
  IF p_ip_hash IS NULL OR p_ip_hash !~ '^iph_[0-9a-f]{32}$' THEN
    RAISE EXCEPTION 'subject erase: not an actor hash' USING ERRCODE = '22023';
  END IF;
  INSERT INTO public.setup_milestones AS m (organization_id, app_id, environment, shield_first_at, guard_first_at)
  SELECT ev.organization_id, ev.app_id, ev.environment, min(ev.received_at),
    min(ev.received_at) FILTER (WHERE ev.payload->'attestation'->>'status' = 'valid')
  FROM public.events ev
  JOIN public.apps a ON a.id = ev.app_id AND a.organization_id = ev.organization_id
  WHERE ev.organization_id = tenant AND ev.payload->'actor'->>'ip_hash' = p_ip_hash
  GROUP BY ev.organization_id, ev.app_id, ev.environment
  ON CONFLICT (organization_id, app_id, environment) DO UPDATE
  SET shield_first_at = LEAST(m.shield_first_at, EXCLUDED.shield_first_at),
    guard_first_at = LEAST(m.guard_first_at, EXCLUDED.guard_first_at);
  WITH gone AS (
    DELETE FROM public.events ev
    WHERE ev.organization_id = tenant AND ev.payload->'actor'->>'ip_hash' = p_ip_hash
    RETURNING 1
  ) SELECT count(*)::integer INTO e FROM gone;
  WITH gone AS (
    DELETE FROM public.containments c
    WHERE c.organization_id = tenant AND c.ip_hash = p_ip_hash
      AND (c.lifted_at IS NOT NULL OR c.expires_at <= p_at)
    RETURNING 1
  ) SELECT count(*)::integer INTO k FROM gone;
  RETURN QUERY SELECT e, k;
END
$$;
