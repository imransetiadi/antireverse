-- Slice 17a: usage metering (FR-CON-08 metering part, PRD §16, D-089). Runs once, as the owner of the database, inside
-- one transaction.
--
-- - `usage_daily`: per Organization, App, Environment and UTC day, the protected requests (Events newly stored at
--   ingest) and the Prove sandbox seconds (Assessments that finished that day). The request role reads its own
--   Organization's rows only and writes none: ingest adds through `usage_add_requests`, the Assessment end through the
--   trigger `assessments_usage`. Counters survive the retention of the Events they count.
-- - Month salts are not stored here (review M3, Jev memory_key_file_per_month): PostgreSQL keeps deleted rows in its
--   heap and WAL, so a deleted salt could be recovered. The API process keeps them (usage-salts.json beside the data
--   directory) and computes each reference itself.
-- - `usage_devices`: the monthly references of the devices that received an Attestation Token with a counted verdict:
--   HMAC-SHA-256 (month salt, per-App device subject `dev_…`), 32 bytes, computed by the API. No raw device identifier
--   is stored. The request role reads its own rows (the live distinct count of the current month) and writes through
--   `usage_record_device` only.
-- - `usage_device_days`: per Organization, App and UTC day, the new references recorded and whether the daily cap
--   stopped recording (review M2, Jev cap_and_flag). Read by the usage read (the cap flag) and by the rollup (which
--   App-months to count), deleted by the rollup when its month closes.
-- - `usage_monthly_devices`: per Organization, App and closed month, the distinct count and the cap flag, written by
--   the rollup.
-- - `usage_rollup(at, batch)`: the daily owner step (run by the retention job): closes each month that ended at least an
--   hour before `at` (counts each App-month once, then deletes its references in batches), and removes usage rows of
--   months older than 13 months before `at`'s month. Owner only. The API forgets the closed months' salts after it.
-- - `usage_sandbox_cap_seconds(tier)`: the most an Assessment run is metered: the tier's seconds (`TIERS`) plus the
--   runner's grace (`RUNNER_DEFAULTS.graceMs`, 120 s), the runner's own deadline (review M1). A test pins both.
--
-- Nothing new is granted DELETE to the request role.

CREATE TABLE usage_daily (
  organization_id text NOT NULL REFERENCES organizations(id),
  app_id text NOT NULL REFERENCES apps(id),
  environment text NOT NULL CHECK (environment IN ('production', 'staging', 'development')),
  day date NOT NULL,
  requests bigint NOT NULL DEFAULT 0 CHECK (requests >= 0),
  sandbox_seconds bigint NOT NULL DEFAULT 0 CHECK (sandbox_seconds >= 0),
  PRIMARY KEY (organization_id, app_id, environment, day)
);
-- The read of a month and the sweep of old days, per Organization.
CREATE INDEX usage_daily_by_day ON usage_daily (organization_id, day);
GRANT SELECT ON usage_daily TO ar_app;
ALTER TABLE usage_daily ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_daily FORCE ROW LEVEL SECURITY;
CREATE POLICY usage_daily_tenant ON usage_daily
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

CREATE TABLE usage_devices (
  organization_id text NOT NULL REFERENCES organizations(id),
  app_id text NOT NULL REFERENCES apps(id),
  month date NOT NULL CHECK (extract(day FROM month) = 1),
  device_ref bytea NOT NULL CHECK (octet_length(device_ref) = 32),
  PRIMARY KEY (organization_id, app_id, month, device_ref)
);
-- The rollup reads and deletes by month.
CREATE INDEX usage_devices_by_month ON usage_devices (month);
GRANT SELECT ON usage_devices TO ar_app;
ALTER TABLE usage_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY usage_devices_tenant ON usage_devices
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

CREATE TABLE usage_device_days (
  organization_id text NOT NULL REFERENCES organizations(id),
  app_id text NOT NULL REFERENCES apps(id),
  day date NOT NULL,
  new_refs integer NOT NULL DEFAULT 0 CHECK (new_refs >= 0),
  capped boolean NOT NULL DEFAULT false,
  PRIMARY KEY (organization_id, app_id, day)
);
CREATE INDEX usage_device_days_by_day ON usage_device_days (day);
GRANT SELECT ON usage_device_days TO ar_app;
ALTER TABLE usage_device_days ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_device_days FORCE ROW LEVEL SECURITY;
CREATE POLICY usage_device_days_tenant ON usage_device_days
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

CREATE TABLE usage_monthly_devices (
  organization_id text NOT NULL REFERENCES organizations(id),
  app_id text NOT NULL REFERENCES apps(id),
  month date NOT NULL CHECK (extract(day FROM month) = 1),
  devices bigint NOT NULL CHECK (devices >= 0),
  capped boolean NOT NULL DEFAULT false,
  PRIMARY KEY (organization_id, app_id, month)
);
CREATE INDEX usage_monthly_devices_by_month ON usage_monthly_devices (month);
GRANT SELECT ON usage_monthly_devices TO ar_app;
ALTER TABLE usage_monthly_devices ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_monthly_devices FORCE ROW LEVEL SECURITY;
CREATE POLICY usage_monthly_devices_tenant ON usage_monthly_devices
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- Adds `n` newly stored Events to the transaction's own Organization's App, Environment and day. Ingest calls it in the
-- transaction of the insert, with the insert's RETURNING count: a batch sent again adds nothing.
CREATE FUNCTION usage_add_requests(p_app_id text, p_environment text, p_day date, p_n bigint)
RETURNS void
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  tenant text := NULLIF(current_setting('app.tenant_id', true), '');
BEGIN
  IF tenant IS NULL THEN
    RAISE EXCEPTION 'usage: no tenant' USING ERRCODE = '42501';
  END IF;
  IF p_n IS NULL OR p_n < 0 OR p_day IS NULL THEN
    RAISE EXCEPTION 'usage: not a count' USING ERRCODE = '22023';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM public.apps a WHERE a.id = p_app_id AND a.organization_id = tenant) THEN
    RAISE EXCEPTION 'usage: not an App of the tenant' USING ERRCODE = '42501';
  END IF;
  IF p_n = 0 THEN
    RETURN;
  END IF;
  INSERT INTO public.usage_daily AS u (organization_id, app_id, environment, day, requests)
  VALUES (tenant, p_app_id, p_environment, p_day, p_n)
  ON CONFLICT (organization_id, app_id, environment, day) DO UPDATE SET requests = u.requests + EXCLUDED.requests;
END
$$;
REVOKE ALL ON FUNCTION usage_add_requests(text, text, date, bigint) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION usage_add_requests(text, text, date, bigint) TO ar_app;

-- Records that a device received an Attestation Token with a counted verdict at `p_at`: its reference `p_ref` (the
-- HMAC the API computed under the month's salt) for the App and UTC month, once. At most `p_cap` new references per App
-- and UTC day: beyond it nothing is recorded and the day is flagged as capped (a device already recorded this month
-- still answers `known`). The Organization is the App's (the attest route has no tenant). Answers `recorded`, `known`,
-- `capped` or `unknown_app`. Granted to the request role.
CREATE FUNCTION usage_record_device(p_app_id text, p_ref bytea, p_at timestamptz, p_cap integer)
RETURNS text
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  org text;
  m date;
  d date;
  n integer;
BEGIN
  IF p_ref IS NULL OR octet_length(p_ref) <> 32 OR p_at IS NULL OR p_cap IS NULL OR p_cap < 0 THEN
    RAISE EXCEPTION 'usage: not a device reference' USING ERRCODE = '22023';
  END IF;
  SELECT a.organization_id INTO org FROM public.apps a WHERE a.id = p_app_id;
  IF org IS NULL THEN
    RETURN 'unknown_app';
  END IF;
  d := (p_at AT TIME ZONE 'UTC')::date;
  m := date_trunc('month', d)::date;
  IF EXISTS (
    SELECT 1 FROM public.usage_devices x
    WHERE x.organization_id = org AND x.app_id = p_app_id AND x.month = m AND x.device_ref = p_ref
  ) THEN
    RETURN 'known';
  END IF;
  -- The day's counter, locked: concurrent recordings of one App and day take turns.
  INSERT INTO public.usage_device_days (organization_id, app_id, day) VALUES (org, p_app_id, d)
  ON CONFLICT (organization_id, app_id, day) DO NOTHING;
  SELECT x.new_refs INTO n FROM public.usage_device_days x
  WHERE x.organization_id = org AND x.app_id = p_app_id AND x.day = d
  FOR UPDATE;
  IF n >= p_cap THEN
    UPDATE public.usage_device_days x SET capped = true
    WHERE x.organization_id = org AND x.app_id = p_app_id AND x.day = d AND NOT x.capped;
    RETURN 'capped';
  END IF;
  INSERT INTO public.usage_devices (organization_id, app_id, month, device_ref)
  VALUES (org, p_app_id, m, p_ref)
  ON CONFLICT DO NOTHING;
  IF NOT FOUND THEN
    RETURN 'known';
  END IF;
  UPDATE public.usage_device_days x SET new_refs = x.new_refs + 1
  WHERE x.organization_id = org AND x.app_id = p_app_id AND x.day = d;
  RETURN 'recorded';
END
$$;
REVOKE ALL ON FUNCTION usage_record_device(text, bytea, timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION usage_record_device(text, bytea, timestamptz, integer) TO ar_app;

-- The most a run is metered, in seconds: the tier's seconds plus the runner's grace of 120 s (review M1).
CREATE FUNCTION usage_sandbox_cap_seconds(p_tier text)
RETURNS bigint
LANGUAGE sql IMMUTABLE
AS $$
  SELECT CASE p_tier WHEN 'T1' THEN 900 WHEN 'T2' THEN 7200 WHEN 'T3' THEN 28800 END + 120
$$;

-- The sandbox seconds of an Assessment, recorded once: when its status moves from queued or running to an end
-- (finished by the runner, or failed by the interruption on start), on the UTC day of `finished_at`. The run time is
-- the call log's `seconds` for a failed run that has one, else `finished_at - started_at`, else (no start) the call
-- log's `seconds`, else nothing; rounded up to a whole second, and never more than `usage_sandbox_cap_seconds`: a run
-- interrupted by a stop is not billed for the outage before the restart (review M1).
CREATE FUNCTION usage_assessment_finished()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  secs bigint := 0;
  logged boolean := NEW.call_totals IS NOT NULL AND jsonb_typeof(NEW.call_totals->'seconds') = 'number';
BEGIN
  IF logged AND (NEW.status = 'failed' OR NEW.started_at IS NULL) THEN
    secs := ceil((NEW.call_totals->>'seconds')::numeric)::bigint;
  ELSIF NEW.started_at IS NOT NULL THEN
    secs := ceil(extract(epoch FROM NEW.finished_at - NEW.started_at))::bigint;
  END IF;
  secs := LEAST(GREATEST(secs, 0), COALESCE(public.usage_sandbox_cap_seconds(NEW.tier), 0));
  IF secs > 0 THEN
    INSERT INTO public.usage_daily AS u (organization_id, app_id, environment, day, sandbox_seconds)
    VALUES (NEW.organization_id, NEW.app_id, NEW.environment, (NEW.finished_at AT TIME ZONE 'UTC')::date, secs)
    ON CONFLICT (organization_id, app_id, environment, day)
    DO UPDATE SET sandbox_seconds = u.sandbox_seconds + EXCLUDED.sandbox_seconds;
  END IF;
  RETURN NULL;
END
$$;
REVOKE ALL ON FUNCTION usage_assessment_finished() FROM PUBLIC;
CREATE TRIGGER assessments_usage
  AFTER UPDATE OF status ON assessments
  FOR EACH ROW
  WHEN (OLD.status IN ('queued', 'running') AND NEW.status IN ('scored', 'inconclusive', 'failed')
    AND NEW.finished_at IS NOT NULL)
  EXECUTE FUNCTION usage_assessment_finished();

-- The daily rollup. A month is closed once it ended at least an hour before `p_at` (an attestation in flight at the turn
-- of the month lands before its month closes). Each App-month of a closed month is counted once (review L1): the
-- App-months come from `usage_device_days` (at most 31 rows each), each count reads that App-month's references once
-- by primary key, and the day rows are then deleted, so a later call does not count again. An App-month already
-- counted keeps its count (a late reference changes nothing) and gains the cap flag if it has one. Then at most
-- `p_batch` references of closed months are deleted, and at most `p_batch` rows each of `usage_daily` and
-- `usage_monthly_devices` older than 13 months before `p_at`'s month. Answers the rows removed per Organization and
-- table (references and old usage), and whether a step used its whole batch.
CREATE FUNCTION usage_rollup(p_at timestamptz, p_batch integer)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  lim integer := LEAST(GREATEST(COALESCE(p_batch, 1), 1), 100000);
  closed_before date;
  keep_from date;
  counts jsonb := '{}'::jsonb;
  saturated boolean := false;
  total bigint;
  g record;
  r record;
BEGIN
  IF p_at IS NULL THEN
    RAISE EXCEPTION 'usage rollup: no time' USING ERRCODE = '22023';
  END IF;
  closed_before := date_trunc('month', (p_at - interval '1 hour') AT TIME ZONE 'UTC')::date;
  keep_from := (date_trunc('month', p_at AT TIME ZONE 'UTC') - interval '13 months')::date;

  FOR g IN
    SELECT x.organization_id, x.app_id, date_trunc('month', x.day)::date AS month, bool_or(x.capped) AS capped
    FROM public.usage_device_days x
    WHERE x.day < closed_before
    GROUP BY 1, 2, 3
  LOOP
    INSERT INTO public.usage_monthly_devices AS m (organization_id, app_id, month, devices, capped)
    SELECT g.organization_id, g.app_id, g.month, count(*), g.capped
    FROM public.usage_devices d
    WHERE d.organization_id = g.organization_id AND d.app_id = g.app_id AND d.month = g.month
    ON CONFLICT (organization_id, app_id, month) DO UPDATE SET capped = m.capped OR EXCLUDED.capped;
  END LOOP;
  DELETE FROM public.usage_device_days x WHERE x.day < closed_before;

  -- References of closed months, at most `lim`, each deleted by its row address: the call reads its batch only.
  total := 0;
  FOR r IN
    SELECT x.ctid AS address FROM public.usage_devices x WHERE x.month < closed_before LIMIT lim
  LOOP
    DELETE FROM public.usage_devices d WHERE d.ctid = r.address RETURNING d.organization_id INTO g;
    IF g.organization_id IS NOT NULL THEN
      counts := public.retention_add(counts, g.organization_id, 'usage_devices', 1);
      total := total + 1;
    END IF;
  END LOOP;
  saturated := saturated OR total >= lim;

  total := 0;
  FOR r IN
    WITH gone AS (
      DELETE FROM public.usage_daily u
      WHERE u.ctid = ANY (ARRAY(SELECT x.ctid FROM public.usage_daily x WHERE x.day < keep_from LIMIT lim))
      RETURNING u.organization_id
    )
    SELECT organization_id, count(*)::integer AS n FROM gone GROUP BY organization_id
  LOOP
    counts := public.retention_add(counts, r.organization_id, 'usage_daily', r.n);
    total := total + r.n;
  END LOOP;
  saturated := saturated OR total >= lim;

  total := 0;
  FOR r IN
    WITH gone AS (
      DELETE FROM public.usage_monthly_devices m
      WHERE m.ctid = ANY (ARRAY(SELECT x.ctid FROM public.usage_monthly_devices x WHERE x.month < keep_from LIMIT lim))
      RETURNING m.organization_id
    )
    SELECT organization_id, count(*)::integer AS n FROM gone GROUP BY organization_id
  LOOP
    counts := public.retention_add(counts, r.organization_id, 'usage_monthly_devices', r.n);
    total := total + r.n;
  END LOOP;
  saturated := saturated OR total >= lim;

  RETURN jsonb_build_object('rows', counts, 'saturated', saturated);
END
$$;
REVOKE ALL ON FUNCTION usage_rollup(timestamptz, integer) FROM PUBLIC;
