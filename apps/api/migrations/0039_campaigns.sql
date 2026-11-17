-- Slice 15a: Pentest Campaigns with a scripted stand-in engine (D-105). Runs once, as the owner of the database,
-- inside one transaction.
--
-- - `campaigns`: one authorised test of an Organization's own Verified Target under the Rules of Engagement version
--   bound at creation. queued → running → completed | stopped | refused | failed | interrupted. An ended Campaign
--   never changes again and never runs again (trigger). At most one queued or running per Organization (index).
-- - `campaign_requests`: the request log, at most 200 rows per Campaign, sent and refused probes alike. No bodies.
-- - `campaign_findings`: what the engine reported, with evidence the gate redacted. `unverified` until a repeat.
-- - `prove_switch`, `prove_suspensions`: the operator's kill switch and suspensions. Not tenant tables: the request
--   role reaches them only through the definer functions below.
-- - The audit log gains two actors: the system (a Campaign it started, ended or refused) and the operator.

-- An audit entry's actor is an admin key (named by its id), the system or the operator (neither has a key).
ALTER TABLE audit_entries DROP CONSTRAINT audit_entries_actor_kind_check;
ALTER TABLE audit_entries DROP CONSTRAINT audit_entries_actor_key_id_check;
ALTER TABLE audit_entries ALTER COLUMN actor_key_id DROP NOT NULL;
ALTER TABLE audit_entries ADD CONSTRAINT audit_entries_actor_kind_check
  CHECK (actor_kind IN ('admin_key', 'system', 'operator'));
ALTER TABLE audit_entries ADD CONSTRAINT audit_entries_actor_key_id_check
  CHECK (CASE WHEN actor_kind = 'admin_key' THEN actor_key_id IS NOT NULL AND actor_key_id ~ '^key_[0-9a-f]{24}$'
              ELSE actor_key_id IS NULL END);

CREATE TABLE campaigns (
  organization_id text NOT NULL REFERENCES organizations(id),
  id text NOT NULL CHECK (id ~ '^cmp_[0-9a-f]{24}$'),
  -- The target as it was at creation. No foreign key: a target may be deleted later; the Campaign keeps its record.
  target_id text NOT NULL CHECK (target_id ~ '^tgt_[0-9a-f]{24}$'),
  host text NOT NULL CHECK (char_length(host) BETWEEN 1 AND 253),
  -- The Rules of Engagement version bound at creation, and its content hash.
  roe_id text NOT NULL CHECK (roe_id ~ '^roe_[0-9a-f]{24}$'),
  roe_sha256 text NOT NULL CHECK (roe_sha256 ~ '^[0-9a-f]{64}$'),
  -- Never `full` in this slice.
  intensity text NOT NULL CHECK (intensity IN ('passive', 'safe-active')),
  engine jsonb NOT NULL CHECK (jsonb_typeof(engine) = 'object'),
  status text NOT NULL CHECK (status IN ('queued', 'running', 'completed', 'stopped', 'refused', 'failed',
    'interrupted')),
  end_reason text CHECK (end_reason ~ '^[a-z_]{1,40}$'),
  -- The creator's declaration that the target is a staging system. Not verified technically.
  staging_declared boolean NOT NULL CHECK (staging_declared),
  created_by text NOT NULL CHECK (created_by ~ '^key_[0-9a-f]{24}$'),
  -- The address resolved once at the start and used for every request.
  pinned_address text CHECK (char_length(pinned_address) BETWEEN 2 AND 45),
  checks_ran integer CHECK (checks_ran >= 0),
  checks_reported integer CHECK (checks_reported >= 0),
  checks_skipped integer CHECK (checks_skipped >= 0),
  -- Checks whose response could not be read as text or in full: they could not tell, and are never counted as ran.
  checks_inconclusive integer CHECK (checks_inconclusive >= 0),
  -- Findings the engine reported that could not be stored: any makes the Campaign end as failed.
  findings_dropped integer NOT NULL DEFAULT 0 CHECK (findings_dropped >= 0),
  -- The owner's stop request: durable, read by the gate before every request.
  stop_requested_at timestamptz,
  stop_requested_by text CHECK (stop_requested_by ~ '^key_[0-9a-f]{24}$'),
  stop_reason text CHECK (char_length(stop_reason) BETWEEN 1 AND 500),
  created_at timestamptz NOT NULL,
  started_at timestamptz,
  finished_at timestamptz,
  PRIMARY KEY (organization_id, id),
  UNIQUE (id),
  CHECK ((status IN ('queued', 'running')) = (end_reason IS NULL)),
  CHECK ((status IN ('queued', 'running')) = (finished_at IS NULL)),
  CHECK (status <> 'queued' OR started_at IS NULL),
  CHECK (status <> 'running' OR started_at IS NOT NULL),
  CHECK ((stop_requested_at IS NULL) = (stop_requested_by IS NULL)),
  CHECK ((stop_requested_at IS NULL) = (stop_reason IS NULL)),
  CHECK ((checks_ran IS NULL) = (checks_reported IS NULL) AND (checks_ran IS NULL) = (checks_skipped IS NULL)
    AND (checks_ran IS NULL) = (checks_inconclusive IS NULL))
);
-- One queued or running Campaign per Organization.
CREATE UNIQUE INDEX campaigns_one_active ON campaigns (organization_id) WHERE status IN ('queued', 'running');
CREATE INDEX campaigns_recent ON campaigns (organization_id, created_at DESC, id DESC);
CREATE INDEX campaigns_queue ON campaigns (created_at, id) WHERE status IN ('queued', 'running');
CREATE INDEX campaigns_finished ON campaigns (organization_id, finished_at) WHERE finished_at IS NOT NULL;
GRANT SELECT, INSERT ON campaigns TO ar_app;
GRANT UPDATE (status, end_reason, pinned_address, checks_ran, checks_reported, checks_skipped, checks_inconclusive, findings_dropped, stop_requested_at,
  stop_requested_by, stop_reason, started_at, finished_at) ON campaigns TO ar_app;
ALTER TABLE campaigns ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaigns FORCE ROW LEVEL SECURITY;
CREATE POLICY campaigns_tenant ON campaigns
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- An end is final, whoever asks: an ended Campaign is never changed, and a running one never goes back to queued.
-- A stop request is set once: it is never cleared or rewritten, on a queued or running Campaign either.
CREATE FUNCTION campaigns_end_is_final() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.status NOT IN ('queued', 'running') THEN
    RAISE EXCEPTION 'a Campaign that ended is final' USING ERRCODE = '23514';
  END IF;
  IF OLD.status = 'running' AND NEW.status = 'queued' THEN
    RAISE EXCEPTION 'a running Campaign is never queued again' USING ERRCODE = '23514';
  END IF;
  IF OLD.stop_requested_at IS NOT NULL AND (NEW.stop_requested_at IS DISTINCT FROM OLD.stop_requested_at
      OR NEW.stop_requested_by IS DISTINCT FROM OLD.stop_requested_by
      OR NEW.stop_reason IS DISTINCT FROM OLD.stop_reason) THEN
    RAISE EXCEPTION 'a stop request is set once' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER campaigns_end_is_final BEFORE UPDATE ON campaigns
  FOR EACH ROW EXECUTE FUNCTION campaigns_end_is_final();

-- The request log: every request the gate judged, sent or refused, in order — the ownership check's GET first. Never
-- a body. A row is written as `sending` BEFORE its request goes out and settled to `sent` with the result (or to
-- `not_sent` when a stop came before it left), so a request that reached the target is in the log whatever fails
-- afterwards. `bytes`: what the connection read (the TLS handshake, headers, body), for failed requests too.
CREATE TABLE campaign_requests (
  organization_id text NOT NULL,
  campaign_id text NOT NULL,
  seq integer NOT NULL CHECK (seq BETWEEN 1 AND 200),
  at timestamptz NOT NULL,
  method text CHECK (method ~ '^[A-Z]{1,16}$'),
  target text CHECK (char_length(target) <= 1024),
  outcome text NOT NULL CHECK (outcome IN ('sending', 'sent', 'not_sent', 'refused')),
  reason text CHECK (reason ~ '^[a-z_]{1,40}$'),
  status integer CHECK (status BETWEEN 100 AND 599),
  failure text CHECK (failure IN ('timeout', 'connect_failed', 'tls_failed', 'aborted', 'invalid_response')),
  bytes integer NOT NULL DEFAULT 0 CHECK (bytes BETWEEN 0 AND 1048576),
  ms integer NOT NULL DEFAULT 0 CHECK (ms >= 0),
  PRIMARY KEY (organization_id, campaign_id, seq),
  FOREIGN KEY (organization_id, campaign_id) REFERENCES campaigns (organization_id, id) ON DELETE CASCADE,
  CHECK ((outcome = 'refused') = (reason IS NOT NULL)),
  CHECK (outcome = 'sent' OR (status IS NULL AND failure IS NULL AND bytes = 0)),
  CHECK (outcome <> 'sent' OR ((status IS NULL) <> (failure IS NULL)))
);
GRANT SELECT, INSERT ON campaign_requests TO ar_app;
-- Settling a `sending` row: nothing else of a row can change (and a settled row not at all: trigger).
GRANT UPDATE (outcome, status, failure, bytes, ms) ON campaign_requests TO ar_app;

-- A Campaign's history, whoever writes: a row is added only while the Campaign is queued or running, and only as
-- the next one (seq = last + 1: no gaps, no row slipped in later); a row changes only once, from `sending` to
-- `sent` or `not_sent` — which is still allowed after the end, for the request that was in flight when it came.
CREATE FUNCTION campaign_requests_history() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  state text;
  last integer;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF OLD.outcome <> 'sending' OR NEW.outcome NOT IN ('sent', 'not_sent') THEN
      RAISE EXCEPTION 'a request log row is settled once, from sending to sent or not_sent' USING ERRCODE = '23514';
    END IF;
    RETURN NEW;
  END IF;
  SELECT c.status INTO state FROM public.campaigns c
  WHERE c.organization_id = NEW.organization_id AND c.id = NEW.campaign_id
  FOR UPDATE;
  IF state IS NULL OR state NOT IN ('queued', 'running') THEN
    RAISE EXCEPTION 'the request log of a Campaign that ended is final' USING ERRCODE = '23514';
  END IF;
  SELECT COALESCE(max(r.seq), 0) INTO last FROM public.campaign_requests r
  WHERE r.organization_id = NEW.organization_id AND r.campaign_id = NEW.campaign_id;
  IF NEW.seq <> last + 1 THEN
    RAISE EXCEPTION 'a request log row is the next one' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER campaign_requests_history BEFORE INSERT OR UPDATE ON campaign_requests
  FOR EACH ROW EXECUTE FUNCTION campaign_requests_history();
ALTER TABLE campaign_requests ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaign_requests FORCE ROW LEVEL SECURITY;
CREATE POLICY campaign_requests_tenant ON campaign_requests
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- Findings of a Campaign, one per check and path. `evidence` is what the gate redacted (request, status, allowlisted
-- headers, an excerpt of at most 2 KB, the SHA-256 of the body read). Unifying with `findings` comes later (D-105).
CREATE TABLE campaign_findings (
  organization_id text NOT NULL,
  campaign_id text NOT NULL,
  check_id text NOT NULL CHECK (check_id ~ '^[A-Z]{2}-[0-9]{2}$'),
  path text NOT NULL CHECK (char_length(path) BETWEEN 1 AND 512),
  title text NOT NULL CHECK (char_length(title) BETWEEN 1 AND 120),
  severity text NOT NULL CHECK (severity IN ('high', 'medium', 'low')),
  state text NOT NULL CHECK (state IN ('unverified', 'confirmed')),
  evidence jsonb NOT NULL CHECK (jsonb_typeof(evidence) = 'object' AND pg_column_size(evidence) <= 16384),
  first_seen_at timestamptz NOT NULL,
  last_seen_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, campaign_id, check_id, path),
  FOREIGN KEY (organization_id, campaign_id) REFERENCES campaigns (organization_id, id) ON DELETE CASCADE
);
GRANT SELECT, INSERT ON campaign_findings TO ar_app;
GRANT UPDATE (state, evidence, last_seen_at) ON campaign_findings TO ar_app;
-- Findings are written while their Campaign is queued or running only: an ended Campaign's Findings are final.
CREATE FUNCTION campaign_findings_history() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  state text;
BEGIN
  SELECT c.status INTO state FROM public.campaigns c
  WHERE c.organization_id = NEW.organization_id AND c.id = NEW.campaign_id
  FOR UPDATE;
  IF state IS NULL OR state NOT IN ('queued', 'running') THEN
    RAISE EXCEPTION 'the Findings of a Campaign that ended are final' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER campaign_findings_history BEFORE INSERT OR UPDATE ON campaign_findings
  FOR EACH ROW EXECUTE FUNCTION campaign_findings_history();
ALTER TABLE campaign_findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE campaign_findings FORCE ROW LEVEL SECURITY;
CREATE POLICY campaign_findings_tenant ON campaign_findings
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- The operator's global kill switch: one row. While `killed`, no Campaign is created or started and the gate refuses
-- every probe.
CREATE TABLE prove_switch (
  singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
  killed boolean NOT NULL DEFAULT false,
  changed_at timestamptz,
  reason text CHECK (char_length(reason) BETWEEN 1 AND 500)
);
INSERT INTO prove_switch DEFAULT VALUES;
REVOKE ALL ON prove_switch FROM PUBLIC;

-- Organizations whose Campaigns the operator suspended. `org_id`, not `organization_id`: this is the operator's
-- list, not the Organization's data (it is neither exported nor swept); it goes with the Organization's row.
CREATE TABLE prove_suspensions (
  org_id text PRIMARY KEY REFERENCES organizations(id) ON DELETE CASCADE,
  suspended_at timestamptz NOT NULL,
  reason text NOT NULL CHECK (char_length(reason) BETWEEN 1 AND 500)
);
REVOKE ALL ON prove_suspensions FROM PUBLIC;

-- What the gate asks before every request, for the transaction's Organization and one of its Campaigns: the kill
-- switch, the Organization's suspension, a stop request and a pending deletion. An unknown Campaign counts as stopped.
CREATE FUNCTION campaign_control(p_campaign_id text)
RETURNS TABLE (killed boolean, suspended boolean, stop_requested boolean, deletion_pending boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT
    (SELECT s.killed FROM public.prove_switch s),
    EXISTS (SELECT 1 FROM public.prove_suspensions p WHERE p.org_id = t.tenant),
    COALESCE((SELECT c.stop_requested_at IS NOT NULL OR c.status <> 'running' FROM public.campaigns c
              WHERE c.organization_id = t.tenant AND c.id = p_campaign_id), true),
    public.organization_deletion_is_pending(t.tenant)
  FROM (SELECT NULLIF(current_setting('app.tenant_id', true), '') AS tenant) t
  WHERE t.tenant IS NOT NULL
$$;
REVOKE ALL ON FUNCTION campaign_control(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION campaign_control(text) TO ar_app;

-- The runner's queue, before any tenant is known, read in pages (so that Campaigns that cannot start now — their
-- Organization's deletion is pending — never hide younger ones): identifiers and hosts of queued and running Campaigns across
-- Organizations, oldest first, and whether the Organization's deletion is pending. Every later read and write
-- happens in a transaction of the Organization named (as `assessment_queue`).
CREATE FUNCTION campaign_queue(p_limit integer, p_offset integer)
RETURNS TABLE (organization_id text, campaign_id text, host text, status text, deletion_pending boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT c.organization_id, c.id, c.host, c.status, public.organization_deletion_is_pending(c.organization_id)
  FROM public.campaigns c
  WHERE c.status IN ('queued', 'running')
  ORDER BY c.created_at, c.id
  LIMIT LEAST(GREATEST(p_limit, 0), 1000) OFFSET GREATEST(p_offset, 0)
$$;
REVOKE ALL ON FUNCTION campaign_queue(integer, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION campaign_queue(integer, integer) TO ar_app;
COMMENT ON FUNCTION campaign_queue(integer, integer) IS
  'Campaign runner and operator routes only: ids and hosts of queued and running Campaigns across Organizations.';

-- On start: a Campaign still running was cut off by a stop or a crash of the API. It becomes interrupted and is never
-- resumed. Queued ones stay queued. Returns the Campaigns interrupted.
CREATE FUNCTION campaigns_interrupt(p_at timestamptz)
RETURNS TABLE (organization_id text, campaign_id text)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
  UPDATE public.campaigns c
  SET status = 'interrupted', end_reason = 'api_restart', finished_at = GREATEST(p_at, c.started_at)
  WHERE c.status = 'running'
  RETURNING c.organization_id, c.id
$$;
REVOKE ALL ON FUNCTION campaigns_interrupt(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION campaigns_interrupt(timestamptz) TO ar_app;

-- The operator's state: the switch, and the suspended Organizations. Called by the operator routes only (behind the
-- operator token), in a transaction without a tenant.
CREATE FUNCTION prove_operator_state()
RETURNS TABLE (killed boolean, killed_at timestamptz, suspended jsonb)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT s.killed, CASE WHEN s.killed THEN s.changed_at END,
    COALESCE((SELECT jsonb_agg(jsonb_build_object('organization_id', p.org_id, 'suspended_at', p.suspended_at)
                               ORDER BY p.suspended_at, p.org_id)
              FROM public.prove_suspensions p), '[]'::jsonb)
  FROM public.prove_switch s
$$;
REVOKE ALL ON FUNCTION prove_operator_state() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION prove_operator_state() TO ar_app;

CREATE FUNCTION prove_switch_set(p_killed boolean, p_at timestamptz, p_reason text)
RETURNS void
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
  UPDATE public.prove_switch SET killed = p_killed, changed_at = p_at, reason = p_reason
$$;
REVOKE ALL ON FUNCTION prove_switch_set(boolean, timestamptz, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION prove_switch_set(boolean, timestamptz, text) TO ar_app;

-- Suspends (or resumes) one Organization. Answers whether anything changed; false for an unknown Organization.
CREATE FUNCTION prove_suspension_set(p_organization text, p_suspended boolean, p_at timestamptz, p_reason text)
RETURNS boolean
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  n integer;
BEGIN
  IF NOT EXISTS (SELECT 1 FROM public.organizations o WHERE o.id = p_organization) THEN
    RETURN false;
  END IF;
  IF p_suspended THEN
    INSERT INTO public.prove_suspensions (org_id, suspended_at, reason) VALUES (p_organization, p_at, p_reason)
    ON CONFLICT (org_id) DO NOTHING;
  ELSE
    DELETE FROM public.prove_suspensions WHERE org_id = p_organization;
  END IF;
  GET DIAGNOSTICS n = ROW_COUNT;
  RETURN n > 0;
END
$$;
REVOKE ALL ON FUNCTION prove_suspension_set(text, boolean, timestamptz, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION prove_suspension_set(text, boolean, timestamptz, text) TO ar_app;

-- Retention (slice 18c): Campaigns that ended more than 395 days ago, with their request log and Findings (cascade).
-- Owner only, like `retention_sweep`; the retention job calls it. Organizations whose deletion is pending are left to
-- the purge. Answers the Campaigns removed per Organization.
CREATE FUNCTION campaigns_retention_sweep(p_at timestamptz, p_batch integer)
RETURNS TABLE (organization_id text, removed integer)
LANGUAGE sql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
  WITH victims AS (
    SELECT c.organization_id, c.id FROM public.campaigns c
    WHERE c.finished_at < p_at - interval '395 days'
      AND NOT public.organization_deletion_is_pending(c.organization_id)
    ORDER BY c.finished_at
    LIMIT LEAST(GREATEST(COALESCE(p_batch, 1), 1), 100000)
  ), gone AS (
    DELETE FROM public.campaigns c USING victims v
    WHERE c.organization_id = v.organization_id AND c.id = v.id
    RETURNING c.organization_id
  )
  SELECT g.organization_id, count(*)::integer FROM gone g GROUP BY g.organization_id
$$;
REVOKE ALL ON FUNCTION campaigns_retention_sweep(timestamptz, integer) FROM PUBLIC;
