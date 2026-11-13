-- Slice 18b review. Runs once, as the owner of the database, inside one transaction.
--
-- - M3: the background work that runs without a request stops for an Organization whose deletion is pending: the
--   Assessment queue no longer lists its Assessments (they stay queued; the purge removes them), and the Prove
--   re-check no longer lists its targets (no probes of its hosts).
-- - Purge backlog: a purge that fails is recorded (`purge_attempts`, `last_failed_at`); the job skips it for an hour
--   and takes it after the rows that never failed, so failing deletions cannot block the others.
-- - Subject requests read and erase Events by Organization and actor hash, without App or Environment: an index of
--   their own (`events_by_actor_hash` leads with App and Environment).

-- A pending deletion of the Organization (the gate's question, for the owner's functions).
CREATE FUNCTION organization_deletion_is_pending(p_organization text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (
    SELECT 1 FROM public.organization_deletions d
    WHERE d.organization_id = p_organization AND d.cancelled_at IS NULL AND d.purged_at IS NULL
  )
$$;
REVOKE ALL ON FUNCTION organization_deletion_is_pending(text) FROM PUBLIC;

CREATE OR REPLACE FUNCTION assessment_queue(p_limit integer)
RETURNS TABLE (organization_id text, assessment_id text, status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT a.organization_id, a.id, a.status
  FROM public.assessments a
  WHERE a.status IN ('queued', 'running')
    AND NOT public.organization_deletion_is_pending(a.organization_id)
  ORDER BY a.created_at, a.id
  LIMIT LEAST(GREATEST(p_limit, 0), 1000)
$$;

CREATE OR REPLACE FUNCTION prove_due_targets(p_cutoff timestamptz, p_limit integer)
RETURNS TABLE (organization_id text, target_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT t.organization_id, t.id
  FROM public.targets t
  WHERE ((t.status = 'verified' AND t.verified_at <= p_cutoff)
     OR (t.status = 'lapsed' AND t.last_checked_at <= p_cutoff))
    AND NOT public.organization_deletion_is_pending(t.organization_id)
  ORDER BY CASE t.status WHEN 'verified' THEN t.verified_at ELSE t.last_checked_at END, t.id
  LIMIT LEAST(GREATEST(p_limit, 0), 1000)
$$;

ALTER TABLE organization_deletions
  ADD COLUMN purge_attempts integer NOT NULL DEFAULT 0 CHECK (purge_attempts >= 0),
  ADD COLUMN last_failed_at timestamptz;

CREATE INDEX events_by_subject ON events (organization_id, (payload->'actor'->>'ip_hash'))
  WHERE payload->'actor'->>'ip_hash' IS NOT NULL;
