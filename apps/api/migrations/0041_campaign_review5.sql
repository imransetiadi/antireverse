-- Slice 15a, fifth independent safety review (D-112, D-113). Runs once, as the owner of the database, inside one
-- transaction. Migrations 0039 and 0040 are not edited.
--
-- - `campaign_requests.asked_chars` is a bucket, not a count (D-113): 0 (nothing), 256 (at most 256 characters), 1024
--   (at most 1,024) or 1000000 (more). A count an engine chooses is a number it can write into the log, one refused
--   row after another; four values a row carry two bits. Counts stored under 0040 are turned into their buckets.
-- - A running Campaign never becomes `refused` (the runner never writes that; "refused" says it did not start).
-- - `campaigns_without_operator_entry`: the Campaigns an operator's stop ended that have no operator entry in their
--   Organization's audit chain yet — what a repeated kill or suspension completes.

ALTER TABLE campaign_requests DISABLE TRIGGER campaign_requests_history;
UPDATE campaign_requests
SET asked_chars = CASE WHEN asked_chars <= 0 THEN 0 WHEN asked_chars <= 256 THEN 256
                       WHEN asked_chars <= 1024 THEN 1024 ELSE 1000000 END
WHERE asked_chars IS NOT NULL;
ALTER TABLE campaign_requests ENABLE TRIGGER campaign_requests_history;
ALTER TABLE campaign_requests DROP CONSTRAINT campaign_requests_asked_chars_check;
ALTER TABLE campaign_requests ADD CONSTRAINT campaign_requests_asked_chars_check
  CHECK (asked_chars IN (0, 256, 1024, 1000000));

-- The states of a Campaign (replaces the function of 0040; the trigger stays). Everything of 0040, and: from running,
-- never to `refused`.
CREATE OR REPLACE FUNCTION campaigns_end_is_final() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  counted boolean;
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
  counted := NEW.checks_ran IS NOT NULL OR NEW.checks_reported IS NOT NULL OR NEW.checks_skipped IS NOT NULL
    OR NEW.checks_inconclusive IS NOT NULL;
  IF OLD.status = 'queued' THEN
    IF NEW.status = 'running' THEN
      IF NEW.pinned_address IS NULL OR NEW.started_at IS NULL OR counted OR NEW.findings_dropped <> 0 THEN
        RAISE EXCEPTION 'a Campaign starts with its pinned address and nothing counted' USING ERRCODE = '23514';
      END IF;
    ELSIF NEW.status IN ('queued', 'stopped', 'refused', 'failed') THEN
      IF NEW.pinned_address IS NOT NULL OR NEW.started_at IS NOT NULL OR counted OR NEW.findings_dropped <> 0 THEN
        RAISE EXCEPTION 'a Campaign that did not start has no address, no start and no counts'
          USING ERRCODE = '23514';
      END IF;
    ELSE
      RAISE EXCEPTION 'a queued Campaign starts, or ends as stopped, refused or failed' USING ERRCODE = '23514';
    END IF;
  ELSE
    IF NEW.pinned_address IS DISTINCT FROM OLD.pinned_address OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
      RAISE EXCEPTION 'the address and the start of a running Campaign do not change' USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'running' AND (counted OR NEW.findings_dropped <> 0) THEN
      RAISE EXCEPTION 'the checks of a Campaign are counted when it ends' USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'refused' THEN
      RAISE EXCEPTION 'a Campaign that started is never refused' USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'completed' AND NOT EXISTS (
        SELECT 1 FROM public.campaign_requests r
        WHERE r.organization_id = OLD.organization_id AND r.campaign_id = OLD.id AND r.outcome = 'sent') THEN
      RAISE EXCEPTION 'a Campaign completes only after a request of it was sent' USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

-- What a repeated operator stop completes: Campaigns that ended with the stop's reason since `p_since` and have no
-- `campaign.operator_kill` entry in their Organization's audit chain. Before any tenant is known, like
-- `campaign_queue`: identifiers only; the entry itself is written in a transaction of the Organization named.
CREATE FUNCTION campaigns_without_operator_entry(p_reason text, p_organization text, p_since timestamptz)
RETURNS TABLE (organization_id text, campaign_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT c.organization_id, c.id
  FROM public.campaigns c
  WHERE c.end_reason = p_reason
    AND p_reason IN ('operator_kill', 'organization_suspended')
    AND c.finished_at >= p_since
    AND (p_organization IS NULL OR c.organization_id = p_organization)
    AND NOT EXISTS (SELECT 1 FROM public.audit_entries a
                    WHERE a.organization_id = c.organization_id AND a.target_id = c.id
                      AND a.action = 'campaign.operator_kill')
  ORDER BY c.finished_at, c.id
  LIMIT 1000
$$;
REVOKE ALL ON FUNCTION campaigns_without_operator_entry(text, text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION campaigns_without_operator_entry(text, text, timestamptz) TO ar_app;
COMMENT ON FUNCTION campaigns_without_operator_entry(text, text, timestamptz) IS
  'Campaign runner (operator stop) only: ids of Campaigns ended by an operator stop that lack the operator entry.';
