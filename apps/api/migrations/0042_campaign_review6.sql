-- Slice 15a, sixth independent safety review. Runs once, as the owner of the database, inside one transaction.
-- Migrations 0039 to 0041 are not edited.
--
-- - `campaigns_awaiting_operator_entry` replaces `campaigns_without_operator_entry` (0041): what an operator's stop
--   completes is bounded by that stop itself, not by a day. A kill completes the entry of Campaigns that ended as
--   `operator_kill` since the switch was last turned on, and only while it is on; a suspension, of the suspended
--   Organization's Campaigns that ended as `organization_suspended` since it was suspended. A Campaign that ended
--   under an earlier stop, already lifted, is nobody's to complete later: it stays without the entry.
-- - A Campaign's status and its end reason agree: completed with `checks_complete` and with nothing else; stopped
--   with one of the four stops; interrupted with a restart or a shutdown; `engine_error` is never "refused".

DROP FUNCTION campaigns_without_operator_entry(text, text, timestamptz);

CREATE FUNCTION campaigns_awaiting_operator_entry(p_reason text, p_organization text)
RETURNS TABLE (organization_id text, campaign_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT c.organization_id, c.id
  FROM public.campaigns c
  WHERE c.end_reason = p_reason
    AND (p_organization IS NULL OR c.organization_id = p_organization)
    AND c.finished_at >= CASE p_reason
      -- Since the kill that is on now; no kill on, no row (a comparison with NULL holds for none).
      WHEN 'operator_kill' THEN (SELECT s.changed_at FROM public.prove_switch s WHERE s.killed)
      -- Since this Organization's suspension that is on now.
      WHEN 'organization_suspended' THEN
        (SELECT p.suspended_at FROM public.prove_suspensions p WHERE p.org_id = c.organization_id)
    END
    AND NOT EXISTS (SELECT 1 FROM public.audit_entries a
                    WHERE a.organization_id = c.organization_id AND a.target_id = c.id
                      AND a.action = 'campaign.operator_kill')
  ORDER BY c.finished_at, c.id
  LIMIT 1000
$$;
REVOKE ALL ON FUNCTION campaigns_awaiting_operator_entry(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION campaigns_awaiting_operator_entry(text, text) TO ar_app;
COMMENT ON FUNCTION campaigns_awaiting_operator_entry(text, text) IS
  'Campaign runner (operator stop) only: ids of Campaigns the stop that is on now ended and that lack its entry.';

-- A status and an end reason that contradict each other are refused, whoever writes: the request role could write
-- `stopped` beside `checks_complete`. This is the mapping the runner has always obeyed (`statusOfEndReason`); every
-- other reason ends a Campaign as failed (it had started) or refused (it had not), which the state trigger judges.
ALTER TABLE campaigns ADD CONSTRAINT campaigns_status_matches_end_reason CHECK (
  end_reason IS NULL OR (
    (status = 'completed') = (end_reason = 'checks_complete')
    AND (status = 'stopped')
      = (end_reason IN ('owner_stop', 'operator_kill', 'organization_suspended', 'deletion_pending'))
    AND (status = 'interrupted') = (end_reason IN ('api_restart', 'api_shutdown'))
    AND NOT (status = 'refused' AND end_reason = 'engine_error')
  )
);
