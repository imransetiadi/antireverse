-- Slice 14, re-check follow-ups (Jev, accepted by the owner's coordinator): a re-check that failed only because our
-- own resolver failed (DNS lookup failed and the file's host did not resolve) does not lapse a verified target at
-- once; it is retried at the next run and lapses after 3 such failures in a row. Lapsed targets are re-checked daily
-- too, so that they recover on their own. Runs once, as the owner of the database, inside one transaction.

-- Consecutive re-checks of a verified target that failed on our side only. Reset by any other recorded check.
ALTER TABLE targets ADD COLUMN recheck_misses integer NOT NULL DEFAULT 0 CHECK (recheck_misses BETWEEN 0 AND 1000);
GRANT UPDATE (recheck_misses) ON targets TO ar_app;

CREATE INDEX targets_lapsed_due ON targets (last_checked_at, id) WHERE status = 'lapsed';

-- Due: a verified target whose last successful check is at or before the cutoff, or a lapsed target whose last
-- check of any kind is. Identifiers only, as before.
DROP FUNCTION prove_due_targets(timestamptz, integer);
CREATE FUNCTION prove_due_targets(p_cutoff timestamptz, p_limit integer)
RETURNS TABLE (organization_id text, target_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT t.organization_id, t.id
  FROM public.targets t
  WHERE (t.status = 'verified' AND t.verified_at <= p_cutoff)
     OR (t.status = 'lapsed' AND t.last_checked_at <= p_cutoff)
  ORDER BY CASE t.status WHEN 'verified' THEN t.verified_at ELSE t.last_checked_at END, t.id
  LIMIT LEAST(GREATEST(p_limit, 0), 1000)
$$;
REVOKE ALL ON FUNCTION prove_due_targets(timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION prove_due_targets(timestamptz, integer) TO ar_app;
