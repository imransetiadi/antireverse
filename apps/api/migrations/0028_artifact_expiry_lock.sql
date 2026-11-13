-- Slice 12a review hardening: the expiry never deletes an artifact that a reassessment has picked. The request picks the
-- Build's most recent kept artifact with `FOR UPDATE` (re-checking `kept_until` in the same statement) and inserts the
-- queued Assessment in that one transaction; the expiry takes its candidates with `FOR UPDATE SKIP LOCKED`, so a row
-- locked by an in-flight pick is skipped (and, once that transaction commits, is held by its queued Assessment), never
-- deleted from an old snapshot after a wait. Runs once, as the owner of the database, inside one transaction.
CREATE OR REPLACE FUNCTION assessment_artifacts_expire(p_now timestamptz)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  n integer;
BEGIN
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
    RETURNING 1
  )
  SELECT count(*) INTO n FROM gone;
  RETURN n;
END
$$;
REVOKE ALL ON FUNCTION assessment_artifacts_expire(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION assessment_artifacts_expire(timestamptz) TO ar_app;
