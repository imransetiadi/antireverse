-- Slice 18b: data controls (FR-CON-11, SECURITY §8, OPERATION §17, TC-CON-007). Runs once, as the owner of the
-- database, inside one transaction.
--
-- - `organization_deletions`: one row per deletion request. The owner's table: the request role has no privilege on
--   it and reaches it only through the definer functions below, each bound to the transaction's own Organization
--   (`app.tenant_id`), except the report, which is read by its unguessable id. It has no foreign key to
--   `organizations`: the row is the tombstone that outlives the purge, and the purge clears its name and reason.
-- - `organization_purge(org, at)`: deletes every row of the Organization in every table that has an `organization_id`
--   column, taken from the catalog at run time (so a table added later is purged without touching this function),
--   children before parents, the audit chain included, then the `organizations` row; marks the deletion purged and
--   answers the rows deleted per table. Owner only: the request role cannot execute it, and it has no DELETE
--   privilege on the audit tables whatever it sets (the append-only property of 0031/0032 for the request role).
-- - `subject_erase(hash, at)`: deletes the transaction's Organization's Events of one actor hash and its ended
--   (lifted or expired) blocks of that hash. The request role has no DELETE on either table otherwise.

CREATE TABLE organization_deletions (
  id text PRIMARY KEY CHECK (id ~ '^del_[0-9a-f]{24}$'),
  organization_id text NOT NULL CHECK (organization_id ~ '^org_[0-9a-f]{24}$'),
  -- The name as typed in the confirmation; cleared by the purge.
  organization_name text CHECK (char_length(organization_name) BETWEEN 1 AND 200),
  requested_at timestamptz NOT NULL,
  requested_by text NOT NULL CHECK (requested_by ~ '^key_[0-9a-f]{24}$'),
  -- Cleared by the purge (the audit entry that also held it is purged with the chain).
  reason text CHECK (char_length(reason) BETWEEN 1 AND 500),
  purge_after timestamptz NOT NULL CHECK (purge_after > requested_at),
  cancelled_at timestamptz,
  purged_at timestamptz,
  -- The deletion report (rows per table, times) and its Ed25519 signature by the audit key; written by the purge job.
  report jsonb,
  report_signature text CHECK (report_signature ~ '^[A-Za-z0-9_-]{86}$'),
  report_key_id text CHECK (report_key_id ~ '^[0-9a-f]{16}$'),
  CHECK (cancelled_at IS NULL OR purged_at IS NULL),
  CHECK ((report IS NULL) = (report_signature IS NULL) AND (report IS NULL) = (report_key_id IS NULL)),
  CHECK (report IS NULL OR purged_at IS NOT NULL)
);
-- At most one pending deletion per Organization.
CREATE UNIQUE INDEX organization_deletions_one_pending ON organization_deletions (organization_id)
  WHERE cancelled_at IS NULL AND purged_at IS NULL;
-- The purge job's question: which pending deletions are due.
CREATE INDEX organization_deletions_due ON organization_deletions (purge_after)
  WHERE cancelled_at IS NULL AND purged_at IS NULL;
REVOKE ALL ON organization_deletions FROM PUBLIC;

-- The transaction's Organization's pending deletion, if any. Every key request asks it (the gate).
CREATE FUNCTION organization_deletion_pending()
RETURNS TABLE (id text, organization_id text, requested_at timestamptz, purge_after timestamptz,
  cancelled_at timestamptz, purged_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT d.id, d.organization_id, d.requested_at, d.purge_after, d.cancelled_at, d.purged_at
  FROM public.organization_deletions d
  WHERE d.organization_id = NULLIF(current_setting('app.tenant_id', true), '')
    AND d.cancelled_at IS NULL AND d.purged_at IS NULL
$$;
REVOKE ALL ON FUNCTION organization_deletion_pending() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_deletion_pending() TO ar_app;

-- Records a deletion request of the transaction's Organization by one of its admin keys. A second pending request is
-- a unique violation (23505).
CREATE FUNCTION organization_deletion_request(p_id text, p_requested_by text, p_reason text, p_at timestamptz,
  p_purge_after timestamptz)
RETURNS TABLE (id text, organization_id text, requested_at timestamptz, purge_after timestamptz,
  cancelled_at timestamptz, purged_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
#variable_conflict use_column
DECLARE
  tenant text := NULLIF(current_setting('app.tenant_id', true), '');
BEGIN
  IF tenant IS NULL THEN
    RAISE EXCEPTION 'organization deletion: no tenant' USING ERRCODE = '42501';
  END IF;
  IF NOT EXISTS (
    SELECT 1 FROM public.api_keys k
    WHERE k.id = p_requested_by AND k.organization_id = tenant AND k.kind = 'admin' AND k.revoked_at IS NULL
  ) THEN
    RAISE EXCEPTION 'organization deletion: not an admin key of the Organization' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  INSERT INTO public.organization_deletions AS d (id, organization_id, organization_name, requested_at, requested_by,
    reason, purge_after)
  SELECT p_id, o.id, o.name, p_at, p_requested_by, p_reason, p_purge_after
  FROM public.organizations o WHERE o.id = tenant
  RETURNING d.id, d.organization_id, d.requested_at, d.purge_after, d.cancelled_at, d.purged_at;
END
$$;
REVOKE ALL ON FUNCTION organization_deletion_request(text, text, text, timestamptz, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_deletion_request(text, text, text, timestamptz, timestamptz) TO ar_app;

-- Cancels the transaction's Organization's pending deletion; no row when there is none.
CREATE FUNCTION organization_deletion_cancel(p_at timestamptz)
RETURNS TABLE (id text, organization_id text, requested_at timestamptz, purge_after timestamptz,
  cancelled_at timestamptz, purged_at timestamptz)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
#variable_conflict use_column
DECLARE
  tenant text := NULLIF(current_setting('app.tenant_id', true), '');
BEGIN
  IF tenant IS NULL THEN
    RAISE EXCEPTION 'organization deletion: no tenant' USING ERRCODE = '42501';
  END IF;
  RETURN QUERY
  UPDATE public.organization_deletions AS d SET cancelled_at = p_at
  WHERE d.organization_id = tenant AND d.cancelled_at IS NULL AND d.purged_at IS NULL
  RETURNING d.id, d.organization_id, d.requested_at, d.purge_after, d.cancelled_at, d.purged_at;
END
$$;
REVOKE ALL ON FUNCTION organization_deletion_cancel(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_deletion_cancel(timestamptz) TO ar_app;

-- The signed report of a purged deletion, by its id; no row for an unknown, pending or cancelled one.
CREATE FUNCTION organization_deletion_report(p_id text)
RETURNS TABLE (report jsonb, report_signature text, report_key_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT d.report, d.report_signature, d.report_key_id
  FROM public.organization_deletions d
  WHERE d.id = p_id AND d.purged_at IS NOT NULL AND d.report IS NOT NULL
$$;
REVOKE ALL ON FUNCTION organization_deletion_report(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION organization_deletion_report(text) TO ar_app;

-- The purge. Owner only (no grant): the purge job runs it in an owner transaction.
CREATE FUNCTION organization_purge(p_organization text, p_at timestamptz)
RETURNS jsonb
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  deletion_id text;
  tbl record;
  n bigint;
  counts jsonb := '{}'::jsonb;
BEGIN
  SELECT d.id INTO deletion_id FROM public.organization_deletions d
  WHERE d.organization_id = p_organization AND d.cancelled_at IS NULL AND d.purged_at IS NULL
    AND d.purge_after <= p_at
  FOR UPDATE;
  IF NOT FOUND THEN
    RAISE EXCEPTION 'organization purge: no due deletion' USING ERRCODE = '55000';
  END IF;
  -- Every table with an organization_id column, ordered so that a table is emptied before any table it references
  -- (its height: the longest chain of tables referencing it). The tombstones are not the Organization's data.
  FOR tbl IN
    WITH RECURSIVE tenant AS (
      SELECT c.oid AS rel, c.relname::text AS name
      FROM pg_catalog.pg_class c
      JOIN pg_catalog.pg_attribute a ON a.attrelid = c.oid AND a.attname = 'organization_id' AND NOT a.attisdropped
      WHERE c.relnamespace = 'public'::regnamespace AND c.relkind IN ('r', 'p')
        AND c.relname <> 'organization_deletions'
    ), edges AS (
      SELECT DISTINCT f.conrelid AS child, f.confrelid AS parent
      FROM pg_catalog.pg_constraint f
      WHERE f.contype = 'f' AND f.conrelid <> f.confrelid
        AND f.conrelid IN (SELECT rel FROM tenant) AND f.confrelid IN (SELECT rel FROM tenant)
    ), heights (rel, height) AS (
      SELECT rel, 0 FROM tenant
      UNION ALL
      SELECT e.parent, h.height + 1 FROM heights h JOIN edges e ON e.child = h.rel WHERE h.height < 64
    )
    SELECT t.name, max(h.height) AS height
    FROM heights h JOIN tenant t ON t.rel = h.rel
    GROUP BY t.name
    ORDER BY max(h.height), t.name
  LOOP
    EXECUTE format('DELETE FROM public.%I WHERE organization_id = $1', tbl.name) USING p_organization;
    GET DIAGNOSTICS n = ROW_COUNT;
    IF n > 0 THEN
      counts := counts || jsonb_build_object(tbl.name, n);
    END IF;
  END LOOP;
  DELETE FROM public.organizations WHERE id = p_organization;
  GET DIAGNOSTICS n = ROW_COUNT;
  IF n > 0 THEN
    counts := counts || jsonb_build_object('organizations', n);
  END IF;
  UPDATE public.organization_deletions
  SET purged_at = p_at, organization_name = NULL, reason = NULL
  WHERE id = deletion_id;
  RETURN jsonb_build_object('deletion_id', deletion_id, 'rows', counts);
END
$$;
REVOKE ALL ON FUNCTION organization_purge(text, timestamptz) FROM PUBLIC;

-- Erases one actor hash of the transaction's Organization: its Events, and its blocks that have ended. Active
-- blocks stay until they end.
CREATE FUNCTION subject_erase(p_ip_hash text, p_at timestamptz)
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
REVOKE ALL ON FUNCTION subject_erase(text, timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION subject_erase(text, timestamptz) TO ar_app;
