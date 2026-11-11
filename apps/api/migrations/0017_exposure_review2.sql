-- Slice 19, second review. Runs once, as the owner of the database, like 0001_init.sql.

-- M-A: an open or ignored build Finding moves to the newest Build that carries its identity.
GRANT UPDATE (build_id) ON findings TO ar_app;

-- L-A: a withdrawn Finding keeps its ignore (restored if the advisory returns before the expiry). Only an ignored
-- Finding must carry one; only an ignored or withdrawn one may.
ALTER TABLE findings DROP CONSTRAINT findings_check1;
ALTER TABLE findings ADD CONSTRAINT findings_ignore_check
  CHECK ((status <> 'ignored' OR ignore_reason IS NOT NULL)
    AND (ignore_reason IS NULL OR status IN ('ignored', 'withdrawn')));

-- The definer functions belong to the sync path only, which runs as the owner (`Db.owner`): the request role may
-- no longer write advisories or list the Organizations that hold an inventory.
REVOKE EXECUTE ON FUNCTION advisory_upsert(text, text[], text, text, text, jsonb, jsonb, timestamptz, timestamptz,
  timestamptz, text[]) FROM ar_app, PUBLIC;
REVOKE EXECUTE ON FUNCTION exposure_inventory_organizations() FROM ar_app, PUBLIC;
