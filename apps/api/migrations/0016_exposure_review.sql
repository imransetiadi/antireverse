-- Slice 19 review fixes (plan amendment A7). Runs once, as the owner of the database, like 0001_init.sql.

-- M2: one runtime inventory per running Shield instance (a random id per process); '' is the shared legacy
-- instance of Shields that send none, and every build inventory's. The runtime set of an App Environment is the
-- union of its live instances (a POST within 24 hours); expired instances are deleted by the request role.
ALTER TABLE inventories ADD COLUMN instance text NOT NULL DEFAULT '' CHECK (instance ~ '^([0-9a-f]{32})?$');
ALTER TABLE inventories ADD CONSTRAINT inventories_instance_check2 CHECK (source = 'runtime' OR instance = '');
DROP INDEX inventories_one;
CREATE UNIQUE INDEX inventories_one
  ON inventories (organization_id, app_id, environment, source, COALESCE(build_id, ''), instance);
GRANT DELETE ON inventories TO ar_app;

-- M4: fixed and withdrawn runtime Findings are deleted 30 days after they closed, and an App Environment keeps at
-- most 20,000 Findings (the oldest closed ones go first).
GRANT DELETE ON findings TO ar_app;
CREATE INDEX findings_closed ON findings (organization_id, app_id, environment, updated_at)
  WHERE status IN ('fixed', 'withdrawn');
