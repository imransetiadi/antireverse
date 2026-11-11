-- Slice 20: Virtual patches (D-061). Runs once, as the owner of the database, like 0001_init.sql.

-- The mode an admin chose for one patch in one App Environment. No row: monitor. A row is kept when the patch drops
-- out (its Finding fixed or withdrawn) and applies again when it comes back. Never deleted; the admin key that
-- last changed it and when are recorded with it.
CREATE TABLE patch_modes (
  organization_id text NOT NULL REFERENCES organizations(id),
  app_id text NOT NULL REFERENCES apps(id),
  environment text NOT NULL CHECK (environment IN ('production', 'staging', 'development')),
  patch_id text NOT NULL CHECK (patch_id ~ '^vp_[a-z0-9_]{3,48}$'),
  mode text NOT NULL CHECK (mode IN ('monitor', 'enforce')),
  updated_at timestamptz NOT NULL,
  updated_by text NOT NULL CHECK (updated_by ~ '^key_[0-9a-f]{24}$'),
  PRIMARY KEY (organization_id, app_id, environment, patch_id)
);

GRANT SELECT, INSERT ON patch_modes TO ar_app;
GRANT UPDATE (mode, updated_at, updated_by) ON patch_modes TO ar_app;

ALTER TABLE patch_modes ENABLE ROW LEVEL SECURITY;
ALTER TABLE patch_modes FORCE ROW LEVEL SECURITY;

-- The same condition as on every tenant table (see 0001_init.sql for why NULLIF is required).
CREATE POLICY patch_modes_tenant ON patch_modes
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- A patch's hits (24 hours, last) read the Events of one App Environment that name it.
CREATE INDEX events_by_patch
  ON events (organization_id, app_id, environment, (payload->'decision'->>'patch_id'), received_at)
  WHERE payload->'decision'->>'patch_id' IS NOT NULL;

-- The `exploit-attempt` rule: an Incident per (App, Environment, advisory), without a network prefix, origin or
-- Build; its Detections keep the prefix of the Event (or none).
ALTER TABLE incidents DROP CONSTRAINT incidents_rule_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_rule_check
  CHECK (rule IN ('blocked-burst', 'failed-signin-burst', 'canary-touched', 'clone-origin', 'vulnerable-component',
    'exploit-attempt'));
ALTER TABLE detections DROP CONSTRAINT detections_rule_check;
ALTER TABLE detections ADD CONSTRAINT detections_rule_check
  CHECK (rule IN ('blocked-burst', 'failed-signin-burst', 'canary-touched', 'clone-origin', 'vulnerable-component',
    'exploit-attempt'));

ALTER TABLE incidents DROP CONSTRAINT incidents_clone_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_clone_check
  CHECK (CASE WHEN rule = 'clone-origin' THEN origin IS NOT NULL AND ip_prefix IS NULL
              WHEN rule IN ('vulnerable-component', 'exploit-attempt') THEN origin IS NULL AND ip_prefix IS NULL
              ELSE origin IS NULL AND ip_prefix IS NOT NULL END);
ALTER TABLE incidents DROP CONSTRAINT incidents_advisory_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_advisory_check
  CHECK ((rule IN ('vulnerable-component', 'exploit-attempt')) = (advisory_id IS NOT NULL));
ALTER TABLE detections DROP CONSTRAINT detections_clone_check;
ALTER TABLE detections ADD CONSTRAINT detections_clone_check
  CHECK (CASE WHEN rule = 'clone-origin' THEN origin IS NOT NULL
              WHEN rule = 'vulnerable-component' THEN origin IS NULL AND ip_prefix IS NULL
              WHEN rule = 'exploit-attempt' THEN origin IS NULL
              ELSE origin IS NULL AND ip_prefix IS NOT NULL END);
ALTER TABLE detections DROP CONSTRAINT detections_advisory_check;
ALTER TABLE detections ADD CONSTRAINT detections_advisory_check
  CHECK ((rule IN ('vulnerable-component', 'exploit-attempt')) = (advisory_id IS NOT NULL));
