-- Slice 07: the Canaries planted in a Build, and the `canary-touched` rule's Incidents and Detections.
-- Runs once, as the owner of the database, like 0001_init.sql.

-- One row per Canary of a registered Build, written in the Build's own transaction. Immutable like the Build:
-- the request role may read Canaries and add them, nothing else. A Canary id is unique within an
-- Organization (a second Build claiming it is a conflict, SQL state 23505); another Organization's ids are
-- never visible, so they never collide. `value` is a decoy, not a secret; it goes into the signed Policy Bundle
-- of its App and Environment and is never returned by an admin route.
CREATE TABLE canaries (
  organization_id text NOT NULL REFERENCES organizations(id),
  id text NOT NULL,
  app_id text NOT NULL REFERENCES apps(id),
  environment text NOT NULL CHECK (environment IN ('production', 'staging', 'development')),
  build_id text NOT NULL,
  -- The Canary's index in its Manifest: the order within a Build, in the bundle.
  position integer NOT NULL CHECK (position >= 0),
  kind text NOT NULL CHECK (kind IN ('key', 'route')),
  value text NOT NULL,
  created_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, id),
  FOREIGN KEY (organization_id, app_id, build_id) REFERENCES builds (organization_id, app_id, build_id)
);
CREATE INDEX canaries_of_build ON canaries (organization_id, app_id, build_id, position);

GRANT SELECT, INSERT ON canaries TO ar_app;

ALTER TABLE canaries ENABLE ROW LEVEL SECURITY;
ALTER TABLE canaries FORCE ROW LEVEL SECURITY;

-- The same condition as on every tenant table (see 0001_init.sql for why NULLIF is required).
CREATE POLICY canaries_tenant ON canaries
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- The Bundle reads the most recent Builds of one App Environment.
CREATE INDEX builds_recent_by_environment ON builds (organization_id, app_id, environment, registered_at DESC, build_id DESC);

-- A `canary-touched` Incident names its Canary and the Build it was planted in; a Detection names its Canary.
-- Every other rule has neither.
ALTER TABLE incidents ADD COLUMN canary_id text, ADD COLUMN build_id text;
ALTER TABLE detections ADD COLUMN canary_id text;

ALTER TABLE incidents DROP CONSTRAINT incidents_rule_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_rule_check
  CHECK (rule IN ('blocked-burst', 'failed-signin-burst', 'canary-touched'));
ALTER TABLE incidents ADD CONSTRAINT incidents_canary_check
  CHECK ((rule = 'canary-touched') = (canary_id IS NOT NULL AND build_id IS NOT NULL)
    AND (canary_id IS NULL) = (build_id IS NULL));
ALTER TABLE detections DROP CONSTRAINT detections_rule_check;
ALTER TABLE detections ADD CONSTRAINT detections_rule_check
  CHECK (rule IN ('blocked-burst', 'failed-signin-burst', 'canary-touched'));
ALTER TABLE detections ADD CONSTRAINT detections_canary_check
  CHECK ((rule = 'canary-touched') = (canary_id IS NOT NULL));

-- One open or acknowledged Incident per (App, Environment, rule, Canary, prefix). The Canary is null for every
-- other rule, and NULLs are distinct in a unique index: COALESCE makes them equal, so those groups stay one.
DROP INDEX incidents_active_group;
CREATE UNIQUE INDEX incidents_active_group
  ON incidents (organization_id, app_id, environment, rule, COALESCE(canary_id, ''), ip_prefix)
  WHERE status IN ('open', 'acknowledged');
