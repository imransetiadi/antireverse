-- Slice 05: the Builds registered for an App, one row per registered Build. Runs once, as the owner of
-- the database, like 0001_init.sql.

-- A Build is immutable once registered: the request role may read Builds and add one, nothing else.
-- The primary key includes the Organization, so one tenant can never occupy another's Build identifiers,
-- and it is what makes a repeated (organization, app, build) registration a conflict (SQL state 23505).
CREATE TABLE builds (
  organization_id text NOT NULL REFERENCES organizations(id),
  app_id text NOT NULL REFERENCES apps(id),
  build_id text NOT NULL,
  environment text NOT NULL CHECK (environment IN ('production', 'staging', 'development')),
  -- The developer's own version string, not a monotonic number.
  version text NOT NULL,
  profile text NOT NULL CHECK (profile IN ('light', 'balanced', 'maximum')),
  -- The whole Build Manifest, as validated by the API. Holds no source and no secret.
  manifest jsonb NOT NULL,
  registered_at timestamptz NOT NULL DEFAULT now(),
  PRIMARY KEY (organization_id, app_id, build_id)
);
CREATE INDEX builds_recent ON builds (organization_id, app_id, registered_at DESC, build_id DESC);

-- No UPDATE and no DELETE: Builds are immutable.
GRANT SELECT, INSERT ON builds TO ar_app;

ALTER TABLE builds ENABLE ROW LEVEL SECURITY;
ALTER TABLE builds FORCE ROW LEVEL SECURITY;

-- The same condition as on every tenant table (see 0001_init.sql for why NULLIF is required).
CREATE POLICY builds_tenant ON builds
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));
