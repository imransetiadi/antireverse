-- Slice 02: the versions of a Policy, one row per publish, per App and Environment.
-- Runs once, as the owner of the database, like 0001_init.sql.

-- A version is never changed after it was published: a rollback publishes the old Rules as a new version.
-- The primary key is what makes two publishes at once end with two different versions.
CREATE TABLE policy_versions (
  organization_id text NOT NULL REFERENCES organizations(id),
  app_id text NOT NULL REFERENCES apps(id),
  environment text NOT NULL CHECK (environment IN ('production', 'staging', 'development')),
  -- Counts from 1. Version 0 is the built-in Policy without Rules and is never stored.
  version integer NOT NULL CHECK (version >= 1),
  -- The Rules in order, as validated by the API: [{ id, name, path, methods, action, mode }].
  rules jsonb NOT NULL CHECK (jsonb_typeof(rules) = 'array'),
  published_at timestamptz NOT NULL DEFAULT now(),
  -- The prefix of the admin key that published. The key itself is never stored.
  published_by text NOT NULL,
  PRIMARY KEY (organization_id, app_id, environment, version)
);

-- No UPDATE and no DELETE: the request role can read versions and add one, nothing else.
GRANT SELECT, INSERT ON policy_versions TO ar_app;

ALTER TABLE policy_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_versions FORCE ROW LEVEL SECURITY;

-- The same condition as on every tenant table (see 0001_init.sql for why NULLIF is required).
CREATE POLICY policy_versions_tenant ON policy_versions
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));
