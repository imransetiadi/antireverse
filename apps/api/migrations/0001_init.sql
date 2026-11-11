-- Slice 01: Organizations, Apps, keys and Events, with row-level security on every tenant table.
-- Runs once, as the superuser that owns the database. Request code never runs as that user: after
-- migrating, the session switches to the role ar_app created below (see src/db/db.ts).

CREATE TABLE organizations (
  id text PRIMARY KEY,
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE apps (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  name text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX apps_recent ON apps (organization_id, created_at DESC, id DESC);

CREATE TABLE api_keys (
  id text PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  kind text NOT NULL CHECK (kind IN ('admin', 'shield')),
  app_id text REFERENCES apps(id),
  environment text CHECK (environment IN ('production', 'staging', 'development')),
  -- SHA-256 of the key as lowercase hex. The key itself is never stored.
  key_hash text NOT NULL UNIQUE,
  prefix text NOT NULL,
  last4 text NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now(),
  revoked_at timestamptz,
  CHECK ((kind = 'shield') = (app_id IS NOT NULL AND environment IS NOT NULL))
);

-- The primary key includes the Organization so that one tenant can never occupy another tenant's
-- event identifiers.
CREATE TABLE events (
  organization_id text NOT NULL,
  event_id uuid NOT NULL,
  app_id text NOT NULL,
  environment text NOT NULL,
  ts timestamptz NOT NULL,
  received_at timestamptz NOT NULL DEFAULT now(),
  type text NOT NULL,
  payload jsonb NOT NULL,
  PRIMARY KEY (organization_id, event_id)
);
CREATE INDEX events_recent ON events (organization_id, app_id, received_at DESC, event_id DESC);

-- The role every request runs as: no login, no superuser, no way around row-level security.
CREATE ROLE ar_app NOLOGIN NOSUPERUSER NOBYPASSRLS NOCREATEDB NOCREATEROLE;
GRANT SELECT, INSERT, UPDATE ON organizations, apps, api_keys, events TO ar_app;
-- Holds file names and checksums only; readable so that an operator can see what was applied.
GRANT SELECT ON schema_migrations TO ar_app;

ALTER TABLE organizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE organizations FORCE ROW LEVEL SECURITY;
ALTER TABLE apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps FORCE ROW LEVEL SECURITY;
ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE ROW LEVEL SECURITY;
ALTER TABLE events ENABLE ROW LEVEL SECURITY;
ALTER TABLE events FORCE ROW LEVEL SECURITY;

-- NULLIF is required: after a transaction that set app.tenant_id the setting reads '' (not NULL).
-- A comparison with NULL is never true, so without a tenant every table is empty and every write fails.
CREATE POLICY organizations_tenant ON organizations
  USING (id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (id = NULLIF(current_setting('app.tenant_id', true), ''));
CREATE POLICY apps_tenant ON apps
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));
CREATE POLICY api_keys_tenant ON api_keys
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));
CREATE POLICY events_tenant ON events
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- Authentication happens before the tenant is known. This is the only way to read a key row without
-- a tenant: it runs as the owner, matches one hash exactly and never returns a revoked key.
CREATE FUNCTION auth_lookup_key(p_hash text)
RETURNS TABLE (key_id text, organization_id text, kind text, app_id text, environment text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT k.id, k.organization_id, k.kind, k.app_id, k.environment
  FROM public.api_keys k
  WHERE k.key_hash = p_hash AND k.revoked_at IS NULL
$$;
REVOKE ALL ON FUNCTION auth_lookup_key(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION auth_lookup_key(text) TO ar_app;
