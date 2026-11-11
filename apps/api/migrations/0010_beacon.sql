-- Slice 10: the Clone Beacon of a Build (its token and allowed origins), and the `clone-origin` rule's Incidents
-- and Detections. Runs once, as the owner of the database, like 0001_init.sql.

-- One row per Build that carries a beacon, written in the Build's own transaction. Immutable like the Build: the
-- request role may read beacons and add one, nothing else. The token is unique across all Organizations: a
-- report names only the token, so the token alone must name one Build. Tokens are derived from the seed, the
-- App and the version, so two Organizations never derive the same one; a second registration of a token is a
-- conflict (SQL state 23505) and the route answers 409.
CREATE TABLE build_beacons (
  organization_id text NOT NULL REFERENCES organizations(id),
  app_id text NOT NULL REFERENCES apps(id),
  build_id text NOT NULL,
  environment text NOT NULL CHECK (environment IN ('production', 'staging', 'development')),
  token text NOT NULL UNIQUE CHECK (token ~ '^bcn_[0-9a-f]{24}$'),
  -- Canonical origins (the protocol's `OriginSchema`), as the Manifest lists them.
  origins text[] NOT NULL CHECK (cardinality(origins) BETWEEN 1 AND 20),
  created_at timestamptz NOT NULL,
  PRIMARY KEY (organization_id, app_id, build_id),
  FOREIGN KEY (organization_id, app_id, build_id) REFERENCES builds (organization_id, app_id, build_id)
);

GRANT SELECT, INSERT ON build_beacons TO ar_app;

ALTER TABLE build_beacons ENABLE ROW LEVEL SECURITY;
ALTER TABLE build_beacons FORCE ROW LEVEL SECURITY;

-- The same condition as on every tenant table (see 0001_init.sql for why NULLIF is required).
CREATE POLICY build_beacons_tenant ON build_beacons
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- The one lookup that needs no tenant, like `auth_lookup_key`: a public report names a token, and the token
-- names its Build. Every write that follows runs in a transaction of the Organization returned here.
CREATE FUNCTION beacon_lookup_token(p_token text)
RETURNS TABLE (organization_id text, build_id text, app_id text, environment text, origins text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT b.organization_id, b.build_id, b.app_id, b.environment, b.origins
  FROM public.build_beacons b
  WHERE b.token = p_token
$$;
REVOKE ALL ON FUNCTION beacon_lookup_token(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION beacon_lookup_token(text) TO ar_app;

-- A `clone-origin` Incident names the foreign origin and the Build whose beacon reported it, and has no network
-- prefix; its Detections name the origin and the reporter's prefix, which may be unknown. Every other rule has
-- a prefix and no origin.
ALTER TABLE incidents ADD COLUMN origin text CHECK (char_length(origin) <= 255);
ALTER TABLE detections ADD COLUMN origin text CHECK (char_length(origin) <= 255);
ALTER TABLE incidents ALTER COLUMN ip_prefix DROP NOT NULL;
ALTER TABLE detections ALTER COLUMN ip_prefix DROP NOT NULL;

ALTER TABLE incidents DROP CONSTRAINT incidents_rule_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_rule_check
  CHECK (rule IN ('blocked-burst', 'failed-signin-burst', 'canary-touched', 'clone-origin'));
ALTER TABLE detections DROP CONSTRAINT detections_rule_check;
ALTER TABLE detections ADD CONSTRAINT detections_rule_check
  CHECK (rule IN ('blocked-burst', 'failed-signin-burst', 'canary-touched', 'clone-origin'));

-- 0007 tied `build_id` to `canary-touched`; a clone Incident names its Build too.
ALTER TABLE incidents DROP CONSTRAINT incidents_canary_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_canary_check
  CHECK ((rule = 'canary-touched') = (canary_id IS NOT NULL)
    AND (rule IN ('canary-touched', 'clone-origin')) = (build_id IS NOT NULL));
ALTER TABLE incidents ADD CONSTRAINT incidents_clone_check
  CHECK (CASE WHEN rule = 'clone-origin' THEN origin IS NOT NULL AND ip_prefix IS NULL
              ELSE origin IS NULL AND ip_prefix IS NOT NULL END);
ALTER TABLE detections ADD CONSTRAINT detections_clone_check
  CHECK (CASE WHEN rule = 'clone-origin' THEN origin IS NOT NULL
              ELSE origin IS NULL AND ip_prefix IS NOT NULL END);

-- One open or acknowledged Incident per (App, Environment, rule, Canary, origin, prefix). NULLs are distinct in
-- a unique index: COALESCE makes them equal, so each rule's groups stay one.
DROP INDEX incidents_active_group;
CREATE UNIQUE INDEX incidents_active_group
  ON incidents (organization_id, app_id, environment, rule, COALESCE(canary_id, ''), COALESCE(origin, ''),
    COALESCE(ip_prefix, ''))
  WHERE status IN ('open', 'acknowledged');
