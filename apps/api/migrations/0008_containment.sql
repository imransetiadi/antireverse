-- Slice 09: Containments (time-limited blocks of one Actor or one network prefix of an App Environment) and the
-- Organization's never-block allowlist. Runs once, as the owner of the database, like 0001_init.sql.

-- One row per block, created from an Incident. Never deleted: the request role may read and add blocks, and
-- may change only the two columns a lift sets. The status is not stored: it follows from `lifted_at` and from
-- `expires_at` against the clock. An actor block names a keyed hash of the client address, never the address;
-- a prefix block names the Event's /24 or /48 prefix.
CREATE TABLE containments (
  organization_id text NOT NULL REFERENCES organizations(id),
  id text NOT NULL CHECK (id ~ '^cnt_[0-9a-f]{24}$'),
  app_id text NOT NULL REFERENCES apps(id),
  environment text NOT NULL CHECK (environment IN ('production', 'staging', 'development')),
  incident_id text REFERENCES incidents(id),
  target_kind text NOT NULL CHECK (target_kind IN ('actor', 'prefix')),
  ip_hash text CHECK (ip_hash ~ '^iph_[0-9a-f]{32}$'),
  ip_prefix text,
  created_at timestamptz NOT NULL,
  expires_at timestamptz NOT NULL,
  -- The id of the admin key that created, and the one that lifted, the block.
  created_by text NOT NULL CHECK (created_by ~ '^key_[0-9a-f]{24}$'),
  lifted_at timestamptz,
  lifted_by text CHECK (lifted_by ~ '^key_[0-9a-f]{24}$'),
  PRIMARY KEY (organization_id, id),
  CHECK (expires_at > created_at),
  -- Exactly the target member of its kind.
  CHECK ((target_kind = 'actor') = (ip_hash IS NOT NULL) AND (target_kind = 'prefix') = (ip_prefix IS NOT NULL)),
  CHECK ((lifted_at IS NULL) = (lifted_by IS NULL))
);
-- The active blocks of one App Environment (the bundle, the limit, the same-target lookup).
CREATE INDEX containments_active ON containments (organization_id, app_id, environment, expires_at)
  WHERE lifted_at IS NULL;
-- The blocks of one Incident, newest first; and every block of an Organization, newest first.
CREATE INDEX containments_of_incident ON containments (organization_id, incident_id, created_at DESC, id DESC);
CREATE INDEX containments_recent ON containments (organization_id, created_at DESC, id DESC);

GRANT SELECT, INSERT ON containments TO ar_app;
GRANT UPDATE (lifted_at, lifted_by) ON containments TO ar_app;

-- The ranges no Containment may block, per Organization. Canonical CIDR text (the protocol's `CidrSchema`), so
-- that equal ranges are equal strings and the unique constraint finds duplicates. Removed with DELETE.
CREATE TABLE allowlist_entries (
  organization_id text NOT NULL REFERENCES organizations(id),
  id text NOT NULL CHECK (id ~ '^alw_[0-9a-f]{24}$'),
  cidr text NOT NULL,
  note text NOT NULL CHECK (char_length(note) <= 80),
  created_at timestamptz NOT NULL,
  created_by text NOT NULL CHECK (created_by ~ '^key_[0-9a-f]{24}$'),
  PRIMARY KEY (organization_id, id),
  UNIQUE (organization_id, cidr)
);
CREATE INDEX allowlist_entries_order ON allowlist_entries (organization_id, created_at, id);

GRANT SELECT, INSERT, DELETE ON allowlist_entries TO ar_app;

ALTER TABLE containments ENABLE ROW LEVEL SECURITY;
ALTER TABLE containments FORCE ROW LEVEL SECURITY;
ALTER TABLE allowlist_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE allowlist_entries FORCE ROW LEVEL SECURITY;

-- The same condition as on every tenant table (see 0001_init.sql for why NULLIF is required).
CREATE POLICY containments_tenant ON containments
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));
CREATE POLICY allowlist_entries_tenant ON allowlist_entries
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- An Incident's evidence, its Actors and the check that an actor hash belongs to it all read the Events of one
-- App Environment and network prefix in a time span; the check also narrows by actor hash. Both live in the
-- payload (the Event as Shield sent it).
CREATE INDEX events_by_prefix
  ON events (organization_id, app_id, environment, (payload->'actor'->>'ip_prefix'), ts);
CREATE INDEX events_by_actor_hash
  ON events (organization_id, app_id, environment, (payload->'actor'->>'ip_hash'), ts)
  WHERE payload->'actor'->>'ip_hash' IS NOT NULL;
