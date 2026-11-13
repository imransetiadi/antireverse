-- Slice 18a: the audit log (FR-CON-06, SECURITY O6 / SC-LOG-01). Runs once, as the owner of the database, inside one
-- transaction.
--
-- One entry per administrative change, written by the API in the change's own transaction (src/audit.ts), so a change
-- that cannot write its entry does not commit. Entries are hash-chained per Organization: `seq` from 1 without gaps,
-- `prev_hash` the previous entry's `hash` (64 zeros for the first), `hash` = sha256(prev_hash ‖ canonical JSON of the
-- entry without its hash), computed by the API with the protocol's `auditHash`. Retention: at least one year; there is
-- no deletion job, and the request role cannot UPDATE or DELETE an entry.

-- The chain head: one row per Organization, the last `seq` and `hash`. A writer takes it FOR UPDATE inside its
-- transaction, so two changes of one Organization never compute the same `seq`. Verification compares it with the
-- newest entry, so a deleted tail is seen too.
CREATE TABLE audit_heads (
  organization_id text PRIMARY KEY REFERENCES organizations(id),
  seq bigint NOT NULL CHECK (seq >= 0),
  hash text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$')
);

CREATE TABLE audit_entries (
  id text PRIMARY KEY CHECK (id ~ '^aud_[0-9a-f]{24}$'),
  organization_id text NOT NULL REFERENCES organizations(id),
  seq bigint NOT NULL CHECK (seq >= 1),
  at timestamptz NOT NULL,
  actor_kind text NOT NULL CHECK (actor_kind = 'admin_key'),
  actor_key_id text NOT NULL CHECK (actor_key_id ~ '^key_[0-9a-f]{24}$'),
  -- The protocol's closed list (AUDIT_ACTIONS); the API validates it, the column only bounds it.
  action text NOT NULL CHECK (action ~ '^[a-z_]+(\.[a-z_]+)+$' AND char_length(action) <= 64),
  app_id text CHECK (app_id ~ '^app_[0-9a-f]{24}$'),
  target_kind text NOT NULL CHECK (target_kind ~ '^[a-z_]{1,32}$'),
  target_id text NOT NULL CHECK (char_length(target_id) BETWEEN 1 AND 128),
  reason text CHECK (char_length(reason) BETWEEN 1 AND 500),
  summary text NOT NULL CHECK (char_length(summary) BETWEEN 1 AND 500),
  request_id uuid NOT NULL,
  prev_hash text NOT NULL CHECK (prev_hash ~ '^[0-9a-f]{64}$'),
  hash text NOT NULL CHECK (hash ~ '^[0-9a-f]{64}$'),
  UNIQUE (organization_id, seq)
);
-- Listing newest first is the unique index above, read backwards; the filters have their own.
CREATE INDEX audit_entries_by_action ON audit_entries (organization_id, action, seq DESC);
CREATE INDEX audit_entries_by_app ON audit_entries (organization_id, app_id, seq DESC) WHERE app_id IS NOT NULL;
CREATE INDEX audit_entries_by_target ON audit_entries (organization_id, target_id, seq DESC);
CREATE INDEX audit_entries_by_time ON audit_entries (organization_id, at DESC);

-- Append only: no UPDATE, DELETE or TRUNCATE for the request role. The head moves forward, so it may be updated, but
-- never deleted.
GRANT SELECT, INSERT ON audit_entries TO ar_app;
GRANT SELECT, INSERT, UPDATE ON audit_heads TO ar_app;

ALTER TABLE audit_entries ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_entries FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_heads ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_heads FORCE ROW LEVEL SECURITY;
-- The same condition as on every tenant table (see 0001_init.sql for why NULLIF is required).
CREATE POLICY audit_entries_tenant ON audit_entries
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));
CREATE POLICY audit_heads_tenant ON audit_heads
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- Every Organization that exists already starts an empty chain.
INSERT INTO audit_heads (organization_id, seq, hash)
SELECT id, 0, repeat('0', 64) FROM organizations;
