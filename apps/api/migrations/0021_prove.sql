-- Slice 14: Verified Targets and Rules of Engagement (D-069). Runs once, as the owner of the database, inside one
-- transaction, like 0001_init.sql.

-- A host an Organization proves it controls. The token is shown to admins only and never logged. A target is
-- pending until a check passes; verified (method, verified_at = the last successful ownership check); lapsed when a
-- later check failed (reason), and verified again when one passes. The attempts window is the per-target rate limit
-- of manual verification (10 per hour, a fixed window that starts at the first attempt).
CREATE TABLE targets (
  organization_id text NOT NULL REFERENCES organizations(id),
  id text PRIMARY KEY CHECK (id ~ '^tgt_[0-9a-f]{24}$'),
  host text NOT NULL CHECK (char_length(host) BETWEEN 1 AND 253 AND host ~ '^[a-z0-9][a-z0-9.-]*[a-z0-9]$'),
  token text NOT NULL CHECK (token ~ '^[A-Za-z0-9_-]{43}$'),
  status text NOT NULL CHECK (status IN ('pending', 'verified', 'lapsed')),
  method text CHECK (method IN ('dns', 'file')),
  verified_at timestamptz,
  last_checked_at timestamptz,
  lapsed_reason text CHECK (char_length(lapsed_reason) BETWEEN 1 AND 200),
  created_at timestamptz NOT NULL,
  verify_window_start timestamptz,
  verify_attempts integer NOT NULL DEFAULT 0 CHECK (verify_attempts BETWEEN 0 AND 1000),
  UNIQUE (organization_id, host),
  CHECK (CASE status
           WHEN 'pending' THEN method IS NULL AND verified_at IS NULL AND lapsed_reason IS NULL
           WHEN 'verified' THEN method IS NOT NULL AND verified_at IS NOT NULL AND lapsed_reason IS NULL
           ELSE method IS NOT NULL AND verified_at IS NOT NULL AND lapsed_reason IS NOT NULL
         END)
);
CREATE INDEX targets_listed ON targets (organization_id, created_at, id);
CREATE INDEX targets_due ON targets (verified_at, id) WHERE status = 'verified';

-- Host, token and creation never change: a new host is a new target.
GRANT SELECT, INSERT, DELETE ON targets TO ar_app;
GRANT UPDATE (status, method, verified_at, last_checked_at, lapsed_reason, verify_window_start, verify_attempts)
  ON targets TO ar_app;

ALTER TABLE targets ENABLE ROW LEVEL SECURITY;
ALTER TABLE targets FORCE ROW LEVEL SECURITY;
CREATE POLICY targets_tenant ON targets
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- Signed Rules of Engagement versions. Immutable: the request role may insert and read, never update or delete. The
-- newest (highest version number of the Organization) is current. `signed_by` is the admin key that signed;
-- `content_sha256` the SHA-256 of the canonical JSON of the five content fields.
CREATE TABLE rules_of_engagement (
  organization_id text NOT NULL REFERENCES organizations(id),
  id text PRIMARY KEY CHECK (id ~ '^roe_[0-9a-f]{24}$'),
  version integer NOT NULL CHECK (version >= 1),
  scope text[] NOT NULL CHECK (cardinality(scope) BETWEEN 1 AND 50),
  exclusions text[] NOT NULL CHECK (cardinality(exclusions) <= 50),
  intensity text NOT NULL CHECK (intensity IN ('passive', 'safe-active', 'full')),
  window_days text[] NOT NULL CHECK (cardinality(window_days) BETWEEN 1 AND 7
    AND window_days <@ ARRAY['mon', 'tue', 'wed', 'thu', 'fri', 'sat', 'sun']),
  window_from text NOT NULL CHECK (window_from ~ '^([01][0-9]|2[0-3]):[0-5][0-9]$'),
  window_to text NOT NULL CHECK (window_to ~ '^(([01][0-9]|2[0-3]):[0-5][0-9]|24:00)$'),
  contacts text[] NOT NULL CHECK (cardinality(contacts) BETWEEN 1 AND 5),
  signed_by text NOT NULL CHECK (signed_by ~ '^key_[0-9a-f]{24}$'),
  signed_at timestamptz NOT NULL,
  content_sha256 text NOT NULL CHECK (content_sha256 ~ '^[0-9a-f]{64}$'),
  UNIQUE (organization_id, version)
);

GRANT SELECT, INSERT ON rules_of_engagement TO ar_app;

ALTER TABLE rules_of_engagement ENABLE ROW LEVEL SECURITY;
ALTER TABLE rules_of_engagement FORCE ROW LEVEL SECURITY;
CREATE POLICY rules_of_engagement_tenant ON rules_of_engagement
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- The daily re-check runs before any tenant is known: this is the only way to find the targets due, across
-- Organizations. It returns identifiers only (no host, no token), oldest check first; every read and write that
-- follows runs in a transaction of the Organization returned here.
CREATE FUNCTION prove_due_targets(p_cutoff timestamptz, p_limit integer)
RETURNS TABLE (organization_id text, target_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT t.organization_id, t.id
  FROM public.targets t
  WHERE t.status = 'verified' AND t.verified_at <= p_cutoff
  ORDER BY t.verified_at, t.id
  LIMIT LEAST(GREATEST(p_limit, 0), 1000)
$$;
REVOKE ALL ON FUNCTION prove_due_targets(timestamptz, integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION prove_due_targets(timestamptz, integer) TO ar_app;
