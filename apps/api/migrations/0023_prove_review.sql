-- Slice 14, review fixes (plan amendment A3). Runs once, as the owner of the database, inside one transaction.

-- F2: verification limits are kept per (Organization, host) and per Organization, in a table of their own, so that
-- deleting a target and adding the host again does not reset its limit. `subject` is the host, or '*' for the
-- Organization as a whole. Fixed one-hour windows that start at the first attempt; rows of windows that ended are
-- removed by the next attempt of the Organization. Manual verification only: re-checks never count.
CREATE TABLE verify_limits (
  organization_id text NOT NULL REFERENCES organizations(id),
  subject text NOT NULL CHECK (subject = '*' OR (char_length(subject) BETWEEN 1 AND 253
    AND subject ~ '^[a-z0-9][a-z0-9.-]*[a-z0-9]$')),
  window_start timestamptz NOT NULL,
  attempts integer NOT NULL CHECK (attempts BETWEEN 0 AND 1000),
  PRIMARY KEY (organization_id, subject)
);
GRANT SELECT, INSERT, DELETE ON verify_limits TO ar_app;
GRANT UPDATE (window_start, attempts) ON verify_limits TO ar_app;

ALTER TABLE verify_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE verify_limits FORCE ROW LEVEL SECURITY;
CREATE POLICY verify_limits_tenant ON verify_limits
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- The per-target window of 0021 is replaced by the table above.
ALTER TABLE targets DROP COLUMN verify_window_start;
ALTER TABLE targets DROP COLUMN verify_attempts;

-- F5 (accepted, documented): the request role may call this definer function with or without a tenant, and it then
-- lists the identifiers (Organization id, target id) of every Organization's due targets. That is the price of a
-- re-check job that runs before any tenant is known: it returns no host, token or status, every later read and write
-- happens in a transaction of the Organization it names, and target ids are random and useless without that tenant.
COMMENT ON FUNCTION prove_due_targets(timestamptz, integer) IS
  'Re-check job only: ids of due targets across Organizations (no host, token or status). Callable by ar_app with or without a tenant; accepted in slice 14 review F5.';
