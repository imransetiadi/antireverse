-- Slice 18g: the synthetic probes (OPERATION §7). Runs once, as the owner of the database, inside one transaction.
--
-- - `system_organizations`: the Organizations the API itself owns, by kind. One kind today: `probe`, the Organization
--   and App the synthetic probes publish their marked block in and emit their marked Event from, so that no tenant's
--   data or counts ever hold probe traffic. An operator table like `slo_minutes`: the request role has no right on it
--   at all; the prober reads and writes it as the owner. It holds no key: the probe's keys are made anew at each start
--   and exist as plaintext in the process's memory only.
--   The column is `org_id`, not `organization_id`: the row is the operator's registry, not data of that Organization
--   (the export, the purge and the retention catalog find tenant data by an `organization_id` column). No foreign
--   key: the row is written first and the Organization after it, so a start that is cut in between is completed by the
--   next one instead of leaving an unregistered Organization behind.

CREATE TABLE system_organizations (
  kind text PRIMARY KEY CHECK (kind IN ('probe')),
  org_id text NOT NULL UNIQUE CHECK (org_id ~ '^org_[0-9a-f]{24}$'),
  app_id text NOT NULL UNIQUE CHECK (app_id ~ '^app_[0-9a-f]{24}$'),
  created_at timestamptz NOT NULL
);
REVOKE ALL ON system_organizations FROM PUBLIC;
