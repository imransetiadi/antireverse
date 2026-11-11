-- Slice 19: Exposure — the advisories synced from OSV (global), the inventories Harden and Shield send (tenant),
-- and the Findings matching makes of them (tenant). Runs once, as the owner of the database, like 0001_init.sql.

-- Advisories are public data, the same for every Organization: no tenant column and no row-level security. The
-- request role may only read them (matching and the Finding page). Only the sync path writes, and only through the
-- definer function `advisory_upsert` below: the role has no INSERT, UPDATE or DELETE on either table.
CREATE TABLE advisories (
  id text PRIMARY KEY CHECK (char_length(id) <= 120),
  aliases text[] NOT NULL DEFAULT '{}' CHECK (cardinality(aliases) <= 50),
  summary text NOT NULL DEFAULT '' CHECK (char_length(summary) <= 500),
  -- `severityOf` of the advisory, computed when it is stored.
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
  -- The GHSA rating (`database_specific.severity`), when the advisory has one.
  ghsa_severity text CHECK (ghsa_severity IN ('LOW', 'MODERATE', 'HIGH', 'CRITICAL')),
  -- The CVSS vectors (`severity` of the OSV record): v3 scored, v4 for display only.
  cvss jsonb NOT NULL DEFAULT '[]',
  -- The `affected` entries as validated by the protocol's AdvisorySchema.
  affected jsonb NOT NULL,
  published timestamptz NOT NULL,
  modified timestamptz NOT NULL,
  withdrawn timestamptz,
  synced_at timestamptz NOT NULL DEFAULT now()
);

-- The lookup of matching: which advisories name an npm package. One row per (package, advisory).
CREATE TABLE advisory_packages (
  package text NOT NULL CHECK (char_length(package) <= 214),
  advisory_id text NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
  PRIMARY KEY (package, advisory_id)
);
CREATE INDEX advisory_packages_of_advisory ON advisory_packages (advisory_id);

GRANT SELECT ON advisories, advisory_packages TO ar_app;

-- Stores one advisory (inserted, or replaced when its `modified` differs) and its npm package names. Returns
-- 'inserted', 'updated' or 'unchanged'. The caller validated the advisory against the protocol's schema.
CREATE FUNCTION advisory_upsert(
  p_id text, p_aliases text[], p_summary text, p_severity text, p_ghsa_severity text, p_cvss jsonb,
  p_affected jsonb, p_published timestamptz, p_modified timestamptz, p_withdrawn timestamptz, p_packages text[]
)
RETURNS text
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  v_modified timestamptz;
  v_withdrawn timestamptz;
  v_existed boolean;
BEGIN
  SELECT a.modified, a.withdrawn INTO v_modified, v_withdrawn FROM public.advisories a WHERE a.id = p_id FOR UPDATE;
  v_existed := FOUND;
  IF v_existed AND v_modified = p_modified AND v_withdrawn IS NOT DISTINCT FROM p_withdrawn THEN
    RETURN 'unchanged';
  END IF;
  INSERT INTO public.advisories AS a (id, aliases, summary, severity, ghsa_severity, cvss, affected, published,
    modified, withdrawn, synced_at)
  VALUES (p_id, p_aliases, p_summary, p_severity, p_ghsa_severity, p_cvss, p_affected, p_published, p_modified,
    p_withdrawn, now())
  ON CONFLICT (id) DO UPDATE SET aliases = EXCLUDED.aliases, summary = EXCLUDED.summary,
    severity = EXCLUDED.severity, ghsa_severity = EXCLUDED.ghsa_severity, cvss = EXCLUDED.cvss,
    affected = EXCLUDED.affected, published = EXCLUDED.published, modified = EXCLUDED.modified,
    withdrawn = EXCLUDED.withdrawn, synced_at = now();
  DELETE FROM public.advisory_packages ap WHERE ap.advisory_id = p_id;
  INSERT INTO public.advisory_packages (package, advisory_id)
    SELECT DISTINCT name, p_id FROM unnest(p_packages) AS name;
  RETURN CASE WHEN v_existed THEN 'updated' ELSE 'inserted' END;
END
$$;
REVOKE ALL ON FUNCTION advisory_upsert(text, text[], text, text, text, jsonb, jsonb, timestamptz, timestamptz,
  timestamptz, text[]) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION advisory_upsert(text, text[], text, text, text, jsonb, jsonb, timestamptz, timestamptz,
  timestamptz, text[]) TO ar_app;

-- The component lists Harden (one per registered Build) and Shield (the latest per App Environment) sent. Names,
-- versions and the dev flag only. A Build's inventory is immutable; a runtime inventory is replaced by the next.
CREATE TABLE inventories (
  id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
  organization_id text NOT NULL REFERENCES organizations(id),
  app_id text NOT NULL REFERENCES apps(id),
  environment text NOT NULL CHECK (environment IN ('production', 'staging', 'development')),
  source text NOT NULL CHECK (source IN ('build', 'runtime')),
  build_id text,
  components jsonb NOT NULL,
  received_at timestamptz NOT NULL,
  CHECK ((source = 'build') = (build_id IS NOT NULL))
);
CREATE UNIQUE INDEX inventories_one ON inventories (organization_id, app_id, environment, source, COALESCE(build_id, ''));
CREATE INDEX inventories_recent ON inventories (organization_id, app_id, environment, source, received_at DESC);

GRANT SELECT, INSERT ON inventories TO ar_app;
GRANT UPDATE (components, received_at) ON inventories TO ar_app;

-- One advisory matched by one component of one App Environment from one source (and, for a build Finding, one
-- Build). Status: open → fixed by matching; open → ignored (reason, expiry) → open by hand or at the expiry.
CREATE TABLE findings (
  id text PRIMARY KEY CHECK (id ~ '^fnd_[0-9a-f]{24}$'),
  organization_id text NOT NULL REFERENCES organizations(id),
  app_id text NOT NULL REFERENCES apps(id),
  environment text NOT NULL CHECK (environment IN ('production', 'staging', 'development')),
  source text NOT NULL CHECK (source IN ('build', 'runtime')),
  build_id text,
  package text NOT NULL CHECK (char_length(package) <= 214),
  version text NOT NULL CHECK (char_length(version) <= 256),
  dev boolean NOT NULL,
  advisory_id text NOT NULL REFERENCES advisories(id),
  severity text NOT NULL CHECK (severity IN ('critical', 'high', 'medium', 'low', 'unknown')),
  fixed_versions text[] NOT NULL DEFAULT '{}',
  status text NOT NULL CHECK (status IN ('open', 'fixed', 'ignored')),
  ignore_reason text CHECK (char_length(ignore_reason) <= 200),
  ignore_until timestamptz,
  ignore_by text,
  first_seen timestamptz NOT NULL,
  last_seen timestamptz NOT NULL,
  updated_at timestamptz NOT NULL,
  CHECK ((source = 'build') = (build_id IS NOT NULL)),
  CHECK ((status = 'ignored') = (ignore_reason IS NOT NULL AND ignore_until IS NOT NULL AND ignore_by IS NOT NULL)),
  CHECK (ignore_reason IS NULL = (ignore_until IS NULL) AND ignore_until IS NULL = (ignore_by IS NULL))
);
CREATE UNIQUE INDEX findings_one
  ON findings (organization_id, app_id, environment, source, package, version, advisory_id, COALESCE(build_id, ''));
CREATE INDEX findings_recent ON findings (organization_id, last_seen DESC, id DESC);
CREATE INDEX findings_of_scope ON findings (organization_id, app_id, environment, source, status);

GRANT SELECT, INSERT ON findings TO ar_app;
GRANT UPDATE (dev, severity, fixed_versions, status, ignore_reason, ignore_until, ignore_by, last_seen, updated_at)
  ON findings TO ar_app;

ALTER TABLE inventories ENABLE ROW LEVEL SECURITY;
ALTER TABLE inventories FORCE ROW LEVEL SECURITY;
ALTER TABLE findings ENABLE ROW LEVEL SECURITY;
ALTER TABLE findings FORCE ROW LEVEL SECURITY;

-- The same condition as on every tenant table (see 0001_init.sql for why NULLIF is required).
CREATE POLICY inventories_tenant ON inventories
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));
CREATE POLICY findings_tenant ON findings
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- After a sync, every Organization's latest inventories are matched again. The sync has no tenant: this names the
-- Organizations that hold an inventory, and nothing else; each is then matched in its own tenant transaction.
CREATE FUNCTION exposure_inventory_organizations()
RETURNS TABLE (organization_id text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT DISTINCT i.organization_id FROM public.inventories i ORDER BY 1
$$;
REVOKE ALL ON FUNCTION exposure_inventory_organizations() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION exposure_inventory_organizations() TO ar_app;
