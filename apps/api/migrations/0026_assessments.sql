-- Slice 12a: Reverse Assessment v1. The route inventory of a Build (W1 Map), the uploaded artifacts an Assessment works
-- on, and the Assessments themselves. Runs once, as the owner of the database, inside one transaction, like
-- 0001_init.sql. Every table is a tenant table under row-level security with FORCE.

-- The route inventory a tenant registers beside the Manifest (`METHOD /path`, at most 2,000), written in the Build's
-- own transaction. Never returned by any route and never given to an Assessment's agent: only the W1 verifier reads
-- it. Immutable like the Build.
CREATE TABLE build_routes (
  organization_id text NOT NULL REFERENCES organizations(id),
  app_id text NOT NULL,
  build_id text NOT NULL,
  routes jsonb NOT NULL CHECK (jsonb_typeof(routes) = 'array' AND jsonb_array_length(routes) <= 2000),
  PRIMARY KEY (organization_id, app_id, build_id),
  FOREIGN KEY (organization_id, app_id, build_id) REFERENCES builds (organization_id, app_id, build_id)
);
GRANT SELECT, INSERT ON build_routes TO ar_app;
ALTER TABLE build_routes ENABLE ROW LEVEL SECURITY;
ALTER TABLE build_routes FORCE ROW LEVEL SECURITY;
CREATE POLICY build_routes_tenant ON build_routes
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- An uploaded protected artifact of a Build, whose every file matched the Manifest's SHA-256 (Proof of Ownership).
-- Stored in the database (bytea), not under the data directory: the bytes then sit under the same row-level security,
-- transactions and backups as everything else of the tenant, and an in-memory database (tests) needs no directory.
-- At most 25 MB decoded per artifact (checked by the API, recorded in `bytes`). Kept until `kept_until`: set to the
-- upload plus 30 days, and moved to each finished Assessment's finish plus 30 days. Deleted by the periodic expiry
-- job (`assessment_artifacts_expire`) once `kept_until` passed and no queued or running Assessment uses it.
CREATE TABLE artifacts (
  organization_id text NOT NULL REFERENCES organizations(id),
  id text NOT NULL CHECK (id ~ '^art_[0-9a-f]{24}$'),
  app_id text NOT NULL,
  build_id text NOT NULL,
  files integer NOT NULL CHECK (files BETWEEN 1 AND 1000),
  bytes bigint NOT NULL CHECK (bytes BETWEEN 0 AND 26214400),
  created_at timestamptz NOT NULL,
  kept_until timestamptz NOT NULL,
  PRIMARY KEY (organization_id, id),
  FOREIGN KEY (organization_id, app_id, build_id) REFERENCES builds (organization_id, app_id, build_id)
);
CREATE INDEX artifacts_of_build ON artifacts (organization_id, app_id, build_id, created_at DESC, id DESC);
CREATE INDEX artifacts_expiry ON artifacts (kept_until);
GRANT SELECT, INSERT ON artifacts TO ar_app;
GRANT UPDATE (kept_until) ON artifacts TO ar_app;
ALTER TABLE artifacts ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifacts FORCE ROW LEVEL SECURITY;
CREATE POLICY artifacts_tenant ON artifacts
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- The files of an artifact, by the Manifest's path, with the SHA-256 they were checked against.
CREATE TABLE artifact_files (
  organization_id text NOT NULL,
  artifact_id text NOT NULL,
  path text NOT NULL CHECK (char_length(path) BETWEEN 1 AND 256),
  sha256 text NOT NULL CHECK (sha256 ~ '^[0-9a-f]{64}$'),
  content bytea NOT NULL,
  PRIMARY KEY (organization_id, artifact_id, path),
  FOREIGN KEY (organization_id, artifact_id) REFERENCES artifacts (organization_id, id) ON DELETE CASCADE
);
GRANT SELECT, INSERT ON artifact_files TO ar_app;
ALTER TABLE artifact_files ENABLE ROW LEVEL SECURITY;
ALTER TABLE artifact_files FORCE ROW LEVEL SECURITY;
CREATE POLICY artifact_files_tenant ON artifact_files
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- One Assessment of a Build: queued → running → scored | inconclusive | failed. `results` is the protocol's list of
-- `{ objective, result }` (empty while queued or running; partial when failed); `rrs`, `renormalised` and the
-- inconclusive reason and code are `scoreAssessment`'s. `scope` is the scope statement. `artifact_id` is null once
-- the artifact was deleted (its `kept_until` is then the Assessment's `artifact_kept_until` = null).
CREATE TABLE assessments (
  organization_id text NOT NULL REFERENCES organizations(id),
  id text NOT NULL CHECK (id ~ '^asm_[0-9a-f]{24}$'),
  app_id text NOT NULL,
  build_id text NOT NULL,
  environment text NOT NULL CHECK (environment IN ('production', 'staging', 'development')),
  tier text NOT NULL CHECK (tier IN ('T1', 'T2', 'T3')),
  status text NOT NULL CHECK (status IN ('queued', 'running', 'scored', 'inconclusive', 'failed')),
  results jsonb NOT NULL DEFAULT '[]' CHECK (jsonb_typeof(results) = 'array' AND jsonb_array_length(results) <= 5),
  rrs integer CHECK (rrs BETWEEN 0 AND 100),
  renormalised boolean NOT NULL DEFAULT false,
  inconclusive_reason text CHECK (char_length(inconclusive_reason) BETWEEN 1 AND 500),
  inconclusive_code text CHECK (inconclusive_code IN ('excluded_over_limit')),
  scope jsonb NOT NULL,
  failure_reason text CHECK (char_length(failure_reason) BETWEEN 1 AND 200),
  artifact_id text,
  created_at timestamptz NOT NULL,
  started_at timestamptz,
  finished_at timestamptz,
  PRIMARY KEY (organization_id, id),
  UNIQUE (id),
  FOREIGN KEY (organization_id, app_id, build_id) REFERENCES builds (organization_id, app_id, build_id),
  FOREIGN KEY (organization_id, artifact_id) REFERENCES artifacts (organization_id, id) ON DELETE SET NULL (artifact_id),
  CHECK ((status = 'scored') = (rrs IS NOT NULL)),
  CHECK (renormalised = false OR status = 'scored'),
  CHECK ((status = 'inconclusive') = (inconclusive_reason IS NOT NULL)),
  CHECK ((status = 'inconclusive') = (inconclusive_code IS NOT NULL)),
  CHECK ((status = 'failed') = (failure_reason IS NOT NULL)),
  CHECK (CASE status
           WHEN 'queued' THEN started_at IS NULL AND finished_at IS NULL AND jsonb_array_length(results) = 0
           WHEN 'running' THEN started_at IS NOT NULL AND finished_at IS NULL AND jsonb_array_length(results) = 0
           WHEN 'failed' THEN finished_at IS NOT NULL
           ELSE started_at IS NOT NULL AND finished_at IS NOT NULL AND jsonb_array_length(results) = 5
         END)
);
CREATE INDEX assessments_of_build ON assessments (organization_id, app_id, build_id, created_at DESC, id DESC);
CREATE INDEX assessments_queue ON assessments (created_at, id) WHERE status IN ('queued', 'running');
-- What a run decides is written once by the runner: the request role may insert and read, and change only these.
GRANT SELECT, INSERT ON assessments TO ar_app;
GRANT UPDATE (status, results, rrs, renormalised, inconclusive_reason, inconclusive_code, scope, failure_reason,
  started_at, finished_at) ON assessments TO ar_app;
ALTER TABLE assessments ENABLE ROW LEVEL SECURITY;
ALTER TABLE assessments FORCE ROW LEVEL SECURITY;
CREATE POLICY assessments_tenant ON assessments
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));

-- The queue runs before any tenant is known: identifiers (Organization id, Assessment id) of queued and running
-- Assessments across Organizations, oldest first, and nothing else. Every later read and write happens in a
-- transaction of the Organization it names (as `prove_due_targets`, accepted in slice 14 review F5).
CREATE FUNCTION assessment_queue(p_limit integer)
RETURNS TABLE (organization_id text, assessment_id text, status text)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT a.organization_id, a.id, a.status
  FROM public.assessments a
  WHERE a.status IN ('queued', 'running')
  ORDER BY a.created_at, a.id
  LIMIT LEAST(GREATEST(p_limit, 0), 1000)
$$;
REVOKE ALL ON FUNCTION assessment_queue(integer) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION assessment_queue(integer) TO ar_app;
COMMENT ON FUNCTION assessment_queue(integer) IS
  'Assessment runner only: ids of queued and running Assessments across Organizations (no results, no artifact).';

-- On start, before the runner takes anything: an Assessment still running was cut off by a stop or a crash. It becomes
-- failed with the given reason (its results stay empty: they were never written) and its artifact's retention
-- starts. Returns how many.
CREATE FUNCTION assessments_interrupt(p_at timestamptz, p_reason text)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  n integer;
BEGIN
  WITH failed AS (
    UPDATE public.assessments
    SET status = 'failed', failure_reason = p_reason, finished_at = GREATEST(p_at, started_at)
    WHERE status = 'running'
    RETURNING organization_id, artifact_id, finished_at
  ), kept AS (
    UPDATE public.artifacts ar
    SET kept_until = GREATEST(ar.kept_until, f.finished_at + interval '30 days')
    FROM failed f
    WHERE ar.organization_id = f.organization_id AND ar.id = f.artifact_id
    RETURNING 1
  )
  SELECT count(*) INTO n FROM failed;
  RETURN n;
END
$$;
REVOKE ALL ON FUNCTION assessments_interrupt(timestamptz, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION assessments_interrupt(timestamptz, text) TO ar_app;

-- The periodic expiry: deletes every artifact whose `kept_until` passed and that no queued or running Assessment uses.
-- Its files go with it (cascade); its Assessments keep their results, with `artifact_id` null. Returns how many.
CREATE FUNCTION assessment_artifacts_expire(p_now timestamptz)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  n integer;
BEGIN
  WITH gone AS (
    DELETE FROM public.artifacts ar
    WHERE ar.kept_until <= p_now
      AND NOT EXISTS (
        SELECT 1 FROM public.assessments a
        WHERE a.organization_id = ar.organization_id AND a.artifact_id = ar.id AND a.status IN ('queued', 'running')
      )
    RETURNING 1
  )
  SELECT count(*) INTO n FROM gone;
  RETURN n;
END
$$;
REVOKE ALL ON FUNCTION assessment_artifacts_expire(timestamptz) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION assessment_artifacts_expire(timestamptz) TO ar_app;
