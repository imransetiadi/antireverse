-- Slice 21a: tamper detection. A registered Build may carry an integrity marker (`manifest.integrity.files`); an
-- attestation may report the hashes a browser observed for those files; a mismatch on an armed Build records a
-- `tampered-build` Detection. No new table (D-100): two columns on `detections`, one on `builds`. Runs once, as the
-- owner of the database, inside one transaction.

-- A `tampered-build` Detection names the file (a path of the Build's `integrity.files`) and the SHA-256 a browser
-- observed for it, as lowercase hex like `artifacts[].sha256`. Every other rule has neither.
ALTER TABLE detections
  ADD COLUMN artifact_path text CHECK (char_length(artifact_path) BETWEEN 1 AND 256),
  ADD COLUMN observed_sha256 text CHECK (observed_sha256 ~ '^[0-9a-f]{64}$');

-- When the Build was armed: the time of its first fully matching integrity report. Null until then, and before it no
-- report of the Build can record a Detection. A Build stays immutable apart from this one column, which the request
-- role may set (the recorder sets it once, in a transaction of the Build's Organization).
ALTER TABLE builds ADD COLUMN integrity_first_match_at timestamptz;
GRANT UPDATE (integrity_first_match_at) ON builds TO ar_app;

-- Set once: the column may go from NULL to a time and never change again, whoever asks (the request role and the
-- owner alike). An armed Build can be neither disarmed nor re-dated. An UPDATE that leaves it as it is passes.
CREATE FUNCTION builds_integrity_first_match_once() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF OLD.integrity_first_match_at IS NOT NULL
     AND NEW.integrity_first_match_at IS DISTINCT FROM OLD.integrity_first_match_at THEN
    RAISE EXCEPTION 'integrity_first_match_at is set once' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER builds_integrity_first_match_once BEFORE UPDATE ON builds
  FOR EACH ROW EXECUTE FUNCTION builds_integrity_first_match_once();

-- A `tampered-build` Incident says when a cap first dropped a distinct observed hash while it was open: its
-- Detections then show fewer distinct hashes than were reported. Null otherwise, and for every other rule.
ALTER TABLE incidents ADD COLUMN capped_at timestamptz;
GRANT UPDATE (capped_at) ON incidents TO ar_app;

-- The one lookup that needs no tenant, like `beacon_lookup_token`: the public attestation endpoint has no key. An
-- integrity report names its App (proved by the attestation's nonce) and a Build id. The function answers what
-- reports of that App are judged against and nothing else: the App's Organization, and for the named Build and the
-- App's newest 20 Builds their Environment, the marker's files, the registered digests of exactly those files, and
-- whether the Build is armed. One call so warms every recent Build of the App: after a restart the recorder asks
-- once per App, not once per Build. An App without such a Build answers one row with its Organization only; an
-- unknown App answers none. Every read and write that follows runs in a transaction of the Organization returned.
-- It reads at most 21 Manifests, each in one pass (`builds_recent`, 0004, orders them).
CREATE FUNCTION integrity_lookup_builds(p_app_id text, p_build_id text)
RETURNS TABLE (organization_id text, build_id text, environment text, files jsonb, digests jsonb,
  first_match_at timestamptz)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT a.organization_id, b.build_id, b.environment, m.files,
    (SELECT COALESCE(jsonb_object_agg(x->>'path', x->>'sha256'), '{}'::jsonb)
     FROM jsonb_array_elements(b.manifest->'artifacts') AS x
     WHERE x->>'path' = ANY (ARRAY(SELECT jsonb_array_elements_text(m.files)))),
    b.integrity_first_match_at
  FROM public.apps a
  LEFT JOIN public.builds b ON b.organization_id = a.organization_id AND b.app_id = a.id
    AND (b.build_id = p_build_id OR b.build_id IN (
      SELECT r.build_id FROM public.builds r
      WHERE r.organization_id = a.organization_id AND r.app_id = a.id
      ORDER BY r.registered_at DESC, r.build_id DESC
      LIMIT 20))
  LEFT JOIN LATERAL (
    SELECT CASE WHEN jsonb_typeof(b.manifest->'integrity'->'files') = 'array'
                THEN b.manifest->'integrity'->'files' ELSE '[]'::jsonb END AS files
  ) AS m ON true
  WHERE a.id = p_app_id
$$;
REVOKE ALL ON FUNCTION integrity_lookup_builds(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION integrity_lookup_builds(text, text) TO ar_app;

-- The `tampered-build` rule: an Incident per (App, Environment, Build), without a network prefix or an origin of its
-- own; its Detections carry the page's origin and the reporter's prefix (or none).
ALTER TABLE incidents DROP CONSTRAINT incidents_rule_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_rule_check
  CHECK (rule IN ('blocked-burst', 'failed-signin-burst', 'canary-touched', 'clone-origin', 'vulnerable-component',
    'exploit-attempt', 'credential-stuffing', 'tampered-build'));
ALTER TABLE detections DROP CONSTRAINT detections_rule_check;
ALTER TABLE detections ADD CONSTRAINT detections_rule_check
  CHECK (rule IN ('blocked-burst', 'failed-signin-burst', 'canary-touched', 'clone-origin', 'vulnerable-component',
    'exploit-attempt', 'credential-stuffing', 'tampered-build'));

-- 0013 tied `build_id` to the Canary and clone rules (and allowed it for a Finding); a tampered-build Incident names
-- its Build too.
ALTER TABLE incidents DROP CONSTRAINT incidents_canary_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_canary_check
  CHECK ((rule = 'canary-touched') = (canary_id IS NOT NULL)
    AND CASE WHEN rule IN ('canary-touched', 'clone-origin', 'tampered-build') THEN build_id IS NOT NULL
             WHEN rule = 'vulnerable-component' THEN true
             ELSE build_id IS NULL END);
ALTER TABLE incidents DROP CONSTRAINT incidents_clone_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_clone_check
  CHECK (CASE WHEN rule = 'clone-origin' THEN origin IS NOT NULL AND ip_prefix IS NULL
              WHEN rule IN ('vulnerable-component', 'exploit-attempt', 'tampered-build')
                THEN origin IS NULL AND ip_prefix IS NULL
              ELSE origin IS NULL AND ip_prefix IS NOT NULL END);
ALTER TABLE detections DROP CONSTRAINT detections_clone_check;
ALTER TABLE detections ADD CONSTRAINT detections_clone_check
  CHECK (CASE WHEN rule IN ('clone-origin', 'tampered-build') THEN origin IS NOT NULL
              WHEN rule = 'vulnerable-component' THEN origin IS NULL AND ip_prefix IS NULL
              WHEN rule = 'exploit-attempt' THEN origin IS NULL
              ELSE origin IS NULL AND ip_prefix IS NOT NULL END);
-- `incidents_advisory_check` and `detections_advisory_check` (0018) already hold the new rule to no advisory.
ALTER TABLE incidents ADD CONSTRAINT incidents_capped_check
  CHECK (capped_at IS NULL OR rule = 'tampered-build');
ALTER TABLE detections ADD CONSTRAINT detections_tamper_check
  CHECK ((rule = 'tampered-build') = (artifact_path IS NOT NULL)
    AND (artifact_path IS NULL) = (observed_sha256 IS NULL));

-- One open or acknowledged Incident per (App, Environment, rule, Canary, origin, advisory, prefix) and, for
-- `tampered-build` only, Build. For every other rule the Build is not a group component, as before: a clone Incident
-- of one origin stays one whichever Build reported it.
DROP INDEX incidents_active_group;
CREATE UNIQUE INDEX incidents_active_group
  ON incidents (organization_id, app_id, environment, rule, COALESCE(canary_id, ''), COALESCE(origin, ''),
    COALESCE(advisory_id, ''), COALESCE(ip_prefix, ''),
    (CASE WHEN rule = 'tampered-build' THEN build_id ELSE '' END))
  WHERE status IN ('open', 'acknowledged');
