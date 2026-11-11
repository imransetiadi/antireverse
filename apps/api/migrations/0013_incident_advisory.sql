-- Slice 19: the `vulnerable-component` rule's Incidents and Detections. Runs once, as the owner of the database,
-- like 0001_init.sql.

-- A `vulnerable-component` Incident names the advisory a new Critical or High Finding matched, and (for a build
-- Finding) the Build it was found in; it has neither a network prefix nor an origin. Its Detections likewise.
-- Every other rule's Incident has no advisory.
ALTER TABLE incidents ADD COLUMN advisory_id text CHECK (char_length(advisory_id) <= 120);
ALTER TABLE detections ADD COLUMN advisory_id text CHECK (char_length(advisory_id) <= 120);

ALTER TABLE incidents DROP CONSTRAINT incidents_rule_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_rule_check
  CHECK (rule IN ('blocked-burst', 'failed-signin-burst', 'canary-touched', 'clone-origin', 'vulnerable-component'));
ALTER TABLE detections DROP CONSTRAINT detections_rule_check;
ALTER TABLE detections ADD CONSTRAINT detections_rule_check
  CHECK (rule IN ('blocked-burst', 'failed-signin-burst', 'canary-touched', 'clone-origin', 'vulnerable-component'));

-- 0010 tied `build_id` to the Canary and clone rules; a vulnerable-component Incident names its Build when the
-- Finding came from one (a runtime Finding has none).
ALTER TABLE incidents DROP CONSTRAINT incidents_canary_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_canary_check
  CHECK ((rule = 'canary-touched') = (canary_id IS NOT NULL)
    AND CASE WHEN rule IN ('canary-touched', 'clone-origin') THEN build_id IS NOT NULL
             WHEN rule = 'vulnerable-component' THEN true
             ELSE build_id IS NULL END);
ALTER TABLE incidents DROP CONSTRAINT incidents_clone_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_clone_check
  CHECK (CASE WHEN rule = 'clone-origin' THEN origin IS NOT NULL AND ip_prefix IS NULL
              WHEN rule = 'vulnerable-component' THEN origin IS NULL AND ip_prefix IS NULL
              ELSE origin IS NULL AND ip_prefix IS NOT NULL END);
ALTER TABLE incidents ADD CONSTRAINT incidents_advisory_check
  CHECK ((rule = 'vulnerable-component') = (advisory_id IS NOT NULL));
ALTER TABLE detections DROP CONSTRAINT detections_clone_check;
ALTER TABLE detections ADD CONSTRAINT detections_clone_check
  CHECK (CASE WHEN rule = 'clone-origin' THEN origin IS NOT NULL
              WHEN rule = 'vulnerable-component' THEN origin IS NULL AND ip_prefix IS NULL
              ELSE origin IS NULL AND ip_prefix IS NOT NULL END);
ALTER TABLE detections ADD CONSTRAINT detections_advisory_check
  CHECK ((rule = 'vulnerable-component') = (advisory_id IS NOT NULL));

-- One open or acknowledged Incident per (App, Environment, rule, Canary, origin, advisory, prefix).
DROP INDEX incidents_active_group;
CREATE UNIQUE INDEX incidents_active_group
  ON incidents (organization_id, app_id, environment, rule, COALESCE(canary_id, ''), COALESCE(origin, ''),
    COALESCE(advisory_id, ''), COALESCE(ip_prefix, ''))
  WHERE status IN ('open', 'acknowledged');
