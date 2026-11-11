-- Slice 08: the `credential-stuffing` rule's Incidents and Detections. Runs once, as the owner of the database,
-- inside one transaction.

-- An Incident per (App, Environment, network prefix), like `blocked-burst`: a prefix, no origin, no advisory, no
-- Canary. The other checks already hold it to that shape (their ELSE branches); only the list of rules grows.
ALTER TABLE incidents DROP CONSTRAINT incidents_rule_check;
ALTER TABLE incidents ADD CONSTRAINT incidents_rule_check
  CHECK (rule IN ('blocked-burst', 'failed-signin-burst', 'canary-touched', 'clone-origin', 'vulnerable-component',
    'exploit-attempt', 'credential-stuffing'));
ALTER TABLE detections DROP CONSTRAINT detections_rule_check;
ALTER TABLE detections ADD CONSTRAINT detections_rule_check
  CHECK (rule IN ('blocked-burst', 'failed-signin-burst', 'canary-touched', 'clone-origin', 'vulnerable-component',
    'exploit-attempt', 'credential-stuffing'));
