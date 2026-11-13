-- Slice 16: the Guard step of an App's set-up — the first Event received, per App and Environment, whose Attestation
-- Token Shield verified. Runs once, as the owner of the database, inside one transaction.
--
-- Without it, finding that Event filters every Event of the Organization (and finds nothing while Guard is not set
-- up, every time the Console polls). This index holds only the Events with a verified token, ordered by receipt, so
-- MIN(received_at) reads one entry. The Shield and Harden steps need none: `events_recent` and
-- `builds_recent_by_environment` serve them (a test checks the plans).
CREATE INDEX events_first_attested ON events (organization_id, app_id, environment, received_at)
  WHERE payload->'attestation'->>'status' = 'valid';
