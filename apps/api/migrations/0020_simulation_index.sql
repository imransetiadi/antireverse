-- Slice 11: the read of a Policy simulation — the `request.decision` Events of one App and Environment in a span of
-- `ts`, newest first. Runs once, as the owner of the database, inside one transaction.
--
-- `events_recent` orders by time of receipt and does not know the Environment; this index gives the simulation its
-- rows in order, so that it reads at most the Events it replays and sorts nothing.
CREATE INDEX events_replay ON events (organization_id, app_id, environment, ts DESC, event_id DESC)
  WHERE type = 'request.decision';
