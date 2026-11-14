-- Slice 18d: SLO measurement (PERFORMANCE §3, OPERATION §7). Runs once, as the owner of the database, inside one
-- transaction.
--
-- - `slo_minutes`: per UTC minute, SLO and latency variant, the good and total counts of the SLI and a fixed latency
--   histogram (one count per bound of `SLO_LATENCY_BOUNDS_MS`, 22, plus the overflow bucket: 23). Written by the API
--   process's in-memory recorder once a minute and on close: a flush of a minute already stored adds to it. No tenant
--   identifier: an operator table, global (no `organization_id`). The request role has no right on it at all; the
--   owner writes, reads and sweeps it (minutes older than 35 days, `SLO_RETENTION_DAYS`).

CREATE TABLE slo_minutes (
  minute timestamptz NOT NULL CHECK (date_trunc('minute', minute) = minute),
  slo text NOT NULL CHECK (slo IN ('SLO-01', 'SLO-02', 'SLO-03', 'SLO-04', 'SLO-05', 'SLO-06', 'SLO-07', 'SLO-08',
    'SLO-09', 'SLO-10')),
  variant text NOT NULL CHECK (variant IN ('all', 'read', 'write')),
  good bigint NOT NULL CHECK (good >= 0),
  total bigint NOT NULL CHECK (total >= good),
  histogram bigint[] NOT NULL CHECK (cardinality(histogram) = 23 AND array_ndims(histogram) = 1),
  PRIMARY KEY (minute, slo, variant)
);
REVOKE ALL ON slo_minutes FROM PUBLIC;

-- - `slo_alerts`: the burn rules firing now, one row per SLO and rule with the start of the episode (review M2), so that a
--   restart neither fires a still-holding burn again nor forgets to send `resolved`. Owner only.
CREATE TABLE slo_alerts (
  slo text NOT NULL CHECK (slo IN ('SLO-01', 'SLO-02', 'SLO-03', 'SLO-04', 'SLO-05', 'SLO-06', 'SLO-07', 'SLO-08',
    'SLO-09', 'SLO-10')),
  rule text NOT NULL CHECK (rule IN ('fast', 'slow', 'ticket')),
  since timestamptz NOT NULL,
  PRIMARY KEY (slo, rule)
);
REVOKE ALL ON slo_alerts FROM PUBLIC;

-- - `slo_flushes`: the id of every recorder batch written, in the batch's own transaction, so that a batch written again
--   after an ambiguous failure (committed, but the caller saw an error) adds nothing. Swept after a day. Owner only.
CREATE TABLE slo_flushes (
  id text PRIMARY KEY CHECK (length(id) BETWEEN 1 AND 64),
  at timestamptz NOT NULL
);
REVOKE ALL ON slo_flushes FROM PUBLIC;
