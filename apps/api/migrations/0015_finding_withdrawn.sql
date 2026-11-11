-- Slice 19, D-060 (plan amendment A6): a Finding is `withdrawn` when a sync finds its advisory withdrawn, or its
-- ranges no longer covering the installed version. Never open, never counted, no Incident; open again if a later
-- sync covers the version again. Runs once, as the owner of the database, like 0001_init.sql.

ALTER TABLE findings DROP CONSTRAINT findings_status_check;
ALTER TABLE findings ADD CONSTRAINT findings_status_check
  CHECK (status IN ('open', 'fixed', 'ignored', 'withdrawn'));
