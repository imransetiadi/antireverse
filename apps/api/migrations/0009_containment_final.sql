-- Slice 09: a lifted Containment is final. Runs once, as the owner of the database, like 0001_init.sql.
--
-- The column grants of 0008 already limit the request role to `lifted_at` and `lifted_by`. This trigger holds
-- for every role, the owner included: only the lift itself may change a row, from not lifted to lifted, and
-- nothing changes a lifted row again (no un-lift, no second lift with another key or time). The error names
-- no value of the row.

CREATE FUNCTION containments_lift_only() RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
  IF OLD.lifted_at IS NOT NULL OR OLD.lifted_by IS NOT NULL THEN
    RAISE EXCEPTION 'A lifted containment cannot change.' USING ERRCODE = 'check_violation';
  END IF;
  IF (to_jsonb(NEW) - 'lifted_at' - 'lifted_by') IS DISTINCT FROM (to_jsonb(OLD) - 'lifted_at' - 'lifted_by') THEN
    RAISE EXCEPTION 'Only lifting may change a containment (lifted_at, lifted_by).' USING ERRCODE = 'check_violation';
  END IF;
  RETURN NEW;
END;
$$;

CREATE TRIGGER containments_lift_only
  BEFORE UPDATE ON containments
  FOR EACH ROW EXECUTE FUNCTION containments_lift_only();
