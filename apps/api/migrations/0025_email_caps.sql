-- Slice 06b review (F1, F6): more daily counters in the one table without a tenant. Besides the count per address
-- (normalised: no +tag, Gmail dots ignored), it now keeps counts per Organization and address, per Organization, for
-- the whole service, and of email-channel creations per Organization. Every key is an HMAC under the server secret
-- (mail-hash-key.json); the table holds no tenant id and no address. Runs once, as the owner of the database.

ALTER TABLE confirmation_mail_counts DROP CONSTRAINT confirmation_mail_counts_mails_check;
ALTER TABLE confirmation_mail_counts ADD CONSTRAINT confirmation_mail_counts_mails_check
  CHECK (mails BETWEEN 0 AND 100000000);

-- Takes one of each counter of p_day, all or none: 0 when every counter was below its maximum (each is then counted
-- once), else the 1-based position of the first full counter (nothing is counted). Rows of days before yesterday are
-- removed on the way.
CREATE FUNCTION take_mail_caps(p_hashes text[], p_maxes integer[], p_day date)
RETURNS integer
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  used integer;
BEGIN
  IF cardinality(p_hashes) <> cardinality(p_maxes) OR cardinality(p_hashes) = 0 THEN
    RAISE EXCEPTION 'take_mail_caps: one maximum per counter';
  END IF;
  DELETE FROM public.confirmation_mail_counts WHERE day < p_day - 1;
  INSERT INTO public.confirmation_mail_counts (address_hash, day, mails)
  SELECT h, p_day, 0 FROM unnest(p_hashes) AS h
  ON CONFLICT (address_hash, day) DO NOTHING;
  FOR i IN 1 .. cardinality(p_hashes) LOOP
    SELECT c.mails INTO used FROM public.confirmation_mail_counts c
    WHERE c.address_hash = p_hashes[i] AND c.day = p_day FOR UPDATE;
    IF used >= p_maxes[i] THEN
      RETURN i;
    END IF;
  END LOOP;
  UPDATE public.confirmation_mail_counts SET mails = mails + 1
  WHERE address_hash = ANY (p_hashes) AND day = p_day;
  RETURN 0;
END
$$;
REVOKE ALL ON FUNCTION take_mail_caps(text[], integer[], date) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION take_mail_caps(text[], integer[], date) TO ar_app;

-- Replaced by take_mail_caps.
DROP FUNCTION take_confirmation_mail(text, date, integer);
