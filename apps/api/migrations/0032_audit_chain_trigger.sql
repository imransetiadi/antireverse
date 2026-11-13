-- Slice 18a review (F3): the chain head is moved by the database, never by the request role. Runs once, as the owner of
-- the database, inside one transaction.
--
-- Before: the API updated `audit_heads` itself, so the request role could also roll a head back (every later change of
-- the Organization then failed) or move it to hide a truncated tail. Now:
-- - the request role may only read `audit_heads`;
-- - `audit_head_lock()` (definer) takes the transaction's own Organization's head FOR UPDATE, creating it at seq 0 when
--   missing, and answers its seq and hash: the writer computes the next entry from it, under the lock;
-- - a trigger on every INSERT into `audit_entries` (definer) refuses an entry whose seq is not head + 1 or whose
--   prev_hash is not the head's hash, and moves the head to the new entry. It fires for every role, the owner included.
-- The owner can still rewrite both tables; the signed heads that verify and export hand out let a verifier see that.

REVOKE INSERT, UPDATE, DELETE ON audit_heads FROM ar_app;

CREATE FUNCTION audit_head_lock()
RETURNS TABLE (seq bigint, hash text)
LANGUAGE plpgsql VOLATILE SECURITY DEFINER SET search_path = public
AS $$
#variable_conflict use_column
DECLARE
  tenant text := NULLIF(current_setting('app.tenant_id', true), '');
BEGIN
  IF tenant IS NULL THEN
    RAISE EXCEPTION 'audit chain: no tenant' USING ERRCODE = '42501';
  END IF;
  INSERT INTO public.audit_heads (organization_id, seq, hash) VALUES (tenant, 0, repeat('0', 64))
  ON CONFLICT (organization_id) DO NOTHING;
  RETURN QUERY SELECT h.seq, h.hash FROM public.audit_heads h WHERE h.organization_id = tenant FOR UPDATE;
END
$$;
REVOKE ALL ON FUNCTION audit_head_lock() FROM PUBLIC;
GRANT EXECUTE ON FUNCTION audit_head_lock() TO ar_app;

CREATE FUNCTION audit_chain_advance()
RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = public
AS $$
DECLARE
  head_seq bigint;
  head_hash text;
BEGIN
  SELECT h.seq, h.hash INTO head_seq, head_hash
  FROM public.audit_heads h WHERE h.organization_id = NEW.organization_id FOR UPDATE;
  IF NOT FOUND THEN
    head_seq := 0;
    head_hash := repeat('0', 64);
    INSERT INTO public.audit_heads (organization_id, seq, hash) VALUES (NEW.organization_id, 0, head_hash);
  END IF;
  IF NEW.seq <> head_seq + 1 OR NEW.prev_hash <> head_hash THEN
    RAISE EXCEPTION 'audit chain: an entry must follow the head (seq %, expected %)', NEW.seq, head_seq + 1
      USING ERRCODE = '23514';
  END IF;
  UPDATE public.audit_heads SET seq = NEW.seq, hash = NEW.hash WHERE organization_id = NEW.organization_id;
  RETURN NEW;
END
$$;
REVOKE ALL ON FUNCTION audit_chain_advance() FROM PUBLIC;

CREATE TRIGGER audit_entries_chain BEFORE INSERT ON audit_entries
  FOR EACH ROW EXECUTE FUNCTION audit_chain_advance();
