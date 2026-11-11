-- Slice 03: the public attestation endpoints check that an App exists before they issue a nonce. They have no key
-- and so no tenant: like `auth_lookup_key` and `beacon_lookup_token`, one definer function answers exactly that
-- question (true or false) and nothing else about the App. Runs once, as the owner of the database.

CREATE FUNCTION attest_app_exists(p_app_id text)
RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT EXISTS (SELECT 1 FROM public.apps a WHERE a.id = p_app_id)
$$;
REVOKE ALL ON FUNCTION attest_app_exists(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION attest_app_exists(text) TO ar_app;
