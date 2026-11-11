-- Slice 10 review (F4): a beacon token is unique per App, not across all Organizations. A report names its App
-- (`a`) beside the token, and the lookup needs both. One Organization registering another's token in its own App
-- therefore neither blocks the other's registration nor receives its reports (it cannot register Builds for
-- another Organization's App at all). Runs once, as the owner of the database, like 0001_init.sql.

ALTER TABLE build_beacons DROP CONSTRAINT build_beacons_token_key;
ALTER TABLE build_beacons ADD CONSTRAINT build_beacons_app_token_key UNIQUE (app_id, token);

DROP FUNCTION beacon_lookup_token(text);
CREATE FUNCTION beacon_lookup_token(p_app_id text, p_token text)
RETURNS TABLE (organization_id text, build_id text, app_id text, environment text, origins text[])
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT b.organization_id, b.build_id, b.app_id, b.environment, b.origins
  FROM public.build_beacons b
  WHERE b.app_id = p_app_id AND b.token = p_token
$$;
REVOKE ALL ON FUNCTION beacon_lookup_token(text, text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION beacon_lookup_token(text, text) TO ar_app;
