-- Slice 15a, third and fourth independent safety reviews (D-107, D-108, D-110). Runs once, as the owner of the
-- database, inside one transaction. Migration 0039 is not edited.
--
-- - `campaign_requests.bytes` holds what the connection really read, however much: no upper bound, 64 bits. A new
--   failure, `read_limit`: the connection read more than one request may and was destroyed.
-- - An ended Campaign's request log: a row still `sending` may be settled to `sent` only, never to `not_sent` (D-108).
-- - A Campaign is born queued: no other state can be inserted, by anyone (D-108).
-- - A Finding's evidence holds a window of at most 200 characters around what its check matched, and no hash of the
--   body (D-107). Excerpts stored before this migration were free cuts of a response body of up to 2 KB: they are
--   emptied, and their body hashes removed.
-- - `campaign_start_control`: the control read of the start checks, where the Campaign is still queued.
-- - Fourth review: a refused probe's row keeps no text an engine chose — its target is NULL (or the target of a
--   catalog probe), its method `GET`, `HEAD` or the label `OTHER`, and `asked_chars` says how much it asked for
--   (D-110). The states of a Campaign: from queued only to running (with its address) or to stopped, refused or
--   failed without check counts; completed only from running, and only when a request of it was sent (D-108). Of a
--   stored Content-Security-Policy header only `[present]` is kept.

-- What the connection read. The request role stored at most 1 MB per row before, whatever had been read.
ALTER TABLE campaign_requests DROP CONSTRAINT campaign_requests_bytes_check;
ALTER TABLE campaign_requests ALTER COLUMN bytes TYPE bigint;
ALTER TABLE campaign_requests ADD CONSTRAINT campaign_requests_bytes_check CHECK (bytes >= 0);
ALTER TABLE campaign_requests DROP CONSTRAINT campaign_requests_failure_check;
ALTER TABLE campaign_requests ADD CONSTRAINT campaign_requests_failure_check
  CHECK (failure IN ('timeout', 'connect_failed', 'tls_failed', 'aborted', 'invalid_response', 'read_limit'));

-- A refused probe (D-110): what an engine asked for and the gate refused is text the engine chose — out of a response
-- it read, possibly. None of it is kept: the row says why it was refused and how many characters its path and query
-- held. Rows written before this migration lose their text here (their length is what remains of it).
ALTER TABLE campaign_requests ADD COLUMN asked_chars integer CHECK (asked_chars BETWEEN 0 AND 1000000);
ALTER TABLE campaign_requests DISABLE TRIGGER campaign_requests_history;
UPDATE campaign_requests
SET asked_chars = LEAST(COALESCE(char_length(target), 0), 1000000),
    target = NULL,
    method = CASE WHEN method IS NULL OR method IN ('GET', 'HEAD') THEN method ELSE 'OTHER' END
WHERE outcome = 'refused';
ALTER TABLE campaign_requests ENABLE TRIGGER campaign_requests_history;
ALTER TABLE campaign_requests ADD CONSTRAINT campaign_requests_asked_chars_refused
  CHECK ((outcome = 'refused') = (asked_chars IS NOT NULL));
ALTER TABLE campaign_requests ADD CONSTRAINT campaign_requests_method_label
  CHECK (method IS NULL OR method IN ('GET', 'HEAD', 'OTHER'));

-- A Campaign's history, whoever writes (replaces the function of 0039; the trigger stays). As before: a row is added
-- only while the Campaign is queued or running, and only as the next one; a row changes only once, from `sending`.
-- New: `not_sent` says that a request never left, which only the running gate can know — once the Campaign has ended,
-- a row still `sending` is settled as `sent` (with what came of it) or stays `sending`. A request that went out can
-- no longer be made to look as if it had not.
CREATE OR REPLACE FUNCTION campaign_requests_history() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  state text;
  last integer;
BEGIN
  IF TG_OP = 'UPDATE' THEN
    IF OLD.outcome <> 'sending' OR NEW.outcome NOT IN ('sent', 'not_sent') THEN
      RAISE EXCEPTION 'a request log row is settled once, from sending to sent or not_sent' USING ERRCODE = '23514';
    END IF;
    IF NEW.outcome = 'not_sent' THEN
      SELECT c.status INTO state FROM public.campaigns c
      WHERE c.organization_id = OLD.organization_id AND c.id = OLD.campaign_id
      FOR UPDATE;
      IF state IS NULL OR state NOT IN ('queued', 'running') THEN
        RAISE EXCEPTION 'after a Campaign ended, a request log row is settled as sent only' USING ERRCODE = '23514';
      END IF;
    END IF;
    RETURN NEW;
  END IF;
  SELECT c.status INTO state FROM public.campaigns c
  WHERE c.organization_id = NEW.organization_id AND c.id = NEW.campaign_id
  FOR UPDATE;
  IF state IS NULL OR state NOT IN ('queued', 'running') THEN
    RAISE EXCEPTION 'the request log of a Campaign that ended is final' USING ERRCODE = '23514';
  END IF;
  SELECT COALESCE(max(r.seq), 0) INTO last FROM public.campaign_requests r
  WHERE r.organization_id = NEW.organization_id AND r.campaign_id = NEW.campaign_id;
  IF NEW.seq <> last + 1 THEN
    RAISE EXCEPTION 'a request log row is the next one' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;

-- A Campaign is born queued, whoever inserts it: not started, not ended, not stopped, no address pinned, no check
-- counted. Every other state is reached by an UPDATE, which `campaigns_end_is_final` judges.
CREATE FUNCTION campaigns_born_queued() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
  IF NEW.status <> 'queued' OR NEW.end_reason IS NOT NULL OR NEW.started_at IS NOT NULL
      OR NEW.finished_at IS NOT NULL OR NEW.pinned_address IS NOT NULL
      OR NEW.checks_ran IS NOT NULL OR NEW.checks_reported IS NOT NULL OR NEW.checks_skipped IS NOT NULL
      OR NEW.checks_inconclusive IS NOT NULL OR NEW.findings_dropped <> 0
      OR NEW.stop_requested_at IS NOT NULL OR NEW.stop_requested_by IS NOT NULL OR NEW.stop_reason IS NOT NULL THEN
    RAISE EXCEPTION 'a Campaign is created queued, with nothing started, ended or counted' USING ERRCODE = '23514';
  END IF;
  RETURN NEW;
END
$$;
CREATE TRIGGER campaigns_born_queued BEFORE INSERT ON campaigns
  FOR EACH ROW EXECUTE FUNCTION campaigns_born_queued();

-- The states of a Campaign, whoever writes (replaces the function of 0039; the trigger stays). As before: an end is
-- final, a running Campaign never goes back to queued, a stop request is set once. New (fourth review): the INSERT
-- rule above could be undone by one UPDATE from queued straight to "completed, six clean checks". So:
-- - while queued, nothing is started or counted;
-- - queued → running only with the pinned address and the start time;
-- - queued → an end only as stopped, refused or failed, with nothing started and nothing counted;
-- - while running, the address and the start time do not change and nothing is counted yet;
-- - completed only from running, and only when at least one request of the Campaign was sent and settled (the
--   ownership request is one). It does not prove that the checks ran: a role that may UPDATE campaigns and INSERT
--   request rows can still write a Campaign that looks complete, in several statements.
CREATE OR REPLACE FUNCTION campaigns_end_is_final() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
  counted boolean;
BEGIN
  IF OLD.status NOT IN ('queued', 'running') THEN
    RAISE EXCEPTION 'a Campaign that ended is final' USING ERRCODE = '23514';
  END IF;
  IF OLD.status = 'running' AND NEW.status = 'queued' THEN
    RAISE EXCEPTION 'a running Campaign is never queued again' USING ERRCODE = '23514';
  END IF;
  IF OLD.stop_requested_at IS NOT NULL AND (NEW.stop_requested_at IS DISTINCT FROM OLD.stop_requested_at
      OR NEW.stop_requested_by IS DISTINCT FROM OLD.stop_requested_by
      OR NEW.stop_reason IS DISTINCT FROM OLD.stop_reason) THEN
    RAISE EXCEPTION 'a stop request is set once' USING ERRCODE = '23514';
  END IF;
  counted := NEW.checks_ran IS NOT NULL OR NEW.checks_reported IS NOT NULL OR NEW.checks_skipped IS NOT NULL
    OR NEW.checks_inconclusive IS NOT NULL;
  IF OLD.status = 'queued' THEN
    IF NEW.status = 'running' THEN
      IF NEW.pinned_address IS NULL OR NEW.started_at IS NULL OR counted OR NEW.findings_dropped <> 0 THEN
        RAISE EXCEPTION 'a Campaign starts with its pinned address and nothing counted' USING ERRCODE = '23514';
      END IF;
    ELSIF NEW.status IN ('queued', 'stopped', 'refused', 'failed') THEN
      IF NEW.pinned_address IS NOT NULL OR NEW.started_at IS NOT NULL OR counted OR NEW.findings_dropped <> 0 THEN
        RAISE EXCEPTION 'a Campaign that did not start has no address, no start and no counts'
          USING ERRCODE = '23514';
      END IF;
    ELSE
      RAISE EXCEPTION 'a queued Campaign starts, or ends as stopped, refused or failed' USING ERRCODE = '23514';
    END IF;
  ELSE
    IF NEW.pinned_address IS DISTINCT FROM OLD.pinned_address OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
      RAISE EXCEPTION 'the address and the start of a running Campaign do not change' USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'running' AND (counted OR NEW.findings_dropped <> 0) THEN
      RAISE EXCEPTION 'the checks of a Campaign are counted when it ends' USING ERRCODE = '23514';
    END IF;
    IF NEW.status = 'completed' AND NOT EXISTS (
        SELECT 1 FROM public.campaign_requests r
        WHERE r.organization_id = OLD.organization_id AND r.campaign_id = OLD.id AND r.outcome = 'sent') THEN
      RAISE EXCEPTION 'a Campaign completes only after a request of it was sent' USING ERRCODE = '23514';
    END IF;
  END IF;
  RETURN NEW;
END
$$;

-- Evidence (D-107): no free excerpt of a response body is kept. What was stored before is emptied (the Findings'
-- trigger refuses changes to an ended Campaign's Findings, so it is off for this one statement), and from here on
-- the database itself refuses a window of more than 200 characters and a hash of the body. Of a
-- Content-Security-Policy header, whose value carries a nonce per response and may carry a token, only that it was
-- sent is kept — in what was stored before too (fourth review).
ALTER TABLE campaign_findings DISABLE TRIGGER campaign_findings_history;
UPDATE campaign_findings
SET evidence = CASE
    WHEN evidence #> '{headers,content-security-policy}' IS NOT NULL
      THEN jsonb_set((evidence - 'body_sha256') || jsonb_build_object('excerpt', ''),
                     '{headers,content-security-policy}', '"[present]"'::jsonb)
    ELSE (evidence - 'body_sha256') || jsonb_build_object('excerpt', '')
  END
WHERE evidence ? 'excerpt' OR evidence ? 'body_sha256'
   OR evidence #> '{headers,content-security-policy}' IS NOT NULL;
ALTER TABLE campaign_findings ENABLE TRIGGER campaign_findings_history;
ALTER TABLE campaign_findings ADD CONSTRAINT campaign_findings_evidence_window
  CHECK (NOT (evidence ? 'body_sha256') AND char_length(COALESCE(evidence ->> 'excerpt', '')) <= 200
    AND COALESCE(evidence #>> '{headers,content-security-policy}', '[present]') = '[present]');

-- The control read of the start checks, for the transaction's Organization and one of its Campaigns. As
-- `campaign_control`, except that the Campaign is expected to be queued, not running: `stop_requested` is true when
-- a stop was asked or the Campaign is no longer queued. An unknown Campaign counts as stopped.
CREATE FUNCTION campaign_start_control(p_campaign_id text)
RETURNS TABLE (killed boolean, suspended boolean, stop_requested boolean, deletion_pending boolean)
LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public
AS $$
  SELECT
    (SELECT s.killed FROM public.prove_switch s),
    EXISTS (SELECT 1 FROM public.prove_suspensions p WHERE p.org_id = t.tenant),
    COALESCE((SELECT c.stop_requested_at IS NOT NULL OR c.status <> 'queued' FROM public.campaigns c
              WHERE c.organization_id = t.tenant AND c.id = p_campaign_id), true),
    public.organization_deletion_is_pending(t.tenant)
  FROM (SELECT NULLIF(current_setting('app.tenant_id', true), '') AS tenant) t
  WHERE t.tenant IS NOT NULL
$$;
REVOKE ALL ON FUNCTION campaign_start_control(text) FROM PUBLIC;
GRANT EXECUTE ON FUNCTION campaign_start_control(text) TO ar_app;
