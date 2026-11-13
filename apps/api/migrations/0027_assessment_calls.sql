-- Slice 12a, fork 5 (Jev "store_referenced_calls", 0.70): an Assessment keeps the calls of its run's call log that some
-- Objective's evidence references ({index, tool, cost, summary}, ascending index, at most 200; an index the cap cut is
-- dropped from the evidence) and the totals of the whole log ({count, calls, seconds}). Both or neither: a run without
-- a call log (queued, running, interrupted, timed out, engine error) has neither. Returned by the Assessment detail
-- only. Runs once, as the owner of the database, inside one transaction.
ALTER TABLE assessments
  ADD COLUMN calls jsonb CHECK (calls IS NULL OR (jsonb_typeof(calls) = 'array' AND jsonb_array_length(calls) <= 200)),
  ADD COLUMN call_totals jsonb CHECK (call_totals IS NULL OR jsonb_typeof(call_totals) = 'object'),
  ADD CONSTRAINT assessments_calls_together CHECK ((calls IS NULL) = (call_totals IS NULL));
GRANT UPDATE (calls, call_totals) ON assessments TO ar_app;
