-- Slice 12b: the logic file (W3 Logic) a tenant registers beside the Manifest: 1–5 designated functions, each with a
-- public part (id, description, examples) and hidden test vectors the Assessment's agent never sees. Written in the
-- Build's own transaction, immutable like the Build (the request role may insert and read, never update or delete),
-- never returned by any route; only the Assessment runner reads it, as a verifier input. At most 1 MB (checked by the
-- API against `LogicFileSchema` and the Manifest's `logic_count` and `logic_digest`). Runs once, as the owner of the
-- database, inside one transaction.
CREATE TABLE build_logic (
  organization_id text NOT NULL REFERENCES organizations(id),
  app_id text NOT NULL,
  build_id text NOT NULL,
  logic jsonb NOT NULL CHECK (jsonb_typeof(logic) = 'object' AND jsonb_typeof(logic -> 'functions') = 'array'
    AND jsonb_array_length(logic -> 'functions') BETWEEN 1 AND 5),
  PRIMARY KEY (organization_id, app_id, build_id),
  FOREIGN KEY (organization_id, app_id, build_id) REFERENCES builds (organization_id, app_id, build_id)
);
GRANT SELECT, INSERT ON build_logic TO ar_app;
ALTER TABLE build_logic ENABLE ROW LEVEL SECURITY;
ALTER TABLE build_logic FORCE ROW LEVEL SECURITY;
CREATE POLICY build_logic_tenant ON build_logic
  USING (organization_id = NULLIF(current_setting('app.tenant_id', true), ''))
  WITH CHECK (organization_id = NULLIF(current_setting('app.tenant_id', true), ''));
