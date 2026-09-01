CREATE EXTENSION IF NOT EXISTS vector;

CREATE TABLE documents (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  content text NOT NULL
);
CREATE TABLE chunks (
  id text PRIMARY KEY,
  document_id text REFERENCES documents,
  tenant_id text NOT NULL,
  embedding vector(8)
);
CREATE TABLE tickets (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  version integer NOT NULL DEFAULT 1
);
CREATE TABLE chat_history (
  id uuid PRIMARY KEY,
  tenant_id text NOT NULL,
  subject_id text NOT NULL,
  body text NOT NULL
);
CREATE TABLE approvals (
  id text PRIMARY KEY,
  tenant_id text NOT NULL,
  subject_id text NOT NULL,
  payload jsonb NOT NULL
);
CREATE TABLE audit_events (
  id bigserial PRIMARY KEY,
  tenant_id text NOT NULL,
  event jsonb NOT NULL
);

DO $$
DECLARE
  table_name text;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'documents', 'chunks', 'tickets', 'chat_history', 'approvals', 'audit_events'
  ] LOOP
    EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', table_name);
    EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', table_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))',
      table_name
    );
  END LOOP;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_runtime') THEN
    CREATE ROLE app_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'app_login') THEN
    CREATE ROLE app_login LOGIN PASSWORD 'synthetic-app-password' NOSUPERUSER NOBYPASSRLS;
    GRANT app_runtime TO app_login;
  END IF;
END $$;

GRANT SELECT, INSERT, UPDATE ON
  documents, chunks, tickets, chat_history, approvals, audit_events
TO app_runtime;
GRANT USAGE, SELECT ON SEQUENCE audit_events_id_seq TO app_runtime;

INSERT INTO documents (id, tenant_id, content) VALUES
  ('acme-live-1', 'acme', 'Acme live RLS document visible only to the acme tenant.'),
  ('globex-live-1', 'globex', 'Globex live RLS document visible only to the globex tenant.')
ON CONFLICT (id) DO NOTHING;
