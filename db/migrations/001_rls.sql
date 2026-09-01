CREATE EXTENSION IF NOT EXISTS vector;
CREATE TABLE documents (id text PRIMARY KEY, tenant_id text NOT NULL, content text NOT NULL);
CREATE TABLE chunks (id text PRIMARY KEY, document_id text REFERENCES documents, tenant_id text NOT NULL, embedding vector(8));
CREATE TABLE tickets (id text PRIMARY KEY, tenant_id text NOT NULL, version integer NOT NULL DEFAULT 1);
CREATE TABLE chat_history (id uuid PRIMARY KEY, tenant_id text NOT NULL, subject_id text NOT NULL, body text NOT NULL);
CREATE TABLE approvals (id text PRIMARY KEY, tenant_id text NOT NULL, subject_id text NOT NULL, payload jsonb NOT NULL);
CREATE TABLE audit_events (id bigserial PRIMARY KEY, tenant_id text NOT NULL, event jsonb NOT NULL);
DO $$ DECLARE t text; BEGIN FOREACH t IN ARRAY ARRAY['documents','chunks','tickets','chat_history','approvals','audit_events'] LOOP
  EXECUTE format('ALTER TABLE %I ENABLE ROW LEVEL SECURITY', t);
  EXECUTE format('ALTER TABLE %I FORCE ROW LEVEL SECURITY', t);
  EXECUTE format('CREATE POLICY tenant_isolation ON %I USING (tenant_id = current_setting(''app.tenant_id'', true)) WITH CHECK (tenant_id = current_setting(''app.tenant_id'', true))', t);
END LOOP; END $$;
CREATE ROLE app_runtime NOLOGIN NOSUPERUSER NOBYPASSRLS;
GRANT SELECT, INSERT, UPDATE ON documents, chunks, tickets, chat_history, approvals, audit_events TO app_runtime;

