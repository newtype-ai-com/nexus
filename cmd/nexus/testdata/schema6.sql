-- Nexus schema 6. Idempotent; executed atomically by Migrate under lock 7302001.
-- Keep events.body as json: jsonb would change the hashed payload bytes.
CREATE TABLE IF NOT EXISTS hub_meta (key text PRIMARY KEY, value bigint NOT NULL);
CREATE TABLE IF NOT EXISTS hub_cursors (account_id text PRIMARY KEY, value bigint NOT NULL);
CREATE TABLE IF NOT EXISTS sessions (id text PRIMARY KEY, account_id text NOT NULL, body jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS sessions_account ON sessions(account_id,id);
CREATE TABLE IF NOT EXISTS tasks (id text PRIMARY KEY, account_id text NOT NULL, parent_id text, no integer NOT NULL, body jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS tasks_parent ON tasks(parent_id,no,id);
CREATE INDEX IF NOT EXISTS tasks_roots ON tasks(account_id,id) WHERE parent_id IS NULL;
CREATE TABLE IF NOT EXISTS delegations (id text PRIMARY KEY, account_id text NOT NULL, parent_id text, delegate_id text NOT NULL, body jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS delegations_parent ON delegations(parent_id,id);
CREATE INDEX IF NOT EXISTS delegations_delegate ON delegations(delegate_id,id);
CREATE TABLE IF NOT EXISTS usage (delegation_id text PRIMARY KEY, body jsonb NOT NULL);
CREATE TABLE IF NOT EXISTS policies (id text NOT NULL, version integer NOT NULL, account_id text NOT NULL, body jsonb NOT NULL, PRIMARY KEY(id,version));
CREATE TABLE IF NOT EXISTS events (
 account_id text NOT NULL, cursor bigint NOT NULL, id text NOT NULL UNIQUE,
 session_id text NOT NULL, seq bigint NOT NULL, client_event_id text, body json NOT NULL,
 PRIMARY KEY(account_id,cursor), UNIQUE(session_id,seq)
);
CREATE UNIQUE INDEX IF NOT EXISTS events_client ON events(session_id,client_event_id) WHERE client_event_id IS NOT NULL;
-- Version 2: passkeys. Version 3: approvals.
CREATE TABLE IF NOT EXISTS passkeys (id text PRIMARY KEY, account_id text NOT NULL, body jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS passkeys_account ON passkeys(account_id,id);
CREATE TABLE IF NOT EXISTS approvals (id text PRIMARY KEY, account_id text NOT NULL, status text NOT NULL, body jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS approvals_account ON approvals(account_id,status,id);
-- Version 4: runs and hashed agent tokens.
CREATE TABLE IF NOT EXISTS runs (id text PRIMARY KEY, account_id text NOT NULL, session_id text NOT NULL, bootstrap_hash text NOT NULL UNIQUE, body jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS runs_session ON runs(session_id,id);
CREATE TABLE IF NOT EXISTS agent_tokens (hash text PRIMARY KEY, session_id text NOT NULL, body jsonb NOT NULL);
-- Version 5: encrypted account secrets.
CREATE TABLE IF NOT EXISTS secrets (account_id text NOT NULL, name text NOT NULL, body jsonb NOT NULL, PRIMARY KEY(account_id,name));
-- Version 6: monthly account usage and exact mail-approved increases.
CREATE TABLE IF NOT EXISTS account_quotas (account_id text NOT NULL, month text NOT NULL, body jsonb NOT NULL, PRIMARY KEY(account_id,month));
REVOKE ALL ON account_quotas FROM PUBLIC;
INSERT INTO hub_meta(key,value) VALUES('schema',6) ON CONFLICT(key) DO NOTHING;
UPDATE hub_meta SET value=6 WHERE key='schema' AND value<6;
