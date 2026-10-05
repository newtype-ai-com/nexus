-- Nexus schema 9. Idempotent; executed atomically by Migrate under lock 7302001.
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
-- Version 7: Nexus custody approvals (exact input, single use) and versioned secret values.
CREATE TABLE IF NOT EXISTS custody_approvals (id text PRIMARY KEY, account_id text NOT NULL, input_hash text NOT NULL, body jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS custody_approvals_hash ON custody_approvals(account_id,input_hash,id);
REVOKE ALL ON custody_approvals FROM PUBLIC;
CREATE TABLE IF NOT EXISTS secret_values (account_id text NOT NULL, name text NOT NULL, body jsonb NOT NULL, PRIMARY KEY(account_id,name));
REVOKE ALL ON secret_values FROM PUBLIC;
-- Version 8: secret plan runs (unique attempt) and executor (nte_) credentials. v7 is frozen.
CREATE TABLE IF NOT EXISTS executor_credentials (id text PRIMARY KEY, account_id text NOT NULL, verifier text NOT NULL UNIQUE, body jsonb NOT NULL);
REVOKE ALL ON executor_credentials FROM PUBLIC;
CREATE TABLE IF NOT EXISTS secret_plan_runs (id text PRIMARY KEY, account_id text NOT NULL, attempt_key text NOT NULL UNIQUE, body jsonb NOT NULL);
REVOKE ALL ON secret_plan_runs FROM PUBLIC;
-- Version 9: teams, seats (one active seat per session), installation memory, message edges.
CREATE TABLE IF NOT EXISTS teams (id text PRIMARY KEY, account_id text NOT NULL, body jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS teams_account ON teams(account_id,id);
REVOKE ALL ON teams FROM PUBLIC;
CREATE TABLE IF NOT EXISTS team_seats (id text PRIMARY KEY, account_id text NOT NULL, team_id text NOT NULL, session_id text NOT NULL, state text NOT NULL, body jsonb NOT NULL);
CREATE INDEX IF NOT EXISTS team_seats_team ON team_seats(team_id,id);
CREATE UNIQUE INDEX IF NOT EXISTS team_seats_active_session ON team_seats(account_id,session_id) WHERE state='active' AND session_id<>'';
REVOKE ALL ON team_seats FROM PUBLIC;
CREATE TABLE IF NOT EXISTS team_installs (account_id text NOT NULL, install text NOT NULL, body jsonb NOT NULL, PRIMARY KEY(account_id,install));
REVOKE ALL ON team_installs FROM PUBLIC;
CREATE TABLE IF NOT EXISTS message_edges (account_id text NOT NULL, a text NOT NULL, b text NOT NULL, last_at timestamptz NOT NULL, PRIMARY KEY(account_id,a,b), CHECK (a < b));
-- the reverse-adjacency index is (account_id,b,a) under a new name: an install
-- that already had message_edges_b(account_id,b) gets the ordered index too
DROP INDEX IF EXISTS message_edges_b;
CREATE INDEX IF NOT EXISTS message_edges_reverse ON message_edges(account_id,b,a);
REVOKE ALL ON message_edges FROM PUBLIC;
CREATE TABLE IF NOT EXISTS message_edge_marks (account_id text PRIMARY KEY, body jsonb NOT NULL);
REVOKE ALL ON message_edge_marks FROM PUBLIC;
INSERT INTO hub_meta(key,value) VALUES('schema',9) ON CONFLICT(key) DO NOTHING;
UPDATE hub_meta SET value=9 WHERE key='schema' AND value<9;
