package mcpauth

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/newtype-ai-com/nexus/ids"
)

// SchemaVersion of the mcp_oauth_* tables (gate_meta key "mcp_oauth").
const SchemaVersion = 1

// PostgresStore keeps clients, consents, codes and token verifiers in the
// server's private schema (never a token itself).
type PostgresStore struct{ pool *pgxpool.Pool }

func NewPostgresStore(pool *pgxpool.Pool) *PostgresStore { return &PostgresStore{pool: pool} }

func (s *PostgresStore) Migrate(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7302011)`); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS gate_meta (key text PRIMARY KEY, value integer NOT NULL)`); err != nil {
		return err
	}
	var version int
	err = tx.QueryRow(ctx, `SELECT value FROM gate_meta WHERE key='mcp_oauth'`).Scan(&version)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if version > SchemaVersion {
		return errors.New("mcpauth: unsupported schema")
	}
	_, err = tx.Exec(ctx, `
CREATE TABLE IF NOT EXISTS mcp_oauth_clients (
 client_id text PRIMARY KEY CHECK (client_id ~ '^mcl_[0-9a-f]{64}$'),
 client_name text NOT NULL,
 redirect_uris text[] NOT NULL,
 created_at timestamptz NOT NULL,
 consented boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS mcp_oauth_consents (
 consent_id text PRIMARY KEY CHECK (consent_id ~ '^mcc_[0-9a-f]{64}$'),
 client_id text NOT NULL,
 client_name text NOT NULL,
 account_id text NOT NULL,
 email text NOT NULL,
 session_id text NOT NULL DEFAULT '',
 via text NOT NULL CHECK (via IN ('mail','cli')),
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 delegation_id text NOT NULL DEFAULT '',
 revoked boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS mcp_oauth_consents_account ON mcp_oauth_consents(account_id);
CREATE TABLE IF NOT EXISTS mcp_oauth_codes (
 verifier text PRIMARY KEY CHECK (verifier ~ '^[0-9a-f]{64}$'),
 client_id text NOT NULL,
 redirect_uri text NOT NULL,
 challenge text NOT NULL,
 resource text NOT NULL,
 scope text NOT NULL,
 consent_id text NOT NULL,
 expires_at timestamptz NOT NULL,
 used boolean NOT NULL DEFAULT false
);
CREATE TABLE IF NOT EXISTS mcp_oauth_tokens (
 verifier text PRIMARY KEY CHECK (verifier ~ '^[0-9a-f]{64}$'),
 kind text NOT NULL CHECK (kind IN ('access','refresh')),
 client_id text NOT NULL,
 consent_id text NOT NULL,
 account_id text NOT NULL,
 email text NOT NULL,
 audience text NOT NULL,
 scope text NOT NULL,
 expires_at timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS mcp_oauth_tokens_consent ON mcp_oauth_tokens(consent_id);
CREATE TABLE IF NOT EXISTS mcp_oauth_settings (
 id integer PRIMARY KEY CHECK (id = 1),
 mail_consent boolean NOT NULL DEFAULT false,
 updated_at timestamptz,
 updated_by text NOT NULL DEFAULT ''
);
INSERT INTO mcp_oauth_settings(id) VALUES (1) ON CONFLICT (id) DO NOTHING;
REVOKE ALL ON mcp_oauth_clients, mcp_oauth_consents, mcp_oauth_codes, mcp_oauth_tokens, mcp_oauth_settings FROM PUBLIC;
INSERT INTO gate_meta(key,value) VALUES ('mcp_oauth',1)
 ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value;`)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) Settings(ctx context.Context) (Settings, error) {
	var out Settings
	var at *time.Time
	if err := s.pool.QueryRow(ctx, `SELECT mail_consent,updated_at,updated_by FROM mcp_oauth_settings WHERE id=1`).Scan(&out.MailConsent, &at, &out.UpdatedBy); err != nil {
		return Settings{}, err
	}
	if at != nil {
		out.UpdatedAt = *at
	}
	return out, nil
}

func (s *PostgresStore) PutSettings(ctx context.Context, v Settings) error {
	_, err := s.pool.Exec(ctx, `UPDATE mcp_oauth_settings SET mail_consent=$1, updated_at=$2, updated_by=$3 WHERE id=1`, v.MailConsent, v.UpdatedAt, v.UpdatedBy)
	return err
}

func (s *PostgresStore) PutClient(ctx context.Context, c Client) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO mcp_oauth_clients(client_id,client_name,redirect_uris,created_at) VALUES ($1,$2,$3,$4)`, c.ID, c.Name, c.RedirectURIs, c.Created)
	return err
}

func (s *PostgresStore) Client(ctx context.Context, id string) (Client, error) {
	var c Client
	err := s.pool.QueryRow(ctx, `SELECT client_id,client_name,redirect_uris,created_at,consented FROM mcp_oauth_clients WHERE client_id=$1`, id).Scan(&c.ID, &c.Name, &c.RedirectURIs, &c.Created, &c.Consented)
	if err != nil {
		return Client{}, ErrNotFound
	}
	return c, nil
}

func (s *PostgresStore) MarkConsented(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE mcp_oauth_clients SET consented=true WHERE client_id=$1`, id)
	return err
}

func (s *PostgresStore) PurgeClients(ctx context.Context, before time.Time) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM mcp_oauth_clients WHERE ctid IN (SELECT ctid FROM mcp_oauth_clients WHERE NOT consented AND created_at<$1 LIMIT 1000)`, before)
	return err
}

func (s *PostgresStore) ConsumeRefresh(ctx context.Context, v string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE mcp_oauth_tokens SET revoked=true WHERE verifier=$1 AND kind='refresh' AND NOT revoked`, v)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrUsed
	}
	return nil
}

func (s *PostgresStore) PutConsent(ctx context.Context, c Consent) error {
	tag, err := s.pool.Exec(ctx, `INSERT INTO mcp_oauth_consents(consent_id,client_id,client_name,account_id,email,session_id,via,created_at,expires_at,delegation_id,revoked)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
 ON CONFLICT (consent_id) DO UPDATE SET session_id=EXCLUDED.session_id, delegation_id=EXCLUDED.delegation_id, revoked=mcp_oauth_consents.revoked OR EXCLUDED.revoked
 WHERE mcp_oauth_consents.account_id=EXCLUDED.account_id AND mcp_oauth_consents.client_id=EXCLUDED.client_id`,
		c.ID, c.ClientID, c.Name, string(c.Account), c.Email, string(c.Session), c.Via, c.Created, c.Expires, string(c.Delegation), c.Revoked)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrUsed
	}
	return nil
}

const consentCols = `consent_id,client_id,client_name,account_id,email,session_id,via,created_at,expires_at,delegation_id,revoked`

func scanConsent(row pgx.Row) (Consent, error) {
	var c Consent
	var account, session, delegation string
	if err := row.Scan(&c.ID, &c.ClientID, &c.Name, &account, &c.Email, &session, &c.Via, &c.Created, &c.Expires, &delegation, &c.Revoked); err != nil {
		return Consent{}, err
	}
	c.Account, c.Session, c.Delegation = ids.Account(account), ids.Session(session), ids.Delegation(delegation)
	return c, nil
}

func (s *PostgresStore) Consent(ctx context.Context, id string) (Consent, error) {
	c, err := scanConsent(s.pool.QueryRow(ctx, `SELECT `+consentCols+` FROM mcp_oauth_consents WHERE consent_id=$1`, id))
	if err != nil {
		return Consent{}, ErrNotFound
	}
	return c, nil
}

func (s *PostgresStore) Consents(ctx context.Context, account ids.Account) ([]Consent, error) {
	rows, err := s.pool.Query(ctx, `SELECT `+consentCols+` FROM mcp_oauth_consents WHERE account_id=$1 ORDER BY created_at`, string(account))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Consent
	for rows.Next() {
		c, err := scanConsent(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *PostgresStore) RevokeConsent(ctx context.Context, id string) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	tag, err := tx.Exec(ctx, `UPDATE mcp_oauth_consents SET revoked=true WHERE consent_id=$1`, id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	if _, err = tx.Exec(ctx, `UPDATE mcp_oauth_tokens SET revoked=true WHERE consent_id=$1`, id); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresStore) PutCode(ctx context.Context, c Code) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO mcp_oauth_codes(verifier,client_id,redirect_uri,challenge,resource,scope,consent_id,expires_at,used) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,false)`,
		c.Verifier, c.ClientID, c.Redirect, c.Challenge, c.Resource, c.Scope, c.ConsentID, c.Expires)
	return err
}

func (s *PostgresStore) TakeCode(ctx context.Context, v string) (Code, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Code{}, err
	}
	defer tx.Rollback(context.WithoutCancel(ctx))
	c := Code{Verifier: v}
	err = tx.QueryRow(ctx, `SELECT client_id,redirect_uri,challenge,resource,scope,consent_id,expires_at,used FROM mcp_oauth_codes WHERE verifier=$1 FOR UPDATE`, v).
		Scan(&c.ClientID, &c.Redirect, &c.Challenge, &c.Resource, &c.Scope, &c.ConsentID, &c.Expires, &c.Used)
	if err != nil {
		return Code{}, ErrNotFound
	}
	if c.Used {
		return c, ErrUsed
	}
	if _, err = tx.Exec(ctx, `UPDATE mcp_oauth_codes SET used=true WHERE verifier=$1`, v); err != nil {
		return Code{}, err
	}
	c.Used = true
	return c, tx.Commit(ctx)
}

func (s *PostgresStore) PutToken(ctx context.Context, t Token) error {
	_, err := s.pool.Exec(ctx, `INSERT INTO mcp_oauth_tokens(verifier,kind,client_id,consent_id,account_id,email,audience,scope,expires_at,revoked) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		t.Verifier, t.Kind, t.ClientID, t.ConsentID, string(t.Account), t.Email, t.Audience, t.Scope, t.Expires, t.Revoked)
	return err
}

func (s *PostgresStore) Token(ctx context.Context, v string) (Token, error) {
	t := Token{Verifier: v}
	var account string
	err := s.pool.QueryRow(ctx, `SELECT kind,client_id,consent_id,account_id,email,audience,scope,expires_at,revoked FROM mcp_oauth_tokens WHERE verifier=$1`, v).
		Scan(&t.Kind, &t.ClientID, &t.ConsentID, &account, &t.Email, &t.Audience, &t.Scope, &t.Expires, &t.Revoked)
	if err != nil {
		return Token{}, ErrNotFound
	}
	t.Account = ids.Account(account)
	return t, nil
}

func (s *PostgresStore) RevokeToken(ctx context.Context, v string) error {
	tag, err := s.pool.Exec(ctx, `UPDATE mcp_oauth_tokens SET revoked=true WHERE verifier=$1`, v)
	if err != nil {
		return err
	}
	if tag.RowsAffected() != 1 {
		return ErrNotFound
	}
	return nil
}
