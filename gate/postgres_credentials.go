package gate

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

const CredentialSchemaVersion = 1

// PostgresCredentials shares the server's private-schema session pool. Only
// verifiers are persisted; this is not an enrolment or token issuance endpoint.
type PostgresCredentials struct{ pool *pgxpool.Pool }

func NewPostgresCredentials(pool *pgxpool.Pool) *PostgresCredentials {
	return &PostgresCredentials{pool: pool}
}

func (s *PostgresCredentials) Migrate(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7302003)`); err != nil {
		return err
	}
	if _, err = tx.Exec(ctx, `CREATE TABLE IF NOT EXISTS gate_meta (key text PRIMARY KEY, value integer NOT NULL)`); err != nil {
		return err
	}
	var version int
	err = tx.QueryRow(ctx, `SELECT value FROM gate_meta WHERE key='credentials'`).Scan(&version)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	if version > CredentialSchemaVersion {
		return errors.New("gate: unsupported credential schema")
	}
	_, err = tx.Exec(ctx, `
CREATE TABLE IF NOT EXISTS gate_credentials (
 verifier text PRIMARY KEY CHECK (verifier ~ '^[0-9a-f]{64}$'),
 kind text NOT NULL CHECK (kind IN ('licence','login','agent')),
 account_id text NOT NULL,
 email text NOT NULL DEFAULT '',
 session_id text NOT NULL DEFAULT '',
 expires_at timestamptz NOT NULL,
 revoked boolean NOT NULL DEFAULT false
);
REVOKE ALL ON gate_credentials, gate_meta FROM PUBLIC;
INSERT INTO gate_meta(key,value) VALUES ('credentials',1)
 ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value;`)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}

func (s *PostgresCredentials) LookupCredential(ctx context.Context, verifier string) (Credential, error) {
	var c Credential
	err := s.pool.QueryRow(ctx, `SELECT verifier,kind,account_id,email,session_id,expires_at,revoked
 FROM gate_credentials WHERE verifier=$1`, verifier).Scan(&c.Verifier, &c.Kind, &c.Account, &c.Email, &c.Session, &c.Expires, &c.Revoked)
	if err != nil {
		return Credential{}, ErrUnauthenticated
	}
	return c, nil
}

// PutCredential preserves identity and makes revocation sticky. Reissuing a
// revoked token requires a NEW random token, never un-revoking its old verifier.
func (s *PostgresCredentials) PutCredential(ctx context.Context, c Credential) error {
	if !validCredential(c) {
		return nexus.ErrInvalid
	}
	tag, err := s.pool.Exec(ctx, `INSERT INTO gate_credentials
 (verifier,kind,account_id,email,session_id,expires_at,revoked) VALUES ($1,$2,$3,$4,$5,$6,$7)
 ON CONFLICT (verifier) DO UPDATE SET expires_at=EXCLUDED.expires_at,
 revoked=gate_credentials.revoked OR EXCLUDED.revoked
 WHERE gate_credentials.kind=EXCLUDED.kind AND gate_credentials.account_id=EXCLUDED.account_id
 AND gate_credentials.session_id=EXCLUDED.session_id AND gate_credentials.email=EXCLUDED.email`,
		c.Verifier, c.Kind, c.Account, c.Email, c.Session, c.Expires, c.Revoked)
	if err != nil {
		return errors.New("gate: credential write failed")
	}
	if tag.RowsAffected() != 1 {
		return nexus.ErrConflict
	}
	return nil
}

// AccountForEmail returns the account that owns an address (the remote MCP
// endpoint binds a mail-confirmed consent to it). Exactly one account or an
// error. Enrolment's gate_accounts is consulted when that table exists.
func (s *PostgresCredentials) AccountForEmail(ctx context.Context, email string) (ids.Account, error) {
	found := map[string]bool{}
	collect := func(query string) error {
		rows, err := s.pool.Query(ctx, query, email)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var a string
			if err := rows.Scan(&a); err != nil {
				return err
			}
			found[a] = true
		}
		return rows.Err()
	}
	if collect(`SELECT DISTINCT account_id FROM gate_credentials WHERE lower(email)=lower($1) AND kind IN ('licence','login') AND NOT revoked`) != nil {
		return "", errors.New("gate: account lookup failed")
	}
	var exists bool
	if s.pool.QueryRow(ctx, `SELECT to_regclass('gate_accounts') IS NOT NULL`).Scan(&exists) == nil && exists {
		if collect(`SELECT account_id FROM gate_accounts WHERE email=lower($1)`) != nil {
			return "", errors.New("gate: account lookup failed")
		}
	}
	if len(found) != 1 {
		return "", nexus.ErrNotFound
	}
	for a := range found {
		if _, err := ids.ParseAccount(a); err != nil {
			return "", nexus.ErrNotFound
		}
		return ids.Account(a), nil
	}
	return "", nexus.ErrNotFound
}

// LiveCredentials returns the account's unrevoked, unexpired licence and login
// verifier records (the remote MCP endpoint ends consents whose person no
// longer holds both).
func (s *PostgresCredentials) LiveCredentials(ctx context.Context, account ids.Account, now time.Time) ([]Credential, error) {
	rows, err := s.pool.Query(ctx, `SELECT verifier,kind,account_id,email,session_id,expires_at,revoked FROM gate_credentials
 WHERE account_id=$1 AND kind IN ('licence','login') AND NOT revoked AND expires_at>$2 LIMIT 100`, string(account), now)
	if err != nil {
		return nil, errors.New("gate: credential lookup failed")
	}
	defer rows.Close()
	var out []Credential
	for rows.Next() {
		var c Credential
		if rows.Scan(&c.Verifier, &c.Kind, &c.Account, &c.Email, &c.Session, &c.Expires, &c.Revoked) != nil {
			return nil, errors.New("gate: credential lookup failed")
		}
		out = append(out, c)
	}
	if rows.Err() != nil {
		return nil, errors.New("gate: credential lookup failed")
	}
	return out, nil
}
