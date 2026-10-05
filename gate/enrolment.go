package gate

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

const EnrolmentSchemaVersion = 4

var ErrAlreadyFetched = errors.New("already_fetched")

// Enrolment contains hashes only. Verify and poll secrets never enter the DB.
type Enrolment struct {
	ID         string      `json:"enrolment_id"`
	Email      string      `json:"email"`
	Account    ids.Account `json:"account_id,omitempty"`
	Expires    time.Time   `json:"expires_at"`
	Approved   bool        `json:"-"`
	KeyTaken   bool        `json:"-"`
	LoginTaken bool        `json:"-"`
	ApprovedAt *time.Time  `json:"-"`
}

func randomToken(prefix string) (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", errors.New("gate: random source unavailable")
	}
	return prefix + hex.EncodeToString(b[:]), nil
}

func rollback(tx pgx.Tx) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = tx.Rollback(ctx)
}

func (s *PostgresCredentials) MigrateEnrolments(ctx context.Context) error {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return errors.New("gate: enrolment migration failed")
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(7302004)`); err != nil {
		return errors.New("gate: enrolment migration failed")
	}
	var version int
	err = tx.QueryRow(ctx, `SELECT value FROM gate_meta WHERE key='enrolments'`).Scan(&version)
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		return errors.New("gate: enrolment schema unavailable")
	}
	if version > EnrolmentSchemaVersion {
		return errors.New("gate: unsupported enrolment schema")
	}
	_, err = tx.Exec(ctx, `
CREATE TABLE IF NOT EXISTS gate_accounts (
 email text PRIMARY KEY CHECK (email=lower(email)),
 account_id text NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS gate_enrolments (
 id text PRIMARY KEY,
 poll_hash text NOT NULL UNIQUE,
 verify_hash text NOT NULL UNIQUE,
 email text NOT NULL,
 account_id text NOT NULL DEFAULT '',
 expires_at timestamptz NOT NULL,
 approved_at timestamptz,
 key_taken boolean NOT NULL DEFAULT false,
 login_taken boolean NOT NULL DEFAULT false
);
CREATE INDEX IF NOT EXISTS gate_enrolments_email ON gate_enrolments(email,expires_at);
CREATE TABLE IF NOT EXISTS gate_devices (
 device_hash text PRIMARY KEY,
 approve_hash text NOT NULL UNIQUE,
 licence_hash text NOT NULL REFERENCES gate_credentials(verifier),
 expires_at timestamptz NOT NULL,
 approved boolean NOT NULL DEFAULT false,
 denied boolean NOT NULL DEFAULT false,
 consumed boolean NOT NULL DEFAULT false,
 interval_seconds integer NOT NULL DEFAULT 5,
 last_poll timestamptz
);
CREATE INDEX IF NOT EXISTS gate_devices_licence ON gate_devices(licence_hash,expires_at);
CREATE INDEX IF NOT EXISTS gate_devices_expiry ON gate_devices(expires_at);
CREATE INDEX IF NOT EXISTS gate_enrolments_expiry ON gate_enrolments(expires_at);
CREATE TABLE IF NOT EXISTS gate_rate_limits (
 bucket text PRIMARY KEY,
 window_start timestamptz NOT NULL,
 hits integer NOT NULL CHECK (hits > 0)
);
CREATE TABLE IF NOT EXISTS gate_user_requests (
 id text PRIMARY KEY,
 requester_account text NOT NULL,
 client_id text NOT NULL,
 owner_email text NOT NULL,
 target_email text NOT NULL,
 approval_hash text NOT NULL UNIQUE,
 created_at timestamptz NOT NULL,
 expires_at timestamptz NOT NULL,
 status text NOT NULL CHECK (status IN ('pending','approved','denied','failed')),
 UNIQUE(requester_account,client_id)
);
CREATE INDEX IF NOT EXISTS gate_user_requests_expiry ON gate_user_requests(expires_at);
CREATE TABLE IF NOT EXISTS gate_admitted_users (
 email text PRIMARY KEY CHECK (email=lower(email)),
 owner_email text NOT NULL,
 request_id text NOT NULL REFERENCES gate_user_requests(id),
 approved_at timestamptz NOT NULL
);
REVOKE ALL ON gate_accounts,gate_enrolments,gate_devices,gate_rate_limits,gate_user_requests,gate_admitted_users FROM PUBLIC;
INSERT INTO gate_meta(key,value) VALUES ('enrolments',4) ON CONFLICT(key) DO UPDATE SET value=EXCLUDED.value;`)
	if err != nil {
		return errors.New("gate: enrolment migration failed")
	}
	if tx.Commit(ctx) != nil {
		return errors.New("gate: enrolment migration failed")
	}
	return nil
}

func (s *PostgresCredentials) CheckEnrolments(ctx context.Context) error {
	var v int
	if s.pool.QueryRow(ctx, `SELECT value FROM gate_meta WHERE key='enrolments'`).Scan(&v) != nil || v != EnrolmentSchemaVersion {
		return errors.New("gate: enrolment schema mismatch")
	}
	return nil
}

// BeginEnrolment stores no recoverable token. A per-address transaction lock
// bounds pending attempts and mail floods across all server processes.
func (s *PostgresCredentials) BeginEnrolment(ctx context.Context, email string, now time.Time) (Enrolment, string, string, error) {
	return s.beginEnrolment(ctx, email, now, 30*time.Minute, false)
}

// OwnerCodeTTL bounds a mail-free owner bootstrap code (nexus enrol-owner).
const OwnerCodeTTL = 15 * time.Minute

// BeginOwnerCode is the operator-only, mail-free owner bootstrap. It stores an
// ordinary enrolment row whose verify_hash is the code's verifier; the poll
// token is discarded and minted again only by RedeemOwnerCode, so the printed
// code is the single capability. Owner codes have their own limit: at most one
// unredeemed code per owner (issuing replaces it). They never count against,
// and are never blocked by, the public mail-enrolment limit.
func (s *PostgresCredentials) BeginOwnerCode(ctx context.Context, owner string, now time.Time) (Enrolment, string, error) {
	if !ValidOwnerEmail(owner) {
		return Enrolment{}, "", nexus.ErrInvalid
	}
	e, _, code, err := s.beginEnrolment(ctx, owner, now, OwnerCodeTTL, true)
	return e, code, err
}

// Owner-code enrolments are told apart by their id prefix (no schema change).
const (
	ownerCodePrefix    = "eoc_"
	ownerEnrolmentID   = "eno_"
	mailEnrolmentID    = "enr_"
	notOwnerCodeRowSQL = `left(id,4)<>'eno_'`
)

// RedeemOwnerCode consumes the code once: in one transaction it approves the
// owner's enrolment, burns the code (verify_hash replaced) and returns a fresh
// poll token for the normal one-shot key/session claims. Only codes made by
// BeginOwnerCode for this exact owner match; a mailed vfy_ token never does.
func (s *PostgresCredentials) RedeemOwnerCode(ctx context.Context, owner, code string, now time.Time) (Enrolment, string, error) {
	if !ValidOwnerEmail(owner) || len(code) != 68 || !strings.HasPrefix(code, ownerCodePrefix) || now.IsZero() {
		return Enrolment{}, "", nexus.ErrNotFound
	}
	want := Verifier(code)
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Enrolment{}, "", nexus.ErrConflict
	}
	defer rollback(tx)
	var stored string
	var e Enrolment
	err = tx.QueryRow(ctx, `SELECT verify_hash,`+enrolColumns+` FROM gate_enrolments WHERE verify_hash=$1 FOR UPDATE`, want).Scan(&stored, &e.ID, &e.Email, &e.Account, &e.Expires, &e.ApprovedAt, &e.KeyTaken, &e.LoginTaken)
	e.Approved = e.ApprovedAt != nil
	if err != nil || subtle.ConstantTimeCompare([]byte(stored), []byte(want)) != 1 || !strings.HasPrefix(e.ID, ownerEnrolmentID) || e.Email != owner || e.Approved || !now.Before(e.Expires) {
		return Enrolment{}, "", nexus.ErrNotFound
	}
	if err = approveLocked(ctx, tx, &e, now); err != nil {
		return Enrolment{}, "", err
	}
	poll, err := randomToken("enp_")
	if err != nil {
		return Enrolment{}, "", err
	}
	burnt, err := randomToken("eob_")
	if err != nil {
		return Enrolment{}, "", err
	}
	if _, err = tx.Exec(ctx, `UPDATE gate_enrolments SET poll_hash=$2,verify_hash=$3 WHERE id=$1`, e.ID, Verifier(poll), Verifier(burnt)); err != nil || tx.Commit(ctx) != nil {
		return Enrolment{}, "", nexus.ErrConflict
	}
	return e, poll, nil
}

func (s *PostgresCredentials) beginEnrolment(ctx context.Context, email string, now time.Time, ttl time.Duration, ownerCode bool) (Enrolment, string, string, error) {
	idPrefix, verifyPrefix := mailEnrolmentID, "vfy_"
	if ownerCode {
		idPrefix, verifyPrefix = ownerEnrolmentID, ownerCodePrefix
	}
	email = strings.ToLower(strings.TrimSpace(email))
	if !validEmail(email) || now.IsZero() {
		return Enrolment{}, "", "", nexus.ErrInvalid
	}
	id, err := randomToken(idPrefix)
	if err != nil {
		return Enrolment{}, "", "", err
	}
	poll, err := randomToken("enp_")
	if err != nil {
		return Enrolment{}, "", "", err
	}
	verify, err := randomToken(verifyPrefix)
	if err != nil {
		return Enrolment{}, "", "", err
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Enrolment{}, "", "", nexus.ErrConflict
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7302004))`, email); err != nil {
		return Enrolment{}, "", "", nexus.ErrConflict
	}
	if ownerCode {
		// One active operator code per owner: a new one replaces the old.
		if _, err = tx.Exec(ctx, `DELETE FROM gate_enrolments WHERE email=$1 AND left(id,4)='eno_' AND approved_at IS NULL`, email); err != nil {
			return Enrolment{}, "", "", nexus.ErrConflict
		}
	} else {
		var count int
		if tx.QueryRow(ctx, `SELECT count(*) FROM gate_enrolments WHERE email=$1 AND expires_at>$2 AND `+notOwnerCodeRowSQL, email, now).Scan(&count) != nil {
			return Enrolment{}, "", "", nexus.ErrConflict
		}
		if count >= 3 {
			return Enrolment{}, "", "", nexus.ErrLimit
		}
	}
	e := Enrolment{ID: id, Email: email, Expires: now.Add(ttl)}
	if _, err = tx.Exec(ctx, `INSERT INTO gate_enrolments(id,poll_hash,verify_hash,email,expires_at) VALUES($1,$2,$3,$4,$5)`, id, Verifier(poll), Verifier(verify), email, e.Expires); err != nil {
		return Enrolment{}, "", "", nexus.ErrConflict
	}
	if tx.Commit(ctx) != nil {
		return Enrolment{}, "", "", nexus.ErrConflict
	}
	return e, poll, verify, nil
}

// CancelEnrolment is used after failed delivery; it never makes credentials live.
func (s *PostgresCredentials) CancelEnrolment(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM gate_enrolments WHERE id=$1 AND approved_at IS NULL`, id)
	if err != nil {
		return errors.New("gate: cancellation failed")
	}
	return nil
}

func scanEnrolment(row pgx.Row) (Enrolment, error) {
	var e Enrolment
	err := row.Scan(&e.ID, &e.Email, &e.Account, &e.Expires, &e.ApprovedAt, &e.KeyTaken, &e.LoginTaken)
	e.Approved = e.ApprovedAt != nil
	if err != nil {
		return Enrolment{}, nexus.ErrNotFound
	}
	return e, nil
}

const enrolColumns = `id,email,account_id,expires_at,approved_at,key_taken,login_taken`

func (s *PostgresCredentials) EnrolmentByVerify(ctx context.Context, verify string) (Enrolment, error) {
	return scanEnrolment(s.pool.QueryRow(ctx, `SELECT `+enrolColumns+` FROM gate_enrolments WHERE verify_hash=$1`, Verifier(verify)))
}

func (s *PostgresCredentials) PollEnrolment(ctx context.Context, id, token string) (Enrolment, error) {
	return scanEnrolment(s.pool.QueryRow(ctx, `SELECT `+enrolColumns+` FROM gate_enrolments WHERE id=$1 AND poll_hash=$2`, id, Verifier(token)))
}

// ApproveEnrolment is idempotent. The email->account unique mapping serializes
// concurrent approvals; legacy provisioned identities are adopted, never merged.
func (s *PostgresCredentials) ApproveEnrolment(ctx context.Context, verify string, now time.Time) (Enrolment, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Enrolment{}, nexus.ErrConflict
	}
	defer rollback(tx)
	e, err := scanEnrolment(tx.QueryRow(ctx, `SELECT `+enrolColumns+` FROM gate_enrolments WHERE verify_hash=$1 FOR UPDATE`, Verifier(verify)))
	if err != nil || !now.Before(e.Expires) {
		return Enrolment{}, nexus.ErrNotFound
	}
	if !e.Approved {
		if err = approveLocked(ctx, tx, &e, now); err != nil {
			return Enrolment{}, err
		}
	}
	if tx.Commit(ctx) != nil {
		return Enrolment{}, nexus.ErrConflict
	}
	return e, nil
}

// approveLocked binds the enrolment to its address's single account inside the
// caller's transaction (row already locked FOR UPDATE).
func approveLocked(ctx context.Context, tx pgx.Tx, e *Enrolment, now time.Time) error {
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7302004))`, e.Email); err != nil {
		return nexus.ErrConflict
	}
	var accounts []string
	rows, err := tx.Query(ctx, `SELECT DISTINCT account_id FROM gate_credentials WHERE lower(email)=$1 UNION SELECT account_id FROM gate_accounts WHERE email=$1`, e.Email)
	if err != nil {
		return nexus.ErrConflict
	}
	for rows.Next() {
		var a string
		if rows.Scan(&a) != nil {
			rows.Close()
			return nexus.ErrConflict
		}
		accounts = append(accounts, a)
	}
	err = rows.Err()
	rows.Close()
	if err != nil || len(accounts) > 1 {
		return nexus.ErrConflict
	}
	e.Account = ids.Account(ids.New(ids.KindAccount))
	if len(accounts) == 1 {
		e.Account = ids.Account(accounts[0])
	}
	if _, err = tx.Exec(ctx, `INSERT INTO gate_accounts(email,account_id) VALUES($1,$2) ON CONFLICT(email) DO NOTHING`, e.Email, e.Account); err != nil {
		return nexus.ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE gate_enrolments SET account_id=$2,approved_at=$3 WHERE id=$1`, e.ID, e.Account, now); err != nil {
		return nexus.ErrConflict
	}
	e.Approved = true
	e.ApprovedAt = &now
	return nil
}

// ClaimEnrolment generates a token only inside the one-shot claim transaction.
// A committed claim with a lost HTTP response is not replayable; start anew.
func (s *PostgresCredentials) ClaimEnrolment(ctx context.Context, id, poll, kind string, now time.Time) (Credential, string, error) {
	if kind != "licence" && kind != "login" {
		return Credential{}, "", nexus.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Credential{}, "", nexus.ErrConflict
	}
	defer rollback(tx)
	e, err := scanEnrolment(tx.QueryRow(ctx, `SELECT `+enrolColumns+` FROM gate_enrolments WHERE id=$1 AND poll_hash=$2 FOR UPDATE`, id, Verifier(poll)))
	if err != nil || !e.Approved || !now.Before(e.Expires) {
		return Credential{}, "", nexus.ErrNotFound
	}
	if (kind == "licence" && e.KeyTaken) || (kind == "login" && e.LoginTaken) {
		return Credential{}, "", ErrAlreadyFetched
	}
	prefix, column := "ntl_", "key_taken"
	expiry := e.ApprovedAt.Add(365 * 24 * time.Hour)
	if kind == "login" {
		prefix, column = "ntg_", "login_taken"
		expiry = e.ApprovedAt.Add(30 * 24 * time.Hour)
	}
	token, err := randomToken(prefix)
	if err != nil {
		return Credential{}, "", err
	}
	c := Credential{Verifier: Verifier(token), Kind: kind, Account: e.Account, Email: e.Email, Expires: expiry}
	if _, err = tx.Exec(ctx, `INSERT INTO gate_credentials(verifier,kind,account_id,email,expires_at) VALUES($1,$2,$3,$4,$5)`, c.Verifier, c.Kind, c.Account, c.Email, c.Expires); err != nil {
		return Credential{}, "", nexus.ErrConflict
	}
	if _, err = tx.Exec(ctx, `UPDATE gate_enrolments SET `+column+`=true WHERE id=$1`, e.ID); err != nil {
		return Credential{}, "", nexus.ErrConflict
	}
	if tx.Commit(ctx) != nil {
		return Credential{}, "", nexus.ErrConflict
	}
	return c, token, nil
}

func (s *PostgresCredentials) RevokeCredential(ctx context.Context, verifier string) error {
	if len(verifier) != 64 || strings.ToLower(verifier) != verifier {
		return nexus.ErrInvalid
	}
	if _, err := hex.DecodeString(verifier); err != nil {
		return nexus.ErrInvalid
	}
	tag, err := s.pool.Exec(ctx, `UPDATE gate_credentials SET revoked=true WHERE verifier=$1`, verifier)
	if err != nil {
		return errors.New("gate: revocation failed")
	}
	if tag.RowsAffected() != 1 {
		return nexus.ErrNotFound
	}
	return nil
}
