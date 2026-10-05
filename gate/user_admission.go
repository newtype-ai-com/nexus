package gate

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// UserAdministrator is an example owner address used by tests and docs. It
// grants nothing by itself: every owner check compares against the server's
// configured owner (NEXUS_OWNER_EMAIL, see ValidOwnerEmail).
const UserAdministrator = "owner@example.com"

func isASCII(s string) bool {
	for i := 0; i < len(s); i++ {
		if s[i] >= 0x80 {
			return false
		}
	}
	return true
}

// SameEmail compares two addresses after trimming and ASCII lowercasing. A
// non-ASCII or empty address never matches: Unicode case folding would let
// lookalikes such as "ſ" (long s) or "K" (Kelvin sign) equal an ASCII owner.
func SameEmail(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	return a != "" && isASCII(a) && isASCII(b) && strings.ToLower(a) == strings.ToLower(b)
}

// ValidOwnerEmail reports whether s is one exact, already normalised owner
// address. An empty or malformed owner disables owner features; it never
// widens them.
func ValidOwnerEmail(s string) bool {
	return s != "" && s == strings.ToLower(strings.TrimSpace(s)) && validEmail(s) && !strings.Contains(s, "*")
}

type UserAdmission struct {
	ID      string    `json:"request_id"`
	Email   string    `json:"email"`
	Status  string    `json:"status"`
	Expires time.Time `json:"expires_at"`
}

func (s *PostgresCredentials) Admitted(ctx context.Context, owner, email string) (bool, error) {
	var ok bool
	err := s.pool.QueryRow(ctx, `SELECT EXISTS(SELECT 1 FROM gate_admitted_users WHERE owner_email=$1 AND email=$2)`, owner, email).Scan(&ok)
	if err != nil {
		return false, nexus.ErrConflict
	}
	return ok, nil
}

// BeginUserAdmission never grants access. Stable client IDs are scoped to the
// authenticated requesting account; retrying returns the same request without
// sending another mail or recovering its approval secret.
func (s *PostgresCredentials) BeginUserAdmission(ctx context.Context, account ids.Account, owner, email, client string, now time.Time) (UserAdmission, string, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if ids.Check(ids.KindAccount, string(account)) != nil || !ValidOwnerEmail(owner) || !validEmail(email) || strings.Contains(email, "*") || email == owner || len(client) < 1 || len(client) > 128 || now.IsZero() {
		return UserAdmission{}, "", nexus.ErrInvalid
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return UserAdmission{}, "", nexus.ErrConflict
	}
	defer rollback(tx)
	if _, err = tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,7302005))`, owner); err != nil {
		return UserAdmission{}, "", nexus.ErrConflict
	}
	var a UserAdmission
	err = tx.QueryRow(ctx, `SELECT id,target_email,status,expires_at FROM gate_user_requests WHERE requester_account=$1 AND client_id=$2`, account, client).Scan(&a.ID, &a.Email, &a.Status, &a.Expires)
	if err == nil {
		if a.Email != email {
			return UserAdmission{}, "", nexus.ErrConflict
		}
		if a.Status == "pending" && !now.Before(a.Expires) {
			a.Status = "expired"
		}
		return a, "", nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return UserAdmission{}, "", nexus.ErrConflict
	}
	var count int
	if tx.QueryRow(ctx, `SELECT count(*) FROM gate_user_requests WHERE owner_email=$1 AND created_at>$2`, owner, now.Add(-time.Hour)).Scan(&count) != nil {
		return UserAdmission{}, "", nexus.ErrConflict
	}
	if count >= 5 {
		return UserAdmission{}, "", nexus.ErrLimit
	}
	id, err := randomToken("uar_")
	if err != nil {
		return UserAdmission{}, "", err
	}
	token, err := randomToken("uap_")
	if err != nil {
		return UserAdmission{}, "", err
	}
	a = UserAdmission{ID: id, Email: email, Status: "pending", Expires: now.Add(30 * time.Minute)}
	_, err = tx.Exec(ctx, `INSERT INTO gate_user_requests(id,requester_account,client_id,owner_email,target_email,approval_hash,created_at,expires_at,status) VALUES($1,$2,$3,$4,$5,$6,$7,$8,'pending')`, id, account, client, owner, email, Verifier(token), now, a.Expires)
	if err != nil || tx.Commit(ctx) != nil {
		return UserAdmission{}, "", nexus.ErrConflict
	}
	return a, token, nil
}

func (s *PostgresCredentials) FailUserAdmission(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `UPDATE gate_user_requests SET status='failed' WHERE id=$1 AND status='pending'`, id)
	if err != nil {
		return nexus.ErrConflict
	}
	return nil
}

func (s *PostgresCredentials) UserAdmissionByToken(ctx context.Context, owner, token string, now time.Time) (UserAdmission, error) {
	var a UserAdmission
	err := s.pool.QueryRow(ctx, `SELECT id,target_email,status,expires_at FROM gate_user_requests WHERE owner_email=$1 AND approval_hash=$2 AND status='pending' AND expires_at>$3`, owner, Verifier(token), now).Scan(&a.ID, &a.Email, &a.Status, &a.Expires)
	if err != nil {
		return UserAdmission{}, nexus.ErrNotFound
	}
	return a, nil
}

// DecideUserAdmission consumes the exact mail capability once, atomically with
// admission. A denial, expired token or replay cannot add a user or change a
// prior decision. Admitting a user does not make them an administrator.
func (s *PostgresCredentials) DecideUserAdmission(ctx context.Context, owner, token string, approve bool, now time.Time) error {
	if !ValidOwnerEmail(owner) {
		return nexus.ErrForbidden
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return nexus.ErrConflict
	}
	defer rollback(tx)
	var id, email string
	err = tx.QueryRow(ctx, `SELECT id,target_email FROM gate_user_requests WHERE owner_email=$1 AND approval_hash=$2 AND status='pending' AND expires_at>$3 FOR UPDATE`, owner, Verifier(token), now).Scan(&id, &email)
	if err != nil {
		return nexus.ErrNotFound
	}
	status := "denied"
	if approve {
		status = "approved"
		if _, err = tx.Exec(ctx, `INSERT INTO gate_admitted_users(email,owner_email,request_id,approved_at) VALUES($1,$2,$3,$4) ON CONFLICT(email) DO NOTHING`, email, owner, id, now); err != nil {
			return nexus.ErrConflict
		}
	}
	if _, err = tx.Exec(ctx, `UPDATE gate_user_requests SET status=$2 WHERE id=$1`, id, status); err != nil || tx.Commit(ctx) != nil {
		return nexus.ErrConflict
	}
	return nil
}
