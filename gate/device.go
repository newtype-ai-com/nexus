package gate

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/newtype-ai-com/nexus/nexus"
)

var (
	ErrDeviceExpired = errors.New("expired_token")
	ErrDevicePending = errors.New("authorization_pending")
	ErrDeviceSlow    = errors.New("slow_down")
	ErrDeviceDenied  = errors.New("access_denied")
)

type DeviceStart struct {
	Code      string `json:"device_code"`
	ExpiresIn int    `json:"expires_in"`
	Interval  int    `json:"interval"`
}

// BeginDevice binds the request to the licence verifier, never caller identity.
func (s *PostgresCredentials) BeginDevice(ctx context.Context, licence string, now time.Time) (DeviceStart, string, string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return DeviceStart{}, "", "", nexus.ErrConflict
	}
	defer rollback(tx)
	hash := Verifier(licence)
	c, err := deviceLicence(ctx, tx, hash, now)
	if err != nil {
		return DeviceStart{}, "", "", err
	}
	// The locked licence serializes rate limits across processes.
	var count int
	if tx.QueryRow(ctx, `SELECT count(*) FROM gate_devices WHERE licence_hash=$1 AND expires_at>$2`, hash, now).Scan(&count) != nil {
		return DeviceStart{}, "", "", nexus.ErrConflict
	}
	if count >= 3 {
		return DeviceStart{}, "", "", nexus.ErrLimit
	}
	code, err := randomToken("dev_")
	if err != nil {
		return DeviceStart{}, "", "", err
	}
	approve, err := randomToken("apv_")
	if err != nil {
		return DeviceStart{}, "", "", err
	}
	_, err = tx.Exec(ctx, `INSERT INTO gate_devices(device_hash,approve_hash,licence_hash,expires_at) VALUES($1,$2,$3,$4)`, Verifier(code), Verifier(approve), hash, now.Add(10*time.Minute))
	if err != nil || tx.Commit(ctx) != nil {
		return DeviceStart{}, "", "", nexus.ErrConflict
	}
	return DeviceStart{Code: code, ExpiresIn: 600, Interval: 5}, approve, c.Email, nil
}

func deviceLicence(ctx context.Context, tx pgx.Tx, hash string, now time.Time) (Credential, error) {
	var c Credential
	err := tx.QueryRow(ctx, `SELECT verifier,kind,account_id,email,expires_at,revoked FROM gate_credentials WHERE verifier=$1 FOR UPDATE`, hash).Scan(&c.Verifier, &c.Kind, &c.Account, &c.Email, &c.Expires, &c.Revoked)
	if err != nil || !validCredential(c) || c.Kind != "licence" || c.Revoked || !now.Before(c.Expires) {
		return Credential{}, ErrUnauthenticated
	}
	return c, nil
}

func (s *PostgresCredentials) CancelDevice(ctx context.Context, code string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM gate_devices WHERE device_hash=$1 AND NOT approved AND NOT consumed`, Verifier(code))
	if err != nil {
		return nexus.ErrConflict
	}
	return nil
}

// ConfirmDevice accepts only a private mail capability; GET handlers never call it.
func (s *PostgresCredentials) ConfirmDevice(ctx context.Context, link string, deny bool, now time.Time) error {
	tag, err := s.pool.Exec(ctx, `UPDATE gate_devices SET approved=$2,denied=$3 WHERE approve_hash=$1 AND expires_at>$4 AND NOT consumed AND NOT approved AND NOT denied`, Verifier(link), !deny, deny, now)
	if err != nil {
		return nexus.ErrConflict
	}
	if tag.RowsAffected() != 1 {
		return ErrDeviceExpired
	}
	return nil
}

// ClaimDevice commits rate-limit state even on pending/slow polls. Successful
// claims and credential issuance share one transaction; lost responses never replay.
func (s *PostgresCredentials) ClaimDevice(ctx context.Context, code string, now time.Time) (Credential, string, error) {
	return s.claimDevice(ctx, code, now, nil)
}

// ClaimDeviceAllowed rechecks current enrolment policy before issuing a login,
// including requests approved before a policy change or server restart.
func (s *PostgresCredentials) ClaimDeviceAllowed(ctx context.Context, code string, now time.Time, allowed func(pgx.Tx, string) bool) (Credential, string, error) {
	if allowed == nil {
		return Credential{}, "", ErrDeviceDenied
	}
	return s.claimDevice(ctx, code, now, allowed)
}

func (s *PostgresCredentials) claimDevice(ctx context.Context, code string, now time.Time, allowed func(pgx.Tx, string) bool) (Credential, string, error) {
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return Credential{}, "", nexus.ErrConflict
	}
	defer rollback(tx)
	var hash string
	var expiry time.Time
	var last *time.Time
	var approved, denied, consumed bool
	var interval int
	err = tx.QueryRow(ctx, `SELECT licence_hash,expires_at,approved,denied,consumed,interval_seconds,last_poll FROM gate_devices WHERE device_hash=$1 FOR UPDATE`, Verifier(code)).Scan(&hash, &expiry, &approved, &denied, &consumed, &interval, &last)
	if err != nil || consumed || !now.Before(expiry) {
		return Credential{}, "", ErrDeviceExpired
	}
	if denied {
		return Credential{}, "", ErrDeviceDenied
	}
	if last != nil && now.Sub(*last) < time.Duration(interval)*time.Second {
		if interval < 600 {
			interval += 5
		}
		_, err = tx.Exec(ctx, `UPDATE gate_devices SET interval_seconds=$2,last_poll=$3 WHERE device_hash=$1`, Verifier(code), interval, now)
		if err != nil || tx.Commit(ctx) != nil {
			return Credential{}, "", nexus.ErrConflict
		}
		return Credential{}, "", ErrDeviceSlow
	}
	_, err = tx.Exec(ctx, `UPDATE gate_devices SET last_poll=$2 WHERE device_hash=$1`, Verifier(code), now)
	if err != nil {
		return Credential{}, "", nexus.ErrConflict
	}
	if !approved {
		if tx.Commit(ctx) != nil {
			return Credential{}, "", nexus.ErrConflict
		}
		return Credential{}, "", ErrDevicePending
	}
	lic, err := deviceLicence(ctx, tx, hash, now)
	if err != nil || (allowed != nil && !allowed(tx, lic.Email)) {
		return Credential{}, "", ErrDeviceDenied
	}
	token, err := randomToken("ntg_")
	if err != nil {
		return Credential{}, "", err
	}
	c := Credential{Verifier: Verifier(token), Kind: "login", Account: lic.Account, Email: lic.Email, Expires: now.Add(30 * 24 * time.Hour)}
	_, err = tx.Exec(ctx, `INSERT INTO gate_credentials(verifier,kind,account_id,email,expires_at) VALUES($1,$2,$3,$4,$5)`, c.Verifier, c.Kind, c.Account, c.Email, c.Expires)
	if err != nil {
		return Credential{}, "", nexus.ErrConflict
	}
	_, err = tx.Exec(ctx, `UPDATE gate_devices SET consumed=true WHERE device_hash=$1`, Verifier(code))
	if err != nil || tx.Commit(ctx) != nil {
		return Credential{}, "", nexus.ErrConflict
	}
	return c, token, nil
}
