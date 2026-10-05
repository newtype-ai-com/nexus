package nexus

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"regexp"
	"strconv"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus/secretplan"
)

// SecretValueLimit bounds one secret value (raw bytes) for FD supply.
const SecretValueLimit = 16 << 10

var secretName = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]{0,63}$`)

// SecretValue is one account secret. Version is a per-name generation that
// never goes back: a DELETE keeps the row as a tombstone (Deleted, no
// ciphertext) so a later PUT continues from the last version and an old
// plan/approval naming (name, version) can never match a new value.
type SecretValue struct {
	AccountID  ids.Account `json:"account_id"`
	Name       string      `json:"name"`
	Version    int64       `json:"version"`
	Deleted    bool        `json:"deleted"`
	Ciphertext []byte      `json:"ciphertext,omitempty"`
	KID        string      `json:"kid,omitempty"`
	CreatedAt  time.Time   `json:"created_at"`
	UpdatedAt  time.Time   `json:"updated_at"`
	UsedAt     *time.Time  `json:"used_at"`
}

// SecretSummary is all a listing shows: never a value, digest or length.
type SecretSummary struct {
	Name      string     `json:"name"`
	Version   int64      `json:"version"`
	UpdatedAt time.Time  `json:"updated_at"`
	UsedAt    *time.Time `json:"used_at"`
}

func secretInfo(name string) []byte { return []byte("newtype-secret/v1|" + name) }
func secretAAD(account ids.Account, name string, version int64) []byte {
	return []byte(string(account) + "|" + name + "|" + strconv.FormatInt(version, 10))
}

// secretKey derives the per-name key OUTSIDE any store transaction (a KMS
// deriver performs network I/O). No sealer → every secret operation refuses.
func (s *Service) secretKey(ctx context.Context, account ids.Account, name string) ([]byte, string, error) {
	if s.sealer == nil || s.sealer.Deriver == nil {
		return nil, "", ErrInvalid
	}
	key, kid, err := s.sealer.Deriver.Derive(ctx, string(account), secretInfo(name))
	if err != nil || len(key) != 32 {
		return nil, "", ErrInvalid
	}
	return key, kid, nil
}

func sealSecret(key []byte, aad, plain []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrInvalid
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrInvalid
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, ErrInvalid
	}
	return gcm.Seal(nonce, nonce, plain, aad), nil
}

func openSecret(key []byte, aad, ct []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrConflict
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil || len(ct) < gcm.NonceSize()+gcm.Overhead() {
		return nil, ErrConflict
	}
	plain, err := gcm.Open(nil, ct[:gcm.NonceSize()], ct[gcm.NonceSize():], aad)
	if err != nil {
		return nil, ErrConflict
	}
	return plain, nil
}

// PutSecret stores a new generation of name (person only). The value is
// never logged; the ledger records name and version only.
func (s *Service) PutSecret(ctx context.Context, actor Principal, name string, value []byte) (int64, error) {
	if actor.Kind != PrincipalUser {
		return 0, ErrForbidden
	}
	if !secretName.MatchString(name) || len(value) == 0 || len(value) > SecretValueLimit {
		return 0, ErrInvalid
	}
	key, kid, err := s.secretKey(ctx, actor.AccountID, name)
	if err != nil {
		return 0, err
	}
	defer clear(key)
	var version int64
	err = s.update(ctx, actor, func(tx Tx) error {
		version = 0
		now := s.now().UTC()
		old, err := tx.SecretValue(actor.AccountID, name)
		switch {
		case err == nil:
		case err == ErrNotFound:
			old = SecretValue{AccountID: actor.AccountID, Name: name, CreatedAt: now}
		default:
			return err
		}
		if old.Version >= secretplan.MaxGeneration {
			return ErrLimit
		}
		next := old
		next.Version, next.Deleted, next.KID, next.UpdatedAt = old.Version+1, false, kid, now
		next.Ciphertext, err = sealSecret(key, secretAAD(actor.AccountID, name, next.Version), value)
		if err != nil {
			return err
		}
		if err := tx.PutSecretValue(next); err != nil {
			return err
		}
		version = next.Version
		return nil
	})
	if err != nil {
		return 0, err
	}
	return version, nil
}

// DeleteSecret tombstones name: the value is gone, the generation stays.
func (s *Service) DeleteSecret(ctx context.Context, actor Principal, name string) error {
	if actor.Kind != PrincipalUser {
		return ErrForbidden
	}
	if !secretName.MatchString(name) {
		return ErrInvalid
	}
	if s.sealer == nil {
		return ErrInvalid
	}
	return s.update(ctx, actor, func(tx Tx) error {
		old, err := tx.SecretValue(actor.AccountID, name)
		if err != nil {
			return err
		}
		if old.Deleted {
			return ErrNotFound
		}
		old.Deleted, old.Ciphertext, old.KID, old.UpdatedAt = true, nil, "", s.now().UTC()
		return tx.PutSecretValue(old)
	})
}

// ListSecrets shows names, current versions and times of live secrets only.
func (s *Service) ListSecrets(ctx context.Context, actor Principal) ([]SecretSummary, error) {
	if actor.Kind != PrincipalUser {
		return nil, ErrForbidden
	}
	if s.sealer == nil {
		return nil, ErrInvalid
	}
	var out []SecretSummary
	err := s.view(ctx, actor, func(tx Tx) error {
		out = []SecretSummary{}
		all, err := tx.SecretValues(actor.AccountID)
		if err != nil {
			return err
		}
		for _, x := range all {
			if !x.Deleted {
				out = append(out, SecretSummary{Name: x.Name, Version: x.Version, UpdatedAt: x.UpdatedAt, UsedAt: x.UsedAt})
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
