package conformance

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/seal"
)

// sealed returns a service with a public fixture master (never an operational key).
func (f *fixture) sealed(t *testing.T) *nexus.Service {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i)
	}
	signer, err := seal.NewEd25519Signer(ed25519.NewKeyFromSeed(seed), "fixture-v1")
	must(t, err)
	deriver, err := seal.NewMasterDeriver(seed)
	must(t, err)
	s, err := nexus.NewServiceWithSealing(f.store, func() time.Time { return f.now }, &seal.Sealer{Signer: signer, Deriver: deriver}, "https://gate.example.test")
	must(t, err)
	return s
}

func runSecrets(t *testing.T, open func() nexus.Store) {
	ctx := context.Background()
	value := []byte("PUBLIC-FIXTURE-SECRET-VALUE-0001")
	t.Run("secret_generations_never_reset", func(t *testing.T) {
		f := newFixture(t, open)
		svc := f.sealed(t)
		v, err := svc.PutSecret(ctx, f.person, "DB_ADMIN", value)
		must(t, err)
		if v != 1 {
			t.Fatal(v)
		}
		v, err = svc.PutSecret(ctx, f.person, "DB_ADMIN", value)
		must(t, err)
		if v != 2 {
			t.Fatal(v)
		}
		must(t, svc.DeleteSecret(ctx, f.person, "DB_ADMIN"))
		wantErr(t, svc.DeleteSecret(ctx, f.person, "DB_ADMIN"), nexus.ErrNotFound)
		list, err := svc.ListSecrets(ctx, f.person)
		must(t, err)
		if len(list) != 0 {
			t.Fatal("tombstone listed")
		}
		v, err = svc.PutSecret(ctx, f.person, "DB_ADMIN", value)
		must(t, err)
		if v != 3 {
			t.Fatalf("generation reset to %d after delete", v)
		}
		list, err = svc.ListSecrets(ctx, f.person)
		must(t, err)
		if len(list) != 1 || list[0].Name != "DB_ADMIN" || list[0].Version != 3 {
			t.Fatalf("%+v", list)
		}
		// the stored record holds ciphertext only
		must(t, f.store.View(ctx, func(tx nexus.Tx) error {
			x, err := tx.SecretValue(f.account, "DB_ADMIN")
			if err != nil {
				return err
			}
			if len(x.Ciphertext) == 0 || containsBytes(x.Ciphertext, value) || x.KID == "" {
				t.Fatal("plaintext stored or no ciphertext")
			}
			return nil
		}))
		// generations never go back at the store level either
		must(t, f.store.Update(ctx, func(tx nexus.Tx) error {
			x, err := tx.SecretValue(f.account, "DB_ADMIN")
			if err != nil {
				return err
			}
			x.Version = 1
			wantErr(t, tx.PutSecretValue(x), nexus.ErrConflict)
			return nil
		}))
	})
	t.Run("secret_access_boundaries", func(t *testing.T) {
		f := newFixture(t, open)
		plain := f.svc // no sealer: every secret route refuses
		_, err := plain.PutSecret(ctx, f.person, "DB_ADMIN", value)
		wantErr(t, err, nexus.ErrInvalid)
		_, err = plain.ListSecrets(ctx, f.person)
		wantErr(t, err, nexus.ErrInvalid)
		svc := f.sealed(t)
		root := f.issue(rootRequest())
		session := nexus.SessionPrincipal(f.account, root.Session.ID)
		_, err = svc.PutSecret(ctx, session, "DB_ADMIN", value)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = svc.ListSecrets(ctx, session)
		wantErr(t, err, nexus.ErrForbidden)
		for _, bad := range []string{"1BAD", "a-b", "", string(make([]byte, 65))} {
			_, err = svc.PutSecret(ctx, f.person, bad, value)
			wantErr(t, err, nexus.ErrInvalid)
		}
		_, err = svc.PutSecret(ctx, f.person, "BIG", make([]byte, nexus.SecretValueLimit+1))
		wantErr(t, err, nexus.ErrInvalid)
		_, err = svc.PutSecret(ctx, f.person, "EMPTY", nil)
		wantErr(t, err, nexus.ErrInvalid)
		_, err = svc.PutSecret(ctx, f.person, "EDGE", make([]byte, nexus.SecretValueLimit))
		must(t, err)
		other := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "other@example.com")
		list, err := svc.ListSecrets(ctx, other)
		must(t, err)
		if len(list) != 0 {
			t.Fatal("cross-account listing")
		}
	})
}

func containsBytes(haystack, needle []byte) bool {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if string(haystack[i:i+len(needle)]) == string(needle) {
			return true
		}
	}
	return false
}
