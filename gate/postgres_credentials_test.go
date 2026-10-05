package gate

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
)

func TestPostgresCredentials(t *testing.T) {
	dsn := os.Getenv("NTS_NEXUS_TEST_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base, err := pgstore.Open(ctx, pgstore.Config{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer base.Close()
	name := "gate_test_" + strings.ToLower(string(ids.New(ids.KindEvent)))
	if err = base.EnsureSchema(ctx, name); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, err := base.Pool().Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{name}.Sanitize()+" CASCADE")
		if err != nil {
			t.Error(err)
		}
	}()
	s, err := pgstore.Open(ctx, pgstore.Config{DSN: dsn, Schema: name})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	store := NewPostgresCredentials(s.Pool())
	for range 2 {
		if err = store.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	c := Credential{Verifier: Verifier("fixture credential with high entropy in production"), Kind: "login", Account: ids.Account(ids.New(ids.KindAccount)), Email: "test@example.test", Expires: time.Now().Add(time.Hour).UTC().Truncate(time.Microsecond)}
	if err = store.PutCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	// A second pool models process restart; no in-memory credential cache.
	s2, err := pgstore.Open(ctx, pgstore.Config{DSN: dsn, Schema: name})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	other := NewPostgresCredentials(s2.Pool())
	got, err := other.LookupCredential(ctx, c.Verifier)
	got.Expires = got.Expires.UTC()
	if err != nil || got != c {
		t.Fatalf("readback mismatch: %v", err)
	}
	bad := c
	bad.Account = ids.Account(ids.New(ids.KindAccount))
	if err = other.PutCredential(ctx, bad); !errors.Is(err, nexus.ErrConflict) {
		t.Fatal("identity overwrite allowed")
	}
	bad = c
	bad.Email = "different@example.test"
	if err = other.PutCredential(ctx, bad); !errors.Is(err, nexus.ErrConflict) {
		t.Fatal("email overwrite allowed")
	}
	c.Revoked = true
	if err = store.PutCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	c.Revoked = false
	if err = store.PutCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	got, err = other.LookupCredential(ctx, c.Verifier)
	if err != nil || !got.Revoked {
		t.Fatal("revocation not sticky")
	}
	if _, err = other.LookupCredential(ctx, Verifier("missing")); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal(err)
	}
	if _, err = s.Pool().Exec(ctx, `UPDATE gate_meta SET value=2 WHERE key='credentials'`); err != nil {
		t.Fatal(err)
	}
	if store.Migrate(ctx) == nil {
		t.Fatal("future schema accepted")
	}
}
