package pgstore

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/newtype-ai-com/nexus/ids"
)

func TestSessionConfigValidation(t *testing.T) {
	for _, cfg := range []Config{
		{Role: "bad;role"}, {StatementTimeoutMS: -1}, {LockTimeoutMS: -1},
	} {
		cfg.DSN = "postgres://localhost/unused"
		if s, err := Open(context.Background(), cfg); err == nil {
			s.Close()
			t.Fatal("invalid config accepted")
		}
	}
}

func TestExplicitSessionSettingsOnEveryConnection(t *testing.T) {
	dsn := os.Getenv("NTS_NEXUS_TEST_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL with CREATEROLE")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	admin, err := Open(ctx, Config{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	name := "session_test_" + strings.ToLower(string(ids.New(ids.KindEvent)))
	q := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Pool().Exec(ctx, "CREATE ROLE "+q+" NOLOGIN; CREATE SCHEMA "+q+" AUTHORIZATION "+q); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Pool().Exec(ctx, "DROP SCHEMA "+q+" CASCADE; DROP ROLE "+q); err != nil {
			t.Error(err)
		}
	}()
	cfg := Config{DSN: dsn, Schema: name, Role: name, StatementTimeoutMS: 60000, LockTimeoutMS: 5000, MaxConns: 3}
	s, err := Open(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	// Hold all connections so the pool must configure three distinct backends.
	var conns []*pgxpool.Conn
	defer func() {
		for _, c := range conns {
			c.Release()
		}
	}()
	for i := 0; i < 3; i++ {
		c, err := s.Pool().Acquire(ctx)
		if err != nil {
			t.Fatal(err)
		}
		conns = append(conns, c)
		var role, path string
		var statement, lock float64
		if err := c.QueryRow(ctx, `SELECT current_user,current_setting('search_path'),extract(epoch FROM current_setting('statement_timeout')::interval),extract(epoch FROM current_setting('lock_timeout')::interval)`).Scan(&role, &path, &statement, &lock); err != nil {
			t.Fatal(err)
		}
		if role != name || path != q || statement != 60 || lock != 5 {
			t.Fatalf("session mismatch: %s %s %v %v", role, path, statement, lock)
		}
	}
	for _, c := range conns {
		c.Release()
	}
	conns = nil
	if err := s.EnsureSchema(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	s.Pool().Reset()
	var role string
	if err := s.Pool().QueryRow(ctx, "SELECT current_user").Scan(&role); err != nil || role != name {
		t.Fatalf("replacement connection: %v", err)
	}
	cfg.Role = name + "_missing"
	if bad, err := Open(ctx, cfg); err == nil {
		bad.Close()
		t.Fatal("missing role must fail closed")
	}
}
