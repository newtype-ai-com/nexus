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

func TestEnsureExistingSchemaWithoutDatabaseCreate(t *testing.T) {
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
	name := "owner_test_" + strings.ToLower(string(ids.New(ids.KindEvent)))
	q := pgx.Identifier{name}.Sanitize()
	if _, err := admin.Pool().Exec(ctx, "CREATE ROLE "+q+" NOLOGIN; CREATE SCHEMA "+q+" AUTHORIZATION "+q); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Pool().Exec(ctx, "DROP SCHEMA "+q+" CASCADE; DROP ROLE "+q); err != nil {
			t.Error(err)
		}
	}()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["role"] = name
	cfg.ConnConfig.RuntimeParams["search_path"] = q
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	s := New(pool)
	var canCreate bool
	if err := pool.QueryRow(ctx, "SELECT has_database_privilege(current_user,current_database(),'CREATE')").Scan(&canCreate); err != nil || canCreate {
		t.Fatalf("fixture must lack database CREATE: %v", err)
	}
	if _, err := pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+q); err == nil {
		t.Fatal("expected direct DDL to fail")
	}
	if err := s.EnsureSchema(ctx, name); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.EnsureSchema(ctx, name+"_absent"); err == nil {
		t.Fatal("must not create an absent schema without permission")
	}
}
