package nexusserver

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
)

func TestSecureSchemaPostgres(t *testing.T) {
	dsn := os.Getenv("NTS_NEXUS_TEST_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx := context.Background()
	db, err := pgstore.Open(ctx, pgstore.Config{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	name := "private_test_" + strings.ToLower(ids.New(ids.KindEvent))
	q := pgx.Identifier{name}.Sanitize()
	if db.EnsureSchema(ctx, name) != nil {
		t.Fatal("create schema")
	}
	defer func() {
		if _, err := db.Pool().Exec(context.Background(), "DROP SCHEMA "+q+" CASCADE"); err != nil {
			t.Error("cleanup")
		}
	}()
	// Reproduce PUBLIC defaults that otherwise expose every newly created table.
	if _, err = db.Pool().Exec(ctx, "CREATE TABLE "+q+".fixture (id int); GRANT ALL ON SCHEMA "+q+" TO PUBLIC; GRANT ALL ON "+q+".fixture TO PUBLIC; ALTER DEFAULT PRIVILEGES IN SCHEMA "+q+" GRANT ALL ON TABLES TO PUBLIC"); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if SecureSchema(ctx, db.Pool(), name) != nil {
			t.Fatal("secure schema")
		}
	}
	var count int
	if db.Pool().QueryRow(ctx, `SELECT count(*) FROM pg_namespace n, LATERAL aclexplode(n.nspacl) a WHERE n.nspname=$1 AND a.grantee=0`, name).Scan(&count) != nil || count != 0 {
		t.Fatal("PUBLIC schema grant remains")
	}
	if _, err = db.Pool().Exec(ctx, "CREATE TABLE "+q+".later (id int)"); err != nil {
		t.Fatal(err)
	}
	if db.Pool().QueryRow(ctx, `SELECT count(*) FROM pg_class c JOIN pg_namespace n ON c.relnamespace=n.oid, LATERAL aclexplode(c.relacl) a WHERE n.nspname=$1 AND a.grantee=0`, name).Scan(&count) != nil || count != 0 {
		t.Fatal("PUBLIC table grant remains")
	}
	if SecureSchema(ctx, db.Pool(), "public") == nil || SecureSchema(ctx, nil, name) == nil {
		t.Fatal("invalid schema accepted")
	}
}
