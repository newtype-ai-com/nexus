package nexusserver

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecureSchema closes Supabase's Data API roles out of the private server
// schema, including grants inherited from the migration owner's defaults.
// Run only in the explicit migration path, never with the serving role.
// It does not alter database-wide defaults or any other schema.
func SecureSchema(ctx context.Context, pool *pgxpool.Pool, schema string) error {
	if pool == nil || schema == "public" || !regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`).MatchString(schema) {
		return errors.New("nexus: invalid private schema")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return errors.New("nexus: schema security transaction failed")
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	roles := []string{"PUBLIC"}
	for _, role := range []string{"anon", "authenticated"} {
		var present bool
		if err := tx.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=$1)`, role).Scan(&present); err != nil {
			return errors.New("nexus: schema security role check failed")
		}
		if present {
			roles = append(roles, pgx.Identifier{role}.Sanitize())
		}
	}
	name := pgx.Identifier{schema}.Sanitize()
	for _, role := range roles {
		statements := []string{
			"REVOKE ALL ON SCHEMA " + name + " FROM " + role,
			"REVOKE ALL ON ALL TABLES IN SCHEMA " + name + " FROM " + role,
			"REVOKE ALL ON ALL SEQUENCES IN SCHEMA " + name + " FROM " + role,
			"REVOKE ALL ON ALL FUNCTIONS IN SCHEMA " + name + " FROM " + role,
			"ALTER DEFAULT PRIVILEGES IN SCHEMA " + name + " REVOKE ALL ON TABLES FROM " + role,
			"ALTER DEFAULT PRIVILEGES IN SCHEMA " + name + " REVOKE ALL ON SEQUENCES FROM " + role,
			"ALTER DEFAULT PRIVILEGES IN SCHEMA " + name + " REVOKE ALL ON FUNCTIONS FROM " + role,
		}
		for _, statement := range statements {
			if _, err := tx.Exec(ctx, statement); err != nil {
				return errors.New("nexus: private schema permission update failed")
			}
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return errors.New("nexus: schema security commit failed")
	}
	return nil
}
