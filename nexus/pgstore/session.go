package pgstore

import (
	"context"

	"strconv"

	"github.com/jackc/pgx/v5"
)

// configureSession is for direct/session pooling only. A transaction pins all
// setup statements to one backend; false makes the settings survive commit.
// Never return a connection whose requested security context was not verified.
func configureSession(ctx context.Context, conn *pgx.Conn, cfg Config) error {
	if cfg.Role == "" && cfg.Schema == "" && cfg.StatementTimeoutMS == 0 && cfg.LockTimeoutMS == 0 {
		return nil
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return stageError("session_begin")
	}
	defer tx.Rollback(ctx)
	if cfg.Role != "" {
		if _, err := tx.Exec(ctx, "SET ROLE "+pgx.Identifier{cfg.Role}.Sanitize()); err != nil {
			return stageError("set_role")
		}
		var role string
		if err := tx.QueryRow(ctx, "SELECT current_user").Scan(&role); err != nil || role != cfg.Role {
			return stageError("verify_role")
		}
	}
	settings := []struct{ key, value string }{}
	if cfg.Schema != "" {
		settings = append(settings, struct{ key, value string }{"search_path", pgx.Identifier{cfg.Schema}.Sanitize()})
	}
	for _, v := range []struct {
		key string
		ms  int
	}{{"statement_timeout", cfg.StatementTimeoutMS}, {"lock_timeout", cfg.LockTimeoutMS}} {
		if v.ms > 0 {
			settings = append(settings, struct{ key, value string }{v.key, strconv.Itoa(v.ms) + "ms"})
		}
	}
	for _, s := range settings {
		var applied, actual string
		if err := tx.QueryRow(ctx, "SELECT pg_catalog.set_config($1,$2,false)", s.key, s.value).Scan(&applied); err != nil {
			return stageError("session_settings")
		}
		if err := tx.QueryRow(ctx, "SELECT pg_catalog.current_setting($1)", s.key).Scan(&actual); err != nil || actual != applied || (s.key == "search_path" && actual != s.value) {
			return stageError("verify_settings")
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return stageError("session_commit")
	}
	return nil
}
