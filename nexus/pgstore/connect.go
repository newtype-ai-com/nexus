package pgstore

import (
	"context"
	_ "embed"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const SchemaVersion = 9

//go:embed schema.sql
var schemaSQL string

type Config struct {
	DSN                string
	Schema             string
	Role               string
	StatementTimeoutMS int
	LockTimeoutMS      int
	MaxConns           int32
	// MinIdleConns keeps that many configured connections idle (pgxpool recreates
	// them on its health check), and Open opens them before returning. serve sets
	// it: one connection is held by LISTEN, and a request that had to dial TLS +
	// SCRAM + session setup through the pooler overran the 2 s public-API DB budget
	// (2026-10-04, first click after a restart answered 503).
	MinIdleConns int32
	// Password, when set, is put into the parsed config directly (pipe-only
	// secret input); the DSN must then carry no password of its own.
	Password string
	// RequireSCRAM refuses every authentication except a complete
	// SCRAM-SHA-256 exchange, before any password message is sent.
	RequireSCRAM bool
}

var schemaName = regexp.MustCompile(`^[a-z_][a-z0-9_]{0,62}$`)

// Open uses DATABASE_URL / NEXUS_DB_DSN supplied by the caller, never cloud IAM.
// Supabase must use direct or session pooling; transaction pooling cannot keep
// advisory locks or LISTEN state. TLS verification is controlled by the DSN.
func Open(ctx context.Context, cfg Config) (*Store, error) {
	if cfg.DSN == "" {
		return nil, fmt.Errorf("pgstore: DSN is required")
	}
	if cfg.Schema != "" && !schemaName.MatchString(cfg.Schema) {
		return nil, fmt.Errorf("pgstore: invalid schema name")
	}
	if cfg.Role != "" && !schemaName.MatchString(cfg.Role) {
		return nil, fmt.Errorf("pgstore: invalid role name")
	}
	if cfg.StatementTimeoutMS < 0 || cfg.LockTimeoutMS < 0 || cfg.StatementTimeoutMS > 2147483647 || cfg.LockTimeoutMS > 2147483647 {
		return nil, fmt.Errorf("pgstore: invalid session timeout")
	}
	if cfg.MaxConns < 0 {
		return nil, fmt.Errorf("pgstore: MaxConns must be positive")
	}
	if cfg.MinIdleConns < 0 || (cfg.MaxConns > 0 && cfg.MinIdleConns >= cfg.MaxConns) || (cfg.MaxConns == 0 && cfg.MinIdleConns >= 8) {
		return nil, fmt.Errorf("pgstore: invalid MinIdleConns")
	}
	pc, err := pgxpool.ParseConfig(cfg.DSN)
	if err != nil {
		return nil, fmt.Errorf("pgstore: invalid DSN")
	} // never echo credentials
	if strings.HasSuffix(strings.ToLower(pc.ConnConfig.Host), ".pooler.supabase.com") && pc.ConnConfig.Port == 6543 {
		return nil, fmt.Errorf("pgstore: Supabase transaction pooling is unsupported; use session mode port 5432")
	}
	if cfg.Password != "" {
		if pc.ConnConfig.Password != "" {
			return nil, fmt.Errorf("pgstore: invalid DSN")
		}
		pc.ConnConfig.Password = cfg.Password
	}
	if cfg.RequireSCRAM {
		if len(pc.ConnConfig.Fallbacks) != 0 {
			return nil, fmt.Errorf("pgstore: invalid DSN")
		}
		pc.ConnConfig.BuildFrontend = scramOnlyFrontend
	}
	pc.MaxConns = cfg.MaxConns
	if pc.MaxConns == 0 {
		pc.MaxConns = 8
	}
	pc.MinIdleConns = cfg.MinIdleConns
	// Session poolers may ignore startup parameters. Configure and verify every
	// physical connection before pgxpool can lend it to a migration or request.
	if cfg.Schema != "" {
		delete(pc.ConnConfig.RuntimeParams, "search_path")
	}
	if cfg.Role != "" {
		delete(pc.ConnConfig.RuntimeParams, "role")
	}
	pc.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		return configureSession(ctx, conn, cfg)
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	pool, err := pgxpool.NewWithConfig(ctx, pc)
	if err != nil {
		return nil, fmt.Errorf("pgstore: cannot create pool")
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, stageError(ConnectionStage(err))
	}
	warm(ctx, pool, int(cfg.MinIdleConns))
	return New(pool), nil
}

// warm opens n configured connections now (concurrently, within Open's deadline)
// and returns them idle to the pool. Best effort: a failure here leaves the pool
// to its health check; requests still fail closed on their own budgets.
func warm(ctx context.Context, pool *pgxpool.Pool, n int) {
	if n <= 0 {
		return
	}
	conns := make(chan *pgxpool.Conn, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if conn, err := pool.Acquire(ctx); err == nil {
				conns <- conn
			}
		}()
	}
	wg.Wait()
	close(conns)
	for conn := range conns {
		conn.Release()
	}
}

// EnsureSchema must be called using a connection whose search_path exists.
func (s *Store) EnsureSchema(ctx context.Context, name string) error {
	if !schemaName.MatchString(name) {
		return fmt.Errorf("pgstore: invalid schema name")
	}
	// A dedicated migration role may own a pre-created schema without having
	// database-wide CREATE. PostgreSQL checks that privilege even for CREATE
	// SCHEMA IF NOT EXISTS, so avoid DDL when the namespace already exists.
	var exists bool
	if err := s.pool.QueryRow(ctx, "SELECT EXISTS (SELECT 1 FROM pg_namespace WHERE nspname=$1)", name).Scan(&exists); err != nil {
		return err
	}
	if exists {
		return nil
	}
	_, err := s.pool.Exec(ctx, "CREATE SCHEMA IF NOT EXISTS "+pgx.Identifier{name}.Sanitize())
	return err
}

// Migrate upgrades atomically under a dedicated session advisory lock. Future
// versions are rejected before any DDL, leaving newer databases untouched.
func (s *Store) Migrate(ctx context.Context) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer releaseLocked(conn)
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_lock($1)", int64(7302001)); err != nil {
		return err
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	var present bool
	if err := tx.QueryRow(ctx, "SELECT to_regclass('hub_meta') IS NOT NULL").Scan(&present); err != nil {
		return err
	}
	if present {
		var version int
		err := tx.QueryRow(ctx, "SELECT value FROM hub_meta WHERE key='schema'").Scan(&version)
		if err != nil && err != pgx.ErrNoRows {
			return err
		}
		if version > SchemaVersion {
			return fmt.Errorf("pgstore: schema version %d exceeds supported %d", version, SchemaVersion)
		}
	}
	if _, err := tx.Exec(ctx, schemaSQL); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
