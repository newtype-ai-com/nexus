// Package pgstore implements Nexus persistence using PostgreSQL session connections.
// Only servers should import this package; CLI binaries need no database driver.
package pgstore

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/newtype-ai-com/nexus/nexus"
)

const Channel = "nexus_hub"
const maxAttempts = 8
const globalLock int64 = 7302002

type Store struct{ pool *pgxpool.Pool }

var _ nexus.Store = (*Store)(nil)

func New(pool *pgxpool.Pool) *Store  { return &Store{pool: pool} }
func (s *Store) Pool() *pgxpool.Pool { return s.pool }
func (s *Store) Close()              { s.pool.Close() }

// releaseLocked never returns a connection with a session lock to the pool.
func releaseLocked(conn *pgxpool.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := conn.Exec(ctx, "SELECT pg_advisory_unlock_all()"); err != nil {
		_ = conn.Conn().Close(ctx)
	}
	conn.Release()
}

func (s *Store) Update(ctx context.Context, fn func(nexus.Tx) error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer releaseLocked(conn)
	account := nexus.AccountOf(ctx)
	// Unscoped maintenance writes exclude all account writes. Scoped writers
	// share the global gate, then serialize only their account, before BEGIN.
	if account == "" {
		_, err = conn.Exec(ctx, "SELECT pg_advisory_lock($1)", globalLock)
	} else {
		_, err = conn.Exec(ctx, "SELECT pg_advisory_lock_shared($1)", globalLock)
		if err == nil {
			h := fnv.New32a()
			_, _ = h.Write([]byte(account))
			_, err = conn.Exec(ctx, "SELECT pg_advisory_lock($1, $2)", int32(7302), int32(h.Sum32()))
		}
	}
	if err != nil {
		return err
	}
	for attempt := 0; attempt < maxAttempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		err = runTx(ctx, conn, pgx.TxOptions{IsoLevel: pgx.Serializable}, true, fn)
		if err == nil || !retryable(err) {
			return err
		}
		if attempt+1 < maxAttempts {
			base := time.Millisecond * time.Duration(1<<attempt)
			timer := time.NewTimer(base + time.Duration(rand.Int64N(int64(base))))
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return fmt.Errorf("%w: gave up after %d conflicting attempts", nexus.ErrConflict, maxAttempts)
}

func retryable(err error) bool {
	var pgerr *pgconn.PgError
	if !errors.As(err, &pgerr) {
		return false
	}
	return pgerr.Code == "40001" || pgerr.Code == "40P01" || pgerr.Code == "23505"
}

func (s *Store) View(ctx context.Context, fn func(nexus.Tx) error) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	defer conn.Release()
	return runTx(ctx, conn, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly}, false, fn)
}

func runTx(ctx context.Context, conn *pgxpool.Conn, options pgx.TxOptions, write bool, fn func(nexus.Tx) error) error {
	tx, err := conn.BeginTx(ctx, options)
	if err != nil {
		return err
	}
	t := &transaction{ctx: ctx, tx: tx, write: write, active: true}
	defer func() {
		t.active = false
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	if err := fn(t); err != nil {
		return err
	}
	if write {
		if _, err := tx.Exec(ctx, "SELECT pg_notify($1, '')", Channel); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// Listen reserves one pool connection until cancellation. Restart on connection
// errors (recommended delay: five seconds). NOTIFY contains no account data.
func (s *Store) Listen(ctx context.Context, onChange func()) error {
	conn, err := s.pool.Acquire(ctx)
	if err != nil {
		return err
	}
	// Close instead of recycling a connection with LISTEN session state.
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = conn.Conn().Close(cleanup)
		conn.Release()
	}()
	if _, err := conn.Exec(ctx, "LISTEN "+Channel); err != nil {
		return err
	}
	for {
		if _, err := conn.Conn().WaitForNotification(ctx); err != nil {
			return err
		}
		if onChange != nil {
			onChange()
		}
	}
}
