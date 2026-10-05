package pgstore

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestPostgresAccountLockAndCancellation(t *testing.T) {
	s := testStore(t)
	account := ids.Account(ids.New(ids.KindAccount))
	ctx := nexus.WithAccount(context.Background(), account)
	entered, release, done := make(chan struct{}), make(chan struct{}), make(chan error, 1)
	var once sync.Once
	unlock := func() { once.Do(func() { close(release) }) }
	defer unlock()
	go func() { done <- s.Update(ctx, func(nexus.Tx) error { close(entered); <-release; return nil }) }()
	<-entered
	// A different account must not wait for the first account's transaction.
	other, cancel := context.WithTimeout(nexus.WithAccount(context.Background(), ids.Account(ids.New(ids.KindAccount))), time.Second)
	defer cancel()
	if err := s.Update(other, func(nexus.Tx) error { return nil }); err != nil {
		t.Fatal("different account blocked", err)
	}
	// Same-account and unscoped transactions cannot enter while the writer runs.
	for _, base := range []context.Context{ctx, context.Background()} {
		blocked, cancel := context.WithTimeout(base, 100*time.Millisecond)
		called := false
		err := s.Update(blocked, func(nexus.Tx) error { called = true; return nil })
		cancel()
		if called || !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("lock did not block/cancel: called=%v err=%v", called, err)
		}
	}
	unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	// Cancelled waiters must not leave session locks in the pool.
	follow, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	if err := s.Update(follow, func(nexus.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresSnapshotAndRetries(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	session := nexus.Session{ID: ids.Session(ids.New(ids.KindSession)), AccountID: ids.Account(ids.New(ids.KindAccount)), Title: "before"}
	if err := s.Update(ctx, func(tx nexus.Tx) error { return tx.PutSession(session) }); err != nil {
		t.Fatal(err)
	}
	if err := s.View(ctx, func(tx nexus.Tx) error {
		first, err := tx.Session(session.ID)
		if err != nil {
			return err
		}
		session.Title = "after"
		if err := s.Update(ctx, func(tx nexus.Tx) error { return tx.PutSession(session) }); err != nil {
			return err
		}
		second, err := tx.Session(session.ID)
		if err == nil && second.Title != first.Title {
			t.Error("view was not a consistent snapshot")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	attempts := 0
	if err := s.Update(ctx, func(tx nexus.Tx) error {
		attempts++
		session.Title = "retried"
		if err := tx.PutSession(session); err != nil {
			return err
		}
		if attempts < 3 {
			return &pgconn.PgError{Code: "40001"}
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if attempts != 3 {
		t.Fatal(attempts)
	}
	attempts = 0
	err := s.Update(ctx, func(tx nexus.Tx) error {
		attempts++
		session.Title = "must roll back"
		if err := tx.PutSession(session); err != nil {
			return err
		}
		return &pgconn.PgError{Code: "40P01"}
	})
	if !errors.Is(err, nexus.ErrConflict) || attempts != 8 {
		t.Fatalf("attempts=%d err=%v", attempts, err)
	}
	if err := s.View(ctx, func(tx nexus.Tx) error {
		got, err := tx.Session(session.ID)
		if err == nil && got.Title != "retried" {
			t.Error("retry rollback leaked")
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresConcurrentMigration(t *testing.T) {
	s := testStore(t)
	errs := make(chan error, 4)
	for i := 0; i < 4; i++ {
		go func() { errs <- s.Migrate(context.Background()) }()
	}
	for i := 0; i < 4; i++ {
		if err := <-errs; err != nil {
			t.Fatal(err)
		}
	}
}
