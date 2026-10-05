package pgstore

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/newtype-ai-com/nexus/conformance"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestMarshalEventPreservesPayload(t *testing.T) {
	payload := []byte(`{"z": 9007199254740993, "a": [ 1e+09, "<>&" ]}`)
	e := nexus.Event{Payload: payload, Kind: `payload:null`}
	body, err := marshalEvent(e)
	if err != nil {
		t.Fatal(err)
	}
	var out nexus.Event
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out.Payload, payload) {
		t.Fatalf("payload changed: %s", out.Payload)
	}
	if _, err := marshalEvent(nexus.Event{Payload: []byte("not json")}); !errors.Is(err, nexus.ErrInvalid) {
		t.Fatal(err)
	}
}
func TestRetryable(t *testing.T) {
	for _, code := range []string{"40001", "40P01", "23505"} {
		if !retryable(fmt.Errorf("wrapped: %w", &pgconn.PgError{Code: code})) {
			t.Fatal(code)
		}
	}
	for _, err := range []error{nil, nexus.ErrConflict, context.Canceled, &pgconn.PgError{Code: "23503"}} {
		if retryable(err) {
			t.Fatal(err)
		}
	}
}
func TestConfigRejectsInvalidWithoutConnecting(t *testing.T) {
	for _, cfg := range []Config{{}, {DSN: "bad DSN"}, {DSN: "postgres://localhost/db", Schema: "bad;name"}, {DSN: "postgres://localhost/db", MaxConns: -1}, {DSN: "postgres://postgres@aws-0.pooler.supabase.com:6543/db"}} {
		if s, err := Open(context.Background(), cfg); err == nil {
			s.Close()
			t.Fatal("accepted invalid config")
		}
	}
}

func testStore(t *testing.T) *Store {
	t.Helper()
	dsn := os.Getenv("NTS_NEXUS_TEST_DSN")
	if dsn == "" {
		t.Skip("set NTS_NEXUS_TEST_DSN to a disposable PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	base, err := Open(ctx, Config{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	name := "nts_test_" + strings.ToLower(string(ids.New(ids.KindEvent)))
	if err := base.EnsureSchema(ctx, name); err != nil {
		base.Close()
		t.Fatal(err)
	}
	base.Close()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		cleanup, err := Open(ctx, Config{DSN: dsn})
		if err != nil {
			t.Error(err)
			return
		}
		defer cleanup.Close()
		if _, err := cleanup.Pool().Exec(ctx, `DROP SCHEMA "`+name+`" CASCADE`); err != nil {
			t.Error(err)
		}
	})
	s, err := Open(ctx, Config{DSN: dsn, Schema: name, MaxConns: 8})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	for i := 0; i < 2; i++ {
		if err := s.Migrate(ctx); err != nil {
			t.Fatal(err)
		}
	}
	return s
}
func TestPostgresConformance(t *testing.T) {
	if os.Getenv("NTS_NEXUS_TEST_DSN") == "" {
		t.Skip("set NTS_NEXUS_TEST_DSN to a disposable PostgreSQL database")
	}
	// The suite's factory lacks *testing.T; all stores are cleaned up after Run.
	conformance.Run(t, func() nexus.Store { return testStore(t) })
}
func TestPostgresRetriedConformance(t *testing.T) {
	if os.Getenv("NTS_NEXUS_TEST_DSN") == "" {
		t.Skip("set NTS_NEXUS_TEST_DSN to a disposable PostgreSQL database")
	}
	conformance.Run(t, func() nexus.Store { return conformance.Retrying{Store: testStore(t)} })
}
func TestPostgresPayloadAndLifecycle(t *testing.T) {
	s := testStore(t)
	ctx := context.Background()
	account := ids.Account(ids.New(ids.KindAccount))
	session := nexus.Session{ID: ids.Session(ids.New(ids.KindSession)), AccountID: account, Status: nexus.SessionRunning}
	payload := []byte(`{"z": 9007199254740993, "a": [ 1e+09, "<>&" ]}`)
	hash := sha256.Sum256(payload)
	e := nexus.Event{ID: ids.Event(ids.New(ids.KindEvent)), AccountID: account, SessionID: session.ID, Payload: payload, PayloadHash: "sha256:" + hex.EncodeToString(hash[:])}
	var escaped nexus.Tx
	if err := s.Update(ctx, func(tx nexus.Tx) error {
		escaped = tx
		if err := tx.PutSession(session); err != nil {
			return err
		}
		_, err := tx.AppendEvent(e)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := escaped.Session(session.ID); !errors.Is(err, nexus.ErrInvalid) {
		t.Fatal("escaped transaction", err)
	}
	if err := s.View(ctx, func(tx nexus.Tx) error {
		events, err := tx.Events(session.ID, 0, 0)
		if err != nil {
			return err
		}
		if len(events) != 1 || !bytes.Equal(events[0].Payload, payload) || events[0].PayloadHash != e.PayloadHash {
			t.Fatal("payload/hash changed")
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	// A newer schema must be rejected without recreating a missing table.
	if _, err := s.Pool().Exec(ctx, fmt.Sprintf("UPDATE hub_meta SET value=%d WHERE key='schema'; DROP TABLE secrets", SchemaVersion+1)); err != nil {
		t.Fatal(err)
	}
	if err := s.Migrate(ctx); err == nil {
		t.Fatal("accepted future schema")
	}
	var present bool
	if err := s.Pool().QueryRow(ctx, "SELECT to_regclass('secrets') IS NOT NULL").Scan(&present); err != nil {
		t.Fatal(err)
	}
	if present {
		t.Fatal("future schema was mutated")
	}
}
func TestPostgresNotifiesOtherServers(t *testing.T) {
	s := testStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	changes := make(chan struct{}, 16)
	done := make(chan error, 1)
	go func() { done <- s.Listen(ctx, func() { changes <- struct{}{} }) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Error("listener did not stop")
		}
	}()
	// Probe until LISTEN is installed instead of relying on a fixed sleep.
	deadline := time.After(10 * time.Second)
	ready := false
	for !ready {
		if _, err := s.Pool().Exec(ctx, "SELECT pg_notify($1,'')", Channel); err != nil {
			t.Fatal(err)
		}
		select {
		case <-changes:
			ready = true
		case err := <-done:
			t.Fatalf("listener: %v", err)
		case <-deadline:
			t.Fatal("LISTEN not ready")
		case <-time.After(20 * time.Millisecond):
		}
	}
	for len(changes) > 0 {
		<-changes
	}
	rollback := errors.New("rollback")
	if err := s.Update(ctx, func(nexus.Tx) error { return rollback }); !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	select {
	case <-changes:
		t.Fatal("rollback notified")
	case <-time.After(100 * time.Millisecond):
	}
	// A separate pool simulates another server sharing the database/schema.
	pool, err := pgxpool.NewWithConfig(ctx, s.Pool().Config())
	if err != nil {
		t.Fatal(err)
	}
	otherPool := New(pool)
	defer otherPool.Close()
	if err := otherPool.Update(ctx, func(nexus.Tx) error { return nil }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changes:
	case <-time.After(10 * time.Second):
		t.Fatal("commit did not notify")
	}
}
