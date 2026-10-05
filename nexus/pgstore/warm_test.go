package pgstore

import (
	"context"
	"os"
	"testing"
	"time"
)

func TestMinIdleConnsValidatedWithoutConnecting(t *testing.T) {
	for _, cfg := range []Config{
		{DSN: "postgres://localhost/db", MinIdleConns: -1},
		{DSN: "postgres://localhost/db", MaxConns: 2, MinIdleConns: 2},
		{DSN: "postgres://localhost/db", MinIdleConns: 8}, // default MaxConns 8
	} {
		if s, err := Open(context.Background(), cfg); err == nil {
			s.Close()
			t.Fatalf("accepted MinIdleConns %d / MaxConns %d", cfg.MinIdleConns, cfg.MaxConns)
		}
	}
}

// 2026-10-04: the first public request after a restart had to dial through the
// pooler and overran LimitPublicAPI's 2 s budget. Open now returns with the idle
// connections already open.
func TestOpenWarmsIdleConnections(t *testing.T) {
	dsn := os.Getenv("NTS_NEXUS_TEST_DSN")
	if dsn == "" {
		t.Skip("set NTS_NEXUS_TEST_DSN to a disposable PostgreSQL database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	s, err := Open(ctx, Config{DSN: dsn, MaxConns: 8, MinIdleConns: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if idle := s.Pool().Stat().IdleConns(); idle < 2 {
		t.Fatalf("idle connections after Open = %d, want >= 2", idle)
	}
}
