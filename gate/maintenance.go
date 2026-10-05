package gate

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/jackc/pgx/v5"
)

// AdmitPublicRequest uses fixed server buckets, not caller-chosen headers or
// addresses. Global ceilings complement the per-email/licence limits and avoid
// trusting proxy headers or creating unbounded attacker-controlled DB keys.
func (s *PostgresCredentials) AdmitPublicRequest(ctx context.Context, bucket string, limit int, now time.Time) (bool, error) {
	if (bucket != "api" && bucket != "enrol" && bucket != "device") || limit < 1 || limit > 100000 || now.IsZero() {
		return false, errors.New("gate: invalid rate limit")
	}
	window := now.UTC().Truncate(time.Minute)
	var hits int
	err := s.pool.QueryRow(ctx, `INSERT INTO gate_rate_limits(bucket,window_start,hits) VALUES($1,$2,1)
ON CONFLICT(bucket) DO UPDATE SET window_start=EXCLUDED.window_start,
hits=CASE WHEN gate_rate_limits.window_start=EXCLUDED.window_start THEN gate_rate_limits.hits+1 ELSE 1 END
WHERE gate_rate_limits.window_start<EXCLUDED.window_start OR (gate_rate_limits.window_start=EXCLUDED.window_start AND gate_rate_limits.hits<$3)
RETURNING hits`, bucket, window, limit).Scan(&hits)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	}
	if err != nil {
		return false, errors.New("gate: rate limit unavailable")
	}
	return true, nil
}

// publicAPIBudget bounds the rate-limit DB round trip of every public request.
// 2 s was too short for a server reaching a remote managed session pooler: a request that had
// to open a connection (TLS + SCRAM + session setup) answered 503 at 2.0-2.4 s,
// and the client's 5 s lease validate (internal/gateclient Validate) saw a broken
// licence server every ~30 s (2026-10-04). 4 s covers a fresh connection and
// stays below that client timeout, so a real DB outage is still a clean 503 the
// client receives, not its own timeout. serve also keeps idle connections warm
// (pgstore MinIdleConns).
const publicAPIBudget = 4 * time.Second

// LimitPublicAPI fails closed on DB failure, and applies before body parsing or
// mail/model work. Health checks are exempt. Long SSE counts once at admission.
func (s *PostgresCredentials) LimitPublicAPI(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/health" {
			next.ServeHTTP(w, r)
			return
		}
		entry := time.Now()
		w.Header().Set("Cache-Control", "no-store")
		ctx, cancel := context.WithTimeout(r.Context(), publicAPIBudget)
		defer cancel()
		type bucket struct {
			name  string
			limit int
		}
		buckets := []bucket{{"api", 1200}}
		if r.Method == "POST" && (r.URL.Path == "/v1/enrol" || r.URL.Path == "/v1/enrol/code") {
			buckets = append(buckets, bucket{"enrol", 30})
		}
		if r.Method == "POST" && r.URL.Path == "/v1/device" {
			buckets = append(buckets, bucket{"device", 60})
		}
		for _, b := range buckets {
			ok, err := s.AdmitPublicRequest(ctx, b.name, b.limit, time.Now())
			if err != nil {
				gateError(w, 503, "unavailable")
				return
			}
			if !ok {
				w.Header().Set("Retry-After", "60")
				gateError(w, 429, "rate_limited")
				return
			}
		}
		// Hand the admission DB time to the route's timing log (model relay,
		// validate). Durations only; nothing request-identifying.
		pt := publicTiming{start: entry, admission: time.Since(entry)}
		next.ServeHTTP(w, r.WithContext(withPublicTiming(r.Context(), pt)))
	})
}

// CleanupExpiredChallenges removes at most 1000 rows per table and sweep, only
// after a 24h diagnostic grace. Account mappings, credential verifiers (including
// revoked tombstones) and the Nexus ledger are deliberately never deleted.
func (s *PostgresCredentials) CleanupExpiredChallenges(ctx context.Context, now time.Time) error {
	if now.IsZero() {
		return errors.New("gate: invalid cleanup time")
	}
	tx, err := s.pool.Begin(ctx)
	if err != nil {
		return errors.New("gate: cleanup unavailable")
	}
	defer rollback(tx)
	for _, table := range []string{"gate_enrolments", "gate_devices"} {
		_, err = tx.Exec(ctx, `DELETE FROM `+table+` WHERE ctid IN (SELECT ctid FROM `+table+` WHERE expires_at<$1 ORDER BY expires_at LIMIT 1000 FOR UPDATE SKIP LOCKED)`, now.Add(-24*time.Hour))
		if err != nil {
			return errors.New("gate: cleanup failed")
		}
	}
	if tx.Commit(ctx) != nil {
		return errors.New("gate: cleanup failed")
	}
	return nil
}
