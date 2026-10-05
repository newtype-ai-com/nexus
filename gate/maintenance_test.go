package gate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/nexus/pgstore"
)

func TestRateLimitAndCleanupPostgres(t *testing.T) {
	st, db, schema := enrolmentDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Minute)
	other, err := pgstore.Open(ctx, pgstore.Config{DSN: os.Getenv("NTS_NEXUS_TEST_DSN"), Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	st2 := NewPostgresCredentials(other.Pool())
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			store := st
			if i%2 == 0 {
				store = st2
			}
			ok, err := store.AdmitPublicRequest(ctx, "enrol", 10, now)
			if err != nil {
				t.Error(err)
			}
			if ok {
				accepted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if accepted.Load() != 10 {
		t.Fatal("concurrent ceiling violated", accepted.Load())
	}
	if ok, err := st2.AdmitPublicRequest(ctx, "enrol", 10, now.Add(time.Minute)); err != nil || !ok {
		t.Fatal("new window")
	}
	if ok, _ := st.AdmitPublicRequest(ctx, "enrol", 10, now); ok {
		t.Fatal("old clock reopened window")
	}
	if ok, _ := st.AdmitPublicRequest(ctx, "caller-controlled", 10, now); ok {
		t.Fatal("unbounded bucket")
	}
	old, _, _, err := st.BeginEnrolment(ctx, "old@example.test", now.Add(-48*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	live, _, _, err := st.BeginEnrolment(ctx, "live@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.CleanupExpiredChallenges(ctx, now); err != nil {
		t.Fatal(err)
	}
	var count int
	if db.Pool().QueryRow(ctx, `SELECT count(*) FROM gate_enrolments WHERE id=$1`, old.ID).Scan(&count) != nil || count != 0 {
		t.Fatal("expired retained")
	}
	if db.Pool().QueryRow(ctx, `SELECT count(*) FROM gate_enrolments WHERE id=$1`, live.ID).Scan(&count) != nil || count != 1 {
		t.Fatal("live removed")
	}
	// A saturated durable bucket rejects before the next handler parses a body.
	if _, err := db.Pool().Exec(ctx, `INSERT INTO gate_rate_limits(bucket,window_start,hits) VALUES('api',$1,1200) ON CONFLICT(bucket) DO UPDATE SET hits=1200,window_start=$1`, time.Now().UTC().Truncate(time.Minute)); err != nil {
		t.Fatal(err)
	}
	called := false
	h := st.LimitPublicAPI(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { called = true }))
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", "https://gate.test/v1/enrol", nil)
	r.Header.Set("X-Forwarded-For", "forged")
	h.ServeHTTP(w, r)
	if w.Code != 429 || called || w.Header().Get("Retry-After") == "" {
		t.Fatal("middleware not limiting")
	}
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", "https://gate.test/v1/health", nil))
	if !called {
		t.Fatal("health blocked")
	}
}
