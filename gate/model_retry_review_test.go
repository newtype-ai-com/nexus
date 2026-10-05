package gate

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestM21ReviewAmbiguousEnvelopesNeverReplay(t *testing.T) {
	for _, frame := range []string{
		`data: {"unknown":"output"}`,
		`event: error` + "\n" + `data: {"type":"response.output_text.delta","error":{"code":"rate_limit_exceeded"}}`,
		`data: {"type":"error","choices":[{}],"error":{"code":"rate_limit_exceeded"}}`,
		`data: {"type":"error","error":{"code":"authentication_error","code":"rate_limit_exceeded"}}`,
		`data: {"type":"error","error":{"code":"rate_limit_exceeded","type":"authentication_error"}}`,
		`data: {"type":"response.created","response":{"output":[{"text":"already generated"}]}}`,
		`data: {"type":"response.created"} {"ignored":true}`,
	} {
		raw := frame + "\n\n" + sseLimit
		prefix, rest, verdict := peekStream(strings.NewReader(raw), nil)
		tail, _ := io.ReadAll(rest)
		if verdict == peekLimited || string(prefix)+string(tail) != raw {
			t.Fatalf("unsafe replay or byte loss: %s / %s", frame, verdict)
		}
	}
}

func TestM21ReviewLongHintNeverRetriesEarly(t *testing.T) {
	now := time.Now()
	for _, hint := range []string{"86401", "999999999999999999999", now.Add(48 * time.Hour).UTC().Format(http.TimeFormat)} {
		after, ok := parseRetryAfter(hint, now)
		if !ok || after <= modelRetryBudget {
			t.Fatalf("long hint discarded: %s %v", hint, after)
		}
	}
	target := time.Now().Add(10 * time.Second).UTC().Truncate(time.Second)
	now = target.Add(-5*time.Second - 100*time.Millisecond)
	after, _ := parseRetryAfter(target.Format(http.TimeFormat), now)
	if after < target.Sub(now) {
		t.Fatal("date rounded down")
	}
	f := newRetryFixture(t, true, answerSSE(sseLimit))
	f.answers[0] = func(w http.ResponseWriter, _ int) { w.Header().Set("Retry-After", "3600"); answerSSE(sseLimit)(w, 0) }
	w := f.serve(responsesBody)
	if f.calls.Load() != 1 || w.Header().Get("X-Newtype-Model-Retry") != "exhausted" {
		t.Fatal("SSE hint ignored")
	}
}

func TestM21ReviewExtendedHoldPreservesCharge(t *testing.T) {
	f := newRetryFixture(t, false, refuse429(""))
	f.handler.retry.sleep = func(ctx context.Context, d time.Duration) error {
		f.handler.pace.hold(time.Now(), time.Hour)
		return nil
	}
	w := f.serve(chatBody)
	if f.calls.Load() != 1 {
		t.Fatal(f.calls.Load())
	}
	state := f.execution(w)
	if state.Charged == 0 || state.Status == "completed" {
		t.Fatalf("prior dispatch erased: %+v", state)
	}
}

func TestM21ReviewWatchCancelsRetryWait(t *testing.T) {
	f := newRetryFixture(t, true, answerSSE(sseLimit))
	f.handler.cfg.StreamIdleTimeout = 10 * time.Millisecond
	f.handler.retry.waits = []time.Duration{time.Second}
	f.handler.retry.budget = 2 * time.Second
	start := time.Now()
	f.serve(responsesBody)
	if time.Since(start) > 500*time.Millisecond || f.calls.Load() != 1 {
		t.Fatal("watch cancellation did not stop retry wait")
	}
}
