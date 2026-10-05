package core

import (
	"context"
	"errors"
	"net/http"
	"sync"
	"testing"
	"time"
)

// fakeHTTPError stands in for coremodel.HTTPError without importing the
// provider package into core tests.
type fakeHTTPError struct {
	code      int
	after     time.Duration
	exhausted bool
}

func (e *fakeHTTPError) Error() string                                { return "model HTTP" }
func (e *fakeHTTPError) StatusCode() int                              { return e.code }
func (e *fakeHTTPError) RateLimitedRetryAfter() (time.Duration, bool) { return e.after, e.exhausted }

func TestM21FinalRateLimitDoesNotMultiplyCoreRetries(t *testing.T) {
	// The decision table.
	base := 2 * time.Second
	if w, retry, rl := modelRetryPlan(&fakeHTTPError{code: 429, exhausted: true}, 0, 0, base); retry || !rl || w != 0 {
		t.Fatalf("gate-exhausted refusal retried: %v %v %v", w, retry, rl)
	}
	if w, retry, rl := modelRetryPlan(&fakeHTTPError{code: 429}, 0, 0, base); !retry || !rl || w != directRateLimitWait {
		t.Fatalf("direct 429 without Retry-After: %v %v %v", w, retry, rl)
	}
	if w, retry, _ := modelRetryPlan(&fakeHTTPError{code: 429, after: 12 * time.Second}, 0, 0, base); !retry || w != 12*time.Second {
		t.Fatalf("Retry-After not honoured: %v %v", w, retry)
	}
	if _, retry, rl := modelRetryPlan(&fakeHTTPError{code: 429, after: 61 * time.Second}, 0, 0, base); retry || !rl {
		t.Fatal("Retry-After beyond the direct budget retried")
	}
	if _, retry, _ := modelRetryPlan(&fakeHTTPError{code: 429}, 1, 56*time.Second, base); retry {
		t.Fatal("direct budget exceeded by accumulated waits")
	}
	if w, retry, rl := modelRetryPlan(&fakeHTTPError{code: 503}, 1, 0, base); !retry || rl || w != 4*time.Second {
		t.Fatalf("transient non-429 lost its ladder: %v %v %v", w, retry, rl)
	}
	if _, retry, _ := modelRetryPlan(&fakeHTTPError{code: 401}, 0, 0, base); retry {
		t.Fatal("permanent error retried")
	}
	if _, retry, _ := modelRetryPlan(context.Canceled, 0, 0, base); retry {
		t.Fatal("cancellation retried")
	}
	if w, retry, _ := modelRetryPlan(errors.New("model transport failed"), 0, 0, -time.Second); !retry || w != 0 {
		t.Fatalf("negative base delay must mean no wait: %v %v", w, retry)
	}

	// Through the engine: a Gate-final refusal is one invocation, no sleep.
	var mu sync.Mutex
	var slept []time.Duration
	prev := modelRetrySleep
	modelRetrySleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		slept = append(slept, d)
		mu.Unlock()
		return ctx.Err()
	}
	defer func() { modelRetrySleep = prev }()

	calls := 0
	final := modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		calls++
		return ModelResponse{}, &fakeHTTPError{code: http.StatusTooManyRequests, after: 7 * time.Second, exhausted: true}
	})
	e := newTestEngine(t, final, nil)
	events := send(t, e, ChatRequest{Message: "go"})
	if calls != 1 || len(slept) != 0 {
		t.Fatalf("gate-final 429 multiplied: calls=%d slept=%v", calls, slept)
	}
	if eventCount(events, "error") == 0 && eventCount(events, "done") == 0 {
		t.Fatalf("turn did not end: %s", eventText(events))
	}
	rec, _ := e.LoadSession(events[0].SessionID)
	if len(rec.Turns) != 1 || len(rec.Turns[0].Invocations) != 1 {
		t.Fatalf("invocations recorded: %+v", rec.Turns)
	}

	// Direct provider 429 (no Gate): waits at least Retry-After, bounded,
	// three attempts at most, same request each time.
	calls, slept = 0, nil
	var bodies []string
	direct := modelFunc(func(_ context.Context, r ModelRequest, _ func(string)) (ModelResponse, error) {
		calls++
		bodies = append(bodies, r.Messages[len(r.Messages)-1].Content)
		if calls < 3 {
			return ModelResponse{}, &fakeHTTPError{code: 429, after: 9 * time.Second}
		}
		return ModelResponse{Content: "late but fine"}, nil
	})
	e2 := newTestEngine(t, direct, nil)
	events = send(t, e2, ChatRequest{Message: "same"})
	assertTerminated(t, events)
	if calls != 3 || len(slept) != 2 || slept[0] != 9*time.Second || slept[1] != 9*time.Second {
		t.Fatalf("direct 429 ladder: calls=%d slept=%v", calls, slept)
	}
	for _, b := range bodies {
		if b != bodies[0] {
			t.Fatal("retry sent a different request")
		}
	}
	if eventCount(events, "notice") < 2 {
		t.Fatalf("rate-limit waits not announced: %s", eventText(events))
	}
	// Budget: a direct 429 asking for more than the client budget ends the turn
	// with the error and no sleep.
	calls, slept = 0, nil
	slow := modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		calls++
		return ModelResponse{}, &fakeHTTPError{code: 429, after: 2 * time.Minute}
	})
	e3 := newTestEngine(t, slow, nil)
	send(t, e3, ChatRequest{Message: "x"})
	if calls != 1 || len(slept) != 0 {
		t.Fatalf("over-budget Retry-After retried: calls=%d slept=%v", calls, slept)
	}
	// Partial output before a 429 is never replayed (existing rule, kept).
	calls, slept = 0, nil
	partial := modelFunc(func(_ context.Context, _ ModelRequest, on func(string)) (ModelResponse, error) {
		calls++
		on("half an answer")
		return ModelResponse{}, &fakeHTTPError{code: 429}
	})
	e4 := newTestEngine(t, partial, nil)
	send(t, e4, ChatRequest{Message: "x"})
	if calls != 1 || len(slept) != 0 {
		t.Fatalf("partial output replayed: calls=%d slept=%v", calls, slept)
	}
	// Cancellation while sleeping ends the turn without another call.
	calls = 0
	ctxModel := modelFunc(func(context.Context, ModelRequest, func(string)) (ModelResponse, error) {
		calls++
		return ModelResponse{}, &fakeHTTPError{code: 429, after: 5 * time.Second}
	})
	e5 := newTestEngine(t, ctxModel, nil)
	modelRetrySleep = func(ctx context.Context, d time.Duration) error {
		e5.Cancel()
		<-ctx.Done()
		return ctx.Err()
	}
	send(t, e5, ChatRequest{Message: "x"})
	if calls != 1 {
		t.Fatalf("called again after cancellation: %d", calls)
	}
}
