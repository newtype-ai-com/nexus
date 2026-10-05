package gate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/internal/streamprogress"
)

// Unit tests of the M21 pieces: Retry-After parsing, the wait table and
// budget, the shared hold, and the bounded stream peek. No network, no clock.

func TestM21RetryAfterAndBudget(t *testing.T) {
	now := time.Date(2026, 10, 3, 6, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		header string
		want   time.Duration
		ok     bool
	}{
		{"", 0, false}, {"0", 0, false}, {"-5", 0, false}, {"3", 3 * time.Second, true},
		{" 7 ", 7 * time.Second, true}, {"9223372036854775807", retryAfterMax, true}, {"99999999999999999999", retryAfterMax, true},
		{"1e3", 0, false}, {"abc", 0, false}, {strings.Repeat("1", 65), retryAfterMax, true},
		{now.Add(30 * time.Second).UTC().Format(http.TimeFormat), 30 * time.Second, true},
		{now.Add(-30 * time.Second).UTC().Format(http.TimeFormat), 0, false},
		{now.Add(48 * time.Hour).UTC().Format(http.TimeFormat), retryAfterMax, true},
		{now.Add(30 * time.Second).UTC().Format(time.RFC1123), 0, false}, // "UTC" zone is not an HTTP-date
		{"86401", retryAfterMax, true}, {"86400", 24 * time.Hour, true},
	} {
		got, ok := parseRetryAfter(tc.header, now)
		if got != tc.want || ok != tc.ok {
			t.Fatalf("Retry-After %q: got %v,%v want %v,%v", tc.header, got, ok, tc.want, tc.ok)
		}
	}

	pol := defaultRetryPolicy()
	if len(pol.waits) != 4 || pol.waits[0] != 5*time.Second || pol.waits[3] != 40*time.Second || pol.budget != 90*time.Second {
		t.Fatalf("host defaults changed: %+v", pol)
	}
	// The table: 5, 10, 20, 40 fits 90 exactly (75 waited before the 4th);
	// a fifth retry never happens.
	var waited time.Duration
	for n := 0; n < 4; n++ {
		w, ok := pol.wait(n, waited, 0)
		if !ok || w != pol.waits[n] {
			t.Fatalf("retry %d: %v %v", n, w, ok)
		}
		waited += w
	}
	if waited != 75*time.Second {
		t.Fatal(waited)
	}
	if _, ok := pol.wait(4, waited, 0); ok {
		t.Fatal("fifth retry allowed")
	}
	// Retry-After longer than the table wait replaces it...
	if w, ok := pol.wait(0, 0, 30*time.Second); !ok || w != 30*time.Second {
		t.Fatal("Retry-After not honoured", w, ok)
	}
	// ...but one that does not fit the remaining budget ends retrying rather
	// than retrying earlier than asked.
	if _, ok := pol.wait(0, 0, 91*time.Second); ok {
		t.Fatal("retried earlier than Retry-After asked")
	}
	if w, ok := pol.wait(1, 70*time.Second, 0); !ok || w != 10*time.Second {
		t.Fatal("70s waited + 10s fits the 90s budget", w, ok)
	}
	if _, ok := pol.wait(2, 75*time.Second, 0); ok {
		t.Fatal("75s waited + 20s exceeds the 90s budget")
	}
}

func TestM21SharedHoldExtensionAndCancellation(t *testing.T) {
	var mu sync.Mutex
	now := time.Date(2026, 10, 3, 6, 0, 0, 0, time.UTC)
	var slept []time.Duration
	pol := retryPolicy{waits: modelRetryWaits, budget: 90 * time.Second,
		now: func() time.Time { mu.Lock(); defer mu.Unlock(); return now },
		sleep: func(ctx context.Context, d time.Duration) error {
			mu.Lock()
			slept = append(slept, d)
			now = now.Add(d) // the fake clock advances by exactly the sleep
			mu.Unlock()
			return ctx.Err()
		}}
	var p pacing
	// No hold: returns at once.
	if s, err := p.wait(context.Background(), pol, now.Add(time.Minute)); err != nil || s != 0 {
		t.Fatal(s, err)
	}
	// A hold of 5s: wait sleeps 5s once.
	p.hold(pol.now(), 5*time.Second)
	if s, err := p.wait(context.Background(), pol, pol.now().Add(time.Minute)); err != nil || s != 5*time.Second || len(slept) != 1 {
		t.Fatal(s, err, slept)
	}
	// Extension while waiting: the first sleep ends, the hold has moved, the
	// waiter sleeps again for the remainder — and re-checks its deadline.
	slept = nil
	p.hold(pol.now(), 5*time.Second)
	extended := false
	pol.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		slept = append(slept, d)
		now = now.Add(d)
		mu.Unlock()
		if !extended {
			extended = true
			p.hold(pol.now(), 3*time.Second) // another turn's refusal moves the hold
		}
		return ctx.Err()
	}
	if s, err := p.wait(context.Background(), pol, pol.now().Add(time.Minute)); err != nil || s != 8*time.Second || len(slept) != 2 {
		t.Fatalf("extension not honoured: %v %v %v", s, err, slept)
	}
	// Hold moves earlier? Never: a shorter hold does not shorten an existing one.
	p.hold(pol.now(), 10*time.Second)
	p.hold(pol.now(), time.Second)
	p.mu.Lock()
	until := p.until
	p.mu.Unlock()
	if until != pol.now().Add(10*time.Second) {
		t.Fatal("hold shortened")
	}
	// A hold past this request's deadline is refused without sleeping.
	slept = nil
	if _, err := p.wait(context.Background(), pol, pol.now().Add(5*time.Second)); !errors.Is(err, errHoldExceedsBudget) || len(slept) != 0 {
		t.Fatalf("waited past budget: %v %v", err, slept)
	}
	// Extension past the deadline during the wait is also refused.
	extended = false
	pol.sleep = func(ctx context.Context, d time.Duration) error {
		mu.Lock()
		slept = append(slept, d)
		now = now.Add(d)
		mu.Unlock()
		if !extended {
			extended = true
			p.hold(pol.now(), time.Hour)
		}
		return ctx.Err()
	}
	if _, err := p.wait(context.Background(), pol, pol.now().Add(time.Minute)); !errors.Is(err, errHoldExceedsBudget) {
		t.Fatalf("extension past budget accepted: %v", err)
	}
	// Cancellation during the wait returns the context error.
	p = pacing{}
	ctx, cancel := context.WithCancel(context.Background())
	pol.sleep = func(ctx context.Context, d time.Duration) error { cancel(); return ctx.Err() }
	p.hold(pol.now(), 5*time.Second)
	if _, err := p.wait(ctx, pol, pol.now().Add(time.Minute)); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation lost: %v", err)
	}
	// sleepCtx itself is cancellable and never sleeps for non-positive durations.
	ctx2, cancel2 := context.WithCancel(context.Background())
	cancel2()
	if err := sleepCtx(ctx2, time.Hour); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if err := sleepCtx(context.Background(), -time.Second); err != nil {
		t.Fatal(err)
	}
}

func peek(t *testing.T, raw string) (string, peekVerdict, io.Reader) {
	t.Helper()
	prefix, rest, v := peekStream(strings.NewReader(raw), nil)
	return string(prefix), v, rest
}

func TestM21PrefixBoundedAndKeepaliveStalls(t *testing.T) {
	created := "event: response.created\ndata: {\"type\":\"response.created\",\"response\":{\"id\":\"PRIVATE\"}}\n\n"
	inProgress := "data: {\"type\":\"response.in_progress\"}\n\n"
	limit := "event: error\ndata: {\"type\":\"error\",\"error\":{\"code\":\"rate_limit_exceeded\",\"message\":\"PRIVATE BODY\"}}\n\n"
	failed := "event: response.failed\ndata: {\"type\":\"response.failed\",\"response\":{\"error\":{\"code\":\"server_error\",\"message\":\"PRIVATE\"}}}\n\n"
	text := "data: {\"type\":\"response.output_text.delta\",\"delta\":\"hi\"}\n\n"
	keepalive := ": keepalive\n\n"

	// Exact pre-output rate limit after the echoing opening events.
	prefix, v, rest := peek(t, created+inProgress+strings.Repeat(keepalive, 3)+limit+"data: AFTER\n\n")
	if v != peekLimited || prefix != created+inProgress+strings.Repeat(keepalive, 3)+limit {
		t.Fatalf("limited: %q %q", v, prefix)
	}
	if tail, _ := io.ReadAll(rest); string(tail) != "data: AFTER\n\n" {
		t.Fatalf("rest lost or duplicated: %q", tail)
	}
	// Another failure before output: relay, never retry.
	if _, v, _ := peek(t, created+failed); v != peekFailed {
		t.Fatal("non-rate-limit failure classified", v)
	}
	// Output before the refusal: never retry (text, tool, reasoning).
	for name, out := range map[string]string{
		"text":      text,
		"tool":      "data: {\"type\":\"response.function_call_arguments.delta\",\"delta\":\"{\"}\n\n",
		"reasoning": "data: {\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"...\"}\n\n",
		"item":      "data: {\"type\":\"response.output_item.added\",\"item\":{}}\n\n",
		"chat":      "data: {\"id\":\"x\",\"choices\":[{\"delta\":{\"content\":\"rate_limit_exceeded\"}}]}\n\n",
		"done":      "data: [DONE]\n\n",
	} {
		if _, v, _ := peek(t, created+out+limit); v != peekOutput {
			t.Fatalf("%s before refusal classified %q", name, v)
		}
	}
	// Ambiguity never retries: malformed JSON, duplicate key, header/body
	// conflict, oversized line, oversized frame, non-object data.
	for name, raw := range map[string]string{
		"malformed":     created + "event: error\ndata: {not json\n\n",
		"duplicate key": created + "data: {\"type\":\"error\",\"type\":\"response.created\",\"error\":{\"code\":\"rate_limit_exceeded\"}}\n\n",
		"conflict":      created + "event: response.output_text.delta\ndata: {\"type\":\"error\",\"error\":{\"code\":\"rate_limit_exceeded\"}}\n\n",
		"two events":    created + "event: error\nevent: response.failed\ndata: {\"type\":\"error\",\"error\":{\"code\":\"rate_limit_exceeded\"}}\n\n",
		"oversize line": created + "data: " + strings.Repeat("x", modelPeekLine+10) + "\n\n",
		"oversize data": created + strings.Repeat("data: "+strings.Repeat("y", 1000)+"\n", 70) + "\n",
		"array":         created + "data: [1,2,3]\n\n",
		"empty object":  created + "data: {}\n\n",
	} {
		if _, v, _ := peek(t, raw); v != peekAmbiguous {
			t.Fatalf("%s classified %q, want ambiguous", name, v)
		}
	}
	// EOF before any decision: relay what came, no retry.
	if prefix, v, _ := peek(t, created+inProgress); v != peekOutput || prefix != created+inProgress {
		t.Fatalf("EOF: %q %q", v, prefix)
	}
	if prefix, v, _ := peek(t, "data: {\"type\":\"response.created\""); v != peekOutput || prefix != "data: {\"type\":\"response.created\"" {
		t.Fatalf("cut EOF: %q %q", v, prefix)
	}
	// The total prefix is bounded: a stream of only openings/keepalives stops
	// at modelPeekMax and is relayed as ambiguous (no retry), bytes intact.
	long := strings.Repeat(inProgress, modelPeekMax/len(inProgress)+10)
	prefix, v, rest = peek(t, long)
	if v != peekAmbiguous || len(prefix) < modelPeekMax || len(prefix) > modelPeekMax+len(inProgress) {
		t.Fatalf("prefix not bounded: %q len=%d", v, len(prefix))
	}
	if tail, _ := io.ReadAll(rest); prefix+string(tail) != long {
		t.Fatal("bytes lost across the peek boundary")
	}
	// Keepalives are read while peeking but are not progress for the stall
	// watch: a watch fed only keepalives expires.
	watch := streamprogress.NewWatch(context.Background(), 40*time.Millisecond)
	watch.Feed([]byte(strings.Repeat(keepalive, 50)))
	time.Sleep(80 * time.Millisecond)
	if !errors.Is(watch.Err(), streamprogress.ErrIdleTimeout) {
		t.Fatal("keepalives counted as progress")
	}
	_ = watch.Finish()
	// Real progress through the same watch resets it.
	watch = streamprogress.NewWatch(context.Background(), 60*time.Millisecond)
	time.Sleep(40 * time.Millisecond)
	watch.Feed([]byte(text))
	time.Sleep(40 * time.Millisecond)
	if watch.Err() != nil {
		t.Fatal("output did not reset the watch")
	}
	_ = watch.Finish()
}

func TestM21PartialOutputNeverReplaysUnit(t *testing.T) {
	// A refusal that arrives after a single delta of any kind is "output".
	limit := "data: {\"type\":\"error\",\"error\":{\"code\":\"rate_limit_exceeded\"}}\n\n"
	for _, first := range []string{
		"data: {\"type\":\"response.output_text.delta\",\"delta\":\"x\"}\n\n",
		"data: {\"type\":\"response.function_call_arguments.delta\",\"delta\":\"x\"}\n\n",
		"data: {\"type\":\"response.reasoning_summary_text.delta\",\"delta\":\"x\"}\n\n",
		"data: {\"type\":\"response.refusal.delta\",\"delta\":\"x\"}\n\n",
	} {
		if _, v, _ := peek(t, first+limit); v != peekOutput {
			t.Fatalf("output %q then refusal classified %q", first, v)
		}
	}
}
