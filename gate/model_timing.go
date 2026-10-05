package gate

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"time"
)

// Per-call timing for the model relay (decision 2026-10-04: "where does the time
// go on a model call?"). Only time.Now differences of steps the call already
// takes; no extra queries. Fields are bounded numbers and fixed labels, never
// prompts, outputs, keys, licence/login tokens or emails.

// publicTiming is what LimitPublicAPI measured before the route handler ran.
type publicTiming struct {
	start     time.Time     // request entry (before the admission write)
	admission time.Duration // the gate_rate_limits DB write(s)
}

type publicTimingKey struct{}

func withPublicTiming(ctx context.Context, t publicTiming) context.Context {
	return context.WithValue(ctx, publicTimingKey{}, t)
}

// publicTimingFrom reports the entry time and admission DB time recorded by
// LimitPublicAPI, if this request passed through it.
func publicTimingFrom(ctx context.Context) (publicTiming, bool) {
	t, ok := ctx.Value(publicTimingKey{}).(publicTiming)
	return t, ok
}

// modelTiming accumulates one relay call. Not shared across goroutines except
// through firstByteReader, which only runs on the handler goroutine.
type modelTiming struct {
	start     time.Time
	admission time.Duration // -1: not measured (no LimitPublicAPI in front)
	auth      time.Duration
	prepare   time.Duration
	budget    time.Duration
	pace      time.Duration
	firstByte time.Duration // last dispatch: headers, then first body byte
	upstream  time.Duration // sum over dispatches: Do until body end / decision
	settle    time.Duration

	dispatchAt time.Time // zero when no dispatch is open
}

func newModelTiming(ctx context.Context) *modelTiming {
	t := &modelTiming{start: time.Now(), admission: -1}
	if p, ok := publicTimingFrom(ctx); ok {
		t.start, t.admission = p.start, p.admission
	}
	return t
}

// add runs f and adds its wall time to *into.
func (t *modelTiming) add(into *time.Duration, f func()) {
	t0 := time.Now()
	f()
	*into += time.Since(t0)
}

func (t *modelTiming) dispatch() { t.dispatchAt = time.Now(); t.firstByte = 0 }

// headers marks response headers received for the open dispatch.
func (t *modelTiming) headers() {
	if !t.dispatchAt.IsZero() {
		t.firstByte = time.Since(t.dispatchAt)
	}
}

// endUpstream closes the open dispatch (body end, refusal decision or abort).
func (t *modelTiming) endUpstream() {
	if !t.dispatchAt.IsZero() {
		t.upstream += time.Since(t.dispatchAt)
		t.dispatchAt = time.Time{}
	}
}

// body wraps an upstream body so its first byte updates firstByte.
func (t *modelTiming) body(rc io.ReadCloser) io.ReadCloser {
	return &firstByteReader{ReadCloser: rc, t: t, at: t.dispatchAt}
}

type firstByteReader struct {
	io.ReadCloser
	t    *modelTiming
	at   time.Time
	seen bool
}

func (r *firstByteReader) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	if n > 0 && !r.seen {
		r.seen = true
		r.t.firstByte = time.Since(r.at)
	}
	return n, err
}

func ms(d time.Duration) int64 {
	if d < 0 {
		return -1
	}
	return d.Milliseconds()
}

// log writes the one "model relay timing" line. All durations in ms.
func (t *modelTiming) log(logger *slog.Logger, model, protocol string, stream bool, status int, outcome string, retries int, owner bool, tokens int64) {
	logger.Info("model relay timing",
		"admission_db", ms(t.admission),
		"auth_db", ms(t.auth),
		"prepare_db", ms(t.prepare),
		"budget_check", ms(t.budget),
		"pace_wait", ms(t.pace),
		"upstream_first_byte", ms(t.firstByte),
		"upstream_total", ms(t.upstream),
		"settle_db", ms(t.settle),
		"total", ms(time.Since(t.start)),
		"model", model,
		"protocol", protocol,
		"stream", stream,
		"status", status,
		"outcome", outcome,
		"retries", retries,
		"owner", owner,
		"tokens_total", tokens,
	)
}

// statusWriter records the HTTP status sent downstream. Unwrap keeps
// http.NewResponseController (flush, deadlines) working on the real writer.
type statusWriter struct {
	http.ResponseWriter
	code int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.code == 0 {
		w.code = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(p []byte) (int, error) {
	if w.code == 0 {
		w.code = http.StatusOK
	}
	return w.ResponseWriter.Write(p)
}

func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
