package streamprogress

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const GateIdleTimeout = 5 * time.Minute
const ClientIdleTimeout = 6 * time.Minute

var ErrIdleTimeout = errors.New("model stream made no progress")

// Watch starts before HTTP dispatch, covering response headers as well as body.
// Feed, expiry and Finish are serialized: late data/EOF cannot revive an expired
// request. Finish must be called even when dispatch or decoding fails.
type Watch struct {
	mu          sync.Mutex
	parent, ctx context.Context
	cancel      context.CancelCauseFunc
	timer       *time.Timer
	deadline    time.Time
	limit       time.Duration
	parser      StreamProgress
	err         error
	finished    bool
}

func NewWatch(parent context.Context, limit time.Duration) *Watch {
	ctx, cancel := context.WithCancelCause(parent)
	w := &Watch{parent: parent, ctx: ctx, cancel: cancel, limit: limit, deadline: time.Now().Add(limit)}
	w.timer = time.AfterFunc(limit, func() { w.mu.Lock(); defer w.mu.Unlock(); w.check() })
	return w
}
func (w *Watch) Context() context.Context { return w.ctx }
func (w *Watch) check() {
	if w.finished || w.err != nil {
		return
	}
	if err := w.parent.Err(); err != nil {
		w.err = err
	} else if !time.Now().Before(w.deadline) {
		last := w.parser.Last
		if last == "" {
			last = "none"
		}
		w.err = fmt.Errorf("%w: last_event=%s", ErrIdleTimeout, last)
	}
	if w.err != nil {
		w.cancel(w.err)
	}
}
func (w *Watch) Feed(p []byte) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.check()
	if w.finished || w.err != nil {
		return
	}
	if w.parser.Feed(p) {
		w.check()
		if w.err != nil {
			return
		}
		w.deadline = time.Now().Add(w.limit)
		w.timer.Reset(w.limit)
	}
}
func (w *Watch) ObserveJSON(raw []byte) {
	if len(raw) > maxFrame {
		return
	}
	// Native Gemini objects use the same complete-object and type semantics as
	// SSE data. No byte-count or content substring can reset the deadline.
	typ, ok := topLevelType(raw)
	if !ok || KeepAliveEvent(typ) {
		return
	}
	if typ == "" {
		typ = "data"
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.check()
	if w.finished || w.err != nil {
		return
	}
	w.parser.Last = safeType(typ)
	w.deadline = time.Now().Add(w.limit)
	w.timer.Reset(w.limit)
}
func (b *watchedBody) ObserveJSON(raw []byte) { b.watch.ObserveJSON(raw) }

func (w *Watch) Last() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.parser.Last == "" {
		return "none"
	}
	return w.parser.Last
}
func (w *Watch) Err() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.check()
	return w.err
}
func (w *Watch) Finish() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.check()
	w.finished = true
	w.timer.Stop()
	w.cancel(context.Canceled)
	return w.err
}

// WrapBody ensures cancellation also interrupts a body whose Read only unblocks
// on Close, including a peer that never sends another byte. HTTP body Close must
// be safe concurrently with Read (the net/http transport satisfies this).
func (w *Watch) WrapBody(body io.ReadCloser) io.ReadCloser {
	b := &watchedBody{body: body, watch: w, closed: make(chan struct{})}
	b.stop = context.AfterFunc(w.ctx, func() { b.close() })
	return b
}

type watchedBody struct {
	body     io.ReadCloser
	watch    *Watch
	once     sync.Once
	stop     func() bool
	closed   chan struct{}
	closeErr error
}

func (b *watchedBody) close() { b.once.Do(func() { b.closeErr = b.body.Close(); close(b.closed) }) }
func (b *watchedBody) Close() error {
	b.stop()
	b.close()
	<-b.closed
	return b.closeErr
}
func (b *watchedBody) Read(p []byte) (int, error) {
	if err := b.watch.Err(); err != nil {
		return 0, err
	}
	n, err := b.body.Read(p)
	if n > 0 {
		b.watch.Feed(p[:n])
	}
	if e := b.watch.Err(); e != nil {
		return 0, e
	}
	return n, err
}
