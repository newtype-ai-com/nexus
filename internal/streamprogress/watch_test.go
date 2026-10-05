package streamprogress

import (
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type eofOnClose struct {
	done   chan struct{}
	once   sync.Once
	closes atomic.Int32
}

func (b *eofOnClose) Read([]byte) (int, error) { <-b.done; return 0, io.EOF }
func (b *eofOnClose) Close() error             { b.closes.Add(1); b.once.Do(func() { close(b.done) }); return nil }
func TestWatchCloseEOFIsNotSuccess(t *testing.T) {
	for _, mode := range []string{"idle", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			w := NewWatch(ctx, 20*time.Millisecond)
			raw := &eofOnClose{done: make(chan struct{})}
			body := w.WrapBody(raw)
			if mode == "cancel" {
				cancel()
			}
			_, err := body.Read(make([]byte, 10))
			want := ErrIdleTimeout
			if mode == "cancel" {
				want = context.Canceled
			}
			if !errors.Is(err, want) || !errors.Is(w.Finish(), want) {
				t.Fatal(err)
			}
			if body.Close() != nil || body.Close() != nil || raw.closes.Load() != 1 {
				t.Fatal("close not exactly once")
			}
		})
	}
}
func TestWatchNativeJSONObjectChecks(t *testing.T) {
	for _, raw := range []string{`{"type":"heartbeat"}`, `{"type":"delta","type":"heartbeat"}`, `{"type":null}`, `broken`} {
		w := NewWatch(context.Background(), time.Hour)
		w.mu.Lock()
		before := w.deadline
		w.mu.Unlock()
		w.ObserveJSON([]byte(raw))
		w.mu.Lock()
		after := w.deadline
		w.mu.Unlock()
		if before != after {
			t.Fatal("invalid native progress")
		}
		w.Finish()
	}
}
