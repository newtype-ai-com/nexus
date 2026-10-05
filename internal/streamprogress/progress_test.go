package streamprogress

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestStreamProgressFrames(t *testing.T) {
	cases := []struct {
		name, frame, last string
		progress          bool
	}{
		{"comment", ": PRIVATE\n\n", "comment", false},
		{"heartbeat", "data: {\"type\":\"x.HEARTBEAT.y\"}\n\n", "unknown", false},
		{"ping", "data: {\"type\":\"x.ping\"}\n\n", "unknown", false},
		{"header-after", "data: {}\nevent: keep-alive\n\n", "keep-alive", false},
		{"header-conflict", "event: ping\ndata: {\"type\":\"response.output_text.delta\"}\n\n", "ping", false},
		{"header-done", "event: heartbeat\ndata: [DONE]\n\n", "heartbeat", false},
		{"empty-data", "data:\n\n", "unknown", false},
		{"nested", "event: heartbeat\ndata: {\"nested\":{\"type\":\"delta\"}}\n\n", "heartbeat", false},
		{"content", "data: {\"choices\":[{\"delta\":{\"content\":\"keepalive PRIVATE\"}}]}\n\n", "data", true},
		{"duplicate", "data: {\"type\":\"heartbeat\",\"type\":\"delta\"}\n\n", "unknown", false},
		{"duplicate-reverse", "data: {\"type\":\"delta\",\"t\\u0079pe\":\"heartbeat\"}\n\n", "unknown", false},
		{"null", "data: {\"type\":null}\n\n", "unknown", false},
		{"wrong-type", "data: {\"type\":5}\n\n", "unknown", false},
		{"malformed", "data: {\"type\":\"delta\"\n\n", "unknown", false},
		{"multiline", "data: {\ndata: \"type\":\"keep_alive\"}\n\n", "keep_alive", false},
		{"safe-log", "data: {\"type\":\"PRIVATE_SECRET\"}\n\n", "unknown", true},
		{"done", "data: [DONE]\n\n", "done", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for _, sep := range []string{"\n", "\r\n", "\r"} {
				raw := strings.ReplaceAll(tc.frame, "\n", sep)
				for _, size := range []int{1, 2, 7, 32768} {
					s := &StreamProgress{}
					got := false
					for i := 0; i < len(raw); i += size {
						got = s.Feed([]byte(raw[i:min(i+size, len(raw))])) || got
					}
					if got != tc.progress || s.Last != tc.last {
						t.Fatalf("size=%d got=%v last=%s", size, got, s.Last)
					}
				}
			}
		})
	}
}
func TestStreamProgressBoundedAndRecovery(t *testing.T) {
	var s StreamProgress
	raw := "data: {\"text\":\"" + strings.Repeat("x", maxFrame*3) + "\",\"type\":\"heartbeat\"}\n\n"
	for i := 0; i < len(raw); i += 17 {
		if s.Feed([]byte(raw[i:min(i+17, len(raw))])) {
			t.Fatal("oversize progress")
		}
		if len(s.line) > maxFrame || len(s.data) > maxFrame {
			t.Fatal("unbounded")
		}
	}
	if !s.Feed([]byte("data: {}\n\n")) {
		t.Fatal("did not recover")
	}
	var partial StreamProgress
	if partial.Feed([]byte("data: {}\n")) {
		t.Fatal("unfinished frame")
	}
}
func TestWatchTimeoutCloseAndNoResurrection(t *testing.T) {
	w := NewWatch(context.Background(), 20*time.Millisecond)
	r, p := io.Pipe()
	defer p.Close()
	body := w.WrapBody(r)
	defer body.Close()
	_, err := body.Read(make([]byte, 10))
	if !errors.Is(err, ErrIdleTimeout) {
		t.Fatal(err)
	}
	w.Feed([]byte("data: {}\n\n"))
	if !errors.Is(w.Finish(), ErrIdleTimeout) {
		t.Fatal("late EOF revived timeout")
	}
}
func TestWatchProgressCancelFinishRace(t *testing.T) {
	for i := 0; i < 50; i++ {
		ctx, cancel := context.WithCancel(context.Background())
		w := NewWatch(ctx, time.Second)
		var wg sync.WaitGroup
		wg.Add(3)
		go func() { defer wg.Done(); w.Feed([]byte("data: {}\n\n")) }()
		go func() { defer wg.Done(); cancel() }()
		go func() { defer wg.Done(); _ = w.Finish() }()
		wg.Wait()
		// Once Finish wins, later cancel cannot change an accepted outcome.
		first := w.Finish()
		if w.Finish() != first {
			t.Fatal("non-idempotent finish")
		}
	}
}
func TestWatchDeadlineCheckedWithoutTimerCallback(t *testing.T) {
	w := NewWatch(context.Background(), time.Hour)
	w.mu.Lock()
	w.deadline = time.Now().Add(-time.Second)
	w.mu.Unlock()
	w.Feed([]byte("data: {}\n\n"))
	if !errors.Is(w.Finish(), ErrIdleTimeout) {
		t.Fatal("late progress")
	}
}
