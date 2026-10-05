package httpapi_test

// M12: an open stream is not evidence that its reader is alive. Presence is
// recorded by the request that opens the stream and by nothing inside it;
// the server ends every stream after StreamLife so a live reader has to come
// back — and a dead one is seen to be gone.

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/httpapi"
)

func (f *apiFixture) sessionSeen(t *testing.T) time.Time {
	t.Helper()
	s, err := f.service.Session(context.Background(), f.person, f.actor.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	return s.SeenAt
}

func (f *apiFixture) advance(d time.Duration) {
	f.now.Store(time.Unix(0, f.now.Load()).Add(d).UnixNano())
}

// openStream returns the response of a stream request made as the session,
// from the given cursor. The caller reads or ignores the body.
func (f *apiFixture) openStream(t *testing.T, server *httptest.Server, ctx context.Context, after int64, who string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(ctx, "GET", server.URL+"/v1/sessions/"+string(f.actor.SessionID)+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", who)
	if after >= 0 {
		req.Header.Set("Last-Event-ID", strconv.FormatInt(after, 10))
	}
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// readStream drains a stream to its end and returns the ledger event ids seen.
func readStream(t *testing.T, body io.Reader) []int64 {
	t.Helper()
	var ids []int64
	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		if line := scanner.Text(); strings.HasPrefix(line, "id: ") {
			seq, err := strconv.ParseInt(strings.TrimPrefix(line, "id: "), 10, 64)
			if err != nil {
				t.Fatal(line)
			}
			ids = append(ids, seq)
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatal("stream did not end cleanly:", err)
	}
	return ids
}

func TestM12StreamTouchesOnlyOpeningRequest(t *testing.T) {
	f := apiSetup(t, "auto")
	f.cfg.StreamLife = 600 * time.Millisecond
	f.cfg.Heartbeat = 20 * time.Millisecond
	f.reset(t)
	server := httptest.NewServer(f.api)
	defer server.Close()

	// The opening request records presence (ServeHTTP touches every request).
	f.advance(2 * time.Minute) // past the SeenAt write throttle
	opened := time.Unix(0, f.now.Load()).UTC()
	resp := f.openStream(t, server, context.Background(), -1, "session")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	if got := f.sessionSeen(t); !got.Equal(opened) {
		t.Fatalf("opening request should record presence: seen %v, opened %v", got, opened)
	}

	// Now the clock moves on while the stream stays open. Heartbeats tick,
	// notifications wake the loop, pages are re-read — none of it may count
	// as the reader being there.
	f.advance(2 * time.Minute)
	for i := 0; i < 5; i++ {
		f.service.Notify()
		time.Sleep(60 * time.Millisecond)
	}
	if got := f.sessionSeen(t); !got.Equal(opened) {
		t.Fatalf("heartbeat or wakeup touched presence: seen %v, opened %v", got, opened)
	}
	if got := f.service.LastSeen(f.actor.SessionID); !got.Equal(opened) {
		t.Fatalf("process-local presence moved without a request: %v vs %v", got, opened)
	}
	// And the stream ends by itself.
	readStream(t, resp.Body)
}

func TestM12DefaultStreamLife(t *testing.T) {
	if httpapi.DefaultStreamLife != 3*time.Minute {
		t.Fatalf("DefaultStreamLife = %v, want 3m", httpapi.DefaultStreamLife)
	}
	if httpapi.MaxStreamLife >= nexus.PresenceGrace {
		t.Fatal("a stream must end well before presence grace would hide a dead reader")
	}
	f := apiSetup(t, "auto")
	// Zero means the default; an injected life past the bound is refused.
	f.cfg.StreamLife = 0
	if _, err := httpapi.New(f.cfg); err != nil {
		t.Fatal("zero StreamLife must mean the default:", err)
	}
	f.cfg.StreamLife = nexus.PresenceGrace
	if _, err := httpapi.New(f.cfg); err == nil {
		t.Fatal("StreamLife at presence grace must be refused")
	}
	f.cfg.StreamLife = 300 * time.Millisecond
	f.cfg.Heartbeat = 20 * time.Millisecond
	f.reset(t)
	server := httptest.NewServer(f.api)
	defer server.Close()

	// A short injected life ends the stream on its own; this verifies the
	// ending runs, not the 3-minute figure, which no unit test waits for.
	start := time.Now()
	resp := f.openStream(t, server, context.Background(), -1, "session")
	defer resp.Body.Close()
	readStream(t, resp.Body)
	took := time.Since(start)
	if took < 250*time.Millisecond || took > 3*time.Second {
		t.Fatalf("stream lived %v, want about its injected life", took)
	}
}

func TestM12UnreadStreamDoesNotKeepSessionAlive(t *testing.T) {
	f := apiSetup(t, "auto")
	f.cfg.StreamLife = 300 * time.Millisecond
	f.cfg.Heartbeat = 20 * time.Millisecond
	f.reset(t)
	// Wrap the API to know when the handler actually returned.
	done := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.api.ServeHTTP(w, r)
		if strings.HasSuffix(r.URL.Path, "/stream") {
			done <- struct{}{}
		}
	}))
	defer server.Close()
	ctx := context.Background()

	// A process attached as the session and is running.
	if _, err := f.service.SetSessionStatus(ctx, f.actor, f.actor.SessionID, nexus.SessionRunning); err != nil {
		t.Fatal(err)
	}
	f.advance(2 * time.Minute)
	resp := f.openStream(t, server, ctx, -1, "session")
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	// The reader is alive on the wire but never reads: a dead peer looks the
	// same from here. Keep the server busy writing meanwhile.
	go func() {
		for i := 0; i < 20; i++ {
			f.service.Notify()
			time.Sleep(10 * time.Millisecond)
		}
	}()
	// The handler must end on its own — life plus the write deadline — even
	// though nothing was read.
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		t.Fatal("stream handler did not end for a reader that stopped reading")
	}
	// Presence has not moved since the opening request, so a sweep after the
	// grace stops the session although a stream was "open" the whole time.
	f.advance(nexus.PresenceGrace + time.Minute)
	since := time.Unix(0, f.now.Load()).Add(-time.Hour)
	if _, err := f.service.Sweep(ctx, since, nexus.PresenceGrace, nexus.ArchiveAfter); err != nil {
		t.Fatal(err)
	}
	s, err := f.service.Session(ctx, f.person, f.actor.SessionID)
	if err != nil {
		t.Fatal(err)
	}
	if s.Status != nexus.SessionStopped || s.StoppedBy != nexus.PrincipalSystem {
		t.Fatalf("session should be stopped by presence sweep, got %s/%s", s.Status, s.StoppedBy)
	}
}

func TestM12LiveReconnectPreservesCursor(t *testing.T) {
	f := apiSetup(t, "auto")
	f.cfg.StreamLife = 300 * time.Millisecond
	f.cfg.Heartbeat = 20 * time.Millisecond
	f.reset(t)
	server := httptest.NewServer(f.api)
	defer server.Close()
	ctx := context.Background()

	// Something in the ledger before the first stream.
	if _, err := f.service.SetSessionStatus(ctx, f.actor, f.actor.SessionID, nexus.SessionRunning); err != nil {
		t.Fatal(err)
	}
	events, tail, err := f.service.Events(ctx, f.actor, f.actor.SessionID, 0, 100)
	if err != nil || len(events) == 0 {
		t.Fatal("no ledger", err)
	}
	cursor := tail - 1 // the reader has processed everything but the last event

	f.advance(2 * time.Minute)
	first := f.openStream(t, server, ctx, cursor, "session")
	got := readStream(t, first.Body)
	first.Body.Close()
	if len(got) != 1 || got[0] != tail {
		t.Fatalf("first stream should deliver exactly the one event after the cursor, got %v (tail %d)", got, tail)
	}
	cursor = tail // the reader's own committed position, not an SSE id

	// While no stream is open, the ledger moves on.
	if _, err := f.service.SetSessionStatus(ctx, f.actor, f.actor.SessionID, nexus.SessionWaiting); err != nil {
		t.Fatal(err)
	}
	_, tail2, err := f.service.Events(ctx, f.actor, f.actor.SessionID, 0, 100)
	if err != nil || tail2 <= tail {
		t.Fatal("ledger did not advance", err)
	}

	// Reopening is a request: it records presence again.
	f.advance(2 * time.Minute)
	reopened := time.Unix(0, f.now.Load()).UTC()
	second := f.openStream(t, server, ctx, cursor, "session")
	got = readStream(t, second.Body)
	second.Body.Close()
	if !f.sessionSeen(t).Equal(reopened) {
		t.Fatal("reopening the stream should record presence")
	}
	seen := map[int64]bool{}
	for _, seq := range got {
		if seq <= cursor {
			t.Fatalf("event %d before the cursor %d delivered again", seq, cursor)
		}
		if seen[seq] {
			t.Fatalf("event %d delivered twice", seq)
		}
		seen[seq] = true
	}
	if !seen[tail2] {
		t.Fatalf("event %d written while no stream was open was lost: %v", tail2, got)
	}
}

func TestM12StreamRevocationAndExpiry(t *testing.T) {
	f := apiSetup(t, "auto")
	f.cfg.StreamLife = 2 * time.Second
	f.cfg.Heartbeat = 20 * time.Millisecond
	f.reset(t)
	server := httptest.NewServer(f.api)
	defer server.Close()
	ctx := context.Background()

	// Another account cannot open this session's stream.
	other := f.openStream(t, server, ctx, -1, "other")
	other.Body.Close()
	if other.StatusCode == 200 {
		t.Fatal("another account opened the stream")
	}
	// A person of the account may read; a bad principal may not.
	bad := f.openStream(t, server, ctx, -1, "bad")
	bad.Body.Close()
	if bad.StatusCode == 200 {
		t.Fatal("malformed principal opened the stream")
	}

	// Revocation during the stream ends it at the next wakeup, before life.
	start := time.Now()
	resp := f.openStream(t, server, ctx, -1, "session")
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	time.Sleep(50 * time.Millisecond)
	f.valid.Store(false)
	f.service.Notify()
	readStream(t, resp.Body)
	resp.Body.Close()
	if time.Since(start) >= f.cfg.StreamLife {
		t.Fatal("revoked stream should end before its life")
	}
	// And a revoked credential cannot open one.
	denied := f.openStream(t, server, ctx, -1, "session")
	denied.Body.Close()
	if denied.StatusCode != 401 {
		t.Fatalf("revoked credential opened a stream: %d", denied.StatusCode)
	}
}
