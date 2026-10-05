package nexustransport

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// TestM12LeaveStopsOnlyOwnedSessions (transport side): Leave makes exactly one
// request, to the status route of the session it was given, as that session,
// and asks for nothing but "stopped". Without a session or login it does not
// go to the network at all.
func TestM12LeaveStopsOnlyOwnedSessions(t *testing.T) {
	session := ids.New(ids.KindSession)
	var calls atomic.Int32
	var gotPath, gotLogin, gotSession, gotAuth string
	var gotBody map[string]any
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Method != http.MethodPost {
			t.Errorf("method %s", r.Method)
		}
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		gotLogin = r.Header.Get("X-Newtype-Login")
		gotSession = r.Header.Get("X-Newtype-Session")
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &gotBody)
		w.Write([]byte(`{"id":"` + session + `","status":"stopped","stopped_by":"session"}`))
	}))
	defer server.Close()

	// No identity to leave as: nothing is sent, nothing fails.
	for _, a := range []Auth{{Token: "licence-fixture"}, {Token: "licence-fixture", Login: "login-fixture"}, {Token: "licence-fixture", Session: session}} {
		if err := Leave(server.URL, a); err != nil {
			t.Fatalf("leave without a full identity should be a no-op, got %v", err)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("leave without identity reached the server")
	}
	// A malformed session is refused before the network.
	if err := Leave(server.URL, Auth{Token: "licence-fixture", Login: "login-fixture", Session: "not-a-session"}); err == nil || calls.Load() != 0 {
		t.Fatal("malformed session should be refused locally", err)
	}
	// A bad endpoint is refused before the network.
	if err := Leave("http://example.com", Auth{Token: "licence-fixture", Login: "login-fixture", Session: session}); err == nil || calls.Load() != 0 {
		t.Fatal("non-loopback http endpoint should be refused locally", err)
	}

	if err := Leave(server.URL, Auth{Token: "licence-fixture", Login: "login-fixture", Session: session}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("leave made %d requests, want 1", calls.Load())
	}
	if gotPath != "/v1/sessions/"+session+"/status" {
		t.Fatalf("leave went to %s", gotPath)
	}
	if gotAuth != "Bearer licence-fixture" || gotLogin != "login-fixture" || gotSession != session {
		t.Fatal("leave did not carry the session's own identity")
	}
	if len(gotBody) != 1 || gotBody["status"] != string(nexus.SessionStopped) {
		t.Fatalf("leave body %v, want only status=stopped", gotBody)
	}
}

// TestM12LeaveDoesNotRestoreAuthority (transport side): a refusal is reported,
// not retried, and a server that never answers cannot hold the exiting
// process past the leave deadline.
func TestM12LeaveDoesNotRestoreAuthority(t *testing.T) {
	session := ids.New(ids.KindSession)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.WriteHeader(http.StatusForbidden)
		w.Write([]byte(`{"error":"forbidden"}`))
	}))
	defer server.Close()
	err := Leave(server.URL, Auth{Token: "licence-fixture", Login: "login-fixture", Session: session})
	if err == nil {
		t.Fatal("a refused leave must be reported")
	}
	if calls.Load() != 1 {
		t.Fatalf("a refused leave was retried: %d requests", calls.Load())
	}

	// A server that hangs.
	release := make(chan struct{})
	hang := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer hang.Close()
	defer close(release)
	old := leaveTimeout
	leaveTimeout = 200 * time.Millisecond
	defer func() { leaveTimeout = old }()
	start := time.Now()
	err = Leave(hang.URL, Auth{Token: "licence-fixture", Login: "login-fixture", Session: session})
	took := time.Since(start)
	if err == nil {
		t.Fatal("a leave that never got an answer must be reported")
	}
	if took > 3*time.Second {
		t.Fatalf("leave held the process %v past its deadline", took)
	}
}
