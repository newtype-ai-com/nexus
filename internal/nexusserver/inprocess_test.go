package nexusserver

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func remoteFixture(t *testing.T) (http.Handler, *nexus.Service, nexus.Principal, ids.Session) {
	t.Helper()
	s := nexus.NewService(nexus.NewMemStore(), nil)
	h, err := NewHandler(s, gate.NewMemoryCredentials(), func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	person := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "owner@example.test")
	out, err := s.CreateRoot(context.Background(), person, nexus.RootRequest{Title: "mcp:fixture", Runner: nexus.Remote, Scope: []string{"session:delegate"}, Limits: nexus.Limits{MaxDepth: 1}})
	if err != nil {
		t.Fatal(err)
	}
	if out.Session.Runner != nexus.Remote {
		t.Fatalf("runner %q", out.Session.Runner)
	}
	return h, s, person, out.Session.ID
}

// The connector acts as the remote session in process; the stream works too.
func TestInProcessPrincipalServesRoutesAndStreams(t *testing.T) {
	h, _, person, session := remoteFixture(t)
	client := &http.Client{Transport: InProcess{Handler: h, Principal: nexus.SessionPrincipal(person.AccountID, session)}}
	req, _ := http.NewRequest("GET", InProcessEndpoint+"/v1/peers", nil)
	req.Header.Set("Authorization", "Bearer "+InProcessToken)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("peers %d", resp.StatusCode)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	req, _ = http.NewRequestWithContext(ctx, "GET", InProcessEndpoint+"/v1/sessions/"+string(session)+"/stream", nil)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		t.Fatalf("stream %d %v", resp.StatusCode, resp.Header)
	}
	line, _ := bufio.NewReader(resp.Body).ReadString('\n')
	if !strings.HasPrefix(line, ": connected") {
		t.Fatalf("first line %q", line)
	}
}

// Over the network: the placeholder and /mcp tokens are just unauthenticated,
// and nobody can create or delegate to a remote session through the API.
func TestNetworkCannotActInProcessOrUseMCPTokens(t *testing.T) {
	h, s, person, session := remoteFixture(t)
	for _, bearer := range []string{InProcessToken, "ntm_" + strings.Repeat("a", 40), "ntr_" + strings.Repeat("b", 40)} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "/v1/peers", nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		r.Header.Set("X-Newtype-Session", string(session))
		h.ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatalf("bearer %q.. got %d", bearer[:4], w.Code)
		}
	}
	// even in process, the public root route refuses runner "remote"
	client := &http.Client{Transport: InProcess{Handler: h, Principal: person}}
	resp, err := client.Post(InProcessEndpoint+"/v1/requests", "application/json", strings.NewReader(`{"title":"x","runner":"remote","scope":[],"limits":{},"ttl_seconds":60}`))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != 400 {
		t.Fatalf("remote root via API %d", resp.StatusCode)
	}
	_ = s
}
