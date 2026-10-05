package gate

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestModelStreamRevocationCancelsUpstream(t *testing.T) {
	ctx := context.Background()
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	creds := NewMemoryCredentials()
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "user@example.test")
	root, err := svc.CreateRoot(ctx, user, nexus.RootRequest{Title: "revocation", Runner: nexus.Local, Scope: []string{"model:fixture"}, Rules: []nexus.Rule{{Action: "model:fixture", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 4000}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	key, login := "ntl_"+strings.Repeat("a", 64), "ntg_"+strings.Repeat("b", 64)
	for token, kind := range map[string]string{key: "licence", login: "login"} {
		if err := creds.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: user.AccountID, Email: user.Email, Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	cancelled := make(chan struct{})
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"partial\"}}]}\n\n")
		w.(http.Flusher).Flush()
		<-r.Context().Done()
		close(cancelled)
	}))
	defer upstream.Close()
	h, err := NewModelHandler(ModelConfig{Service: svc, Store: creds, Upstream: upstream.URL + "/v1/chat/completions", Key: "fixture", Models: []string{"fixture"}, Budget: 2000, MaxOutput: 100, Transport: upstream.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(h)
	defer server.Close()
	requestCtx, stop := context.WithTimeout(ctx, 5*time.Second)
	defer stop()
	req, _ := http.NewRequestWithContext(requestCtx, "POST", server.URL, strings.NewReader(`{"model":"fixture","stream":true,"messages":[{"role":"user","content":"test"}]}`))
	req.Header.Set("Authorization", "Bearer "+key)
	req.Header.Set("X-Newtype-Login", login)
	req.Header.Set("X-Newtype-Session", string(root.Session.ID))
	req.Header.Set("X-Newtype-Delegation", string(root.Delegation.ID))
	res, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal(res.StatusCode)
	}
	if _, err := svc.Revoke(ctx, user, root.Delegation.ID, "test revoke"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadAll(res.Body); err == nil {
		t.Fatal("revoked stream ended as success")
	}
	select {
	case <-cancelled:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream not cancelled")
	}
	id := ids.Invocation(res.Header.Get("X-Newtype-Invocation"))
	deadline := time.Now().Add(time.Second)
	for {
		state, err := svc.Execution(ctx, user, id)
		if err == nil && state.Status != "running" {
			if state.Charged != 2000 {
				t.Fatal("unconfirmed usage refunded")
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("not settled")
		}
		time.Sleep(time.Millisecond)
	}
}
