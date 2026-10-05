package gate

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestModelGatewayAccountQuotaAcrossRoots(t *testing.T) {
	ctx := context.Background()
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	creds := NewMemoryCredentials()
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "user@example.test")
	root, err := svc.CreateRoot(ctx, user, nexus.RootRequest{Title: "quota", Runner: nexus.Local, Scope: []string{"model:fixture"}, Rules: []nexus.Rule{{Action: "model:fixture", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 30_000_000}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	other, err := svc.CreateRoot(ctx, user, nexus.RootRequest{Title: "quota 2", Runner: nexus.Local, Scope: []string{"model:fixture"}, Rules: []nexus.Rule{{Action: "model:fixture", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 30_000_000}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	key, login := "ntl_"+strings.Repeat("a", 64), "ntg_"+strings.Repeat("b", 64)
	for token, kind := range map[string]string{key: "licence", login: "login"} {
		if err := creds.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: user.AccountID, Email: user.Email, Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"usage":{"input_tokens":9999900,"output_tokens":100}}`))
	}))
	defer upstream.Close()
	h, err := NewModelHandler(ModelConfig{Service: svc, Store: creds, Upstream: upstream.URL + "/v1/chat/completions", Key: "fixture", Models: []string{"fixture"}, Budget: 10_000_000, MaxOutput: 100, Transport: upstream.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	call := func(session ids.Session, delegation ids.Delegation, want int) {
		t.Helper()
		r := httptest.NewRequest("POST", "/v1/model/chat/completions", strings.NewReader(`{"messages":[{"role":"user","content":"fixture"}]}`))
		r.Header.Set("Authorization", "Bearer "+key)
		r.Header.Set("X-Newtype-Login", login)
		r.Header.Set("X-Newtype-Session", string(session))
		r.Header.Set("X-Newtype-Delegation", string(delegation))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatal(w.Code, w.Body.String())
		}
	}
	call(root.Session.ID, root.Delegation.ID, 200)
	call(other.Session.ID, other.Delegation.ID, 403)
	if calls.Load() != 1 {
		t.Fatal("new root bypassed account quota")
	}
	q, err := svc.AccountQuota(ctx, user)
	if err != nil || q.Used != 10_000_000 {
		t.Fatal(q, err)
	}
	request, _, err := svc.BeginQuotaRequest(ctx, user, "request-resume", "resume", strings.Repeat("c", 64), 10_000_000)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.DecideQuotaRequest(ctx, nexus.SystemPrincipal(user.AccountID), request.Month, request.ID, strings.Repeat("c", 64), true); err != nil {
		t.Fatal(err)
	}
	call(other.Session.ID, other.Delegation.ID, 200)
	if calls.Load() != 2 {
		t.Fatal("approved quota did not resume")
	}
}
