package gate

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestResponsesGatewayContract(t *testing.T) {
	ctx := context.Background()
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "fixture@example.test")
	root, err := svc.CreateRoot(ctx, user, nexus.RootRequest{Title: "responses", Runner: nexus.Local, Scope: []string{"model:example-model"}, Rules: []nexus.Rule{{Action: "model:example-model", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 100000}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	creds := NewMemoryCredentials()
	key, login := "ntl_"+strings.Repeat("a", 64), "ntg_"+strings.Repeat("b", 64)
	for token, kind := range map[string]string{key: "licence", login: "login"} {
		if err := creds.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: user.AccountID, Email: user.Email, Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	calls, status := 0, 200
	up := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		var b map[string]any
		if json.NewDecoder(r.Body).Decode(&b) != nil || b["model"] != "example-model" || b["max_output_tokens"] != float64(256) || b["store"] != false || r.Header.Get("Authorization") != "Bearer fixture" {
			t.Error("Responses contract mismatch")
		}
		if status != 200 {
			// M21: a hint outside the retry budget is relayed without dispatching again.
			w.Header().Set("Retry-After", "3600")
			w.WriteHeader(status)
			_, _ = w.Write([]byte(`{"error":{"message":"fixture credential"}}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"completed","usage":{"input_tokens":2,"output_tokens":1,"total_tokens":3}}`))
	}))
	defer up.Close()
	h, err := NewModelHandler(ModelConfig{Service: svc, Store: creds, Upstream: up.URL + "/openai/v1/responses", Key: "fixture", Models: []string{"example-model"}, Budget: 4096, MaxOutput: 256, Transport: up.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	if h.client.Timeout != 0 {
		t.Fatal("stream client must use turn limit, not global timeout")
	}
	for _, tc := range []struct {
		body                  string
		upstream, want, delta int
	}{
		{`{"model":"","input":[],"store":false}`, 200, 200, 1},
		{`{"input":[],"store":false}`, 200, 200, 1},
		{`{"model":"other","store":false}`, 200, 400, 0},
		{`{"model":42,"store":false}`, 200, 400, 0},
		{`{"store":true}`, 200, 400, 0},
		{`{"store":null}`, 200, 400, 0},
		{`{"store":false}`, 401, 502, 1},
		{`{"store":false}`, 403, 502, 1},
		{`{"store":false}`, 429, 429, 1},
	} {
		status = tc.upstream
		before := calls
		r := httptest.NewRequest("POST", "/v1/model/responses", strings.NewReader(tc.body))
		r.Header.Set("Authorization", "Bearer "+key)
		r.Header.Set("X-Newtype-Login", login)
		r.Header.Set("X-Newtype-Session", string(root.Session.ID))
		r.Header.Set("X-Newtype-Delegation", string(root.Delegation.ID))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want || calls-before != tc.delta {
			t.Fatalf("status=%d calls=%d want=%d/%d", w.Code, calls-before, tc.want, tc.delta)
		}
		if strings.Contains(w.Body.String(), "fixture credential") {
			t.Fatal("credential error leaked")
		}
		if tc.want == 429 && (w.Header().Get("Retry-After") != "3600" || w.Header().Get("X-Newtype-Model-Retry") != "exhausted") {
			t.Fatal("missing retry hint")
		}
	}
}
