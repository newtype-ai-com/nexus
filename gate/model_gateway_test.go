package gate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestModelGatewayStreamingMeterAndRevocation(t *testing.T) {
	ctx := context.Background()
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	creds := NewMemoryCredentials()
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "user@example.test")
	root, err := svc.CreateRoot(ctx, user, nexus.RootRequest{Title: "model", Runner: nexus.Local, Scope: []string{"model:fixture"}, Rules: []nexus.Rule{{Action: "model:fixture", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 6000}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	key, login := "ntl_"+strings.Repeat("a", 64), "ntg_"+strings.Repeat("b", 64)
	for token, kind := range map[string]string{key: "licence", login: "login"} {
		if creds.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: user.AccountID, Email: user.Email, Expires: time.Now().Add(time.Hour)}) != nil {
			t.Fatal("credentials")
		}
	}
	var mode atomic.Int32
	var calls atomic.Int32
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Authorization") != "Bearer upstream-fixture" || r.Header.Get("X-Newtype-Login") != "" {
			t.Error("wrong upstream auth")
		}
		var b map[string]any
		if json.NewDecoder(r.Body).Decode(&b) != nil {
			t.Error("request")
		}
		if b["max_completion_tokens"] != float64(100) || b["model"] != "fixture" {
			t.Error("not pinned")
		}
		if mode.Load() == 1 {
			w.WriteHeader(401)
			_, _ = io.WriteString(w, "upstream-fixture")
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = io.WriteString(w, "data: {\"choices\":[{\"delta\":{\"content\":\"ok\"}}]}\n\n")
		w.(http.Flusher).Flush()
		if mode.Load() == 2 {
			<-r.Context().Done()
			return
		}
		if mode.Load() != 3 {
			_, _ = io.WriteString(w, "data: {\"usage\":{\"prompt_tokens\":4,\"completion_tokens\":2,\"total_tokens\":6}}\n\n")
		}
		_, _ = io.WriteString(w, "data: [DONE]\n\n")
	}))
	defer upstream.Close()
	handler, err := NewModelHandler(ModelConfig{Service: svc, Store: creds, Upstream: upstream.URL + "/v1/chat/completions", Key: "upstream-fixture", Models: []string{"fixture"}, Budget: 2000, MaxOutput: 100, Transport: upstream.Client().Transport})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	request := func(want int, body string) (ids.Invocation, string) {
		t.Helper()
		req, _ := http.NewRequest("POST", server.URL, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		req.Header.Set("X-Newtype-Login", login)
		req.Header.Set("X-Newtype-Session", string(root.Session.ID))
		req.Header.Set("X-Newtype-Delegation", string(root.Delegation.ID))
		res, err := server.Client().Do(req)
		if err != nil {
			t.Fatal("gateway transport")
		}
		defer res.Body.Close()
		raw, _ := io.ReadAll(res.Body)
		if res.StatusCode != want {
			t.Fatalf("gateway status %d want %d", res.StatusCode, want)
		}
		if strings.Contains(string(raw), "upstream-fixture") {
			t.Fatal("upstream key leaked")
		}
		return ids.Invocation(res.Header.Get("X-Newtype-Invocation")), string(raw)
	}
	body := `{"model":"fixture","messages":[{"role":"user","content":"private prompt"}],"stream":true,"max_tokens":99999}`
	id, out := request(200, body)
	if !strings.Contains(out, "ok") {
		t.Fatal("not streamed")
	}
	check := func(id ids.Invocation, charge int64) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for {
			state, err := svc.Execution(ctx, user, id)
			if err == nil && state.Status != "running" {
				if state.Charged != charge {
					t.Fatalf("charged %d want %d", state.Charged, charge)
				}
				return
			}
			if time.Now().After(deadline) {
				t.Fatal("not settled")
			}
			time.Sleep(time.Millisecond)
		}
	}
	check(id, 6)
	mode.Store(1)
	id, _ = request(502, body)
	check(id, 2000)
	mode.Store(3)
	id, _ = request(200, body)
	check(id, 2000)
	request(403, body) // remaining 994 cannot reserve 2000
	if calls.Load() != 3 {
		t.Fatal("limit request reached upstream")
	}
	request(400, `{"model":"other"}`)
	if creds.PutCredential(ctx, Credential{Verifier: Verifier(login), Kind: "login", Account: user.AccountID, Email: user.Email, Expires: time.Now().Add(time.Hour), Revoked: true}) != nil {
		t.Fatal("revoke")
	}
	request(401, body)
}

func TestModelUsageCannotReadGeneratedContent(t *testing.T) {
	for _, raw := range []string{`{"choices":[{"message":{"content":"usage: 1"}}]}`, `{"usage":{"total_tokens":-1}}`, `{"usage":null}`} {
		if modelUsage([]byte(raw), false) != -1 {
			t.Fatal("untrusted usage")
		}
	}
	if modelUsage([]byte(`{"type":"response.completed","response":{"usage":{"input_tokens":4,"output_tokens":3}}}`), false) != 7 {
		t.Fatal("responses usage")
	}
}
