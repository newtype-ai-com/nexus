package gate

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/internal/modelerror"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestM17ObserverBoundedChunking(t *testing.T) {
	errorFrame := "event: response.failed\r\ndata: {\"response\":{\"error\":{\"code\":\"server_error\",\"message\":\"PRIVATE\"}}}\r\n\r\n"
	for _, size := range []int{1, 7, 32768} {
		var got []modelerror.Detail
		o := modelErrorObserver{sse: true, report: func(d modelerror.Detail) { got = append(got, d) }}
		// Oversized unrelated event, content containing fake error, then a real
		// error more than 256KiB from both ends of the stream.
		raw := "data: " + strings.Repeat("x", 300000) + "\n\n" + "data: {\"choices\":[{\"delta\":{\"content\":\"server_error PRIVATE\"}}]}\n\n" + errorFrame + strings.Repeat(": keepalive\n\n", 30000)
		for len(raw) > 0 {
			n := size
			if n > len(raw) {
				n = len(raw)
			}
			o.write([]byte(raw[:n]))
			raw = raw[n:]
			if len(o.line) > modelerror.MaxEnvelope || len(o.data) > modelerror.MaxEnvelope {
				t.Fatal("unbounded observer")
			}
		}
		o.end()
		if len(got) != 1 || got[0].Code != "server_error" || !got[0].Transient {
			t.Fatal(got)
		}
	}
	for _, raw := range []string{"data: {bad}\n\n", "data: {\"choices\":[{\"delta\":{\"content\":\"error\"}}]}\n\n"} {
		o := modelErrorObserver{sse: true, report: func(modelerror.Detail) { t.Fatal("nonerror logged") }}
		o.write([]byte(raw))
		o.end()
	}
}

func TestM17GatewayLogsLabelsAndSettlesFailure(t *testing.T) {
	for _, tc := range []struct{ name, raw, failed, kind string }{
		{"code", `{"error":{"code":"rate_limit_exceeded","type":"rate_limit_error","message":"PRIVATE BODY","request_id":"PRIVATE_ID"}}`, "rate_limit_exceeded", "rate_limit_error"},
		{"type", `{"error":{"type":"overloaded_error","message":"PRIVATE BODY"}}`, "overloaded_error", "overloaded_error"},
		{"unknown", `{"type":"response.failed","message":"PRIVATE BODY"}`, "unknown", ""},
		{"fallback", `{"type":"response.failed","error":{},"response":{"error":{"code":"server_error","message":"PRIVATE BODY"}}}`, "server_error", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			testM17GatewayFailure(t, "data: "+tc.raw+"\n\n", tc.failed, tc.kind)
		})
	}
}

func testM17GatewayFailure(t *testing.T, raw, failed, kind string) {
	t.Helper()
	ctx := context.Background()
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	creds := NewMemoryCredentials()
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "fixture@example.test")
	root, err := svc.CreateRoot(ctx, user, nexus.RootRequest{Title: "fixture", Runner: nexus.Local, Scope: []string{"model:fixture"}, Rules: []nexus.Rule{{Action: "model:*", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 6000}})
	if err != nil {
		t.Fatal(err)
	}
	key, login := "ntl_"+strings.Repeat("a", 64), "ntg_"+strings.Repeat("b", 64)
	for token, kind := range map[string]string{key: "licence", login: "login"} {
		if err := creds.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: user.AccountID, Email: user.Email, Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}

	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, raw)
	}))
	defer upstream.Close()
	var logs bytes.Buffer
	h, err := NewModelHandler(ModelConfig{Service: svc, Store: creds, Upstream: upstream.URL + "/chat/completions", Key: "PRIVATE_KEY", Models: []string{"fixture"}, Budget: 2000, MaxOutput: 100, Transport: upstream.Client().Transport, Logger: slog.New(slog.NewJSONHandler(&logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{"model":"fixture","messages":[{"role":"user","content":"PRIVATE PROMPT"}],"stream":true}`))
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("X-Newtype-Login", login)
	r.Header.Set("X-Newtype-Session", string(root.Session.ID))
	r.Header.Set("X-Newtype-Delegation", string(root.Delegation.ID))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 200 || w.Body.String() != raw {
		t.Fatal("relay changed", w.Code)
	}
	text := logs.String()
	if !strings.Contains(text, `"outcome":"model_failed"`) || !strings.Contains(text, `"failed":"`+failed+`"`) || !strings.Contains(text, `"type":"`+kind+`"`) || strings.Contains(text, "PRIVATE") || strings.Contains(text, string(root.Session.ID)) {
		t.Fatal("unsafe or absent diagnostics", text)
	}
	state, err := svc.Execution(ctx, user, ids.Invocation(w.Header().Get("X-Newtype-Invocation")))
	if err != nil || state.Status != "failed" || state.Charged != 2000 {
		t.Fatal("failed stream accounting", state, err)
	}
}
