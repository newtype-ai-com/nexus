package gate

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

type m11BlockedWriter struct {
	*httptest.ResponseRecorder
	once    sync.Once
	expired chan struct{}
}

func (w *m11BlockedWriter) SetWriteDeadline(t time.Time) error {
	if !t.After(time.Now()) {
		w.once.Do(func() { close(w.expired) })
	}
	return nil
}
func (w *m11BlockedWriter) Write(p []byte) (int, error) {
	<-w.expired
	return 0, context.DeadlineExceeded
}

type m11EOFBody struct {
	done chan struct{}
	once sync.Once
	data string
}

func (b *m11EOFBody) Close() error               { b.once.Do(func() { close(b.done) }); return nil }
func (b *m11EOFBody) Read(p []byte) (int, error) { <-b.done; return copy(p, b.data), io.EOF }

type m11Transport func(*http.Request) (*http.Response, error)

func (f m11Transport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestM11GatewayProgressAndAccounting(t *testing.T) {
	for _, mode := range []string{"headers", "keepalive", "progress", "unsolicited", "cancel", "total", "blocked", "eof", "data-eof"} {
		t.Run(mode, func(t *testing.T) {
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
			exited := make(chan struct{})
			upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				io.Copy(io.Discard, r.Body)
				defer close(exited)
				if mode == "headers" || mode == "cancel" {
					<-r.Context().Done()
					return
				}
				w.Header().Set("Content-Type", "text/event-stream")
				for i := 0; ; i++ {
					if mode == "progress" && i == 6 {
						io.WriteString(w, "data: {\"usage\":{\"total_tokens\":7}}\n\ndata: [DONE]\n\n")
						return
					}
					frame := "data: {\"type\":\"PRIVATE_HEARTBEAT_TOKEN\"}\n\n"
					if mode == "progress" || mode == "total" {
						frame = "data: {\"choices\":[{\"delta\":{\"content\":\"PRIVATE\"}}]}\n\n"
					}
					io.WriteString(w, frame)
					w.(http.Flusher).Flush()
					select {
					case <-r.Context().Done():
						return
					case <-time.After(20 * time.Millisecond):
					}
				}
			}))
			defer upstream.Close()
			var logs bytes.Buffer
			cfg := ModelConfig{Service: svc, Store: creds, Upstream: upstream.URL + "/chat/completions", Key: "PRIVATE_KEY", Models: []string{"fixture"}, Budget: 2000, MaxOutput: 100, Transport: upstream.Client().Transport, StreamIdleTimeout: 80 * time.Millisecond, Logger: slog.New(slog.NewJSONHandler(&logs, nil))}
			if mode == "total" {
				cfg.TurnLimit = time.Second
				cfg.StreamIdleTimeout = 2 * time.Second
			}
			if mode == "eof" || mode == "data-eof" {
				cfg.Transport = m11Transport(func(r *http.Request) (*http.Response, error) {
					close(exited)
					data := ""
					if mode == "data-eof" {
						data = "data: {\"usage\":{\"total_tokens\":7}}\n\ndata: [DONE]\n\n"
					}
					return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"text/event-stream"}}, Body: &m11EOFBody{done: make(chan struct{}), data: data}}, nil
				})
			}
			h, err := NewModelHandler(cfg)
			if err != nil {
				t.Fatal(err)
			}
			streaming := "true"
			if mode == "unsolicited" {
				streaming = "false"
			}
			r := httptest.NewRequest("POST", "/", strings.NewReader(`{"model":"fixture","messages":[{"role":"user","content":"PRIVATE"}],"stream":`+streaming+`}`))
			if mode == "cancel" {
				c, stop := context.WithTimeout(r.Context(), 30*time.Millisecond)
				defer stop()
				r = r.WithContext(c)
			}
			r.Header.Set("Authorization", "Bearer "+key)
			r.Header.Set("X-Newtype-Login", login)
			r.Header.Set("X-Newtype-Session", string(root.Session.ID))
			r.Header.Set("X-Newtype-Delegation", string(root.Delegation.ID))
			w := httptest.NewRecorder()
			func() {
				defer func() {
					if x := recover(); x != nil && x != http.ErrAbortHandler {
						panic(x)
					}
				}()
				var writer http.ResponseWriter = w
				if mode == "blocked" {
					writer = &m11BlockedWriter{ResponseRecorder: w, expired: make(chan struct{})}
				}
				h.ServeHTTP(writer, r)
			}()
			select {
			case <-exited:
			case <-time.After(time.Second):
				t.Fatal("upstream leak")
			}
			state, err := svc.Execution(ctx, user, ids.Invocation(w.Header().Get("X-Newtype-Invocation")))
			if err != nil {
				t.Fatal(err)
			}
			if mode == "progress" {
				if state.Status != "completed" || state.Charged != 7 {
					t.Fatal(state)
				}
			} else {
				if state.Status != "failed" || state.Charged != 2000 {
					t.Fatal("false successful settlement", state)
				}
				if mode != "cancel" && mode != "total" && !strings.Contains(logs.String(), `"failed":"no_progress"`) {
					t.Fatal("missing stall diagnostic", logs.String())
				}
			}
			if strings.Contains(logs.String(), "PRIVATE") {
				t.Fatal("unsafe last event log")
			}
		})
	}
}
