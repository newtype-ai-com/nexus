//go:build darwin || linux

package gate

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func budgetFixture(t *testing.T, max int64) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "calls.jsonl")
	if err := InitializeModelCallBudget(path, ModelCallBudgetHeader{1, "fixture", max, time.Now().UTC().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestModelCallBudgetPersistentAndConcurrent(t *testing.T) {
	path := budgetFixture(t, 5)
	if checkModelCallBudget(path, false) != nil {
		t.Fatal("invalid fresh ledger")
	}
	var accepted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if checkModelCallBudget(path, true) == nil {
				accepted.Add(1)
			}
		}()
	}
	wg.Wait()
	// Nonblocking locks may conservatively reject contention, but never overspend.
	if accepted.Load() > 5 {
		t.Fatal("cap exceeded")
	}
	for checkModelCallBudget(path, true) == nil {
		accepted.Add(1)
	}
	if accepted.Load() != 5 {
		t.Fatal("unexpected total", accepted.Load())
	}
	if checkModelCallBudget(path, false) != nil || checkModelCallBudget(path, true) == nil {
		t.Fatal("restart reset the budget")
	}
	if InitializeModelCallBudget(path, ModelCallBudgetHeader{1, "other", 9, time.Now().Add(time.Hour)}) == nil {
		t.Fatal("reset accepted")
	}
}

func TestModelCallBudgetRejectsUnsafeLedger(t *testing.T) {
	for _, kind := range []string{"missing", "partial", "sequence", "header", "expired", "permissions", "directory", "symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
			path := budgetFixture(t, 2)
			var err error
			switch kind {
			case "missing":
				err = os.Remove(path)
			case "partial", "sequence":
				var f *os.File
				f, err = os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0)
				if err == nil {
					value := "1"
					if kind == "sequence" {
						value = "2\n"
					}
					_, err = f.WriteString(value)
					f.Close()
				}
			case "header":
				err = os.WriteFile(path, []byte("{\"version\":1}\n"), 0600)
			case "expired":
				err = os.WriteFile(path, []byte("{\"version\":1,\"rollout\":\"fixture\",\"max_calls\":2,\"expires_at\":\"2000-01-01T00:00:00Z\"}\n"), 0600)
			case "permissions":
				err = os.Chmod(path, 0644)
			case "directory":
				err = os.Chmod(filepath.Dir(path), 0755)
			case "symlink":
				err = os.Rename(path, path+".old")
				if err == nil {
					err = os.Symlink(path+".old", path)
				}
			case "hardlink":
				err = os.Link(path, path+".link")
			}
			if err != nil {
				t.Fatal(err)
			}
			if checkModelCallBudget(path, false) == nil || checkModelCallBudget(path, true) == nil {
				t.Fatal("unsafe ledger accepted")
			}
		})
	}
}

type budgetTransport func(*http.Request) (*http.Response, error)

func (f budgetTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestModelCallBudgetGatewayDispatchAndRestart(t *testing.T) {
	for _, networkError := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "ambiguous-network-error"}[networkError], func(t *testing.T) {
			ctx := context.Background()
			svc := nexus.NewService(nexus.NewMemStore(), nil)
			user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "fixture@example.test")
			root, err := svc.CreateRoot(ctx, user, nexus.RootRequest{Title: "budget", Runner: nexus.Local, Scope: []string{"model:example-model"}, Rules: []nexus.Rule{{Action: "model:example-model", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 100000}, TTL: time.Hour})
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
			calls := 0
			cfg := ModelConfig{Service: svc, Store: creds, Upstream: "https://fixture.invalid/responses", Key: "fixture", Models: []string{"example-model"}, Budget: 4096, MaxOutput: 256, CallBudgetFile: budgetFixture(t, 1), Transport: budgetTransport(func(*http.Request) (*http.Response, error) {
				calls++
				if networkError {
					return nil, errors.New("ambiguous fixture error")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"status":"completed","usage":{"input_tokens":2,"output_tokens":1}}`))}, nil
			})}
			request := func(h *ModelHandler, authorized bool, body string) int {
				r := httptest.NewRequest("POST", "/v1/model/responses", strings.NewReader(body))
				if authorized {
					r.Header.Set("Authorization", "Bearer "+key)
					r.Header.Set("X-Newtype-Login", login)
					r.Header.Set("X-Newtype-Session", string(root.Session.ID))
					r.Header.Set("X-Newtype-Delegation", string(root.Delegation.ID))
				}
				w := httptest.NewRecorder()
				h.ServeHTTP(w, r)
				return w.Code
			}
			h, err := NewModelHandler(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if request(h, false, `{"input":[]}`) != 401 || request(h, true, `{"model":"wrong"}`) != 400 || calls != 0 {
				t.Fatal("invalid request dispatched")
			}
			want := 200
			if networkError {
				want = 502
			}
			if got := request(h, true, `{"input":[],"store":false}`); got != want {
				t.Fatal("first dispatch", got)
			}
			h, err = NewModelHandler(cfg)
			if err != nil {
				t.Fatal(err)
			}
			if request(h, true, `{"input":[],"store":false}`) != 403 || calls != 1 {
				t.Fatal("restart or error refunded call cap", calls)
			}
		})
	}
}
