package httpapi_test

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/httpapi"
)

type apiFixture struct {
	service              *nexus.Service
	person, actor, other nexus.Principal
	root                 nexus.Issued
	now                  atomic.Int64
	valid                atomic.Bool
	cfg                  httpapi.Config
	api                  *httpapi.API
	calls                atomic.Int32
}

func apiSetup(t *testing.T, effect string) *apiFixture {
	t.Helper()
	f := &apiFixture{}
	f.now.Store(time.Now().UnixNano())
	f.valid.Store(true)
	clock := func() time.Time { return time.Unix(0, f.now.Load()) }
	f.service = nexus.NewService(nexus.NewMemStore(), clock)
	f.person = nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "owner@example.com")
	f.other = nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "other@example.com")
	var err error
	f.root, err = f.service.CreateRoot(context.Background(), f.person, nexus.RootRequest{Title: "test", Scope: []string{"newtype:run"}, Rules: []nexus.Rule{{Action: "tool:local", Effect: effect}}, Limits: nexus.Limits{ModelTokens: 100}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	f.actor = nexus.SessionPrincipal(f.person.AccountID, f.root.Session.ID)
	f.cfg = httpapi.Config{Service: f.service, Clock: clock, ApprovalTTL: time.Minute, Actions: map[string]int64{"tool:local": 7}, Run: func(context.Context, string, json.RawMessage) error { f.calls.Add(1); return nil }, Authenticate: func(r *http.Request) (nexus.Principal, error) {
		if !f.valid.Load() {
			return nexus.Principal{}, errors.New("expired credential")
		}
		switch r.Header.Get("Authorization") {
		case "session":
			return f.actor, nil
		case "person":
			return f.person, nil
		case "other":
			return f.other, nil
		case "system":
			return nexus.SystemPrincipal(f.person.AccountID), nil
		case "bad":
			return nexus.SessionPrincipal(f.person.AccountID, "bad-session"), nil
		}
		return nexus.Principal{}, errors.New("unknown credential")
	}}
	f.reset(t)
	return f
}
func (f *apiFixture) reset(t *testing.T) {
	t.Helper()
	var err error
	f.api, err = httpapi.New(f.cfg)
	if err != nil {
		t.Fatal(err)
	}
}
func (f *apiFixture) request(method, path, body, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	f.api.ServeHTTP(w, r)
	return w
}
func (f *apiFixture) execute(id, args string) *httptest.ResponseRecorder {
	return f.request("POST", "/v1/executions/"+id, fmt.Sprintf(`{"delegation_id":%q,"action":"tool:local","args":%s}`, f.root.Delegation.ID, args), "session")
}
func (f *apiFixture) approve(id, hash, auth string, yes bool) *httptest.ResponseRecorder {
	return f.request("POST", "/v1/executions/"+id+"/approval", fmt.Sprintf(`{"input_hash":%q,"approve":%t}`, hash, yes), auth)
}
func code(t *testing.T, w *httptest.ResponseRecorder, want int) {
	t.Helper()
	if w.Code != want {
		t.Fatalf("got %d %s, want %d", w.Code, w.Body.String(), want)
	}
}
func (f *apiFixture) remaining(t *testing.T, want int64) {
	t.Helper()
	info, err := f.service.DelegationInfo(context.Background(), f.person, f.root.Delegation.ID)
	if err != nil || info.Remaining.ModelTokens != want {
		t.Fatal(info.Remaining, err)
	}
}

func TestHTTPAuthenticationAndInputBoundary(t *testing.T) {
	f := apiSetup(t, "auto")
	id := ids.New(ids.KindInvocation)
	for _, auth := range []string{"", "system", "bad"} {
		code(t, f.request("GET", "/v1/executions/"+id, "", auth), 401)
	}
	body := fmt.Sprintf(`{"delegation_id":%q,"action":"tool:local","args":{}}`, f.root.Delegation.ID)
	code(t, f.request("POST", "/v1/executions/"+id, body, "person"), 403)
	for _, extra := range []string{`,"approved":true`, `,"account_id":"attacker"`, `,"tokens":0`, `,"action":"tool:local"`} {
		code(t, f.request("POST", "/v1/executions/"+id, strings.TrimSuffix(body, "}")+extra+"}", "session"), 400)
	}
	for _, args := range []string{`{"value":"password: private-value"}`, `{"x":1,"x":2}`, `{"x":"` + strings.Repeat("a", 65536) + `"}`} {
		code(t, f.execute(id, args), 400)
	}
	coreResult(t, f.execute(id, `{"x":1}`), 200, "completed")
	code(t, f.request("GET", "/v1/executions/"+id, "", "other"), 404)
	code(t, f.approve(id, "", "other", true), 404)
	f.valid.Store(false)
	code(t, f.execute(id, `{"x":1}`), 401)
	if f.calls.Load() != 1 {
		t.Fatal(f.calls.Load())
	}
	f.remaining(t, 93)
}

func TestHTTPApprovalExactInputOnceAndExpiry(t *testing.T) {
	f := apiSetup(t, "ask")
	id := ids.New(ids.KindInvocation)
	pending := coreResult(t, f.execute(id, `{"x":1}`), 202, "pending")
	code(t, f.approve(id, pending.InputHash, "session", true), 403)
	code(t, f.approve(id, strings.Repeat("0", 64), "person", true), 409)
	code(t, f.execute(id, `{"x":2}`), 409)
	coreResult(t, f.approve(id, pending.InputHash, "person", true), 200, "approved")
	code(t, f.approve(id, pending.InputHash, "person", true), 409)
	coreResult(t, f.execute(id, `{ "x": 1 }`), 200, "completed")
	coreResult(t, f.execute(id, `{"x":1}`), 200, "completed")
	if f.calls.Load() != 1 {
		t.Fatal(f.calls.Load())
	}
	f.remaining(t, 93)
	id = ids.New(ids.KindInvocation)
	pending = coreResult(t, f.execute(id, `{}`), 202, "pending")
	f.now.Add(int64(time.Minute))
	code(t, f.approve(id, pending.InputHash, "person", true), 403)
	coreResult(t, f.execute(id, `{}`), 200, "expired")
	id = ids.New(ids.KindInvocation)
	pending = coreResult(t, f.execute(id, `{}`), 202, "pending")
	coreResult(t, f.approve(id, pending.InputHash, "person", false), 200, "denied")
	coreResult(t, f.execute(id, `{}`), 200, "denied")
	if f.calls.Load() != 1 {
		t.Fatal("expired/denied execution ran")
	}
}

func TestHTTPApprovalRechecksDelegation(t *testing.T) {
	for _, change := range []string{"revoke", "expire", "suspend"} {
		t.Run(change, func(t *testing.T) {
			f := apiSetup(t, "ask")
			id := ids.New(ids.KindInvocation)
			p := coreResult(t, f.execute(id, `{}`), 202, "pending")
			coreResult(t, f.approve(id, p.InputHash, "person", true), 200, "approved")
			switch change {
			case "revoke":
				_, err := f.service.Revoke(context.Background(), f.person, f.root.Delegation.ID, "")
				if err != nil {
					t.Fatal(err)
				}
			case "expire":
				f.now.Add(int64(time.Hour))
			case "suspend":
				_, err := f.service.Suspend(context.Background(), f.person, f.root.Session.ID, "")
				if err != nil {
					t.Fatal(err)
				}
			}
			code(t, f.execute(id, `{}`), 403)
			if f.calls.Load() != 0 {
				t.Fatal("inactive delegation executed")
			}
		})
	}
}

func TestHTTPConcurrentDuplicateAndRestartReceipt(t *testing.T) {
	f := apiSetup(t, "auto")
	started := make(chan struct{})
	release := make(chan struct{})
	f.cfg.Run = func(context.Context, string, json.RawMessage) error {
		f.calls.Add(1)
		close(started)
		<-release
		return nil
	}
	f.reset(t)
	id := ids.New(ids.KindInvocation)
	first := make(chan *httptest.ResponseRecorder, 1)
	go func() { first <- f.execute(id, `{}`) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("not started")
	}
	var wg sync.WaitGroup
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			w := f.execute(id, `{}`)
			if w.Code != 200 {
				t.Errorf("duplicate %d", w.Code)
			}
		}()
	}
	wg.Wait()
	if f.calls.Load() != 1 {
		t.Fatal("duplicate ran", f.calls.Load())
	}
	f.remaining(t, 93)
	close(release)
	coreResult(t, <-first, 200, "completed")
	// A second API instance has no results but shares durable start receipts.
	f.reset(t)
	coreResult(t, f.execute(id, `{}`), 409, "indeterminate")
	if f.calls.Load() != 1 {
		t.Fatal("restart replay ran")
	}
	f.remaining(t, 93)
}

func TestHTTPStreamCursorAndCredentialExpiry(t *testing.T) {
	f := apiSetup(t, "auto")
	events, err := f.service.AppendEvents(context.Background(), f.actor, f.actor.SessionID, []nexus.EventInput{{Source: "engine", Kind: "test", Payload: json.RawMessage(`{}`)}})
	if err != nil {
		t.Fatal(err)
	}
	tail := events[0].Seq
	server := httptest.NewServer(f.api)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, "GET", server.URL+"/v1/sessions/"+string(f.actor.SessionID)+"/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "session")
	req.Header.Set("Last-Event-ID", fmt.Sprint(tail-1))
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 || resp.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatal(resp.StatusCode)
	}
	scanner := bufio.NewScanner(resp.Body)
	found := false
	for scanner.Scan() {
		if scanner.Text() == "id: "+fmt.Sprint(tail) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("cursor event not delivered", scanner.Err())
	}
	// Authenticator is the injected credential boundary; service notifications
	// wake SSE and force reauthentication before any subsequent ledger batch.
	f.valid.Store(false)
	f.service.Notify()
	for scanner.Scan() {
	}
	if err := scanner.Err(); err != nil {
		t.Fatal("stream did not end cleanly on expiry", err)
	}
}

func TestHTTPRunnerPanicAndCapacity(t *testing.T) {
	f := apiSetup(t, "auto")
	f.cfg.MaxRecords = 1
	f.cfg.Run = func(context.Context, string, json.RawMessage) error { panic("private panic") }
	f.reset(t)
	w := f.execute(ids.New(ids.KindInvocation), `{}`)
	coreResult(t, w, 200, "failed")
	if strings.Contains(w.Body.String(), "private") {
		t.Fatal("panic exposed")
	}
	code(t, f.execute(ids.New(ids.KindInvocation), `{}`), 429)
	f.remaining(t, 93)
}
