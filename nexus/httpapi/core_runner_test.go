package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/core"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/httpapi"
)

type coreModelFunc func(context.Context, core.ModelRequest, func(string)) (core.ModelResponse, error)

func (f coreModelFunc) Chat(ctx context.Context, r core.ModelRequest, on func(string)) (core.ModelResponse, error) {
	return f(ctx, r, on)
}

type coreFixture struct {
	service *nexus.Service
	person  nexus.Principal
	actor   nexus.Principal
	root    nexus.Issued
	api     *httpapi.API
	run     httpapi.Runner
}

func coreSetup(t *testing.T, effect string, model core.Model) *coreFixture {
	return coreSetupClock(t, effect, model, time.Now)
}

func coreSetupClock(t *testing.T, effect string, model core.Model, clock func() time.Time) *coreFixture {
	t.Helper()
	f := &coreFixture{service: nexus.NewService(nexus.NewMemStore(), clock), person: nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "test@example.com")}
	var err error
	f.root, err = f.service.CreateRoot(context.Background(), f.person, nexus.RootRequest{Title: "local core", Scope: []string{"model:local"}, Rules: []nexus.Rule{{Action: "model:local", Effect: effect}}, Limits: nexus.Limits{ModelTokens: 100}})
	if err != nil {
		t.Fatal(err)
	}
	f.actor = nexus.SessionPrincipal(f.person.AccountID, f.root.Session.ID)
	f.run, err = httpapi.NewCoreRunner(httpapi.CoreRunnerConfig{Service: f.service, Model: model, ModelName: "local", WorkDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	f.api, err = httpapi.New(httpapi.Config{Service: f.service, Clock: clock, Run: f.run, Actions: map[string]int64{"model:local": 7}, Authenticate: func(r *http.Request) (nexus.Principal, error) {
		if r.Header.Get("Authorization") == "local-person" {
			return f.person, nil
		}
		if r.Header.Get("Authorization") == "local-session" {
			return f.actor, nil
		}
		return nexus.Principal{}, errors.New("no credentials")
	}})
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func coreRequest(f *coreFixture, ctx context.Context, method, path, body, auth string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, path, strings.NewReader(body)).WithContext(ctx)
	r.Header.Set("Authorization", auth)
	w := httptest.NewRecorder()
	f.api.ServeHTTP(w, r)
	return w
}
func coreExecute(f *coreFixture, ctx context.Context, id, args string) *httptest.ResponseRecorder {
	return coreRequest(f, ctx, "POST", "/v1/executions/"+id, fmt.Sprintf(`{"delegation_id":%q,"action":"model:local","args":%s}`, f.root.Delegation.ID, args), "local-session")
}
func coreResult(t *testing.T, w *httptest.ResponseRecorder, code int, status string) httpapi.Result {
	t.Helper()
	var r httpapi.Result
	if w.Code != code || json.Unmarshal(w.Body.Bytes(), &r) != nil || r.Status != status {
		t.Fatalf("got %d %s; want %d %s", w.Code, w.Body.String(), code, status)
	}
	return r
}

func TestCoreRunnerActualEngineIsolationAndReceipt(t *testing.T) {
	var calls atomic.Int32
	var seen []core.ModelRequest
	f := coreSetup(t, "auto", coreModelFunc(func(_ context.Context, r core.ModelRequest, on func(string)) (core.ModelResponse, error) {
		calls.Add(1)
		seen = append(seen, r)
		on("private output")
		return core.ModelResponse{Content: "private output", Usage: core.Usage{InputTokens: 13, OutputTokens: 5}}, nil
	}))
	for i := 0; i < 2; i++ {
		id := ids.New(ids.KindInvocation)
		w := coreExecute(f, context.Background(), id, `{"message":"private input"}`)
		coreResult(t, w, 200, "completed")
		if strings.Contains(w.Body.String(), "private") {
			t.Fatal("private text in response")
		}
		coreResult(t, coreExecute(f, context.Background(), id, `{"message":"private input"}`), 200, "completed")
	}
	if calls.Load() != 2 || len(seen) != 2 {
		t.Fatal("duplicate model execution", calls.Load())
	}
	for _, r := range seen {
		if r.AgentSessionID != string(f.actor.SessionID) || r.SessionID == string(f.actor.SessionID) || !strings.HasPrefix(r.SessionID, "conv_") || len(r.Tools) != 0 || len(r.Messages) != 2 {
			t.Fatal("identity/history/tool isolation failed", r.SessionID)
		}
	}
	if seen[0].SessionID == seen[1].SessionID {
		t.Fatal("conversation was reused")
	}
	info, err := f.service.DelegationInfo(context.Background(), f.person, f.root.Delegation.ID)
	if err != nil || info.Remaining.ModelTokens != 86 {
		t.Fatal("fixed-cost usage", info.Remaining, err)
	}
	events, _, err := f.service.Events(context.Background(), f.actor, f.actor.SessionID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range events {
		if strings.Contains(string(e.Payload), "private") {
			t.Fatal("private text in ledger")
		}
	}
}

func TestCoreRunnerApprovalAndRejectsClientCapabilities(t *testing.T) {
	var calls atomic.Int32
	f := coreSetup(t, "ask", coreModelFunc(func(context.Context, core.ModelRequest, func(string)) (core.ModelResponse, error) {
		calls.Add(1)
		return core.ModelResponse{Content: "ok"}, nil
	}))
	id := ids.New(ids.KindInvocation)
	pending := coreResult(t, coreExecute(f, context.Background(), id, `{"message":"hello"}`), 202, "pending")
	if calls.Load() != 0 {
		t.Fatal("model ran before approval")
	}
	coreResult(t, coreRequest(f, context.Background(), "POST", "/v1/executions/"+id+"/approval", fmt.Sprintf(`{"input_hash":%q,"approve":true}`, pending.InputHash), "local-person"), 200, "approved")
	coreResult(t, coreExecute(f, context.Background(), id, `{"message":"hello"}`), 200, "completed")
	if calls.Load() != 1 {
		t.Fatal(calls.Load())
	}
	if err := f.run(context.Background(), "model:local", json.RawMessage(`{"message":"unbound"}`)); !errors.Is(err, nexus.ErrForbidden) {
		t.Fatal("accepted unbound runner", err)
	}

	// Every field except message is refused by the core adapter. Outer receipts
	// still charge their configured fixed cost even when runner validation fails.
	f = coreSetup(t, "auto", coreModelFunc(func(context.Context, core.ModelRequest, func(string)) (core.ModelResponse, error) {
		t.Error("invalid input reached model")
		return core.ModelResponse{}, nil
	}))
	for _, args := range []string{`{"message":"x","session_id":"other"}`, `{"message":"x","work_dir":"/"}`, `{"message":"x","prompt_type":"agent"}`, `{"message":"x","model":"other"}`, `{"message":""}`} {
		coreResult(t, coreExecute(f, context.Background(), ids.New(ids.KindInvocation), args), 200, "failed")
	}
}

func TestCoreRunnerCancellationAndModelErrorPrivacy(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	f := coreSetup(t, "auto", coreModelFunc(func(ctx context.Context, _ core.ModelRequest, _ func(string)) (core.ModelResponse, error) {
		close(started)
		<-ctx.Done()
		close(stopped)
		return core.ModelResponse{}, ctx.Err()
	}))
	id := ids.New(ids.KindInvocation)
	result := make(chan *httptest.ResponseRecorder, 1)
	go func() { result <- coreExecute(f, context.Background(), id, `{"message":"cancel"}`) }()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("model did not start")
	}
	coreResult(t, coreRequest(f, context.Background(), "POST", "/v1/executions/"+id+"/cancel", "", "local-session"), 200, "cancelling")
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("model did not stop")
	}
	select {
	case w := <-result:
		coreResult(t, w, 200, "cancelled")
	case <-time.After(5 * time.Second):
		t.Fatal("runner did not drain")
	}
	f = coreSetup(t, "auto", coreModelFunc(func(context.Context, core.ModelRequest, func(string)) (core.ModelResponse, error) {
		return core.ModelResponse{}, errors.New("private provider diagnostic")
	}))
	w := coreExecute(f, context.Background(), ids.New(ids.KindInvocation), `{"message":"x"}`)
	coreResult(t, w, 200, "failed")
	if strings.Contains(w.Body.String(), "private") {
		t.Fatal("provider error exposed")
	}
}
