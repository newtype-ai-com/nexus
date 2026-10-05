package httpapi_test

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus/httpapi"
)

func TestDurableApprovalSurvivesAPIReplacement(t *testing.T) {
	f := apiSetup(t, "ask")
	f.cfg.Durable = true
	f.cfg.RunMetered = func(context.Context, string, json.RawMessage) (int64, error) { f.calls.Add(1); return 3, nil }
	f.reset(t)
	id := ids.New(ids.KindInvocation)
	pending := coreResult(t, f.execute(id, `{"x":1}`), 202, "pending")
	f.reset(t)
	coreResult(t, f.request("GET", "/v1/executions/"+id, "", "session"), 200, "pending")
	coreResult(t, f.approve(id, pending.InputHash, "person", true), 200, "approved")
	f.reset(t)
	code(t, f.execute(id, `{"x":2}`), 409)
	coreResult(t, f.execute(id, `{"x":1}`), 200, "completed")
	f.reset(t)
	coreResult(t, f.execute(id, `{"x":1}`), 200, "completed")
	if f.calls.Load() != 1 {
		t.Fatal("replayed after restart")
	}
	f.remaining(t, 97)
}

func TestDurableRunningCancellationAcrossReplicas(t *testing.T) {
	for _, mode := range []string{"cancel", "credential", "revoke", "expiry"} {
		t.Run(mode, func(t *testing.T) {
			f := apiSetup(t, "auto")
			f.cfg.Durable = true
			f.cfg.RecheckInterval = time.Millisecond
			started := make(chan struct{})
			result := make(chan *httptest.ResponseRecorder, 1)
			f.cfg.RunMetered = func(ctx context.Context, _ string, _ json.RawMessage) (int64, error) {
				close(started)
				<-ctx.Done()
				return 2, ctx.Err()
			}
			f.reset(t)
			replica, err := httpapi.New(f.cfg)
			if err != nil {
				t.Fatal(err)
			}
			id := ids.New(ids.KindInvocation)
			go func() { result <- f.execute(id, `{}`) }()
			select {
			case <-started:
			case <-time.After(5 * time.Second):
				t.Fatal("not started")
			}
			switch mode {
			case "cancel":
				r := httptest.NewRequest("POST", "/v1/executions/"+id+"/cancel", nil)
				r.Header.Set("Authorization", "person")
				w := httptest.NewRecorder()
				replica.ServeHTTP(w, r)
				coreResult(t, w, 200, "cancelling")
			case "credential":
				f.valid.Store(false)
			case "revoke":
				_, err = f.service.Revoke(context.Background(), f.person, f.root.Delegation.ID, "")
				if err != nil {
					t.Fatal(err)
				}
			case "expiry":
				f.now.Add(int64(time.Hour))
			}
			select {
			case w := <-result:
				coreResult(t, w, 200, "cancelled")
			case <-time.After(5 * time.Second):
				t.Fatal("runner not cancelled")
			}
			f.remaining(t, 98)
		})
	}
}

func TestDurablePanicRetainsCeiling(t *testing.T) {
	f := apiSetup(t, "auto")
	f.cfg.Durable = true
	f.cfg.RunMetered = func(context.Context, string, json.RawMessage) (int64, error) { panic("provider-private-error") }
	f.reset(t)
	coreResult(t, f.execute(ids.New(ids.KindInvocation), `{}`), 200, "failed")
	f.remaining(t, 93)
}
