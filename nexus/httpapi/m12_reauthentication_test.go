package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestM12DurableWatcherUsesReauthentication(t *testing.T) {
	f := apiSetup(t, "auto")
	f.cfg.Durable = true
	f.cfg.RecheckInterval = time.Millisecond
	opening := f.cfg.Authenticate
	var opens, checks atomic.Int64
	f.cfg.Authenticate = func(r *http.Request) (nexus.Principal, error) { opens.Add(1); return opening(r) }
	f.cfg.Reauthenticate = func(*http.Request) (nexus.Principal, error) {
		checks.Add(1)
		return nexus.Principal{}, errors.New("fixture revoked")
	}
	f.cfg.RunMetered = func(ctx context.Context, _ string, _ json.RawMessage) (int64, error) {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-time.After(time.Second):
			return 0, errors.New("recheck not used")
		}
	}
	f.reset(t)
	coreResult(t, f.execute(ids.New(ids.KindInvocation), `{}`), 200, "cancelled")
	if opens.Load() != 1 || checks.Load() != 1 {
		t.Fatalf("opening=%d rechecks=%d", opens.Load(), checks.Load())
	}
}
