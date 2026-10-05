package conformance

import (
	"context"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// RunExecution tests the fixed-cost receipt transaction on every Store backend,
// including retrying wrappers. It does not assert external side-effect exactly-once.
func RunExecution(t *testing.T, open func() nexus.Store) {
	t.Run("execution_receipt", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		root, err := f.svc.CreateRoot(ctx, f.person, nexus.RootRequest{Title: "execution", Scope: []string{"newtype:run"}, Rules: []nexus.Rule{{Action: "tool:*", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 10}})
		must(t, err)
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		id := ids.Invocation(ids.New(ids.KindInvocation))
		hash := strings.Repeat("a", 64)
		var fresh atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ok, e := f.svc.BeginExecution(ctx, actor, root.Delegation.ID, id, "tool:local", hash, 7, false)
				if e != nil {
					t.Error(e)
				}
				if ok {
					fresh.Add(1)
				}
			}()
		}
		wg.Wait()
		if fresh.Load() != 1 {
			t.Fatal("receipt did not execute once", fresh.Load())
		}
		// Restarting the service against the same store must not rerun the receipt.
		restarted := nexus.NewService(f.store, func() time.Time { return f.now })
		ok, err := restarted.BeginExecution(ctx, actor, root.Delegation.ID, id, "tool:local", hash, 7, false)
		must(t, err)
		if ok {
			t.Fatal("restart returned fresh")
		}
		for _, change := range []struct {
			action, hash string
			cost         int64
		}{{"tool:other", hash, 7}, {"tool:local", strings.Repeat("b", 64), 7}, {"tool:local", hash, 8}} {
			ok, err = f.svc.BeginExecution(ctx, actor, root.Delegation.ID, id, change.action, change.hash, change.cost, false)
			wantErr(t, err, nexus.ErrConflict)
			if ok {
				t.Fatal("conflict returned fresh")
			}
		}
		ok, err = f.svc.BeginExecution(ctx, actor, root.Delegation.ID, ids.Invocation(ids.New(ids.KindInvocation)), "tool:local", hash, 4, false)
		wantErr(t, err, nexus.ErrLimit)
		if ok {
			t.Fatal("limit returned fresh")
		}
		info, err := f.svc.DelegationInfo(ctx, f.person, root.Delegation.ID)
		must(t, err)
		if info.Remaining.ModelTokens != 3 {
			t.Fatal("double charged", info.Remaining)
		}
		events, _, err := f.svc.Events(ctx, actor, actor.SessionID, 0, 100)
		must(t, err)
		count := 0
		for _, e := range events {
			if e.Kind == "execution.started" {
				count++
				if e.InvocationID != id {
					t.Fatal(e)
				}
			}
		}
		if count != 1 {
			t.Fatal("duplicate events", count)
		}
	})
	t.Run("execution_authority", func(t *testing.T) {
		for _, mode := range []string{"ask", "deny", "expired", "revoked", "actor", "invalid_hash"} {
			t.Run(mode, func(t *testing.T) {
				f := newFixture(t, open)
				ctx := context.Background()
				effect := "auto"
				if mode == "ask" || mode == "deny" {
					effect = mode
				}
				root, err := f.svc.CreateRoot(ctx, f.person, nexus.RootRequest{Title: "authority", Scope: []string{"newtype:run"}, Rules: []nexus.Rule{{Action: "tool:local", Effect: effect}}, Limits: nexus.Limits{ModelTokens: 10}, TTL: time.Minute})
				must(t, err)
				actor := nexus.SessionPrincipal(f.account, root.Session.ID)
				hash := strings.Repeat("a", 64)
				want := nexus.ErrForbidden
				switch mode {
				case "expired":
					f.now = f.now.Add(time.Minute)
					want = nexus.ErrExpired
				case "revoked":
					_, err = f.svc.Revoke(ctx, f.person, root.Delegation.ID, "")
					must(t, err)
					want = nexus.ErrRevoked
				case "actor":
					actor = f.person
					want = nexus.ErrInvalid
				case "invalid_hash":
					hash = strings.Repeat("z", 64)
					want = nexus.ErrInvalid
				}
				id := ids.Invocation(ids.New(ids.KindInvocation))
				ok, err := f.svc.BeginExecution(ctx, actor, root.Delegation.ID, id, "tool:local", hash, 7, false)
				if !errors.Is(err, want) || ok {
					t.Fatalf("got fresh=%v err=%v, want %v", ok, err, want)
				}
				if mode == "ask" {
					ok, err = f.svc.BeginExecution(ctx, actor, root.Delegation.ID, id, "tool:local", hash, 7, true)
					must(t, err)
					if !ok {
						t.Fatal("trusted approval did not execute")
					}
				}
				if mode == "deny" {
					ok, err = f.svc.BeginExecution(ctx, actor, root.Delegation.ID, id, "tool:local", hash, 7, true)
					wantErr(t, err, nexus.ErrForbidden)
					if ok {
						t.Fatal("approval widened deny")
					}
				}
			})
		}
	})
}
