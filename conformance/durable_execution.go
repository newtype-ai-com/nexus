package conformance

import (
	"context"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func runDurableExecution(t *testing.T, open func() nexus.Store) {
	ctx := context.Background()
	state := func(d nexus.Issued, action string) nexus.ExecutionState {
		return nexus.ExecutionState{ID: ids.Invocation(ids.New(ids.KindInvocation)), Delegation: d.Delegation.ID, Action: action, InputHash: strings.Repeat("a", 64), Budget: 100, Metered: true}
	}
	t.Run("durable_approval_restart_and_isolation", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(rootRequest())
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		x, err := f.svc.PrepareExecution(ctx, actor, state(root, "tool:remove_file"), time.Minute)
		must(t, err)
		if x.Status != "pending" {
			t.Fatal(x)
		}
		_, fresh, err := f.svc.StartExecution(ctx, actor, x.ID)
		must(t, err)
		if fresh {
			t.Fatal("pending executed")
		}
		_, err = f.svc.DecideExecution(ctx, actor, x.ID, x.InputHash, true)
		wantErr(t, err, nexus.ErrForbidden)
		other := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "other@example.com")
		_, err = f.svc.Execution(ctx, other, x.ID)
		wantErr(t, err, nexus.ErrNotFound)
		_, err = f.svc.DecideExecution(ctx, f.person, x.ID, strings.Repeat("b", 64), true)
		wantErr(t, err, nexus.ErrConflict)
		_, err = f.svc.DecideExecution(ctx, f.person, x.ID, x.InputHash, true)
		must(t, err)
		restarted := nexus.NewService(f.store, func() time.Time { return f.now })
		x, err = restarted.Execution(ctx, actor, x.ID)
		must(t, err)
		if x.Status != "approved" {
			t.Fatal(x)
		}
		var starts atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_, fresh, err := restarted.StartExecution(ctx, actor, x.ID)
				if err != nil {
					t.Error(err)
				}
				if fresh {
					starts.Add(1)
				}
			}()
		}
		wg.Wait()
		if starts.Load() != 1 || f.usage(root.Delegation.ID).Consumed.ModelTokens != 100 {
			t.Fatal("duplicate charge/dispatch", starts.Load())
		}
		_, err = restarted.SettleExecution(ctx, actor, actor.SessionID, x.ID, "completed", 25)
		wantErr(t, err, nexus.ErrForbidden)
		x, err = restarted.SettleExecution(ctx, nexus.SystemPrincipal(f.account), actor.SessionID, x.ID, "completed", 25)
		must(t, err)
		if x.Status != "completed" || x.Charged != 25 {
			t.Fatal(x)
		}
		_, err = restarted.SettleExecution(ctx, nexus.SystemPrincipal(f.account), actor.SessionID, x.ID, "failed", 0)
		must(t, err)
		if f.usage(root.Delegation.ID).Consumed.ModelTokens != 25 {
			t.Fatal("settlement not idempotent")
		}
	})
	t.Run("durable_refund_after_ancestry_ended", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(rootRequest())
		child := f.delegate(root, f.childRequest(root, 500))
		actor := nexus.SessionPrincipal(f.account, child.Session.ID)
		x, err := f.svc.PrepareExecution(ctx, actor, state(child, "model:test"), time.Minute)
		must(t, err)
		_, fresh, err := f.svc.StartExecution(ctx, actor, x.ID)
		must(t, err)
		if !fresh {
			t.Fatal("not started")
		}
		_, err = f.svc.Revoke(ctx, f.person, root.Delegation.ID, "")
		must(t, err)
		if f.usage(root.Delegation.ID).Consumed.ModelTokens != 100 {
			t.Fatal("ceiling not propagated")
		}
		_, err = f.svc.CancelExecution(ctx, f.person, x.ID)
		must(t, err)
		x, err = f.svc.SettleExecution(ctx, nexus.SystemPrincipal(f.account), actor.SessionID, x.ID, "completed", 30)
		must(t, err)
		if x.Status != "cancelled" {
			t.Fatal(x)
		}
		for _, id := range []ids.Delegation{root.Delegation.ID, child.Delegation.ID} {
			if f.usage(id).Consumed.ModelTokens != 30 {
				t.Fatal("refund lost", id)
			}
		}
	})
	t.Run("durable_unknown_usage_and_recovery", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(rootRequest())
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		x, err := f.svc.PrepareExecution(ctx, actor, state(root, "model:test"), time.Minute)
		must(t, err)
		_, _, err = f.svc.StartExecution(ctx, actor, x.ID)
		must(t, err)
		restarted := nexus.NewService(f.store, func() time.Time { return f.now })
		x, fresh, err := restarted.StartExecution(ctx, actor, x.ID)
		must(t, err)
		if fresh || x.Status != "running" {
			t.Fatal("unsafe automatic recovery", x)
		}
		x, err = restarted.SettleExecution(ctx, nexus.SystemPrincipal(f.account), actor.SessionID, x.ID, "indeterminate", -1)
		must(t, err)
		if x.Charged != 100 || f.usage(root.Delegation.ID).Consumed.ModelTokens != 100 {
			t.Fatal("unknown usage refunded")
		}
	})
	t.Run("durable_expiry_denial_cancel_and_conflict", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(rootRequest())
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		for _, mode := range []string{"expired", "denied", "cancelled"} {
			x, err := f.svc.PrepareExecution(ctx, actor, state(root, "tool:remove_file"), time.Minute)
			must(t, err)
			switch mode {
			case "expired":
				f.now = f.now.Add(time.Minute)
				_, err = f.svc.DecideExecution(ctx, f.person, x.ID, x.InputHash, true)
				wantErr(t, err, nexus.ErrExpired)
			case "denied":
				_, err = f.svc.DecideExecution(ctx, f.person, x.ID, x.InputHash, false)
				must(t, err)
			case "cancelled":
				_, err = f.svc.CancelExecution(ctx, actor, x.ID)
				must(t, err)
			}
			current, err := f.svc.Execution(ctx, actor, x.ID)
			must(t, err)
			if current.Status != mode {
				t.Fatal(current)
			}
			_, fresh, err := f.svc.StartExecution(ctx, actor, x.ID)
			must(t, err)
			if fresh {
				t.Fatal("terminal/pending dispatched")
			}
			changed := x
			changed.InputHash = strings.Repeat("b", 64)
			_, err = f.svc.PrepareExecution(ctx, actor, changed, time.Minute)
			wantErr(t, err, nexus.ErrConflict)
		}
		if f.usage(root.Delegation.ID).Consumed.ModelTokens != 0 {
			t.Fatal("nonexecution charged")
		}
	})
	t.Run("durable_adapter_switch_never_replays", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(rootRequest())
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		x := state(root, "model:test")
		_, err := f.svc.BeginExecution(ctx, actor, x.Delegation, x.ID, x.Action, x.InputHash, x.Budget, false)
		must(t, err)
		_, err = f.svc.PrepareExecution(ctx, actor, x, time.Minute)
		wantErr(t, err, nexus.ErrConflict)
		x = state(root, "model:test")
		_, err = f.svc.PrepareExecution(ctx, actor, x, time.Minute)
		must(t, err)
		_, err = f.svc.BeginExecution(ctx, actor, x.Delegation, x.ID, x.Action, x.InputHash, x.Budget, false)
		wantErr(t, err, nexus.ErrConflict)
	})
}
