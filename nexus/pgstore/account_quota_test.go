package pgstore

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

func TestPostgresMonthlyQuotaAtomicRestartAndMonthBoundary(t *testing.T) {
	st := testStore(t)
	ctx := context.Background()
	now := time.Date(2026, 10, 31, 14, 59, 0, 0, time.UTC)
	svc := nexus.NewService(st, func() time.Time { return now })
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "test@example.test")
	root, err := svc.CreateRoot(ctx, user, nexus.RootRequest{Title: "quota", Runner: nexus.Local, Scope: []string{"model:fixture"}, Rules: []nexus.Rule{{Action: "model:fixture", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 30_000_000}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	actor := nexus.SessionPrincipal(user.AccountID, root.Session.ID)
	var won atomic.Int32
	var wg sync.WaitGroup
	started := make(chan ids.Invocation, 32)
	for i := 0; i < 24; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			id := ids.Invocation(ids.New(ids.KindInvocation))
			_, err := svc.PrepareExecution(ctx, actor, nexus.ExecutionState{ID: id, Delegation: root.Delegation.ID, Action: "model:fixture", InputHash: strings.Repeat("a", 64), Budget: 1_000_000, Metered: true}, time.Minute)
			if err != nil {
				t.Error(err)
				return
			}
			_, fresh, err := svc.StartExecution(ctx, actor, id)
			if err == nil && fresh {
				won.Add(1)
				started <- id
			} else if !errors.Is(err, nexus.ErrLimit) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	close(started)
	if won.Load() != 10 {
		t.Fatal(won.Load())
	}
	restarted := nexus.NewService(New(st.Pool()), func() time.Time { return now })
	q, err := restarted.AccountQuota(ctx, user)
	if err != nil || q.Used != 10_000_000 || q.Remaining != 0 {
		t.Fatal(q, err)
	}
	hash := strings.Repeat("b", 64)
	r, _, err := restarted.BeginQuotaRequest(ctx, user, "request-1", "client-1", hash, 1234567)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := restarted.DecideQuotaRequest(ctx, nexus.SystemPrincipal(user.AccountID), r.Month, r.ID, hash, true); err != nil {
		t.Fatal(err)
	}
	var approvals atomic.Int32
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := restarted.DecideQuotaRequest(ctx, nexus.SystemPrincipal(user.AccountID), r.Month, r.ID, hash, true)
			if err == nil {
				approvals.Add(1)
			} else if !errors.Is(err, nexus.ErrConflict) {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if approvals.Load() != 0 {
		t.Fatal("replay applied")
	}
	now = now.Add(time.Minute)
	for id := range started {
		if _, err := restarted.SettleExecution(ctx, nexus.SystemPrincipal(user.AccountID), root.Session.ID, id, "completed", 7); err != nil {
			t.Fatal(err)
		}
		if _, err := restarted.SettleExecution(ctx, nexus.SystemPrincipal(user.AccountID), root.Session.ID, id, "completed", 7); err != nil {
			t.Fatal(err)
		}
	}
	q, err = restarted.AccountQuota(ctx, user)
	if err != nil || q.Month != "2026-11" || q.Used != 0 || q.Increase != 0 || q.Remaining != 10_000_000 {
		t.Fatal(q, err)
	}
	if err := st.View(ctx, func(tx nexus.Tx) error {
		q, err := tx.AccountQuota(user.AccountID, "2026-10")
		if q.Used != 70 || q.Increase != 1234567 {
			t.Fatal(q)
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
}
