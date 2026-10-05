package nexus_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"testing"
	"time"
)

func attachedWorker(t *testing.T, store nexus.Store, account ids.Account, now time.Time) ids.Session {
	t.Helper()
	s := nexus.Session{ID: ids.Session(ids.New(ids.KindSession)), AccountID: account, Kind: nexus.Worker, Runner: nexus.Local, Title: "attached fixture", Status: nexus.SessionWaiting, CreatedAt: now, UpdatedAt: now, SeenAt: now}
	if err := store.Update(nexus.WithAccount(context.Background(), account), func(tx nexus.Tx) error { return tx.PutSession(s) }); err != nil {
		t.Fatal(err)
	}
	return s.ID
}

func TestM16NoRunnerNoMutationAndLiveTarget(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	store := nexus.NewMemStore()
	svc := nexus.NewService(store, func() time.Time { return now })
	person := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "fixture@example.test")
	root, err := svc.CreateRoot(ctx, person, nexus.RootRequest{Title: "root", Scope: []string{"session:delegate"}, Limits: nexus.Limits{ModelTokens: 100, SubSessions: 3}})
	if err != nil {
		t.Fatal(err)
	}
	snapshot := func() string {
		var out string
		if err := store.View(ctx, func(tx nexus.Tx) error {
			sessions, _ := tx.SessionsByAccount(person.AccountID)
			tasks, _ := tx.TasksByParent(root.Task.ID)
			children, _ := tx.DelegationsByParent(root.Delegation.ID)
			usage, _ := tx.Usage(root.Delegation.ID)
			cursor, _ := tx.Cursor(person.AccountID)
			out = fmt.Sprintf("%v/%v/%v/%v/%v", sessions, tasks, children, usage, cursor)
			return nil
		}); err != nil {
			t.Fatal(err)
		}
		return out
	}
	for _, runner := range []nexus.Runner{"", nexus.Local, nexus.Container} {
		before := snapshot()
		_, err := svc.Delegate(ctx, person, nexus.DelegateRequest{ParentID: root.Delegation.ID, Title: "child", Runner: runner, Limits: nexus.Limits{ModelTokens: 10, SubSessions: 1}})
		if !errors.Is(err, nexus.ErrRunnerUnavailable) || before != snapshot() {
			t.Fatalf("orphan/charge: %v", err)
		}
	}
	target := attachedWorker(t, store, person.AccountID, now)
	req := nexus.DelegateRequest{ParentID: root.Delegation.ID, ToSessionID: target, Title: "child", Limits: nexus.Limits{ModelTokens: 10, SubSessions: 1}}
	child, err := svc.Delegate(ctx, person, req)
	if err != nil || child.Session.ID != target {
		t.Fatal(child, err)
	}
	var usage nexus.Usage
	_ = store.View(ctx, func(tx nexus.Tx) error { usage, err = tx.Usage(root.Delegation.ID); return err })
	if usage.Reserved.ModelTokens != 10 || usage.Reserved.SubSessions != 1 || usage.Consumed.SubSessions != 0 {
		t.Fatal(usage)
	}
	now = now.Add(nexus.PresenceGrace)
	before := snapshot()
	if _, err = svc.Delegate(ctx, person, req); !errors.Is(err, nexus.ErrRunnerUnavailable) || before != snapshot() {
		t.Fatal("stale target accepted/mutated", err)
	}
}
