package nexus_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestLeftSelfOnlyLiveSnapshot(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	store := nexus.NewMemStore()
	svc := nexus.NewService(store, func() time.Time { return now })
	owner := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "fixture@example.com")
	root, err := svc.CreateRoot(ctx, owner, nexus.RootRequest{Title: "root", Scope: []string{"session:delegate", "newtype:run"}, Limits: nexus.Limits{ModelTokens: 100, RuntimeMinutes: 20, SubSessions: 1}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	actor := nexus.SessionPrincipal(owner.AccountID, root.Session.ID)
	child, err := svc.Delegate(ctx, owner, nexus.DelegateRequest{Title: "child", ParentID: root.Delegation.ID, ToSessionID: attachedWorker(t, store, owner.AccountID, now), Limits: nexus.Limits{ModelTokens: 40}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Consume(ctx, actor, root.Delegation.ID, nexus.Limits{ModelTokens: 10}); err != nil {
		t.Fatal(err)
	}
	cursor, err := svc.Cursor(ctx, owner)
	if err != nil {
		t.Fatal(err)
	}
	left, err := svc.Left(ctx, actor, root.Delegation.ID)
	if err != nil || left.ModelTokens != 50 || left.SubSessions != 1 {
		t.Fatalf("%+v %v", left, err)
	}
	after, err := svc.Cursor(ctx, owner)
	if err != nil || after != cursor {
		t.Fatal("balance query wrote ledger or reserved budget")
	}
	if _, err = svc.DelegationInfo(ctx, actor, root.Delegation.ID); !errors.Is(err, nexus.ErrForbidden) {
		t.Fatal("raw certificate exposed", err)
	}
	if _, err = svc.Left(ctx, actor, child.Delegation.ID); !errors.Is(err, nexus.ErrForbidden) {
		t.Fatal("other session visible", err)
	}
	other := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "other@example.com")
	if _, err = svc.Left(ctx, other, root.Delegation.ID); !errors.Is(err, nexus.ErrNotFound) {
		t.Fatal("other account visible", err)
	}
	if _, err = svc.Left(ctx, owner, root.Delegation.ID); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Revoke(ctx, owner, child.Delegation.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err = svc.Left(ctx, nexus.SessionPrincipal(owner.AccountID, child.Session.ID), child.Delegation.ID); err == nil {
		t.Fatal("revoked balance accepted")
	}
	now = now.Add(2 * time.Hour)
	if _, err = svc.Left(ctx, actor, root.Delegation.ID); !errors.Is(err, nexus.ErrExpired) {
		t.Fatal("expired balance accepted", err)
	}
}
