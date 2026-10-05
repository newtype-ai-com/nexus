package nexus_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestEmptyPolicyRoundTripAndIdempotency(t *testing.T) {
	ctx := context.Background()
	store := nexus.NewMemStore()
	svc := nexus.NewService(store, nil)
	person := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "owner@example.com")
	root, err := svc.CreateRoot(ctx, person, nexus.RootRequest{Title: "root", Scope: []string{"newtype:run", "session:delegate"}, Rules: []nexus.Rule{{Action: "tool:*", Effect: "auto"}}, Limits: nexus.Limits{SubSessions: 1}})
	if err != nil {
		t.Fatal(err)
	}
	child, err := svc.Delegate(ctx, person, nexus.DelegateRequest{Title: "no local rules", ParentID: root.Delegation.ID, ToSessionID: attachedWorker(t, store, person.AccountID, time.Now()), Scope: []string{"newtype:run"}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err := svc.Authorize(ctx, person, child.Delegation.ID, "tool:read_file")
	if err != nil || decision.Effect != "auto" {
		t.Fatal(decision, err)
	}
	err = store.Update(ctx, func(tx nexus.Tx) error { return tx.PutPolicy(child.Policy) })
	if err != nil {
		t.Fatal(err)
	}
	changed := child.Policy
	changed.Approver = "parent"
	err = store.Update(ctx, func(tx nexus.Tx) error { return tx.PutPolicy(changed) })
	if !errors.Is(err, nexus.ErrConflict) {
		t.Fatal(err)
	}
	observer, err := svc.CreateObserver(ctx, person, nexus.RootRequest{Title: "empty rules", Scope: []string{"newtype:run"}})
	if err != nil {
		t.Fatal(err)
	}
	decision, err = svc.Authorize(ctx, person, observer.Delegation.ID, "tool:read_file")
	if err != nil || decision.Effect != "deny" {
		t.Fatal(decision, err)
	}
}
func TestCurrencyConservationAndSessionTransitions(t *testing.T) {
	ctx := context.Background()
	store := nexus.NewMemStore()
	now := time.Now()
	svc := nexus.NewService(store, func() time.Time { return now })
	person := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "owner@example.com")
	root, err := svc.CreateRoot(ctx, person, nexus.RootRequest{Title: "root", Scope: []string{"session:delegate"}, Limits: nexus.Limits{Spend: 100, Currency: "USD", SubSessions: 1}})
	if err != nil {
		t.Fatal(err)
	}
	child, err := svc.Delegate(ctx, person, nexus.DelegateRequest{Title: "child", ParentID: root.Delegation.ID, ToSessionID: attachedWorker(t, store, person.AccountID, time.Now()), Limits: nexus.Limits{Spend: 80}})
	if err != nil {
		t.Fatal(err)
	}
	actor := nexus.SessionPrincipal(person.AccountID, child.Session.ID)
	if child.Delegation.Limits.Currency != "USD" {
		t.Fatal(child)
	}
	_, err = svc.Consume(ctx, actor, child.Delegation.ID, nexus.Limits{Spend: 30, Currency: "EUR"})
	if !errors.Is(err, nexus.ErrInvalid) {
		t.Fatal(err)
	}
	_, err = svc.Consume(ctx, actor, child.Delegation.ID, nexus.Limits{Spend: 30, Currency: "USD"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.Revoke(ctx, person, child.Delegation.ID, "")
	if err != nil {
		t.Fatal(err)
	}
	info, err := svc.DelegationInfo(ctx, person, root.Delegation.ID)
	if err != nil || info.Remaining.Spend != 70 {
		t.Fatal(info, err)
	}
	_, err = svc.Resume(ctx, person, root.Session.ID)
	if !errors.Is(err, nexus.ErrConflict) {
		t.Fatal(err)
	}
	_, err = svc.Suspend(ctx, person, child.Session.ID, "")
	if !errors.Is(err, nexus.ErrConflict) {
		t.Fatal(err)
	}
	_, err = svc.SetSessionStatus(ctx, actor, child.Session.ID, nexus.SessionDone)
	if !errors.Is(err, nexus.ErrForbidden) {
		t.Fatal(err)
	}
	rootActor := nexus.SessionPrincipal(person.AccountID, root.Session.ID)
	_, err = svc.SetSessionStatus(ctx, rootActor, root.Session.ID, nexus.SessionWaiting)
	if err != nil {
		t.Fatal(err)
	}
	cursor, err := svc.Cursor(ctx, person)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.SetSessionStatus(ctx, rootActor, root.Session.ID, nexus.SessionWaiting)
	if err != nil {
		t.Fatal(err)
	}
	after, err := svc.Cursor(ctx, person)
	if err != nil || after != cursor {
		t.Fatal("same status wrote an event", after, cursor, err)
	}
	_, err = svc.SetSessionStatus(ctx, rootActor, root.Session.ID, nexus.SessionStopped)
	if err != nil {
		t.Fatal(err)
	}
	_, err = svc.SetSessionStatus(ctx, rootActor, root.Session.ID, nexus.SessionRunning)
	if err != nil {
		t.Fatal(err)
	}
}
