// Package conformance supplies reusable phase-one Store and Service tests.
package conformance

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// Retrying simulates a serializable conflict after a successful callback.
// The first attempt is rolled back, and its captured output must be discarded.
type Retrying struct{ nexus.Store }

func (r Retrying) Close() {
	if c, ok := r.Store.(interface{ Close() }); ok {
		c.Close()
	}
}

var errRetry = errors.New("conformance: retry")

func (r Retrying) Update(ctx context.Context, fn func(nexus.Tx) error) error {
	err := r.Store.Update(ctx, func(tx nexus.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		return errRetry
	})
	if !errors.Is(err, errRetry) {
		return err
	}
	return r.Store.Update(ctx, fn)
}

type fixture struct {
	t       *testing.T
	store   nexus.Store
	svc     *nexus.Service
	now     time.Time
	account ids.Account
	person  nexus.Principal
}

func newFixture(t *testing.T, open func() nexus.Store) *fixture {
	f := &fixture{t: t, store: open(), now: time.Date(2026, 9, 30, 0, 0, 0, 0, time.UTC), account: ids.Account(ids.New(ids.KindAccount))}
	// Factories may register schema cleanup on the parent suite. Close each
	// fixture's pool at subtest completion rather than accumulating idle pools.
	if c, ok := f.store.(interface{ Close() }); ok {
		t.Cleanup(c.Close)
	}
	f.person = nexus.UserPrincipal(f.account, "owner@example.com")
	f.svc = nexus.NewService(f.store, func() time.Time { return f.now })
	return f
}
func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}
func wantErr(t *testing.T, err, want error) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("got %v want %v", err, want)
	}
}
func (f *fixture) seed(parent *nexus.Delegation, scope ...string) (nexus.Session, nexus.Delegation) {
	f.t.Helper()
	sid := ids.Session(ids.New(ids.KindSession))
	tid := ids.Task(ids.New(ids.KindTask))
	did := ids.Delegation(ids.New(ids.KindDelegation))
	session := nexus.Session{ID: sid, AccountID: f.account, Kind: nexus.Worker, Runner: nexus.Local, Title: "worker", Status: nexus.SessionRunning, EntryTaskID: tid, CreatedAt: f.now, UpdatedAt: f.now}
	task := nexus.Task{ID: tid, AccountID: f.account, RootID: tid, Assignee: sid, DelegationID: did, Kind: "request", Status: "in_progress"}
	grant := nexus.Delegation{ID: did, AccountID: f.account, Principal: f.person, Delegator: f.person, Delegate: sid, Task: tid, RootID: did, Scope: scope, IssuedAt: f.now, ExpiresAt: f.now.Add(time.Hour)}
	if parent != nil {
		task.ParentID = parent.Task
		task.RootID = parent.Task
		grant.ParentID = parent.ID
		grant.RootID = parent.RootID
		grant.Depth = parent.Depth + 1
	}
	must(f.t, f.store.Update(context.Background(), func(tx nexus.Tx) error {
		if err := tx.PutSession(session); err != nil {
			return err
		}
		if err := tx.PutTask(task); err != nil {
			return err
		}
		return tx.PutDelegation(grant)
	}))
	return session, grant
}
func (f *fixture) append(actor nexus.Principal, session ids.Session, input nexus.EventInput) nexus.Event {
	f.t.Helper()
	events, err := f.svc.AppendEvents(context.Background(), actor, session, []nexus.EventInput{input})
	must(f.t, err)
	if len(events) != 1 {
		f.t.Fatal("retried result duplicated", len(events))
	}
	return events[0]
}
func (f *fixture) grant(session ids.Session, scope ...string) {
	d := nexus.Delegation{ID: ids.Delegation(ids.New(ids.KindDelegation)), AccountID: f.account, Delegate: session, Scope: scope, ExpiresAt: f.now.Add(time.Hour)}
	d.RootID = d.ID
	must(f.t, f.store.Update(context.Background(), func(tx nexus.Tx) error { return tx.PutDelegation(d) }))
}

// Run is the common suite for memory, retrying-memory and future Postgres.
func Run(t *testing.T, open func() nexus.Store) {
	runDurableExecution(t, open)
	RunExecution(t, open)
	runTaskManagement(t, open)
	runMessagesPresence(t, open)
	runSharedPresence(t, open)
	runMessageReceipts(t, open)
	runMessageTasks(t, open)
	runInboxTests(t, open)
	runBoundaryTests(t, open)
	runMandateTests(t, open)
	runCustody(t, open)
	runExecutionGrants(t, open)
	runSecrets(t, open)
	runSecretPlans(t, open)
	runSecretPlanBindings(t, open)
	runSecretPlanV3(t, open)
	runReceipts(t, open)
	runTeams(t, open)
	t.Run("store_atomicity_and_copy", func(t *testing.T) {
		f := newFixture(t, open)
		s, d := f.seed(nil, "newtype:run")
		policy := nexus.Policy{ID: ids.Policy(ids.New(ids.KindPolicy)), AccountID: f.account, Version: 1, Rules: []nexus.Rule{{Action: "tool:*", Effect: "auto"}}}
		must(t, f.store.Update(context.Background(), func(tx nexus.Tx) error { return tx.PutPolicy(policy) }))
		policy.Rules[0].Effect = "deny"
		must(t, f.store.View(context.Background(), func(tx nexus.Tx) error {
			wantErr(t, tx.PutSession(s), nexus.ErrInvalid)
			p, err := tx.Policy(policy.ID, 1)
			if err != nil {
				return err
			}
			if p.Rules[0].Effect != "auto" {
				t.Fatal("input slice leaked")
			}
			p.Rules[0].Effect = "ask"
			x, err := tx.Delegation(d.ID)
			if err != nil {
				return err
			}
			x.Scope[0] = "purchase"
			u, err := tx.Usage(d.ID)
			if err != nil {
				return err
			}
			if u != (nexus.Usage{}) {
				t.Fatal(u)
			}
			roots, err := tx.TasksByParent("")
			if err != nil {
				return err
			}
			if len(roots) != 0 {
				t.Fatal("empty parent lists roots")
			}
			return nil
		}))
		must(t, f.store.View(context.Background(), func(tx nexus.Tx) error {
			p, err := tx.Policy(policy.ID, 1)
			if err != nil {
				return err
			}
			if p.Rules[0].Effect != "auto" {
				t.Fatal("read slice leaked")
			}
			x, err := tx.Delegation(d.ID)
			if err != nil {
				return err
			}
			if x.Scope[0] != "newtype:run" {
				t.Fatal("grant slice leaked")
			}
			return nil
		}))
		wantErr(t, f.store.Update(context.Background(), func(tx nexus.Tx) error { return tx.PutPolicy(policy) }), nexus.ErrConflict)
		rollback := errors.New("rollback")
		wantErr(t, f.store.Update(context.Background(), func(tx nexus.Tx) error {
			s.Title = "changed"
			if err := tx.PutSession(s); err != nil {
				return err
			}
			_, err := tx.AppendEvent(nexus.Event{ID: ids.Event(ids.New(ids.KindEvent)), AccountID: f.account, SessionID: s.ID, Payload: []byte(`null`)})
			if err != nil {
				return err
			}
			return rollback
		}), rollback)
		must(t, f.store.View(context.Background(), func(tx nexus.Tx) error {
			got, err := tx.Session(s.ID)
			if err != nil {
				return err
			}
			if got.Title == "changed" {
				t.Fatal("rollback leaked session")
			}
			events, err := tx.Events(s.ID, 0, 0)
			if err != nil {
				return err
			}
			if len(events) != 0 {
				t.Fatal("rollback leaked events")
			}
			cur, err := tx.Cursor(f.account)
			if cur != 0 {
				t.Fatal("rollback burned cursor")
			}
			return err
		}))
	})
	t.Run("ledger_idempotency_atomicity_notify", func(t *testing.T) {
		f := newFixture(t, open)
		s, _ := f.seed(nil, "newtype:run")
		actor := nexus.SessionPrincipal(f.account, s.ID)
		changed := f.svc.Changed()
		input := nexus.EventInput{Kind: "note", ClientEventID: "one", Payload: []byte(`{"n":9007199254740993}`)}
		first := f.append(actor, s.ID, input)
		select {
		case <-changed:
		default:
			t.Fatal("commit did not notify")
		}
		second := f.append(actor, s.ID, input)
		if first.ID != second.ID || first.Seq != second.Seq {
			t.Fatal("idempotency failed")
		}
		changed = f.svc.Changed()
		input.Payload = []byte(`{"n":2}`)
		_, err := f.svc.AppendEvents(context.Background(), actor, s.ID, []nexus.EventInput{input})
		wantErr(t, err, nexus.ErrConflict)
		select {
		case <-changed:
			t.Fatal("failed write notified")
		default:
		}
		_, err = f.svc.AppendEvents(context.Background(), actor, s.ID, []nexus.EventInput{{Kind: "ok"}, {Kind: "bad", Payload: []byte(`{`)}})
		wantErr(t, err, nexus.ErrInvalid)
		events, next, err := f.svc.Events(context.Background(), actor, s.ID, 0, 0)
		must(t, err)
		if len(events) != 1 || next != 1 {
			t.Fatal("batch leaked", len(events), next)
		}
		if !strings.Contains(string(events[0].Payload), "9007199254740993") {
			t.Fatal("number rounded")
		}
		events[0].Payload[0] = 'x'
		events, _, err = f.svc.Events(context.Background(), actor, s.ID, 0, 0)
		must(t, err)
		if events[0].Payload[0] == 'x' {
			t.Fatal("event read alias")
		}
	})
	t.Run("gapless_under_concurrency", func(t *testing.T) {
		f := newFixture(t, open)
		s, _ := f.seed(nil, "newtype:run")
		actor := nexus.SessionPrincipal(f.account, s.ID)
		var wg sync.WaitGroup
		errs := make(chan error, 200)
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				for j := 0; j < 25; j++ {
					_, err := f.svc.AppendEvents(context.Background(), actor, s.ID, []nexus.EventInput{{Kind: "note", ClientEventID: fmt.Sprintf("%d:%d", i, j)}})
					if err != nil {
						errs <- err
					}
				}
			}(i)
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			t.Error(err)
		}
		events, next, err := f.svc.Events(context.Background(), f.person, s.ID, 0, 1000)
		must(t, err)
		if len(events) != 200 || next != 200 {
			t.Fatalf("%d/%d", len(events), next)
		}
		seen := map[ids.Event]bool{}
		for i, e := range events {
			if e.Seq != int64(i+1) || e.Cursor != int64(i+1) || seen[e.ID] {
				t.Fatalf("gap/duplicate at %d", i)
			}
			seen[e.ID] = true
		}
		events, next, err = f.svc.Events(context.Background(), actor, s.ID, 100, 10)
		must(t, err)
		if len(events) != 10 || events[0].Seq != 101 || next != 110 {
			t.Fatal("pagination")
		}
	})
	t.Run("visibility_and_feed_cursor", func(t *testing.T) {
		f := newFixture(t, open)
		a, da := f.seed(nil, "newtype:run")
		b, _ := f.seed(nil, "newtype:run")
		child, _ := f.seed(&da, "newtype:run")
		actor := nexus.SessionPrincipal(f.account, a.ID)
		f.append(f.person, b.ID, nexus.EventInput{Kind: "turn.user", Source: "user"})
		f.append(f.person, child.ID, nexus.EventInput{Kind: "turn.user", Source: "user"})
		progress := f.append(nexus.SystemPrincipal(f.account), child.ID, nexus.EventInput{Kind: "task.status", Source: "hub"})
		_, _, err := f.svc.Events(context.Background(), actor, b.ID, 0, 0)
		wantErr(t, err, nexus.ErrForbidden)
		_, _, err = f.svc.Events(context.Background(), actor, child.ID, 0, 0)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.Session(context.Background(), actor, child.ID)
		must(t, err)
		_, err = f.svc.Session(context.Background(), actor, b.ID)
		wantErr(t, err, nexus.ErrForbidden)
		events, next, err := f.svc.Feed(context.Background(), actor, 0, 100)
		must(t, err)
		if len(events) != 1 || events[0].ID != progress.ID || next != 3 {
			t.Fatalf("feed %v %d", events, next)
		}
		_, err = f.svc.Sessions(context.Background(), actor)
		wantErr(t, err, nexus.ErrForbidden)
		f.grant(a.ID, "observe:progress")
		sessions, err := f.svc.Sessions(context.Background(), actor)
		must(t, err)
		if len(sessions) != 3 {
			t.Fatal(len(sessions))
		}
		events, next, err = f.svc.Feed(context.Background(), actor, 0, 100)
		must(t, err)
		if len(events) != 1 || next != 3 {
			t.Fatal("progress exposed transcript")
		}
		f.grant(a.ID, "read:transcript")
		events, _, err = f.svc.Events(context.Background(), actor, b.ID, 0, 100)
		must(t, err)
		if len(events) != 1 {
			t.Fatal(len(events))
		}
		events, next, err = f.svc.Feed(context.Background(), actor, 0, 100)
		must(t, err)
		if len(events) != 3 || next != 3 {
			t.Fatal("full observer missing events")
		}
	})
	t.Run("isolation_actor_and_task_tags", func(t *testing.T) {
		f := newFixture(t, open)
		a, _ := f.seed(nil, "newtype:run")
		b, db := f.seed(nil, "newtype:run")
		actor := nexus.SessionPrincipal(f.account, a.ID)
		_, err := f.svc.AppendEvents(context.Background(), actor, b.ID, []nexus.EventInput{{Kind: "note"}})
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.AppendEvents(context.Background(), actor, a.ID, []nexus.EventInput{{Kind: "note", TaskID: db.Task}})
		wantErr(t, err, nexus.ErrForbidden)
		other := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "other@example.com")
		_, _, err = f.svc.Events(context.Background(), other, a.ID, 0, 100)
		wantErr(t, err, nexus.ErrNotFound)
		_, err = f.svc.Session(context.Background(), other, a.ID)
		wantErr(t, err, nexus.ErrNotFound)
		sessions, err := f.svc.Sessions(context.Background(), other)
		must(t, err)
		if len(sessions) != 0 {
			t.Fatal("account leak")
		}
		for _, bad := range []nexus.Principal{{}, {Kind: "bad", AccountID: f.account}, {Kind: nexus.PrincipalSession, AccountID: f.account}} {
			_, err := f.svc.Sessions(context.Background(), bad)
			wantErr(t, err, nexus.ErrForbidden)
		}
		_, err = f.svc.AppendEvents(context.Background(), actor, a.ID, []nexus.EventInput{{Kind: "fake", Source: "hub"}})
		wantErr(t, err, nexus.ErrForbidden)
	})
	t.Run("ancestry_revocation_expiry_suspension", func(t *testing.T) {
		f := newFixture(t, open)
		a, da := f.seed(nil, "newtype:run")
		b, _ := f.seed(&da, "newtype:run")
		actor := nexus.SessionPrincipal(f.account, b.ID)
		f.append(actor, b.ID, nexus.EventInput{Kind: "before"})
		ended := f.now
		da.EndedAt = &ended
		must(t, f.store.Update(context.Background(), func(tx nexus.Tx) error { return tx.PutDelegation(da) }))
		_, err := f.svc.AppendEvents(context.Background(), actor, b.ID, []nexus.EventInput{{Kind: "after"}})
		wantErr(t, err, nexus.ErrRevoked)
		da.EndedAt = nil
		must(t, f.store.Update(context.Background(), func(tx nexus.Tx) error { return tx.PutDelegation(da) }))
		f.now = f.now.Add(2 * time.Hour)
		_, err = f.svc.AppendEvents(context.Background(), actor, b.ID, []nexus.EventInput{{Kind: "expired"}})
		wantErr(t, err, nexus.ErrRevoked)
		f.now = f.now.Add(-2 * time.Hour)
		a.Status = nexus.SessionSuspended
		must(t, f.store.Update(context.Background(), func(tx nexus.Tx) error { return tx.PutSession(a) }))
		_, err = f.svc.AppendEvents(context.Background(), nexus.SessionPrincipal(f.account, a.ID), a.ID, []nexus.EventInput{{Kind: "suspended"}})
		wantErr(t, err, nexus.ErrForbidden)
	})
}
