package conformance

import (
	"context"
	"errors"
	"math"
	"math/rand"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func rootRequest() nexus.RootRequest {
	return nexus.RootRequest{Title: "root", Runner: nexus.Local, Scope: []string{"newtype:run", "session:delegate", "model:*", "purchase", "send:internal"}, Rules: []nexus.Rule{{Action: "tool:*", Effect: "auto"}, {Action: "tool:remove_file", Effect: "ask"}, {Action: "purchase", Effect: "ask"}, {Action: "model:*", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 10000, SubSessions: 100, MaxDepth: 4}}
}

// Seed an already attached worker, not a runner-created child. No independent
// root mandate masks revocation/settlement of the delegated work under test.
func (f *fixture) childRequest(parent nexus.Issued, tokens int64) nexus.DelegateRequest {
	f.t.Helper()
	session := nexus.Session{ID: ids.Session(ids.New(ids.KindSession)), AccountID: f.account, Kind: nexus.Worker, Runner: nexus.Local, Title: "attached worker", Status: nexus.SessionWaiting, CreatedAt: f.now, UpdatedAt: f.now, SeenAt: f.now}
	must(f.t, f.store.Update(context.Background(), func(tx nexus.Tx) error { return tx.PutSession(session) }))
	return nexus.DelegateRequest{ParentID: parent.Delegation.ID, ToSessionID: session.ID, Title: "child", Runner: nexus.Local, Scope: parent.Delegation.Scope, Limits: nexus.Limits{ModelTokens: tokens, SubSessions: 10}}
}
func (f *fixture) issue(req nexus.RootRequest) nexus.Issued {
	f.t.Helper()
	out, err := f.svc.CreateRoot(context.Background(), f.person, req)
	must(f.t, err)
	must(f.t, f.svc.Touch(context.Background(), nexus.SessionPrincipal(f.account, out.Session.ID)))
	return out
}
func (f *fixture) delegate(parent nexus.Issued, req nexus.DelegateRequest) nexus.Issued {
	f.t.Helper()
	out, err := f.svc.Delegate(context.Background(), nexus.SessionPrincipal(f.account, parent.Session.ID), req)
	must(f.t, err)
	return out
}
func (f *fixture) usage(id ids.Delegation) nexus.Usage {
	f.t.Helper()
	var out nexus.Usage
	must(f.t, f.store.View(context.Background(), func(tx nexus.Tx) error { var err error; out, err = tx.Usage(id); return err }))
	return out
}
func (f *fixture) decision(d nexus.Issued, action, effect, approver string) {
	f.t.Helper()
	got, err := f.svc.Authorize(context.Background(), nexus.SessionPrincipal(f.account, d.Session.ID), d.Delegation.ID, action)
	must(f.t, err)
	if got.Effect != effect || got.Approver != approver {
		f.t.Fatalf("%s: %+v want %s/%s", action, got, effect, approver)
	}
}
func runMandateTests(t *testing.T, open func() nexus.Store) {
	runM16(t, open)
	ctx := context.Background()
	t.Run("m16_no_runner_no_mutation", func(t *testing.T) {
		f := newFixture(t, open)
		r := f.issue(rootRequest())
		before := f.usage(r.Delegation.ID)
		cursor, err := f.svc.Cursor(ctx, f.person)
		must(t, err)
		for _, runner := range []nexus.Runner{"", nexus.Local, nexus.Container} {
			_, err := f.svc.Delegate(ctx, f.person, nexus.DelegateRequest{ParentID: r.Delegation.ID, Title: "orphan", Runner: runner, Limits: nexus.Limits{ModelTokens: 1, SubSessions: 1}})
			wantErr(t, err, nexus.ErrRunnerUnavailable)
		}
		after, err := f.svc.Cursor(ctx, f.person)
		must(t, err)
		if before != f.usage(r.Delegation.ID) || cursor != after {
			t.Fatal("rejection mutated accounting/events")
		}
		must(t, f.store.View(ctx, func(tx nexus.Tx) error {
			sessions, err := tx.SessionsByAccount(f.account)
			if err != nil {
				return err
			}
			children, err := tx.DelegationsByParent(r.Delegation.ID)
			if err != nil {
				return err
			}
			tasks, err := tx.TasksByParent(r.Task.ID)
			if len(sessions) != 1 || len(children) != 0 || len(tasks) != 0 {
				t.Fatal("orphan created")
			}
			return err
		}))
	})
	t.Run("mandate_nonamplification", func(t *testing.T) {
		f := newFixture(t, open)
		r := f.issue(rootRequest())
		req := f.childRequest(r, 5000)
		req.Rules = []nexus.Rule{{Action: "purchase", Effect: "auto"}, {Action: "tool:remove_file", Effect: "auto"}, {Action: "tool:shell", Effect: "deny"}, {Action: "send:external", Effect: "auto"}}
		c := f.delegate(r, req)
		f.decision(c, "purchase", "ask", "user")
		f.decision(c, "tool:remove_file", "ask", "user")
		f.decision(c, "tool:shell", "deny", "")
		f.decision(c, "tool:read_file", "auto", "")
		f.decision(c, "secret:place", "deny", "")
		f.decision(c, "send:external", "deny", "")
		req = f.childRequest(c, 1)
		req.Scope = []string{"connector:gmail"}
		_, err := f.svc.Delegate(ctx, nexus.SessionPrincipal(f.account, c.Session.ID), req)
		wantErr(t, err, nexus.ErrForbidden)
		before := f.usage(r.Delegation.ID)
		req = f.childRequest(r, 1)
		req.Limits.SubSessions = math.MaxInt64
		_, err = f.svc.Delegate(ctx, f.person, req)
		wantErr(t, err, nexus.ErrLimit)
		if f.usage(r.Delegation.ID) != before {
			t.Fatal("overflow reservation changed budget")
		}
		_, err = f.svc.Authorize(ctx, nexus.SessionPrincipal(f.account, c.Session.ID), r.Delegation.ID, "tool:read_file")
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.Consume(ctx, nexus.SessionPrincipal(f.account, c.Session.ID), r.Delegation.ID, nexus.Limits{ModelTokens: 1})
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.Delegate(ctx, nexus.SessionPrincipal(f.account, c.Session.ID), f.childRequest(r, 1))
		wantErr(t, err, nexus.ErrForbidden)
		other := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "other@example.com")
		_, err = f.svc.Delegate(ctx, other, f.childRequest(r, 1))
		wantErr(t, err, nexus.ErrNotFound)
		_, err = f.svc.Revoke(ctx, other, r.Delegation.ID, "")
		wantErr(t, err, nexus.ErrNotFound)
		_, err = f.svc.DelegationInfo(ctx, nexus.SessionPrincipal(f.account, r.Session.ID), r.Delegation.ID)
		wantErr(t, err, nexus.ErrForbidden)
	})
	t.Run("mandate_depth_ttl_validation", func(t *testing.T) {
		f := newFixture(t, open)
		for _, mutate := range []func(*nexus.RootRequest){func(r *nexus.RootRequest) { r.TTL = -1 }, func(r *nexus.RootRequest) { r.TTL = 40 * 24 * time.Hour }, func(r *nexus.RootRequest) { r.Limits.ModelTokens = -1 }, func(r *nexus.RootRequest) { r.Limits.Spend = 1 }, func(r *nexus.RootRequest) { r.Title = " " }, func(r *nexus.RootRequest) { r.Scope = []string{"unknown"} }, func(r *nexus.RootRequest) { r.Rules = []nexus.Rule{{Action: "tool:*x", Effect: "auto"}} }} {
			req := rootRequest()
			mutate(&req)
			_, err := f.svc.CreateRoot(ctx, f.person, req)
			wantErr(t, err, nexus.ErrInvalid)
		}
		req := rootRequest()
		req.TTL = 24 * time.Hour
		r := f.issue(req)
		parent := r
		for depth := 1; depth <= 4; depth++ {
			req := f.childRequest(parent, 1)
			req.Limits.SubSessions = int64(10 - depth)
			req.TTL = 30 * 24 * time.Hour
			c := f.delegate(parent, req)
			if c.Delegation.Depth != depth || c.Delegation.Limits.MaxDepth != 4-depth || !c.Delegation.ExpiresAt.Equal(r.Delegation.ExpiresAt) {
				t.Fatal(c.Delegation)
			}
			parent = c
		}
		_, err := f.svc.Delegate(ctx, f.person, f.childRequest(parent, 0))
		wantErr(t, err, nexus.ErrLimit)
	})
	t.Run("mandate_concurrent_carveout", func(t *testing.T) {
		f := newFixture(t, open)
		req := rootRequest()
		req.Limits.ModelTokens = 1000
		r := f.issue(req)
		var successes atomic.Int64
		var wg sync.WaitGroup
		for i := 0; i < 24; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := f.childRequest(r, 100)
				req.Limits.SubSessions = 0
				_, err := f.svc.Delegate(ctx, f.person, req)
				if err == nil {
					successes.Add(1)
				} else if !errors.Is(err, nexus.ErrLimit) {
					t.Errorf("unexpected %v", err)
				}
			}()
		}
		wg.Wait()
		u := f.usage(r.Delegation.ID)
		if successes.Load() != 10 || u.Reserved.ModelTokens != 1000 || u.Consumed.SubSessions != 0 {
			t.Fatal(successes.Load(), u)
		}
		_, err := f.svc.Consume(ctx, nexus.SessionPrincipal(f.account, r.Session.ID), r.Delegation.ID, nexus.Limits{ModelTokens: 1})
		wantErr(t, err, nexus.ErrLimit)
	})
	t.Run("mandate_nested_settlement_and_revoke_rights", func(t *testing.T) {
		f := newFixture(t, open)
		r := f.issue(rootRequest())
		c := f.delegate(r, f.childRequest(r, 5000))
		req := f.childRequest(c, 1000)
		req.Limits.SubSessions = 0
		leaf := f.delegate(c, req)
		_, err := f.svc.Consume(ctx, nexus.SessionPrincipal(f.account, c.Session.ID), c.Delegation.ID, nexus.Limits{ModelTokens: 700})
		must(t, err)
		_, err = f.svc.Consume(ctx, nexus.SessionPrincipal(f.account, leaf.Session.ID), leaf.Delegation.ID, nexus.Limits{ModelTokens: 300})
		must(t, err)
		for _, actor := range []nexus.Principal{nexus.SessionPrincipal(f.account, c.Session.ID), nexus.SessionPrincipal(f.account, leaf.Session.ID)} {
			_, err = f.svc.Revoke(ctx, actor, c.Delegation.ID, "")
			wantErr(t, err, nexus.ErrForbidden)
		}
		ended, err := f.svc.Revoke(ctx, nexus.SessionPrincipal(f.account, r.Session.ID), c.Delegation.ID, "cancel")
		must(t, err)
		if len(ended) != 2 {
			t.Fatal(ended)
		}
		u := f.usage(r.Delegation.ID)
		if u.Reserved.ModelTokens != 0 || u.Reserved.SubSessions != 0 || u.Consumed.ModelTokens != 1000 || u.Consumed.SubSessions != 0 {
			t.Fatal(u)
		}
		for _, x := range []nexus.Issued{c, leaf} {
			_, err = f.svc.Authorize(ctx, nexus.SessionPrincipal(f.account, x.Session.ID), x.Delegation.ID, "tool:read_file")
			wantErr(t, err, nexus.ErrRevoked)
			session, err := f.svc.Session(ctx, f.person, x.Session.ID)
			must(t, err)
			if session.Status != nexus.SessionStopped {
				t.Fatal(session)
			}
			must(t, f.store.View(ctx, func(tx nexus.Tx) error {
				task, err := tx.Task(x.Task.ID)
				if task.Status != "cancelled" {
					t.Error(task)
				}
				return err
			}))
		}
		ended, err = f.svc.Revoke(ctx, f.person, c.Delegation.ID, "")
		must(t, err)
		if len(ended) != 0 {
			t.Fatal(ended)
		}
		f.decision(r, "tool:read_file", "auto", "")
	})
	t.Run("mandate_expiry_rollback_and_sweep", func(t *testing.T) {
		f := newFixture(t, open)
		r := f.issue(rootRequest())
		req := f.childRequest(r, 5000)
		req.TTL = time.Hour
		c := f.delegate(r, req)
		f.now = f.now.Add(2 * time.Hour)
		_, err := f.svc.Authorize(ctx, nexus.SessionPrincipal(f.account, c.Session.ID), c.Delegation.ID, "tool:read_file")
		wantErr(t, err, nexus.ErrExpired)
		before := f.usage(r.Delegation.ID)
		req = f.childRequest(r, 10001)
		_, err = f.svc.Delegate(ctx, f.person, req)
		wantErr(t, err, nexus.ErrLimit)
		if before != f.usage(r.Delegation.ID) {
			t.Fatal("failed reservation committed sweep")
		}
		f.delegate(r, f.childRequest(r, 6000))
		u := f.usage(r.Delegation.ID)
		if u.Reserved.ModelTokens != 6000 {
			t.Fatal(u)
		}
		must(t, f.store.View(ctx, func(tx nexus.Tx) error {
			d, err := tx.Delegation(c.Delegation.ID)
			if d.EndReason != "expired" {
				t.Error(d)
			}
			return err
		}))
	})
	t.Run("mandate_complete_suspend_reuse_observe", func(t *testing.T) {
		f := newFixture(t, open)
		r := f.issue(rootRequest())
		c := f.delegate(r, f.childRequest(r, 5000))
		req := f.childRequest(c, 1000)
		req.Limits.SubSessions = 0
		leaf := f.delegate(c, req)
		_, err := f.svc.Suspend(ctx, nexus.SystemPrincipal(f.account), r.Session.ID, "review")
		must(t, err)
		f.decision(r, "tool:read_file", "deny", "")
		_, err = f.svc.Delegate(ctx, f.person, f.childRequest(r, 1))
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.Resume(ctx, nexus.SystemPrincipal(f.account), r.Session.ID)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.Resume(ctx, f.person, r.Session.ID)
		must(t, err)
		f.decision(r, "tool:read_file", "auto", "")
		_, err = f.svc.SetTaskStatus(ctx, nexus.SessionPrincipal(f.account, c.Session.ID), c.Task.ID, "done")
		must(t, err)
		for _, pair := range []struct {
			x    nexus.Issued
			want nexus.SessionStatus
		}{{c, nexus.SessionDone}, {leaf, nexus.SessionStopped}} {
			got, err := f.svc.Session(ctx, f.person, pair.x.Session.ID)
			must(t, err)
			if got.Status != pair.want {
				t.Fatal(got, pair.want)
			}
		}
		_, err = f.svc.SetTaskStatus(ctx, f.person, c.Task.ID, "in_progress")
		wantErr(t, err, nexus.ErrConflict)
		_, err = f.svc.SetSessionStatus(ctx, f.person, c.Session.ID, nexus.SessionRunning)
		wantErr(t, err, nexus.ErrConflict)
		rr := rootRequest()
		rr.ToSessionID = c.Session.ID
		reused := f.issue(rr)
		if reused.Session.ID != c.Session.ID || reused.Session.Status != nexus.SessionRequested {
			t.Fatal(reused)
		}
		observerReq := nexus.RootRequest{Title: "watch", Scope: []string{"observe:progress"}, TaskID: r.Task.ID}
		observer, err := f.svc.CreateObserver(ctx, f.person, observerReq)
		must(t, err)
		_, err = f.svc.Revoke(ctx, f.person, observer.Delegation.ID, "")
		must(t, err)
		must(t, f.store.View(ctx, func(tx nexus.Tx) error {
			task, err := tx.Task(r.Task.ID)
			if task.Status == "cancelled" {
				t.Error("revoking observer cancelled observed task")
			}
			return err
		}))
		observerReq.Scope = []string{"session:delegate"}
		_, err = f.svc.CreateObserver(ctx, f.person, observerReq)
		wantErr(t, err, nexus.ErrInvalid)
	})
	t.Run("mandate_ancestor_integrity_and_policy_hash", func(t *testing.T) {
		f := newFixture(t, open)
		r := f.issue(rootRequest())
		c := f.delegate(r, f.childRequest(r, 5000))
		must(t, f.store.Update(ctx, func(tx nexus.Tx) error { d := r.Delegation; now := f.now; d.EndedAt = &now; return tx.PutDelegation(d) }))
		actor := nexus.SessionPrincipal(f.account, c.Session.ID)
		_, err := f.svc.Authorize(ctx, actor, c.Delegation.ID, "tool:read_file")
		wantErr(t, err, nexus.ErrRevoked)
		_, err = f.svc.Consume(ctx, actor, c.Delegation.ID, nexus.Limits{ModelTokens: 1})
		wantErr(t, err, nexus.ErrRevoked)
		_, err = f.svc.AppendEvents(ctx, actor, c.Session.ID, []nexus.EventInput{{Kind: "test"}})
		wantErr(t, err, nexus.ErrRevoked)
		r = f.issue(rootRequest())
		must(t, f.store.Update(ctx, func(tx nexus.Tx) error { d := r.Delegation; d.Policy.Hash = "changed"; return tx.PutDelegation(d) }))
		_, err = f.svc.Authorize(ctx, f.person, r.Delegation.ID, "tool:read_file")
		wantErr(t, err, nexus.ErrConflict)
	})
	t.Run("mandate_random_conservation", func(t *testing.T) {
		f := newFixture(t, open)
		r := f.issue(rootRequest())
		all := []nexus.Issued{r}
		random := rand.New(rand.NewSource(47))
		spent := int64(0)
		spawned := int64(0)
		for i := 0; i < 400; i++ {
			parent := all[random.Intn(len(all))]
			switch random.Intn(4) {
			case 0:
				req := f.childRequest(parent, int64(random.Intn(300)))
				req.Limits.SubSessions = 2
				child, err := f.svc.Delegate(ctx, f.person, req)
				if err == nil {
					all = append(all, child)
					// Existing workers consume no new session slot.
				} else if !errors.Is(err, nexus.ErrLimit) && !errors.Is(err, nexus.ErrRevoked) && !errors.Is(err, nexus.ErrForbidden) {
					t.Fatal(err)
				}
			case 1:
				amount := int64(random.Intn(60))
				_, err := f.svc.Consume(ctx, nexus.SessionPrincipal(f.account, parent.Session.ID), parent.Delegation.ID, nexus.Limits{ModelTokens: amount})
				if err == nil {
					spent += amount
				} else if !errors.Is(err, nexus.ErrLimit) && !errors.Is(err, nexus.ErrRevoked) {
					t.Fatal(err)
				}
			case 2:
				if parent.Delegation.ID != r.Delegation.ID {
					_, err := f.svc.Revoke(ctx, f.person, parent.Delegation.ID, "")
					must(t, err)
				}
			case 3:
				if parent.Delegation.ID != r.Delegation.ID {
					_, err := f.svc.SetTaskStatus(ctx, f.person, parent.Task.ID, "done")
					if err != nil && !errors.Is(err, nexus.ErrConflict) {
						t.Fatal(err)
					}
				}
			}
			must(t, f.store.View(ctx, func(tx nexus.Tx) error {
				var totalTokens, totalSessions int64
				for _, x := range all {
					d, err := tx.Delegation(x.Delegation.ID)
					if err != nil {
						return err
					}
					if d.EndedAt != nil {
						continue
					}
					u, err := tx.Usage(d.ID)
					if err != nil {
						return err
					}
					totalTokens += u.Consumed.ModelTokens
					totalSessions += u.Consumed.SubSessions
					children, err := tx.DelegationsByParent(d.ID)
					if err != nil {
						return err
					}
					var tokens, sessions int64
					for _, c := range children {
						if c.EndedAt == nil {
							tokens += c.Limits.ModelTokens
							sessions += c.Limits.SubSessions
						}
					}
					if u.Reserved.ModelTokens != tokens || u.Reserved.SubSessions != sessions || u.Consumed.ModelTokens+tokens > d.Limits.ModelTokens || u.Consumed.SubSessions+sessions > d.Limits.SubSessions {
						t.Fatalf("step %d: %+v %+v", i, d, u)
					}
				}
				if totalTokens != spent || totalSessions != spawned {
					t.Fatalf("step %d: accounted %d/%d actual %d/%d", i, totalTokens, totalSessions, spent, spawned)
				}
				return nil
			}))
		}
	})
}
