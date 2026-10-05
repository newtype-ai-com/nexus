package conformance

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/nexus"
)

// m16AfterSnapshot simulates another instance attaching after candidate selection
// but before the sweep's write transaction. No mutation happens inside a View.
type m16AfterSnapshot struct {
	nexus.Store
	after func()
}

func (s *m16AfterSnapshot) View(ctx context.Context, fn func(nexus.Tx) error) error {
	err := s.Store.View(ctx, fn)
	if err == nil && s.after != nil {
		f := s.after
		s.after = nil
		f()
	}
	return err
}

// Legacy requested rows are seeded through the store: the current service must
// not manufacture them just to exercise cleanup of older persisted records.
func runM16(t *testing.T, open func() nexus.Store) {
	ctx := context.Background()
	t.Run("m16_refuse_unstartable_default_and_fallback", func(t *testing.T) {
		f := newFixture(t, open)
		if !f.svc.RefuseUnstartable {
			t.Fatal("unsafe default")
		}
		r := f.issue(rootRequest())
		actor := nexus.SessionPrincipal(f.account, r.Session.ID)
		for _, enabled := range []bool{true, false} {
			f.svc.RefuseUnstartable = enabled
			for _, runner := range []nexus.Runner{"", nexus.Container, nexus.Local} {
				_, err := f.svc.Delegate(ctx, actor, nexus.DelegateRequest{ParentID: r.Delegation.ID, Title: "child", Runner: runner})
				wantErr(t, err, nexus.ErrRunnerUnavailable)
				if enabled && !strings.Contains(err.Error(), fmt.Sprintf(nexus.UnstartableMessage, "child")) {
					t.Fatal(err)
				}
			}
		}
		if f.usage(r.Delegation.ID) != (nexus.Usage{}) {
			t.Fatal("refusal charged budget")
		}
	})
	for _, mode := range []string{"orphan", "legacy_consumed", "local", "human", "human_entry", "older_session", "seen", "running", "ended", "ancestor_ended", "attach", "foreign_entry"} {
		t.Run("m16_requested_"+mode, func(t *testing.T) {
			f := newFixture(t, open)
			r := f.issue(rootRequest())
			c := f.delegate(r, f.childRequest(r, 100))
			must(t, f.store.Update(ctx, func(tx nexus.Tx) error {
				x, err := tx.Session(c.Session.ID)
				if err != nil {
					return err
				}
				x.Runner, x.Status, x.SeenAt = nexus.Container, nexus.SessionRequested, time.Time{}
				d, err := tx.Delegation(c.Delegation.ID)
				if err != nil {
					return err
				}
				switch mode {
				case "legacy_consumed":
					u, err := tx.Usage(r.Delegation.ID)
					if err != nil {
						return err
					}
					u.Consumed.SubSessions = 1 // historical spawn debit, not a reservation
					if err = tx.PutUsage(r.Delegation.ID, u); err != nil {
						return err
					}
				case "local":
					x.Runner = nexus.Local
				case "human":
					d.Delegator = f.person
				case "human_entry":
					x.EntryTaskID = r.Task.ID
				case "foreign_entry":
					d.Task = r.Task.ID
				case "older_session":
					x.CreatedAt = x.CreatedAt.Add(-time.Second)
				case "seen":
					x.SeenAt = f.now
				case "running":
					x.Status = nexus.SessionRunning
				}
				if err = tx.PutDelegation(d); err != nil {
					return err
				}
				return tx.PutSession(x)
			}))
			if mode == "ended" {
				_, err := f.svc.Revoke(ctx, f.person, c.Delegation.ID, "already ended")
				must(t, err)
			}
			if mode == "ancestor_ended" {
				_, err := f.svc.Revoke(ctx, f.person, r.Delegation.ID, "ancestor revoked")
				must(t, err)
			}
			before := f.usage(r.Delegation.ID)
			f.now = f.now.Add(nexus.RequestedGrace - time.Nanosecond)
			sweep := func() (nexus.SweepResult, error) { return f.svc.Sweep(ctx, f.now, time.Hour, nexus.ArchiveAfter) }
			result, err := sweep()
			must(t, err)
			if result.Stopped != 0 || f.usage(r.Delegation.ID) != before {
				t.Fatal("early settlement", result)
			}
			f.now = f.now.Add(time.Nanosecond)
			if mode == "attach" {
				// A heartbeat may leave status requested; shared presence still
				// proves a process attached, even on another service instance.
				peer := nexus.NewService(f.store, func() time.Time { return f.now })
				interleaved := &m16AfterSnapshot{Store: f.store, after: func() {
					must(t, peer.Touch(ctx, nexus.SessionPrincipal(f.account, c.Session.ID)))
				}}
				janitor := nexus.NewService(interleaved, func() time.Time { return f.now })
				got, err := janitor.Sweep(ctx, f.now, time.Hour, nexus.ArchiveAfter)
				must(t, err)
				if got.Stopped != 0 {
					t.Fatal("stale candidate revoked attached session")
				}
			}
			// Concurrent janitors (plus the retrying Store suite) must settle once.
			var wg sync.WaitGroup
			results := make(chan nexus.SweepResult, 2)
			errs := make(chan error, 2)
			for i := 0; i < 2; i++ {
				wg.Add(1)
				go func() { defer wg.Done(); got, e := sweep(); results <- got; errs <- e }()
			}
			wg.Wait()
			close(results)
			close(errs)
			for e := range errs {
				must(t, e)
			}
			stopped := 0
			for got := range results {
				stopped += got.Stopped
			}
			want := 0
			if mode == "orphan" || mode == "legacy_consumed" {
				want = 1
			}
			if stopped != want {
				t.Fatalf("stopped %d want %d", stopped, want)
			}
			must(t, f.store.View(ctx, func(tx nexus.Tx) error {
				d, e := tx.Delegation(c.Delegation.ID)
				if e != nil {
					return e
				}
				task, e := tx.Task(c.Task.ID)
				if e != nil {
					return e
				}
				if mode == "orphan" || mode == "legacy_consumed" {
					if d.EndedAt == nil || d.EndReason != "no runner took the session within 15m0s; hand the work to a session that runs" || task.Status != "cancelled" {
						t.Fatal(d, task)
					}
				} else if mode != "ended" && mode != "ancestor_ended" && d.EndedAt != nil {
					t.Fatal("unrelated mandate ended")
				}
				return nil
			}))
			if mode == "orphan" || mode == "legacy_consumed" {
				wantUsage := nexus.Usage{Consumed: before.Consumed}
				if f.usage(r.Delegation.ID) != wantUsage {
					t.Fatal("reservation not returned or legacy consumed debit altered", f.usage(r.Delegation.ID))
				}
			} else if f.usage(r.Delegation.ID) != before {
				t.Fatal("unrelated accounting changed")
			}
		})
	}
	t.Run("m16_human_bootstrap_waits", func(t *testing.T) {
		f := newFixture(t, open)
		r, err := f.svc.CreateRoot(ctx, f.person, rootRequest())
		must(t, err)
		f.now = f.now.Add(time.Hour)
		got, err := f.svc.Sweep(ctx, f.now, nexus.PresenceGrace, nexus.ArchiveAfter)
		must(t, err)
		if got.Stopped != 0 {
			t.Fatal(got)
		}
		s, err := f.svc.Session(ctx, f.person, r.Session.ID)
		must(t, err)
		if s.Status != nexus.SessionRequested {
			t.Fatal(s)
		}
	})
}
