package conformance

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// Runs unchanged against memory, retrying memory and disposable PostgreSQL.
func runSharedPresence(t *testing.T, open func() nexus.Store) {
	t.Run("presence_is_shared_between_server_instances", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, _ := f.seed(nil, "newtype:run")
		b, _ := f.seed(nil, "newtype:run")
		pa := nexus.SessionPrincipal(f.account, a.ID)
		newer := nexus.NewService(f.store, func() time.Time { return f.now })
		start := f.now
		msg, err := f.svc.Send(ctx, f.person, nexus.Message{To: a.ID, Text: "kept unread"})
		must(t, err)
		f.now = f.now.Add(6 * time.Minute)
		before := f.svc.Changed()
		must(t, newer.Touch(ctx, pa))
		select {
		case <-before:
			t.Fatal("heartbeat woke old service")
		default:
		}
		x, err := f.svc.Sweep(ctx, start, nexus.PresenceGrace, nexus.ArchiveAfter)
		must(t, err)
		if x.Stopped != 1 {
			t.Fatal(x)
		}
		live, err := f.svc.Session(ctx, f.person, a.ID)
		must(t, err)
		dead, err := f.svc.Session(ctx, f.person, b.ID)
		must(t, err)
		if live.Status != nexus.SessionRunning || !live.SeenAt.Equal(f.now) || dead.StoppedBy != nexus.PrincipalSystem {
			t.Fatal(live, dead)
		}
		status, err := f.svc.MessageDelivery(ctx, f.person, a.ID, msg.Event)
		must(t, err)
		if status.LastSeen == nil || !status.LastSeen.Equal(f.now) || status.Status != "sent" {
			t.Fatal(status)
		}
		restart := nexus.NewService(f.store, func() time.Time { return f.now })
		must(t, restart.Touch(ctx, nexus.SessionPrincipal(f.account, b.ID)))
		restored, err := f.svc.Session(ctx, f.person, b.ID)
		must(t, err)
		if restored.Status != nexus.SessionWaiting || restored.StoppedBy != "" {
			t.Fatal(restored)
		}
		events, _, err := f.svc.Events(ctx, f.person, b.ID, 0, 100)
		must(t, err)
		count := 0
		for _, e := range events {
			if e.Kind == "session.status" {
				count++
				if nexus.ForInbox(e) {
					t.Fatal("presence enters inbox")
				}
			}
		}
		if count != 2 {
			t.Fatal("stop/restore must occur once", count)
		}
	})
	t.Run("presence_explicit_legacy_stops_and_revocation_not_restored", func(t *testing.T) {
		for _, by := range []nexus.PrincipalKind{nexus.PrincipalSession, nexus.PrincipalUser, ""} {
			f := newFixture(t, open)
			ctx := context.Background()
			a, _ := f.seed(nil, "newtype:run")
			p := nexus.SessionPrincipal(f.account, a.ID)
			must(t, f.store.Update(ctx, func(tx nexus.Tx) error { a.Status = nexus.SessionStopped; a.StoppedBy = by; return tx.PutSession(a) }))
			must(t, f.svc.Touch(ctx, p))
			got, err := f.svc.Session(ctx, f.person, a.ID)
			must(t, err)
			if got.Status != nexus.SessionStopped || got.StoppedBy != by || !got.SeenAt.IsZero() {
				t.Fatal(got)
			}
		}
		f := newFixture(t, open)
		ctx := context.Background()
		a, d := f.seed(nil, "newtype:run")
		must(t, f.store.Update(ctx, func(tx nexus.Tx) error {
			a.Status = nexus.SessionStopped
			a.StoppedBy = nexus.PrincipalSystem
			if err := tx.PutSession(a); err != nil {
				return err
			}
			now := f.now
			d.EndedAt = &now
			return tx.PutDelegation(d)
		}))
		wantErr(t, f.svc.Touch(ctx, nexus.SessionPrincipal(f.account, a.ID)), nexus.ErrRevoked)
		got, err := f.svc.Session(ctx, f.person, a.ID)
		must(t, err)
		if got.Status != nexus.SessionStopped {
			t.Fatal(got)
		}
	})
	t.Run("presence_parallel_throttle_rollback_and_retry", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, _ := f.seed(nil, "newtype:run")
		p := nexus.SessionPrincipal(f.account, a.ID)
		changed := f.svc.Changed()
		var wg sync.WaitGroup
		for i := 0; i < 12; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if err := f.svc.Touch(ctx, p); err != nil {
					t.Error(err)
				}
			}()
		}
		wg.Wait()
		select {
		case <-changed:
			t.Fatal("heartbeat notification loop")
		default:
		}
		first := f.now
		f.now = f.now.Add(30 * time.Second)
		must(t, f.svc.Touch(ctx, p))
		got, err := f.svc.Session(ctx, f.person, a.ID)
		must(t, err)
		if !got.SeenAt.Equal(first) || !f.svc.LastSeen(a.ID).Equal(f.now) {
			t.Fatal(got)
		}
		f.now = first.Add(time.Minute)
		fault := &presenceFailStore{Store: f.store, fail: true}
		retry := nexus.NewService(fault, func() time.Time { return f.now })
		if retry.Touch(ctx, p) == nil {
			t.Fatal("write failure lost")
		}
		if !retry.LastSeen(a.ID).IsZero() {
			t.Fatal("failed observation cached")
		}
		got, err = f.svc.Session(ctx, f.person, a.ID)
		must(t, err)
		if !got.SeenAt.Equal(first) {
			t.Fatal("rollback failed")
		}
		fault.fail = false
		must(t, retry.Touch(ctx, p))
		got, err = f.svc.Session(ctx, f.person, a.ID)
		must(t, err)
		if !got.SeenAt.Equal(f.now) {
			t.Fatal(got)
		}
		f.now = first.Add(-time.Minute)
		must(t, retry.Touch(ctx, p))
		got, err = f.svc.Session(ctx, f.person, a.ID)
		must(t, err)
		if !got.SeenAt.Equal(first.Add(time.Minute)) {
			t.Fatal("clock regression", got)
		}
		foreign := nexus.SessionPrincipal(ids.Account(ids.New(ids.KindAccount)), a.ID)
		wantErr(t, retry.Touch(ctx, foreign), nexus.ErrNotFound)
	})
	t.Run("presence_manual_stop_overrides_sweeper_and_wins_touch_race", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, _ := f.seed(nil, "newtype:run")
		p := nexus.SessionPrincipal(f.account, a.ID)
		start := f.now
		f.now = f.now.Add(6 * time.Minute)
		_, err := f.svc.Sweep(ctx, start, nexus.PresenceGrace, nexus.ArchiveAfter)
		must(t, err)
		_, err = f.svc.SetSessionStatus(ctx, f.person, a.ID, nexus.SessionStopped)
		must(t, err)
		must(t, f.svc.Touch(ctx, p))
		got, err := f.svc.Session(ctx, f.person, a.ID)
		must(t, err)
		if got.StoppedBy != nexus.PrincipalUser || got.Status != nexus.SessionStopped {
			t.Fatal(got)
		}
		_, err = f.svc.SetSessionStatus(ctx, f.person, a.ID, nexus.SessionRunning)
		must(t, err)
		var wg sync.WaitGroup
		wg.Add(2)
		go func() {
			defer wg.Done()
			if err := f.svc.Touch(ctx, p); err != nil {
				t.Error(err)
			}
		}()
		go func() {
			defer wg.Done()
			if _, err := f.svc.SetSessionStatus(ctx, f.person, a.ID, nexus.SessionStopped); err != nil {
				t.Error(err)
			}
		}()
		wg.Wait()
		must(t, f.svc.Touch(ctx, p))
		got, err = f.svc.Session(ctx, f.person, a.ID)
		must(t, err)
		if got.StoppedBy != nexus.PrincipalUser || got.Status != nexus.SessionStopped {
			t.Fatal(got)
		}
	})
}

type presenceFailStore struct {
	nexus.Store
	fail bool
}

func (s *presenceFailStore) Update(ctx context.Context, fn func(nexus.Tx) error) error {
	return s.Store.Update(ctx, func(tx nexus.Tx) error {
		if err := fn(tx); err != nil {
			return err
		}
		if s.fail {
			return errors.New("synthetic persistence failure")
		}
		return nil
	})
}
