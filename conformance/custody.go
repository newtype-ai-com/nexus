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

const custodyAction = "custody:bind-static-config"

func custodyRoot(effect string) nexus.RootRequest {
	return nexus.RootRequest{Title: "custody actor", Runner: nexus.Local, Scope: []string{"newtype:run"},
		Rules: []nexus.Rule{{Action: custodyAction, Effect: effect}}, Limits: nexus.Limits{SubSessions: 1, MaxDepth: 1}}
}

func custodyHash(c string) string { return "sha256:" + strings.Repeat(c, 64) }

func runCustody(t *testing.T, open func() nexus.Store) {
	ctx := context.Background()
	t.Run("custody_request_decide_use_once", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(custodyRoot("ask"))
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		h := custodyHash("a")
		x, err := f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, h, 10*time.Minute)
		must(t, err)
		if x.Status != "pending" || x.Standing || x.Revoked || x.DecidedAt != nil || x.DecidedBy != nil || x.UsedAt != nil {
			t.Fatalf("%+v", x)
		}
		// exactly one open approval per exact input
		_, err = f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, h, 10*time.Minute)
		wantErr(t, err, nexus.ErrConflict)
		// only the person decides; the hash must match
		_, err = f.svc.DecideCustodyApproval(ctx, actor, x.ID, h, true)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.DecideCustodyApproval(ctx, f.person, x.ID, custodyHash("b"), true)
		wantErr(t, err, nexus.ErrConflict)
		// not usable before approval
		_, err = f.svc.UseCustodyApproval(ctx, actor, x.ID, h)
		wantErr(t, err, nexus.ErrConflict)
		x, err = f.svc.DecideCustodyApproval(ctx, f.person, x.ID, h, true)
		must(t, err)
		if x.Status != "approved" || x.DecidedAt == nil || x.DecidedBy == nil || *x.DecidedBy != "owner@example.com" {
			t.Fatalf("%+v", x)
		}
		// the person cannot consume; a wrong hash cannot consume
		_, err = f.svc.UseCustodyApproval(ctx, f.person, x.ID, h)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.UseCustodyApproval(ctx, actor, x.ID, custodyHash("b"))
		wantErr(t, err, nexus.ErrConflict)
		// concurrent consumers: exactly one wins (also across a restarted service)
		restarted := nexus.NewService(f.store, func() time.Time { return f.now })
		var wins atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			svc := f.svc
			if i%2 == 1 {
				svc = restarted
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := svc.UseCustodyApproval(ctx, actor, x.ID, h); err == nil {
					wins.Add(1)
				}
			}()
		}
		wg.Wait()
		if wins.Load() != 1 {
			t.Fatalf("uses=%d", wins.Load())
		}
		got, err := f.svc.CustodyApproval(ctx, actor, x.ID)
		must(t, err)
		if got.Status != "used" || got.UsedAt == nil || got.Standing {
			t.Fatalf("%+v", got)
		}
		list, err := f.svc.CustodyApprovals(ctx, actor, h)
		must(t, err)
		if len(list) != 1 || list[0].ID != x.ID || list[0].Status != "used" {
			t.Fatalf("%+v", list)
		}
		// a new request for the same input is allowed after use (a new attempt)
		_, err = f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, h, 10*time.Minute)
		must(t, err)
	})
	t.Run("custody_policy_gate", func(t *testing.T) {
		for _, effect := range []string{"auto", "deny"} {
			f := newFixture(t, open)
			root := f.issue(custodyRoot(effect))
			actor := nexus.SessionPrincipal(f.account, root.Session.ID)
			_, err := f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, custodyHash("a"), time.Minute)
			wantErr(t, err, nexus.ErrForbidden) // auto would pass without an approval; deny refuses
		}
		f := newFixture(t, open)
		root := f.issue(custodyRoot("ask"))
		other := f.issue(custodyRoot("ask"))
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		// not the delegate of that delegation
		_, err := f.svc.RequestCustodyApproval(ctx, actor, other.Delegation.ID, custodyAction, custodyHash("a"), time.Minute)
		wantErr(t, err, nexus.ErrForbidden)
		// another action is not in the policy (deny)
		_, err = f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, "custody:other", custodyHash("a"), time.Minute)
		wantErr(t, err, nexus.ErrForbidden)
		for _, bad := range []string{strings.Repeat("a", 64), "sha256:" + strings.Repeat("A", 64), "sha256:" + strings.Repeat("a", 63), "sha256:" + strings.Repeat("g", 64)} {
			_, err = f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, bad, time.Minute)
			wantErr(t, err, nexus.ErrInvalid)
		}
		_, err = f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, custodyHash("a"), 25*time.Hour)
		wantErr(t, err, nexus.ErrInvalid)
		_, err = f.svc.RequestCustodyApproval(ctx, f.person, root.Delegation.ID, custodyAction, custodyHash("a"), time.Minute)
		wantErr(t, err, nexus.ErrForbidden)
	})
	t.Run("custody_expiry_and_revocation", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(custodyRoot("ask"))
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		h := custodyHash("c")
		x, err := f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, h, time.Minute)
		must(t, err)
		_, err = f.svc.DecideCustodyApproval(ctx, f.person, x.ID, h, true)
		must(t, err)
		f.now = f.now.Add(time.Minute)
		got, err := f.svc.CustodyApproval(ctx, actor, x.ID)
		must(t, err)
		if got.Status != "expired" {
			t.Fatalf("%+v", got)
		}
		_, err = f.svc.UseCustodyApproval(ctx, actor, x.ID, h)
		wantErr(t, err, nexus.ErrExpired)
		// expiry never exceeds the delegation's own expiry
		f2 := newFixture(t, open)
		req := custodyRoot("ask")
		req.TTL = 2 * time.Minute
		r2 := f2.issue(req)
		a2 := nexus.SessionPrincipal(f2.account, r2.Session.ID)
		y, err := f2.svc.RequestCustodyApproval(ctx, a2, r2.Delegation.ID, custodyAction, h, time.Hour)
		must(t, err)
		if y.ExpiresAt != r2.Delegation.ExpiresAt.UTC().Truncate(time.Second).Format(time.RFC3339) {
			t.Fatalf("expiry %s beyond delegation %s", y.ExpiresAt, r2.Delegation.ExpiresAt)
		}
		// revocation: an approved approval reads revoked and cannot be used
		_, err = f2.svc.DecideCustodyApproval(ctx, f2.person, y.ID, h, true)
		must(t, err)
		_, err = f2.svc.Revoke(ctx, f2.person, r2.Delegation.ID, "test")
		must(t, err)
		got, err = f2.svc.CustodyApproval(ctx, a2, y.ID)
		must(t, err)
		if got.Status != "revoked" || !got.Revoked {
			t.Fatalf("%+v", got)
		}
		_, err = f2.svc.UseCustodyApproval(ctx, a2, y.ID, h)
		if err == nil {
			t.Fatal("revoked approval used")
		}
		dv, err := f2.svc.CustodyDelegation(ctx, f2.person, r2.Delegation.ID)
		must(t, err)
		if !dv.Ended || !dv.Revoked || dv.Live || dv.EndReason == nil || *dv.EndReason != "revoked" || dv.Version != nexus.CustodyVersion {
			t.Fatalf("%+v", dv)
		}
	})
	t.Run("custody_visibility_and_delegation_view", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(custodyRoot("ask"))
		other := f.issue(custodyRoot("ask"))
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		otherActor := nexus.SessionPrincipal(f.account, other.Session.ID)
		h := custodyHash("d")
		x, err := f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, h, time.Minute)
		must(t, err)
		_, err = f.svc.RequestCustodyApproval(ctx, otherActor, other.Delegation.ID, custodyAction, h, time.Minute)
		must(t, err)
		// a session sees only its own requests; the person sees the account
		mine, err := f.svc.CustodyApprovals(ctx, actor, h)
		must(t, err)
		all, err := f.svc.CustodyApprovals(ctx, f.person, h)
		must(t, err)
		if len(mine) != 1 || mine[0].ID != x.ID || len(all) != 2 {
			t.Fatalf("mine=%d all=%d", len(mine), len(all))
		}
		_, err = f.svc.CustodyApproval(ctx, otherActor, x.ID)
		wantErr(t, err, nexus.ErrNotFound)
		stranger := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "other@example.com")
		_, err = f.svc.CustodyApproval(ctx, stranger, x.ID)
		wantErr(t, err, nexus.ErrNotFound)
		if l, err := f.svc.CustodyApprovals(ctx, stranger, h); err != nil || len(l) != 0 {
			t.Fatal("cross-account listing")
		}
		// the delegate reads its own delegation's liveness; another session cannot
		dv, err := f.svc.CustodyDelegation(ctx, actor, root.Delegation.ID)
		must(t, err)
		if !dv.Live || dv.Ended || dv.Revoked || dv.EndReason != nil || dv.Delegate != root.Session.ID {
			t.Fatalf("%+v", dv)
		}
		_, err = f.svc.CustodyDelegation(ctx, otherActor, root.Delegation.ID)
		wantErr(t, err, nexus.ErrForbidden)
		// expired but not swept: not live, not ended, not revoked
		f.now = root.Delegation.ExpiresAt
		dv, err = f.svc.CustodyDelegation(ctx, f.person, root.Delegation.ID)
		must(t, err)
		if dv.Live || dv.Ended || dv.Revoked {
			t.Fatalf("%+v", dv)
		}
	})
	t.Run("custody_listing_never_partial", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(custodyRoot("ask"))
		h := custodyHash("e")
		must(t, f.store.Update(ctx, func(tx nexus.Tx) error {
			for i := 0; i <= nexus.CustodyListLimit; i++ {
				x := nexus.CustodyApproval{ID: ids.Approval(ids.New(ids.KindApproval)), AccountID: f.account, SessionID: root.Session.ID,
					Delegation: root.Delegation.ID, Action: custodyAction, InputHash: h, Status: "pending", CreatedAt: f.now, ExpiresAt: f.now.Add(time.Minute)}
				if err := tx.PutCustodyApproval(x); err != nil {
					return err
				}
			}
			return nil
		}))
		_, err := f.svc.CustodyApprovals(ctx, f.person, h)
		wantErr(t, err, nexus.ErrConflict)
	})
	t.Run("custody_store_contract", func(t *testing.T) {
		f := newFixture(t, open)
		x := nexus.CustodyApproval{ID: ids.Approval(ids.New(ids.KindApproval)), AccountID: f.account, InputHash: custodyHash("f"), Status: "pending", CreatedAt: f.now, ExpiresAt: f.now}
		must(t, f.store.View(ctx, func(tx nexus.Tx) error {
			wantErr(t, tx.PutCustodyApproval(x), nexus.ErrInvalid) // write in a view
			_, err := tx.CustodyApproval(x.ID)
			wantErr(t, err, nexus.ErrNotFound)
			return nil
		}))
		must(t, f.store.Update(ctx, func(tx nexus.Tx) error { return tx.PutCustodyApproval(x) }))
		moved := x
		moved.InputHash = custodyHash("0")
		must(t, f.store.Update(ctx, func(tx nexus.Tx) error {
			wantErr(t, tx.PutCustodyApproval(moved), nexus.ErrConflict) // the exact input never changes
			bad := x
			bad.InputHash = strings.Repeat("f", 64)
			wantErr(t, tx.PutCustodyApproval(bad), nexus.ErrInvalid)
			return nil
		}))
	})
	t.Run("custody_session_suspended_and_ancestor_end", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(custodyRoot("ask"))
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		h := custodyHash("1")
		x, err := f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, h, time.Minute)
		must(t, err)
		x, err = f.svc.DecideCustodyApproval(ctx, f.person, x.ID, h, true)
		must(t, err)
		if !x.Usable {
			t.Fatalf("%+v", x)
		}
		_, err = f.svc.Suspend(ctx, f.person, root.Session.ID, "test")
		must(t, err)
		got, err := f.svc.CustodyApproval(ctx, f.person, x.ID)
		must(t, err)
		if got.Usable || got.Status != "approved" {
			t.Fatalf("suspended delegate still usable: %+v", got)
		}
		_, err = f.svc.UseCustodyApproval(ctx, actor, x.ID, h)
		if err == nil {
			t.Fatal("suspended session consumed")
		}
		dv, err := f.svc.CustodyDelegation(ctx, f.person, root.Delegation.ID)
		must(t, err)
		if !dv.Live || dv.SessionActive {
			t.Fatalf("%+v", dv)
		}
	})
	t.Run("custody_concurrent_requests_one_active", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(custodyRoot("ask"))
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		h := custodyHash("2")
		var ok atomic.Int32
		var wg sync.WaitGroup
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				if _, err := f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, h, time.Minute); err == nil {
					ok.Add(1)
				}
			}()
		}
		wg.Wait()
		list, err := f.svc.CustodyApprovals(ctx, actor, h)
		must(t, err)
		if ok.Load() != 1 || len(list) != 1 {
			t.Fatalf("requests ok=%d records=%d", ok.Load(), len(list))
		}
		// an expired open approval no longer blocks a fresh request
		f.now = f.now.Add(time.Minute)
		_, err = f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, h, time.Minute)
		must(t, err)
	})
	t.Run("custody_revoke_then_use_and_ledger_once", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(custodyRoot("ask"))
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		h := custodyHash("3")
		x, err := f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, h, time.Minute)
		must(t, err)
		_, err = f.svc.DecideCustodyApproval(ctx, f.person, x.ID, h, true)
		must(t, err)
		_, err = f.svc.UseCustodyApproval(ctx, actor, x.ID, h)
		must(t, err)
		// the used history survives revocation and expiry unchanged
		_, err = f.svc.Revoke(ctx, f.person, root.Delegation.ID, "test")
		must(t, err)
		f.now = f.now.Add(time.Hour)
		got, err := f.svc.CustodyApproval(ctx, f.person, x.ID)
		must(t, err)
		if got.Status != "used" || got.UsedAt == nil || got.Usable || !got.Revoked {
			t.Fatalf("%+v", got)
		}
		// exactly one ledger event per transition, also under a retried store
		counts := map[string]int{}
		must(t, f.store.View(ctx, func(tx nexus.Tx) error {
			events, err := tx.Events(root.Session.ID, 0, 0)
			if err != nil {
				return err
			}
			for _, e := range events {
				if strings.HasPrefix(e.Kind, "custody_approval.") {
					counts[e.Kind]++
				}
			}
			return nil
		}))
		if counts["custody_approval.requested"] != 1 || counts["custody_approval.decided"] != 1 || counts["custody_approval.used"] != 1 {
			t.Fatalf("ledger %v", counts)
		}
	})
	t.Run("custody_time_rounding", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(custodyRoot("ask"))
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		f.now = f.now.Add(300 * time.Millisecond)
		h := custodyHash("4")
		x, err := f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, h, time.Minute)
		must(t, err)
		created, _ := time.Parse(time.RFC3339, x.CreatedAt)
		expires, _ := time.Parse(time.RFC3339, x.ExpiresAt)
		if created.Before(f.now) || expires.After(f.now.Add(time.Minute)) {
			t.Fatalf("rounded toward fresher: created %s expires %s now %s", x.CreatedAt, x.ExpiresAt, f.now)
		}
		_, err = f.svc.DecideCustodyApproval(ctx, f.person, x.ID, h, true)
		must(t, err)
		u, err := f.svc.UseCustodyApproval(ctx, actor, x.ID, h)
		must(t, err)
		used, _ := time.Parse(time.RFC3339, *u.UsedAt)
		if used.Before(f.now) || used.Before(created) {
			t.Fatalf("used_at %s before now %s", *u.UsedAt, f.now)
		}
	})
	t.Run("custody_store_immutable_and_terminal", func(t *testing.T) {
		f := newFixture(t, open)
		root := f.issue(custodyRoot("ask"))
		put := func(x nexus.CustodyApproval) error {
			return f.store.Update(ctx, func(tx nexus.Tx) error { return tx.PutCustodyApproval(x) })
		}
		decided, used := f.now.Add(time.Second), f.now.Add(2*time.Second)
		base := nexus.CustodyApproval{ID: ids.Approval(ids.New(ids.KindApproval)), AccountID: f.account, SessionID: root.Session.ID,
			Delegation: root.Delegation.ID, Action: custodyAction, InputHash: custodyHash("9"), Status: "pending", CreatedAt: f.now, ExpiresAt: f.now.Add(time.Minute)}
		// a record is born pending, with no decision or use
		for name, bad := range map[string]func(*nexus.CustodyApproval){
			"born used":     func(c *nexus.CustodyApproval) { c.Status = "used" },
			"born approved": func(c *nexus.CustodyApproval) { c.Status = "approved"; c.DecidedAt, c.DecidedBy = &decided, "p" },
			"born decided":  func(c *nexus.CustodyApproval) { c.DecidedAt, c.DecidedBy = &decided, "p" },
		} {
			x := base
			x.ID = ids.Approval(ids.New(ids.KindApproval))
			bad(&x)
			if put(x) == nil {
				t.Errorf("%s accepted", name)
			}
		}
		must(t, put(base))
		approved := base
		approved.Status, approved.DecidedAt, approved.DecidedBy = "approved", &decided, "owner@example.com"
		must(t, put(approved))
		must(t, put(approved)) // unchanged write is idempotent
		usedRec := approved
		usedRec.Status, usedRec.UsedAt = "used", &used
		other := f.now.Add(3 * time.Second)
		for name, mutate := range map[string]func(*nexus.CustodyApproval){
			"approved back to pending": func(c *nexus.CustodyApproval) { *c = base },
			"approved decider rewrite": func(c *nexus.CustodyApproval) { c.DecidedBy = "other@example.com" },
			"use rewrites decision":    func(c *nexus.CustodyApproval) { *c = usedRec; c.DecidedAt = &other },
		} {
			y := approved
			mutate(&y)
			if put(y) == nil {
				t.Errorf("%s accepted", name)
			}
		}
		must(t, put(usedRec))
		must(t, put(usedRec)) // identical terminal write is idempotent
		for name, mutate := range map[string]func(*nexus.CustodyApproval){
			"session":        func(c *nexus.CustodyApproval) { c.SessionID = ids.Session(ids.New(ids.KindSession)) },
			"action":         func(c *nexus.CustodyApproval) { c.Action = "custody:other" },
			"expires":        func(c *nexus.CustodyApproval) { c.ExpiresAt = c.ExpiresAt.Add(time.Hour) },
			"reopen":         func(c *nexus.CustodyApproval) { c.Status, c.UsedAt = "approved", nil },
			"uppercase":      func(c *nexus.CustodyApproval) { c.InputHash = "sha256:" + strings.Repeat("A", 64) },
			"decider":        func(c *nexus.CustodyApproval) { c.DecidedBy = "other@example.com" },
			"decided_at":     func(c *nexus.CustodyApproval) { c.DecidedAt = &other },
			"used_at":        func(c *nexus.CustodyApproval) { c.UsedAt = &other },
			"clear decision": func(c *nexus.CustodyApproval) { c.DecidedAt, c.DecidedBy = nil, "" },
			"clear use":      func(c *nexus.CustodyApproval) { c.UsedAt = nil },
			"used to denied": func(c *nexus.CustodyApproval) { c.Status, c.UsedAt = "denied", nil },
		} {
			y := usedRec
			mutate(&y)
			if put(y) == nil {
				t.Errorf("used record: %s changed at the store level", name)
			}
		}
		// denied is terminal too
		d := base
		d.ID = ids.Approval(ids.New(ids.KindApproval))
		must(t, put(d))
		d.Status, d.DecidedAt, d.DecidedBy = "denied", &decided, "owner@example.com"
		must(t, put(d))
		for name, mutate := range map[string]func(*nexus.CustodyApproval){
			"denied to approved": func(c *nexus.CustodyApproval) { c.Status = "approved" },
			"denied decider":     func(c *nexus.CustodyApproval) { c.DecidedBy = "x@example.com" },
			"denied cleared":     func(c *nexus.CustodyApproval) { c.DecidedAt, c.DecidedBy = nil, "" },
		} {
			y := d
			mutate(&y)
			if put(y) == nil {
				t.Errorf("denied record: %s changed", name)
			}
		}
	})
	t.Run("custody_rollback_and_lost_ack", func(t *testing.T) {
		mode := ""
		calls := 0
		var store nexus.Store
		f := newFixture(t, func() nexus.Store {
			store = open()
			return faultStore{Store: store, mode: &mode, calls: &calls}
		})
		root := f.issue(custodyRoot("ask"))
		actor := nexus.SessionPrincipal(f.account, root.Session.ID)
		h := custodyHash("8")
		x, err := f.svc.RequestCustodyApproval(ctx, actor, root.Delegation.ID, custodyAction, h, time.Minute)
		must(t, err)
		events := func(kind string) int {
			n := 0
			must(t, store.View(ctx, func(tx nexus.Tx) error {
				all, err := tx.Events(root.Session.ID, 0, 0)
				for _, e := range all {
					if e.Kind == kind {
						n++
					}
				}
				return err
			}))
			return n
		}
		// rollback: the decision returns an error and leaves no trace
		mode = "rollback"
		got, err := f.svc.DecideCustodyApproval(ctx, f.person, x.ID, h, true)
		if err == nil || got.ID != "" {
			t.Fatal("rolled-back decision reported success")
		}
		mode = ""
		rb, err := f.svc.CustodyApproval(ctx, f.person, x.ID)
		must(t, err)
		if rb.Status != "pending" || events("custody_approval.decided") != 0 {
			t.Fatalf("rollback left state: %+v", rb)
		}
		_, err = f.svc.DecideCustodyApproval(ctx, f.person, x.ID, h, true)
		must(t, err)
		// lost acknowledgement: committed, but the caller sees only an error,
		// the service does not retry, and readback shows the committed history
		mode = "lostack"
		calls = 0
		got, err = f.svc.UseCustodyApproval(ctx, actor, x.ID, h)
		if err == nil || got.ID != "" {
			t.Fatal("lost acknowledgement reported success")
		}
		if calls != 1 {
			t.Fatalf("service re-mutated after a lost ack: %d updates", calls)
		}
		mode = ""
		rb, err = f.svc.CustodyApproval(ctx, actor, x.ID)
		must(t, err)
		if rb.Status != "used" || events("custody_approval.used") != 1 {
			t.Fatalf("committed history not visible: %+v", rb)
		}
		_, err = f.svc.UseCustodyApproval(ctx, actor, x.ID, h)
		wantErr(t, err, nexus.ErrConflict) // a second use never succeeds
	})
}

var errInjected = errors.New("conformance: injected store fault")

// faultStore injects a rollback (callback succeeded, commit refused) or a lost
// acknowledgement (commit succeeded, caller told it failed) for one Update.
type faultStore struct {
	nexus.Store
	mode  *string
	calls *int
}

func (f faultStore) Close() {
	if c, ok := f.Store.(interface{ Close() }); ok {
		c.Close()
	}
}

func (f faultStore) Update(ctx context.Context, fn func(nexus.Tx) error) error {
	*f.calls++
	switch *f.mode {
	case "rollback":
		return f.Store.Update(ctx, func(tx nexus.Tx) error {
			if err := fn(tx); err != nil {
				return err
			}
			return errInjected
		})
	case "lostack":
		if err := f.Store.Update(ctx, fn); err != nil {
			return err
		}
		return errInjected
	}
	return f.Store.Update(ctx, fn)
}
