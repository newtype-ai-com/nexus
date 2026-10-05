package conformance

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// Execution grants (NMCP stage 3) on every store: memory, retrying memory and
// Postgres (nexus/pgstore TestPostgres*Conformance with NTS_NEXUS_TEST_DSN). The
// grant lives in the receiver's ledger only, so this also proves the event keys,
// NULL client ids for decision records and ledger-order checks on each backend.
func runExecutionGrants(t *testing.T, open func() nexus.Store) {
	ctx := context.Background()
	type world struct {
		f                        *fixture
		recv, send, other        nexus.Issued
		receiver, sender, outsid nexus.Principal
	}
	setup := func(t *testing.T) world {
		f := newFixture(t, open)
		w := world{f: f, recv: f.issue(rootRequest()), send: f.issue(rootRequest()), other: f.issue(rootRequest())}
		w.receiver = nexus.SessionPrincipal(f.account, w.recv.Session.ID)
		w.sender = nexus.SessionPrincipal(f.account, w.send.Session.ID)
		w.outsid = nexus.SessionPrincipal(f.account, w.other.Session.ID)
		return w
	}
	grant := func(t *testing.T, w world, turns int) nexus.ExecutionGrant {
		t.Helper()
		g, err := w.f.svc.IssueExecutionGrant(ctx, w.f.person, nexus.ExecutionGrant{Receiver: w.recv.Session.ID,
			Delegation: w.recv.Delegation.ID, Senders: []ids.Session{w.send.Session.ID},
			Tools: []string{"tool:edit_file", "tool:run_*", "tool:remove_file"}, Paths: []string{"/repo/x/**", "/tmp/build.log"},
			MaxTurns: turns}, 30*time.Minute)
		must(t, err)
		return g
	}
	send := func(t *testing.T, w world, from nexus.Principal, text string) nexus.Received {
		t.Helper()
		r, err := w.f.svc.Send(ctx, from, nexus.Message{To: w.recv.Session.ID, Text: text})
		must(t, err)
		return r
	}
	decide := func(t *testing.T, w world, g nexus.ExecutionGrant, r nexus.Received, action string, paths ...string) nexus.GrantDecision {
		t.Helper()
		d, err := w.f.svc.DecideExecutionGrant(ctx, w.receiver, g.ID, nexus.GrantDecisionInput{SourceEvent: r.Event,
			SourceSeq: r.Seq, Action: action, Paths: paths, InputHash: strings.Repeat("a", 64)})
		must(t, err)
		return d
	}

	t.Run("execution_grant_scope_turns_and_ledger", func(t *testing.T) {
		w := setup(t)
		_, err := w.f.svc.IssueExecutionGrant(ctx, w.sender, nexus.ExecutionGrant{Receiver: w.recv.Session.ID,
			Delegation: w.recv.Delegation.ID, Senders: []ids.Session{w.send.Session.ID}, Tools: []string{"tool:edit_file"},
			Paths: []string{"/repo/x/**"}, MaxTurns: 1}, time.Minute)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = w.f.svc.IssueExecutionGrant(ctx, w.f.person, nexus.ExecutionGrant{Receiver: w.recv.Session.ID,
			Delegation: w.recv.Delegation.ID, Senders: []ids.Session{w.send.Session.ID}, Tools: []string{"tool:edit_file"},
			Paths: []string{"/**"}, MaxTurns: 1}, time.Minute)
		wantErr(t, err, nexus.ErrInvalid)
		g := grant(t, w, 2)
		m1 := send(t, w, w.sender, "fix it")
		if d := decide(t, w, g, m1, "tool:edit_file", "/repo/x/a.go"); d.Effect != "allow" || d.Turn != 1 || d.TurnsLeft != 1 {
			t.Fatal(d)
		}
		if d := decide(t, w, g, m1, "tool:run_tests", "/repo/x"); d.Effect != "allow" || d.Turn != 1 {
			t.Fatal("same message, new turn:", d)
		}
		if d := decide(t, w, g, m1, "tool:edit_file", "/repo/xy/a.go"); d.Effect != "ask" {
			t.Fatal(d)
		}
		if d := decide(t, w, g, m1, "tool:shell", "/repo/x"); d.Effect != "ask" {
			t.Fatal(d)
		}
		if d := decide(t, w, g, m1, "tool:remove_file", "/repo/x/a.go"); d.Effect != "ask" {
			t.Fatal("the root's own ask rule must still apply:", d)
		}
		m2 := send(t, w, w.sender, "next")
		if d := decide(t, w, g, m2, "tool:edit_file", "/tmp/build.log"); d.Effect != "allow" || d.Turn != 2 || d.TurnsLeft != 0 {
			t.Fatal(d)
		}
		m3 := send(t, w, w.sender, "more")
		if d := decide(t, w, g, m3, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" || d.Reason != "turn limit reached" {
			t.Fatal(d)
		}
		list, err := w.f.svc.ExecutionGrants(ctx, w.f.person, w.recv.Session.ID)
		must(t, err)
		if len(list) != 1 || list[0].Status != "exhausted" || list[0].TurnsUsed != 2 {
			t.Fatal(list)
		}
		decided := 0
		must(t, w.f.store.View(nexus.WithAccount(ctx, w.f.account), func(tx nexus.Tx) error {
			decided = 0
			events, err := tx.Events(w.recv.Session.ID, 0, 0)
			for _, e := range events {
				if e.Kind == "execution_grant.decided" {
					decided++
				}
			}
			return err
		}))
		if decided != 7 {
			t.Fatal("decided records:", decided)
		}
	})

	t.Run("execution_grant_refuses_forged_sources", func(t *testing.T) {
		w := setup(t)
		early := send(t, w, w.sender, "before the grant, same instant") // the clock does not move
		g := grant(t, w, 5)
		if d := decide(t, w, g, early, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" || d.Reason != "message predates the grant" {
			t.Fatal(d)
		}
		foreign := send(t, w, w.outsid, "not granted")
		if d := decide(t, w, g, foreign, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" {
			t.Fatal(d)
		}
		mail := send(t, w, w.f.person, "person mail")
		if d := decide(t, w, g, mail, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" {
			t.Fatal(d)
		}
		ok := send(t, w, w.sender, "real")
		mixed := ok
		mixed.Seq = foreign.Seq
		if d := decide(t, w, g, mixed, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" || d.Reason != "source message not found" {
			t.Fatal(d)
		}
		_, err := w.f.svc.DecideExecutionGrant(ctx, w.sender, g.ID, nexus.GrantDecisionInput{SourceEvent: ok.Event, SourceSeq: ok.Seq,
			Action: "tool:edit_file", Paths: []string{"/repo/x/a.go"}, InputHash: strings.Repeat("b", 64)})
		if err == nil {
			t.Fatal("another session decided on the receiver's grant")
		}
		if d := decide(t, w, g, ok, "tool:edit_file", "/repo/x/a.go"); d.Effect != "allow" {
			t.Fatal(d)
		}
	})

	t.Run("execution_grant_ends_on_revoke_expiry_and_delegation", func(t *testing.T) {
		w := setup(t)
		g := grant(t, w, 10)
		m := send(t, w, w.sender, "go")
		_, err := w.f.svc.RevokeExecutionGrant(ctx, w.outsid, w.recv.Session.ID, g.ID, "not mine")
		wantErr(t, err, nexus.ErrForbidden)
		out, err := w.f.svc.RevokeExecutionGrant(ctx, w.receiver, w.recv.Session.ID, g.ID, "done")
		must(t, err)
		if out.Status != "revoked" {
			t.Fatal(out)
		}
		// revoking twice is idempotent (the fixed key holds one record)
		_, err = w.f.svc.RevokeExecutionGrant(ctx, w.f.person, w.recv.Session.ID, g.ID, "again")
		must(t, err)
		if d := decide(t, w, g, m, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" || d.Reason != "grant revoked" {
			t.Fatal(d)
		}
		g2 := grant(t, w, 10)
		m2 := send(t, w, w.sender, "again")
		w.f.now = w.f.now.Add(31 * time.Minute)
		if d := decide(t, w, g2, m2, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" || d.Reason != "grant expired" {
			t.Fatal(d)
		}
		g3 := grant(t, w, 10)
		m3 := send(t, w, w.sender, "third")
		_, err = w.f.svc.Revoke(ctx, w.f.person, w.recv.Delegation.ID, "stop")
		must(t, err)
		d, err := w.f.svc.DecideExecutionGrant(ctx, w.receiver, g3.ID, nexus.GrantDecisionInput{SourceEvent: m3.Event, SourceSeq: m3.Seq,
			Action: "tool:edit_file", Paths: []string{"/repo/x/a.go"}, InputHash: strings.Repeat("c", 64)})
		if err == nil && d.Effect != "deny" {
			t.Fatal("a grant outlived its delegation:", d)
		}
	})
}
