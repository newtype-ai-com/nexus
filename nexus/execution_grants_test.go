package nexus_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

type grantFixture struct {
	ctx      context.Context
	store    nexus.Store
	svc      *nexus.Service
	now      *time.Time
	person   nexus.Principal
	receiver nexus.Principal
	sender   nexus.Principal
	other    nexus.Principal
	recvDel  ids.Delegation
}

func newGrantFixture(t *testing.T) *grantFixture {
	t.Helper()
	ctx := context.Background()
	store := nexus.NewMemStore()
	now := time.Now().UTC()
	f := &grantFixture{ctx: ctx, store: store, now: &now}
	f.svc = nexus.NewService(store, func() time.Time { return *f.now })
	account := ids.Account(ids.New(ids.KindAccount))
	f.person = nexus.UserPrincipal(account, "owner@example.test")
	root, err := f.svc.CreateRoot(ctx, f.person, nexus.RootRequest{Title: "root", Scope: []string{"newtype:run", "session:delegate"},
		Rules: []nexus.Rule{{Action: "tool:*", Effect: "auto"}, {Action: "tool:purchase", Effect: "ask"}}, Limits: nexus.Limits{SubSessions: 3}})
	if err != nil {
		t.Fatal(err)
	}
	issue := func() (nexus.Principal, ids.Delegation) {
		s := attachedWorker(t, store, account, now)
		d, err := f.svc.Delegate(ctx, f.person, nexus.DelegateRequest{Title: "worker", ParentID: root.Delegation.ID, ToSessionID: s, Scope: []string{"newtype:run"}})
		if err != nil {
			t.Fatal(err)
		}
		return nexus.SessionPrincipal(account, s), d.Delegation.ID
	}
	f.receiver, f.recvDel = issue()
	f.sender, _ = issue()
	f.other, _ = issue()
	return f
}

func (f *grantFixture) grant(t *testing.T, turns int) nexus.ExecutionGrant {
	t.Helper()
	g, err := f.svc.IssueExecutionGrant(f.ctx, f.person, nexus.ExecutionGrant{Receiver: f.receiver.SessionID, Delegation: f.recvDel,
		Senders: []ids.Session{f.sender.SessionID}, Tools: []string{"tool:edit_file", "tool:run_*", "tool:purchase"},
		Paths: []string{"/repo/x/**", "/tmp/build.log"}, MaxTurns: turns, Note: "operator task messages"}, 8*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func (f *grantFixture) send(t *testing.T, from nexus.Principal, text string) nexus.Received {
	t.Helper()
	*f.now = f.now.Add(time.Second)
	r, err := f.svc.Send(f.ctx, from, nexus.Message{To: f.receiver.SessionID, Text: text})
	if err != nil {
		t.Fatal(err)
	}
	return r
}

func (f *grantFixture) decide(t *testing.T, g nexus.ExecutionGrant, r nexus.Received, action string, paths ...string) nexus.GrantDecision {
	t.Helper()
	d, err := f.svc.DecideExecutionGrant(f.ctx, f.receiver, g.ID, nexus.GrantDecisionInput{SourceEvent: r.Event, SourceSeq: r.Seq,
		Action: action, Paths: paths, InputHash: strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func TestExecutionGrantIssuedByPersonOnlyAndValidated(t *testing.T) {
	f := newGrantFixture(t)
	base := nexus.ExecutionGrant{Receiver: f.receiver.SessionID, Delegation: f.recvDel, Senders: []ids.Session{f.sender.SessionID},
		Tools: []string{"tool:edit_file"}, Paths: []string{"/repo/x/**"}, MaxTurns: 3}
	if _, err := f.svc.IssueExecutionGrant(f.ctx, f.sender, base, time.Hour); !errors.Is(err, nexus.ErrForbidden) {
		t.Fatal("a session issued a grant:", err)
	}
	for name, mutate := range map[string]func(*nexus.ExecutionGrant){
		"whole machine": func(g *nexus.ExecutionGrant) { g.Paths = []string{"/**"} },
		"relative path": func(g *nexus.ExecutionGrant) { g.Paths = []string{"repo/**"} },
		"dot dot":       func(g *nexus.ExecutionGrant) { g.Paths = []string{"/repo/../etc/**"} },
		"non tool":      func(g *nexus.ExecutionGrant) { g.Tools = []string{"purchase"} },
		"self sender":   func(g *nexus.ExecutionGrant) { g.Senders = []ids.Session{f.receiver.SessionID} },
		"no turns":      func(g *nexus.ExecutionGrant) { g.MaxTurns = 0 },
	} {
		g := base
		mutate(&g)
		if _, err := f.svc.IssueExecutionGrant(f.ctx, f.person, g, time.Hour); !errors.Is(err, nexus.ErrInvalid) {
			t.Fatal(name, err)
		}
	}
	if _, err := f.svc.IssueExecutionGrant(f.ctx, f.person, base, 8*24*time.Hour); !errors.Is(err, nexus.ErrInvalid) {
		t.Fatal("ttl over 7 days accepted:", err)
	}
	wrong := base
	wrong.Receiver = f.other.SessionID // the delegation belongs to another session
	if _, err := f.svc.IssueExecutionGrant(f.ctx, f.person, wrong, time.Hour); !errors.Is(err, nexus.ErrForbidden) {
		t.Fatal(err)
	}
}

func TestExecutionGrantAllowsOnlyInsideScopeAndCountsTurnsPerMessage(t *testing.T) {
	f := newGrantFixture(t)
	g := f.grant(t, 2)
	m1 := f.send(t, f.sender, "please fix the test")
	if d := f.decide(t, g, m1, "tool:edit_file", "/repo/x/a.go"); d.Effect != "allow" || d.Turn != 1 || d.TurnsLeft != 1 {
		t.Fatal(d)
	}
	if d := f.decide(t, g, m1, "tool:run_tests", "/repo/x"); d.Effect != "allow" || d.Turn != 1 {
		t.Fatal("the same message must not use another turn:", d)
	}
	if d := f.decide(t, g, m1, "tool:edit_file", "/repo/xy/a.go"); d.Effect != "ask" || d.Reason != "path outside the grant" {
		t.Fatal(d)
	}
	if d := f.decide(t, g, m1, "tool:shell", "/repo/x"); d.Effect != "ask" || d.Reason != "tool outside the grant" {
		t.Fatal(d)
	}
	if d := f.decide(t, g, m1, "tool:purchase", "/repo/x"); d.Effect != "ask" || !strings.Contains(d.Reason, "policy") {
		t.Fatal("the delegation's own ask rule must still apply:", d)
	}
	m2 := f.send(t, f.sender, "next")
	if d := f.decide(t, g, m2, "tool:edit_file", "/tmp/build.log"); d.Effect != "allow" || d.Turn != 2 || d.TurnsLeft != 0 {
		t.Fatal(d)
	}
	m3 := f.send(t, f.sender, "one more")
	if d := f.decide(t, g, m3, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" || d.Reason != "turn limit reached" {
		t.Fatal(d)
	}
	list, err := f.svc.ExecutionGrants(f.ctx, f.person, f.receiver.SessionID)
	if err != nil || len(list) != 1 || list[0].Status != "exhausted" || list[0].TurnsUsed != 2 {
		t.Fatal(list, err)
	}
	// every judgement is in the receiver's ledger
	var decided int
	_ = f.store.View(nexus.WithAccount(f.ctx, f.person.AccountID), func(tx nexus.Tx) error {
		events, _ := tx.Events(f.receiver.SessionID, 0, 0)
		for _, e := range events {
			if e.Kind == "execution_grant.decided" {
				decided++
			}
		}
		return nil
	})
	if decided != 7 {
		t.Fatal("decided events:", decided)
	}
}

func TestExecutionGrantRefusesForgedOrForeignSources(t *testing.T) {
	f := newGrantFixture(t)
	early := f.send(t, f.sender, "sent before the grant")
	g := f.grant(t, 5)
	if d := f.decide(t, g, early, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" || d.Reason != "message predates the grant" {
		t.Fatal(d)
	}
	foreign := f.send(t, f.other, "I am not granted")
	if d := f.decide(t, g, foreign, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" {
		t.Fatal(d)
	}
	fromPerson := f.send(t, f.person, "person mail is not a grant source")
	if d := f.decide(t, g, fromPerson, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" {
		t.Fatal(d)
	}
	ok := f.send(t, f.sender, "real")
	wrongSeq := ok
	wrongSeq.Seq = foreign.Seq // a granted event id with another event's position
	if d := f.decide(t, g, wrongSeq, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" || d.Reason != "source message not found" {
		t.Fatal(d)
	}
	// only the receiving session asks, and only about its own ledger
	if _, err := f.svc.DecideExecutionGrant(f.ctx, f.sender, g.ID, nexus.GrantDecisionInput{SourceEvent: ok.Event, SourceSeq: ok.Seq,
		Action: "tool:edit_file", Paths: []string{"/repo/x/a.go"}, InputHash: strings.Repeat("b", 64)}); err == nil {
		t.Fatal("another session decided on the receiver's grant")
	}
	if _, err := f.svc.DecideExecutionGrant(f.ctx, f.receiver, g.ID, nexus.GrantDecisionInput{SourceEvent: ok.Event, SourceSeq: ok.Seq,
		Action: "tool:edit_file", Paths: []string{"/repo/x/../../etc/passwd"}, InputHash: strings.Repeat("b", 64)}); !errors.Is(err, nexus.ErrInvalid) {
		t.Fatal("unclean path accepted:", err)
	}
}

func TestExecutionGrantEndsOnRevokeExpiryOrDelegationRevoke(t *testing.T) {
	f := newGrantFixture(t)
	g := f.grant(t, 10)
	m := f.send(t, f.sender, "go")
	if _, err := f.svc.RevokeExecutionGrant(f.ctx, f.other, f.receiver.SessionID, g.ID, "not mine"); !errors.Is(err, nexus.ErrForbidden) {
		t.Fatal(err)
	}
	if out, err := f.svc.RevokeExecutionGrant(f.ctx, f.receiver, f.receiver.SessionID, g.ID, "done"); err != nil || out.Status != "revoked" {
		t.Fatal(out, err)
	}
	if d := f.decide(t, g, m, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" || d.Reason != "grant revoked" {
		t.Fatal(d)
	}
	g2 := f.grant(t, 10)
	m2 := f.send(t, f.sender, "again")
	*f.now = f.now.Add(9 * time.Hour)
	if d := f.decide(t, g2, m2, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" || d.Reason != "grant expired" {
		t.Fatal(d)
	}
	g3 := f.grant(t, 10)
	m3 := f.send(t, f.sender, "third")
	if _, err := f.svc.Revoke(f.ctx, f.person, f.recvDel, "stop"); err != nil {
		t.Fatal(err)
	}
	if d := f.decide(t, g3, m3, "tool:edit_file", "/repo/x/a.go"); d.Effect != "deny" {
		t.Fatal("a grant outlived its delegation:", d)
	}
}
