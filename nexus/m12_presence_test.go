package nexus_test

// M12: a session that says it stopped stays stopped until a process works as
// it again. Neither a late heartbeat nor an HTTP request revives it, and coming
// back changes nothing but the status: same ledger, same grants, same
// approvals.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

type m12Fixture struct {
	ctx    context.Context
	now    time.Time
	store  nexus.Store
	svc    *nexus.Service
	person nexus.Principal
	actor  nexus.Principal
	root   nexus.Issued
}

func m12Setup(t *testing.T) *m12Fixture {
	t.Helper()
	f := &m12Fixture{ctx: context.Background(), now: time.Now().UTC(), store: nexus.NewMemStore()}
	f.svc = nexus.NewService(f.store, func() time.Time { return f.now })
	f.person = nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "owner@example.test")
	root, err := f.svc.CreateRoot(f.ctx, f.person, nexus.RootRequest{Title: "test", Scope: []string{"newtype:run"}, Limits: nexus.Limits{ModelTokens: 100, SubSessions: 2}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	f.root = root
	f.actor = nexus.SessionPrincipal(f.person.AccountID, root.Session.ID)
	if _, err := f.svc.SetSessionStatus(f.ctx, f.actor, root.Session.ID, nexus.SessionRunning); err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *m12Fixture) session(t *testing.T) nexus.Session {
	t.Helper()
	s, err := f.svc.Session(f.ctx, f.person, f.root.Session.ID)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// kinds returns the ledger event kinds after a sequence number.
func (f *m12Fixture) kinds(t *testing.T, after int64) ([]string, int64) {
	t.Helper()
	events, tail, err := f.svc.Events(f.ctx, f.person, f.root.Session.ID, after, 100)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range events {
		out = append(out, e.Kind)
	}
	return out, tail
}

func TestM12LeaveStopsOnlyOwnedSessions(t *testing.T) {
	f := m12Setup(t)
	_, before := f.kinds(t, 0)

	// A second session in the account: the leaving one must not be able to
	// stop it.
	peer := attachedWorker(t, f.store, f.person.AccountID, f.now)
	if _, err := f.svc.SetSessionStatus(f.ctx, f.actor, peer, nexus.SessionStopped); !errors.Is(err, nexus.ErrForbidden) {
		t.Fatalf("session stopped a peer: %v", err)
	}
	// Nor a session in another account, nor mark itself done.
	stranger := nexus.SessionPrincipal(ids.Account(ids.New(ids.KindAccount)), f.root.Session.ID)
	if _, err := f.svc.SetSessionStatus(f.ctx, stranger, f.root.Session.ID, nexus.SessionStopped); err == nil {
		t.Fatal("another account stopped the session")
	}
	if _, err := f.svc.SetSessionStatus(f.ctx, f.actor, f.root.Session.ID, nexus.SessionDone); !errors.Is(err, nexus.ErrForbidden) {
		t.Fatalf("session marked itself done: %v", err)
	}

	// The session reports that its runner is leaving.
	s, err := f.svc.SetSessionStatus(f.ctx, f.actor, f.root.Session.ID, nexus.SessionStopped)
	if err != nil {
		t.Fatal(err)
	}
	if s.Status != nexus.SessionStopped || s.StoppedBy != nexus.PrincipalSession {
		t.Fatalf("leave should record a stop by the session itself, got %s/%s", s.Status, s.StoppedBy)
	}
	kinds, _ := f.kinds(t, before)
	if len(kinds) != 1 || kinds[0] != "session.status" {
		t.Fatalf("leave should write exactly one status event, got %v", kinds)
	}
	// The peer is untouched.
	var peerSession nexus.Session
	if err := f.store.View(f.ctx, func(tx nexus.Tx) error {
		all, err := tx.SessionsByAccount(f.person.AccountID)
		for _, x := range all {
			if x.ID == peer {
				peerSession = x
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if peerSession.Status != nexus.SessionWaiting {
		t.Fatalf("peer status changed to %s", peerSession.Status)
	}

	// Leaving twice is idempotent: no second event.
	_, after := f.kinds(t, 0)
	if _, err := f.svc.SetSessionStatus(f.ctx, f.actor, f.root.Session.ID, nexus.SessionStopped); err != nil {
		t.Fatal(err)
	}
	if kinds, _ := f.kinds(t, after); len(kinds) != 0 {
		t.Fatalf("repeated leave wrote %v", kinds)
	}

	// Presence does not undo an explicit stop: a late heartbeat from a process
	// that is on its way out (or a request from a still-open stream) is not a
	// runner coming back. Only a system stop is restored by Touch.
	f.now = f.now.Add(2 * nexus.PresenceWrite)
	if err := f.svc.Touch(f.ctx, f.actor); err != nil {
		t.Fatal(err)
	}
	s = f.session(t)
	if s.Status != nexus.SessionStopped || s.StoppedBy != nexus.PrincipalSession {
		t.Fatalf("heartbeat revived a session that left: %s/%s", s.Status, s.StoppedBy)
	}
	if kinds, _ := f.kinds(t, after); len(kinds) != 0 {
		t.Fatalf("heartbeat on a left session wrote %v", kinds)
	}
	// And the sweep leaves it alone too (no archive before ArchiveAfter, no
	// re-stop event).
	if _, err := f.svc.Sweep(f.ctx, f.now.Add(-time.Hour), nexus.PresenceGrace, nexus.ArchiveAfter); err != nil {
		t.Fatal(err)
	}
	if kinds, _ := f.kinds(t, after); len(kinds) != 0 {
		t.Fatalf("sweep rewrote a left session: %v", kinds)
	}
}

func TestM12LeaveDoesNotRestoreAuthority(t *testing.T) {
	f := m12Setup(t)
	// Something the session holds before leaving: its root delegation and
	// its reserved budget.
	infoBefore, err := f.svc.DelegationInfo(f.ctx, f.person, f.root.Delegation.ID)
	if err != nil {
		t.Fatal(err)
	}
	delegationBefore := infoBefore.Delegation
	usageBefore := f.usage(t)

	// Leave, then come back as the same session.
	if _, err := f.svc.SetSessionStatus(f.ctx, f.actor, f.root.Session.ID, nexus.SessionStopped); err != nil {
		t.Fatal(err)
	}
	_, mark := f.kinds(t, 0)
	back, err := f.svc.SetSessionStatus(f.ctx, f.actor, f.root.Session.ID, nexus.SessionRunning)
	if err != nil {
		t.Fatal(err)
	}
	if back.Status != nexus.SessionRunning || back.StoppedBy != "" || back.ID != f.root.Session.ID {
		t.Fatalf("return should run the same session, got %+v", back)
	}
	// Coming back is one status event; it creates or revives nothing else.
	kinds, _ := f.kinds(t, mark)
	if len(kinds) != 1 || kinds[0] != "session.status" {
		t.Fatalf("return wrote %v, want one session.status", kinds)
	}
	infoAfter, err := f.svc.DelegationInfo(f.ctx, f.person, f.root.Delegation.ID)
	if err != nil {
		t.Fatal(err)
	}
	delegationAfter := infoAfter.Delegation
	if delegationAfter.ID != delegationBefore.ID || delegationAfter.EndedAt != nil || !delegationAfter.ExpiresAt.Equal(delegationBefore.ExpiresAt) || len(delegationAfter.Scope) != len(delegationBefore.Scope) || infoAfter.Remaining != infoBefore.Remaining {
		t.Fatalf("delegation changed across leave/return:\n%+v\n%+v", infoBefore, infoAfter)
	}
	if f.usage(t) != usageBefore {
		t.Fatalf("budget changed across leave/return: %+v vs %+v", usageBefore, f.usage(t))
	}

	// Authority that ended while the session was away stays ended: the
	// session cannot come back as running once its chain is revoked.
	if _, err := f.svc.SetSessionStatus(f.ctx, f.actor, f.root.Session.ID, nexus.SessionStopped); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.Revoke(f.ctx, f.person, f.root.Delegation.ID, "owner revoked while away"); err != nil {
		t.Fatal(err)
	}
	if _, err := f.svc.SetSessionStatus(f.ctx, f.actor, f.root.Session.ID, nexus.SessionRunning); !errors.Is(err, nexus.ErrRevoked) {
		t.Fatalf("revoked session came back as running: %v", err)
	}
	// Nor does a heartbeat bring it back.
	f.now = f.now.Add(2 * nexus.PresenceWrite)
	if err := f.svc.Touch(f.ctx, f.actor); err != nil {
		t.Fatal(err)
	}
	if s := f.session(t); s.Status != nexus.SessionStopped {
		t.Fatalf("revoked session revived by presence: %s", s.Status)
	}
}

// TestM12SystemStopStillRestoredByPresence pins the other half of M8 that
// M12 must not break: a stop the presence sweep made (not the session, not
// a user) is undone by the next authenticated request while the chain is
// live — and a stop a user made is not.
func TestM12SystemStopStillRestoredByPresence(t *testing.T) {
	f := m12Setup(t)
	// The runner goes silent; the sweep stops the session.
	f.now = f.now.Add(nexus.PresenceGrace + time.Minute)
	if _, err := f.svc.Sweep(f.ctx, f.now.Add(-time.Hour), nexus.PresenceGrace, nexus.ArchiveAfter); err != nil {
		t.Fatal(err)
	}
	if s := f.session(t); s.Status != nexus.SessionStopped || s.StoppedBy != nexus.PrincipalSystem {
		t.Fatalf("sweep should stop a silent running session, got %s/%s", s.Status, s.StoppedBy)
	}
	// Its next request (the one that opens a stream, for instance) is the
	// runner saying it is back: a system stop is restored to waiting.
	if err := f.svc.Touch(f.ctx, f.actor); err != nil {
		t.Fatal(err)
	}
	if s := f.session(t); s.Status != nexus.SessionWaiting || s.StoppedBy != "" {
		t.Fatalf("system stop should be restored by presence, got %s/%s", s.Status, s.StoppedBy)
	}
	// A user's stop is explicit and stays.
	if _, err := f.svc.SetSessionStatus(f.ctx, f.person, f.root.Session.ID, nexus.SessionStopped); err != nil {
		t.Fatal(err)
	}
	f.now = f.now.Add(2 * nexus.PresenceWrite)
	if err := f.svc.Touch(f.ctx, f.actor); err != nil {
		t.Fatal(err)
	}
	if s := f.session(t); s.Status != nexus.SessionStopped || s.StoppedBy != nexus.PrincipalUser {
		t.Fatalf("user stop undone by presence: %s/%s", s.Status, s.StoppedBy)
	}
}

func (f *m12Fixture) usage(t *testing.T) nexus.Usage {
	t.Helper()
	var usage nexus.Usage
	if err := f.store.View(f.ctx, func(tx nexus.Tx) error {
		var err error
		usage, err = tx.Usage(f.root.Delegation.ID)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return usage
}
