package conformance

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// member issues a root session with a title and gives it presence, as a TUI
// process does with its first request.
func (f *fixture) member(title string) (nexus.Session, nexus.Principal) {
	f.t.Helper()
	req := rootRequest()
	req.Title = title
	issued := f.issue(req)
	p := nexus.SessionPrincipal(f.account, issued.Session.ID)
	must(f.t, f.svc.Touch(context.Background(), p))
	return issued.Session, p
}
func (f *fixture) send(from nexus.Principal, to ids.Session) {
	f.t.Helper()
	_, err := f.svc.Send(context.Background(), from, nexus.Message{To: to, Text: "public fixture"})
	must(f.t, err)
}
func (f *fixture) setStatus(id ids.Session, status nexus.SessionStatus) {
	f.t.Helper()
	must(f.t, f.store.Update(context.Background(), func(tx nexus.Tx) error {
		x, err := tx.Session(id)
		if err != nil {
			return err
		}
		x.Status = status
		return tx.PutSession(x)
	}))
}
func (f *fixture) setTitle(id ids.Session, title string) {
	f.t.Helper()
	must(f.t, f.store.Update(context.Background(), func(tx nexus.Tx) error {
		x, err := tx.Session(id)
		if err != nil {
			return err
		}
		x.Title = title
		return tx.PutSession(x)
	}))
}
func memberIDs(p nexus.TeamPreview) []ids.Session {
	out := []ids.Session{}
	for _, m := range p.Members {
		out = append(out, m.SessionID)
	}
	return out
}
func sortedIDs(in ...ids.Session) []ids.Session {
	out := append([]ids.Session(nil), in...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
func sameIDs(a, b []ids.Session) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

const installA = "install-a-0123456789abcdef"
const installB = "install-b-0123456789abcdef"

// teamOf creates a team from seed through preview + confirm.
func (f *fixture) teamOf(seed ids.Session) nexus.TeamView {
	f.t.Helper()
	ctx := context.Background()
	p, err := f.svc.PreviewTeam(ctx, f.person, seed)
	must(f.t, err)
	v, err := f.svc.CreateTeam(ctx, f.person, seed, "", p.RosterHash)
	must(f.t, err)
	return v
}
func seatOf(v nexus.TeamView, session ids.Session) nexus.SeatView {
	for _, s := range v.Seats {
		if s.SessionID == session {
			return s
		}
	}
	return nexus.SeatView{}
}

func runTeams(t *testing.T, open func() nexus.Store) {
	t.Run("teams_closure_message_exchange", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, pa := f.member("alpha")
		b, pb := f.member("beta")
		c, _ := f.member("gamma")
		f.member("unrelated")               // never exchanged a message
		e, pe := f.member("archived")       // archived: excluded, not traversed
		g, _ := f.member("behind archived") // reachable only through e
		// a delegated container sub-task nobody started: requested, no presence
		never := nexus.Session{ID: ids.Session(ids.New(ids.KindSession)), AccountID: f.account, Kind: nexus.Worker, Runner: nexus.Container, Title: "never started", Status: nexus.SessionRequested, CreatedAt: f.now, UpdatedAt: f.now}
		must(t, f.store.Update(ctx, func(tx nexus.Tx) error { return tx.PutSession(never) }))
		// a local root that never reported presence (a model-only TUI) is live
		quiet, err := f.svc.CreateRoot(ctx, f.person, rootRequest())
		must(t, err)
		f.send(pa, b.ID)
		f.send(pb, c.ID)
		f.send(pa, e.ID)
		f.send(pe, g.ID)
		must(t, f.store.Update(ctx, func(tx nexus.Tx) error { return tx.PutMessageEdge(f.account, a.ID, never.ID, f.now) }))
		f.send(pb, quiet.Session.ID)
		f.setStatus(e.ID, nexus.SessionDone)
		_ = g
		p, err := f.svc.PreviewTeam(ctx, f.person, a.ID)
		must(t, err)
		if want := sortedIDs(a.ID, b.ID, c.ID, quiet.Session.ID); !sameIDs(memberIDs(p), want) {
			t.Fatalf("closure %v want %v", memberIDs(p), want)
		}
		// a quiet local root can seed a team itself
		if _, err := f.svc.PreviewTeam(ctx, f.person, quiet.Session.ID); err != nil {
			t.Fatal("quiet local root refused as seed:", err)
		}
		// the same roster from any member, and a stable hash
		p2, err := f.svc.PreviewTeam(ctx, f.person, c.ID)
		must(t, err)
		if !sameIDs(memberIDs(p2), memberIDs(p)) {
			t.Fatal("closure depends on seed", memberIDs(p2))
		}
		// a person's message does not join sessions
		lone, _ := f.member("person only")
		_, err = f.svc.Tell(ctx, f.person, lone.ID, "public fixture")
		must(t, err)
		p3, err := f.svc.PreviewTeam(ctx, f.person, lone.ID)
		must(t, err)
		if len(p3.Members) != 1 {
			t.Fatal("person message joined sessions", memberIDs(p3))
		}
		_, err = f.svc.PreviewTeam(ctx, f.person, e.ID)
		wantErr(t, err, nexus.ErrInvalid)
	})

	// 2026-10-05: /team create listed six stopped "nmcp" sessions left by TUI
	// restarts and a stopped "slave app" next to the live ones. Only live
	// sessions are members or hops; an explicit list narrows the live chain.
	t.Run("teams_live_only_and_explicit_members", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		cn, _ := f.member("claude-newtype")
		n, pn := f.member("nmcp")
		sa, psa := f.member("slave app")
		op, pop := f.member("operator")
		f.send(pn, cn.ID)
		f.send(psa, cn.ID)
		f.send(pop, cn.ID)
		var old []ids.Session
		for i := 0; i < 6; i++ {
			x, px := f.member(fmt.Sprintf("nmcp restart %d", i))
			f.send(px, cn.ID)
			old = append(old, x.ID)
		}
		sa0, psa0 := f.member("slave app before")
		f.send(psa0, cn.ID)
		behind, _ := f.member("only via stopped") // reachable only through a stopped session
		x0 := nexus.SessionPrincipal(f.account, old[0])
		f.send(x0, behind.ID)
		ghost, pghost := f.member("ghost")
		f.send(pghost, cn.ID)
		for _, id := range old {
			f.setTitle(id, "nmcp") // the namesakes a restart left behind
			f.setStatus(id, nexus.SessionStopped)
		}
		f.setTitle(sa0.ID, "slave app")
		f.setStatus(sa0.ID, nexus.SessionStopped)
		f.setStatus(ghost.ID, nexus.SessionStopped)

		p, err := f.svc.PreviewTeam(ctx, f.person, cn.ID)
		must(t, err)
		if want := sortedIDs(cn.ID, n.ID, sa.ID, op.ID); !sameIDs(memberIDs(p), want) {
			t.Fatalf("live chain %v want %v (stopped sessions and what only they reach are out)", memberIDs(p), want)
		}
		for _, m := range p.Members {
			if m.Status == nexus.SessionStopped || m.Status == nexus.SessionDone {
				t.Fatal("a non-live member in the preview", m)
			}
		}
		// a stopped seed is refused
		_, err = f.svc.PreviewTeam(ctx, f.person, old[0])
		wantErr(t, err, nexus.ErrInvalid)

		// the intended team: names resolve to the one live session of that name
		sel := []string{"nmcp", " Slave App "}
		p2, err := f.svc.PreviewTeamMembers(ctx, f.person, cn.ID, sel)
		must(t, err)
		if want := sortedIDs(cn.ID, n.ID, sa.ID); !sameIDs(memberIDs(p2), want) {
			t.Fatalf("explicit %v want %v", memberIDs(p2), want)
		}
		if p2.RosterHash == p.RosterHash {
			t.Fatal("the explicit roster has the whole chain's hash")
		}
		// a session ID works too, the seed is implied, repeats collapse
		p3, err := f.svc.PreviewTeamMembers(ctx, f.person, cn.ID, []string{string(sa.ID), "nmcp", string(cn.ID), "NMCP"})
		must(t, err)
		if p3.RosterHash != p2.RosterHash {
			t.Fatal("the same members by ID and name give another roster")
		}

		// refusals name the entry by position
		other := nexus.Session{ID: ids.Session(ids.New(ids.KindSession)), AccountID: ids.Account(ids.New(ids.KindAccount)), Kind: nexus.Worker, Runner: nexus.Local, Title: "foreign", Status: nexus.SessionRunning, CreatedAt: f.now, UpdatedAt: f.now}
		must(t, f.store.Update(ctx, func(tx nexus.Tx) error { return tx.PutSession(other) }))
		twin1, pt1 := f.member("twin")
		twin2, pt2 := f.member("twin second")
		f.setTitle(twin2.ID, "twin")
		f.send(pt1, cn.ID)
		f.send(pt2, cn.ID)
		f.member("unrelated")
		for _, tc := range []struct {
			list  []string
			index int
			want  error
		}{
			{[]string{"nmcp", string(other.ID)}, 1, nexus.ErrMemberNotFound}, // another account: as if absent
			{[]string{"foreign"}, 0, nexus.ErrMemberNotFound},
			{[]string{"no such session"}, 0, nexus.ErrMemberNotFound},
			{[]string{string(old[2])}, 0, nexus.ErrMemberNotLive},
			{[]string{"ghost"}, 0, nexus.ErrMemberNotLive}, // only a stopped session has that name
			{[]string{"nmcp", "twin"}, 1, nexus.ErrMemberAmbiguous},
			{[]string{"unrelated"}, 0, nexus.ErrMemberNotConnected},
			{[]string{"only via stopped"}, 0, nexus.ErrMemberNotConnected},
			{[]string{"nmcp", " "}, 1, nexus.ErrInvalid},
		} {
			_, err := f.svc.PreviewTeamMembers(ctx, f.person, cn.ID, tc.list)
			var me *nexus.TeamMemberError
			if !errors.As(err, &me) || me.Index != tc.index || !errors.Is(err, tc.want) {
				t.Fatalf("%q: %v (want %v at %d)", tc.list, err, tc.want, tc.index)
			}
			_, err = f.svc.CreateTeamMembers(ctx, f.person, cn.ID, "", p2.RosterHash, tc.list)
			if !errors.Is(err, tc.want) {
				t.Fatalf("create %q: %v", tc.list, err)
			}
		}
		// the ambiguous name is resolved by its ID
		if _, err := f.svc.PreviewTeamMembers(ctx, f.person, cn.ID, []string{string(twin1.ID)}); err != nil {
			t.Fatal("twin by ID:", err)
		}
		_, err = f.svc.PreviewTeamMembers(ctx, f.person, cn.ID, make([]string, nexus.TeamMax+1))
		wantErr(t, err, nexus.ErrClosureTooLarge)

		// create uses the same list: another list, or a member that changed
		// since the preview, is 409 roster_changed
		_, err = f.svc.CreateTeamMembers(ctx, f.person, cn.ID, "", p2.RosterHash, []string{"nmcp"})
		wantErr(t, err, nexus.ErrRosterChanged)
		_, err = f.svc.CreateTeamMembers(ctx, f.person, cn.ID, "", p2.RosterHash, nil)
		wantErr(t, err, nexus.ErrRosterChanged)
		f.setStatus(sa.ID, nexus.SessionWaiting)
		_, err = f.svc.CreateTeamMembers(ctx, f.person, cn.ID, "", p2.RosterHash, sel)
		wantErr(t, err, nexus.ErrRosterChanged)
		if teams, _ := f.svc.Teams(ctx, f.person); len(teams) != 0 {
			t.Fatal("team created from a stale roster")
		}
		p2, err = f.svc.PreviewTeamMembers(ctx, f.person, cn.ID, sel)
		must(t, err)
		v, err := f.svc.CreateTeamMembers(ctx, f.person, cn.ID, "newtype", p2.RosterHash, sel)
		must(t, err)
		got := []ids.Session{}
		for _, s := range v.Seats {
			got = append(got, s.SessionID)
		}
		sort.Slice(got, func(i, j int) bool { return got[i] < got[j] })
		if v.Team.Name != "newtype" || !sameIDs(got, sortedIDs(cn.ID, n.ID, sa.ID)) {
			t.Fatalf("team %q seats %v", v.Team.Name, got)
		}
		// a stopped member still reattaches to its seat (a TUI restart)
		f.setStatus(n.ID, nexus.SessionStopped)
		at, err := f.svc.AttachSeat(ctx, f.person, v.Team.ID, seatOf(v, n.ID).ID, installA, "")
		must(t, err)
		if !at.Reattachable || at.SessionID != n.ID {
			t.Fatalf("stopped member not reattachable: %+v", at)
		}
	})

	t.Run("teams_person_only_create", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, pa := f.member("alpha")
		b, pb := f.member("beta")
		f.send(pa, b.ID)
		_, err := f.svc.PreviewTeam(ctx, pa, a.ID)
		wantErr(t, err, nexus.ErrForbidden)
		p, err := f.svc.PreviewTeam(ctx, f.person, a.ID)
		must(t, err)
		_, err = f.svc.CreateTeam(ctx, pb, a.ID, "", p.RosterHash)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.CreateTeam(ctx, nexus.SystemPrincipal(f.account), a.ID, "", p.RosterHash)
		wantErr(t, err, nexus.ErrForbidden)
		v, err := f.svc.CreateTeam(ctx, f.person, a.ID, "the team", p.RosterHash)
		must(t, err)
		if v.Team.CreatedBy != f.person.Email || v.Team.Name != "the team" || len(v.Seats) != 2 {
			t.Fatal(v)
		}
		seat := seatOf(v, a.ID)
		_, err = f.svc.AddSeat(ctx, pa, v.Team.ID, "extra")
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.AttachSeat(ctx, pa, v.Team.ID, seat.ID, installA, "")
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.LastTeam(ctx, pa, installA)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.RebindSeat(ctx, pa, v.Team.ID, seat.ID, "x", 1, a.ID)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.RenewSeat(ctx, f.person, v.Team.ID, seat.ID, "x", 1)
		wantErr(t, err, nexus.ErrForbidden)
	})

	t.Run("teams_account_isolation", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, pa := f.member("alpha")
		b, _ := f.member("beta")
		f.send(pa, b.ID)
		v := f.teamOf(a.ID)
		other := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "other@example.com")
		_, err := f.svc.PreviewTeam(ctx, other, a.ID)
		wantErr(t, err, nexus.ErrNotFound)
		_, err = f.svc.TeamRoster(ctx, other, v.Team.ID)
		wantErr(t, err, nexus.ErrNotFound)
		_, err = f.svc.AttachSeat(ctx, other, v.Team.ID, v.Seats[0].ID, installA, "")
		wantErr(t, err, nexus.ErrNotFound)
		_, err = f.svc.AddSeat(ctx, other, v.Team.ID, "x")
		wantErr(t, err, nexus.ErrNotFound)
		teams, err := f.svc.Teams(ctx, other)
		must(t, err)
		if len(teams) != 0 {
			t.Fatal("other account sees teams", teams)
		}
		// a session outside the team cannot read its roster either
		_, outsider := f.member("outsider")
		_, err = f.svc.TeamRoster(ctx, outsider, v.Team.ID)
		wantErr(t, err, nexus.ErrNotFound)
		if _, err := f.svc.TeamRoster(ctx, pa, v.Team.ID); err != nil {
			t.Fatal("member cannot read its roster", err)
		}
	})

	t.Run("teams_roster_hash_recheck", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, pa := f.member("alpha")
		b, pb := f.member("beta")
		c, _ := f.member("gamma")
		f.send(pa, b.ID)
		p, err := f.svc.PreviewTeam(ctx, f.person, a.ID)
		must(t, err)
		f.send(pb, c.ID) // the closure grows after the person saw it
		_, err = f.svc.CreateTeam(ctx, f.person, a.ID, "", p.RosterHash)
		wantErr(t, err, nexus.ErrRosterChanged)
		_, err = f.svc.CreateTeam(ctx, f.person, a.ID, "", "sha256:"+strings.Repeat("0", 64))
		wantErr(t, err, nexus.ErrRosterChanged)
		teams, _ := f.svc.Teams(ctx, f.person)
		if len(teams) != 0 {
			t.Fatal("team created from a stale roster")
		}
		p, err = f.svc.PreviewTeam(ctx, f.person, a.ID)
		must(t, err)
		v, err := f.svc.CreateTeam(ctx, f.person, a.ID, "", p.RosterHash)
		must(t, err)
		if len(v.Seats) != 3 {
			t.Fatal(v.Seats)
		}
	})

	t.Run("teams_one_team_per_session", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, pa := f.member("alpha")
		b, _ := f.member("beta")
		f.send(pa, b.ID)
		first := f.teamOf(a.ID)
		second := f.teamOf(a.ID)
		if first.Team.ID == second.Team.ID {
			t.Fatal("same team")
		}
		old, err := f.svc.TeamRoster(ctx, f.person, first.Team.ID)
		must(t, err)
		for _, s := range old.Seats {
			if s.State != nexus.SeatMoved || s.MovedTo != second.Team.ID {
				t.Fatalf("old seat not moved: %+v", s)
			}
		}
		must(t, f.store.View(ctx, func(tx nexus.Tx) error {
			seat, err := tx.ActiveSeatBySession(f.account, a.ID)
			if err != nil || seat.TeamID != second.Team.ID {
				t.Fatalf("active seat %+v %v", seat, err)
			}
			return nil
		}))
		// the store itself refuses a second active seat for one session
		err = f.store.Update(ctx, func(tx nexus.Tx) error {
			return tx.PutSeat(nexus.Seat{ID: ids.Seat(ids.New(ids.KindSeat)), TeamID: first.Team.ID, AccountID: f.account, Name: "dup", SessionID: a.ID, State: nexus.SeatActive, CreatedAt: f.now, UpdatedAt: f.now})
		})
		if err == nil {
			t.Fatal("second active seat for one session accepted")
		}
	})

	t.Run("teams_seat_lease_single_attach", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, pa := f.member("alpha")
		b, pb := f.member("beta")
		f.send(pa, b.ID)
		v := f.teamOf(a.ID)
		seat := seatOf(v, a.ID)
		got, err := f.svc.AttachSeat(ctx, f.person, v.Team.ID, seat.ID, installA, "")
		must(t, err)
		if !got.Reattachable || got.SessionID != a.ID || got.LeaseToken == "" || got.Epoch != 1 {
			t.Fatalf("attach %+v", got)
		}
		_, err = f.svc.AttachSeat(ctx, f.person, v.Team.ID, seat.ID, installB, "")
		wantErr(t, err, nexus.ErrSeatAttached)
		_, err = f.svc.AttachSeat(ctx, f.person, v.Team.ID, seat.ID, installA, "") // same install, no token
		wantErr(t, err, nexus.ErrSeatAttached)
		// the same installation's successor (restart within the grace) takes over at once
		next, err := f.svc.AttachSeat(ctx, f.person, v.Team.ID, seat.ID, installA, got.LeaseToken)
		must(t, err)
		if next.Epoch != 2 || next.LeaseToken == got.LeaseToken {
			t.Fatalf("handover %+v", next)
		}
		_, err = f.svc.RenewSeat(ctx, pa, v.Team.ID, seat.ID, got.LeaseToken, got.Epoch) // the old holder
		wantErr(t, err, nexus.ErrLeaseLost)
		_, err = f.svc.RenewSeat(ctx, pb, v.Team.ID, seat.ID, next.LeaseToken, next.Epoch) // another session
		wantErr(t, err, nexus.ErrLeaseLost)
		f.now = f.now.Add(nexus.SeatLeaseTTL / 2)
		renewed, err := f.svc.RenewSeat(ctx, pa, v.Team.ID, seat.ID, next.LeaseToken, next.Epoch)
		must(t, err)
		if !renewed.ExpiresAt.Equal(f.now.Add(nexus.SeatLeaseTTL)) || renewed.LeaseToken != "" {
			t.Fatalf("renew %+v", renewed)
		}
		must(t, f.svc.ReleaseSeat(ctx, pa, v.Team.ID, seat.ID, next.LeaseToken, next.Epoch))
		wantErr(t, f.svc.ReleaseSeat(ctx, pa, v.Team.ID, seat.ID, next.LeaseToken, next.Epoch), nexus.ErrLeaseLost)
		// concurrent attach to a free seat: exactly one holder
		var wg sync.WaitGroup
		var mu sync.Mutex
		wins := 0
		for i := 0; i < 8; i++ {
			wg.Add(1)
			go func(i int) {
				defer wg.Done()
				_, err := f.svc.AttachSeat(ctx, f.person, v.Team.ID, seat.ID, "install-race-0123456789-"+string(rune('a'+i)), "")
				mu.Lock()
				defer mu.Unlock()
				if err == nil {
					wins++
				} else if !errors.Is(err, nexus.ErrSeatAttached) {
					t.Errorf("race attach: %v", err)
				}
			}(i)
		}
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d concurrent holders", wins)
		}
		// an expired lease lets another installation attach
		f.now = f.now.Add(nexus.SeatLeaseTTL + time.Second)
		if _, err := f.svc.AttachSeat(ctx, f.person, v.Team.ID, seat.ID, installB, ""); err != nil {
			t.Fatal("attach after expiry", err)
		}
	})

	t.Run("teams_seat_replace_only_done", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, pa := f.member("alpha")
		b, pb := f.member("beta")
		f.send(pa, b.ID)
		v := f.teamOf(a.ID)
		seat := seatOf(v, a.ID)
		for _, st := range []nexus.SessionStatus{nexus.SessionRunning, nexus.SessionStopped, nexus.SessionWaiting} {
			f.setStatus(a.ID, st)
			got, err := f.svc.AttachSeat(ctx, f.person, v.Team.ID, seat.ID, installA, "")
			must(t, err)
			if !got.Reattachable || got.SessionID != a.ID {
				t.Fatalf("%s: %+v", st, got)
			}
			fresh, _ := f.member("alpha again")
			_, err = f.svc.RebindSeat(ctx, f.person, v.Team.ID, seat.ID, got.LeaseToken, got.Epoch, fresh.ID)
			wantErr(t, err, nexus.ErrConflict)
			must(t, f.svc.ReleaseSeat(ctx, f.person, v.Team.ID, seat.ID, got.LeaseToken, got.Epoch))
		}
		f.setStatus(a.ID, nexus.SessionSuspended)
		_, err := f.svc.AttachSeat(ctx, f.person, v.Team.ID, seat.ID, installA, "")
		wantErr(t, err, nexus.ErrForbidden)
		f.setStatus(a.ID, nexus.SessionDone)
		got, err := f.svc.AttachSeat(ctx, f.person, v.Team.ID, seat.ID, installA, "")
		must(t, err)
		if got.Reattachable {
			t.Fatal("archived session offered for reattach")
		}
		before, _, err := f.svc.Inbox(ctx, pb, 0, 100)
		must(t, err)
		fresh, _ := f.member("alpha")
		sv, err := f.svc.RebindSeat(ctx, f.person, v.Team.ID, seat.ID, got.LeaseToken, got.Epoch, fresh.ID)
		must(t, err)
		if sv.SessionID != fresh.ID || len(sv.Previous) != 1 || sv.Previous[0] != a.ID {
			t.Fatalf("rebind %+v", sv)
		}
		roster, err := f.svc.TeamRoster(ctx, pb, v.Team.ID)
		must(t, err)
		if seatOf(roster, fresh.ID).ID != seat.ID {
			t.Fatal("other members do not see the new session")
		}
		events, _, err := f.svc.Events(ctx, f.person, b.ID, 0, 200)
		must(t, err)
		if !hasHubKind(events, "team.seat.replaced") {
			t.Fatal("no replaced notice")
		}
		after, _, err := f.svc.Inbox(ctx, pb, 0, 100)
		must(t, err)
		if len(after) != len(before) {
			t.Fatal("team notice entered the inbox")
		}
	})

	t.Run("teams_last_joined_install", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, pa := f.member("alpha")
		b, _ := f.member("beta")
		f.send(pa, b.ID)
		v := f.teamOf(a.ID)
		_, err := f.svc.LastTeam(ctx, f.person, installA)
		wantErr(t, err, nexus.ErrNotFound)
		seat := seatOf(v, b.ID)
		_, err = f.svc.AttachSeat(ctx, f.person, v.Team.ID, seat.ID, installA, "")
		must(t, err)
		last, err := f.svc.LastTeam(ctx, f.person, installA)
		must(t, err)
		if last.TeamID != v.Team.ID || last.SeatID != seat.ID || last.Install == installA {
			t.Fatalf("last %+v", last)
		}
		_, err = f.svc.LastTeam(ctx, f.person, installB)
		wantErr(t, err, nexus.ErrNotFound)
		for _, bad := range []string{"", "short", strings.Repeat("x", 200), "has space 0123456789"} {
			_, err = f.svc.LastTeam(ctx, f.person, bad)
			wantErr(t, err, nexus.ErrInvalid)
		}
	})

	t.Run("teams_hub_events_not_inbox", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, pa := f.member("alpha")
		b, pb := f.member("beta")
		f.send(pb, a.ID)
		before, _, err := f.svc.Inbox(ctx, pa, 0, 100)
		must(t, err)
		v := f.teamOf(a.ID)
		for _, s := range []ids.Session{a.ID, b.ID} {
			events, _, err := f.svc.Events(ctx, f.person, s, 0, 200)
			must(t, err)
			if !hasHubKind(events, "team.joined") {
				t.Fatal("no team.joined on", s)
			}
		}
		after, _, err := f.svc.Inbox(ctx, pa, 0, 100)
		must(t, err)
		if len(after) != len(before) {
			t.Fatal("team event entered the inbox")
		}
		_, err = f.svc.AttachSeat(ctx, f.person, v.Team.ID, seatOf(v, a.ID).ID, installA, "")
		must(t, err)
		events, _, err := f.svc.Events(ctx, f.person, b.ID, 0, 200)
		must(t, err)
		for _, e := range events {
			if strings.HasPrefix(e.Kind, "team.") && nexus.ForInbox(e) {
				t.Fatal("team event is an inbox item", e.Kind)
			}
		}
		if !hasHubKind(events, "team.seat.reattached") {
			t.Fatal("no reattached notice")
		}
		// a client cannot forge a trusted team record
		_, err = f.svc.AppendEvents(ctx, pa, a.ID, []nexus.EventInput{{Kind: "team.joined", Source: "hub", Payload: json.RawMessage(`{}`)}})
		wantErr(t, err, nexus.ErrForbidden)
	})

	t.Run("teams_no_authority_or_secret_fields", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, pa := f.member("alpha")
		b, _ := f.member("beta")
		f.send(pa, b.ID)
		v := f.teamOf(a.ID)
		seat := seatOf(v, a.ID)
		got, err := f.svc.AttachSeat(ctx, f.person, v.Team.ID, seat.ID, installA, "")
		must(t, err)
		roster, err := f.svc.TeamRoster(ctx, pa, v.Team.ID)
		must(t, err)
		raw, _ := json.Marshal(roster)
		for _, banned := range []string{got.LeaseToken, installA, "verifier", "install", "scope", "max_depth", "approval", "budget", "lease_token"} {
			if strings.Contains(string(raw), banned) {
				t.Fatalf("roster carries %q: %s", banned, raw)
			}
		}
		var shape struct {
			Team  map[string]any   `json:"team"`
			Seats []map[string]any `json:"seats"`
		}
		must(t, json.Unmarshal(raw, &shape))
		wantKeys(t, shape.Team, "account_id", "created_at", "created_by", "id", "name")
		for _, s := range shape.Seats {
			for k := range s {
				switch k {
				case "id", "name", "session_id", "session_status", "state", "moved_to", "previous", "attached":
				default:
					t.Fatalf("seat key %q", k)
				}
			}
		}
		if !roster.Seats[0].Attached && !roster.Seats[1].Attached {
			t.Fatal("attached seat not shown")
		}
		// the stored lease keeps only hashes
		must(t, f.store.View(ctx, func(tx nexus.Tx) error {
			s, err := tx.Seat(seat.ID)
			if err != nil {
				return err
			}
			if s.Lease.Verifier == got.LeaseToken || s.Lease.Install == installA || len(s.Lease.Verifier) != 64 {
				t.Fatalf("lease stored in plain form: %+v", s.Lease)
			}
			return nil
		}))
	})

	t.Run("teams_seat_name_addressing", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, pa := f.member("alpha")
		b, pb := f.member("beta")
		f.send(pa, b.ID)
		f.teamOf(a.ID)
		outsider, _ := f.member("beta") // same title outside the team
		got, err := f.svc.ResolveSession(ctx, pa, "BETA")
		must(t, err)
		if got != b.ID {
			t.Fatalf("seat name resolved to %s want %s (outsider %s)", got, b.ID, outsider.ID)
		}
		// a stopped seat session still receives: its inbox waits for the restart
		f.setStatus(b.ID, nexus.SessionStopped)
		got, err = f.svc.ResolveSession(ctx, pa, "beta")
		must(t, err)
		if got != b.ID {
			t.Fatal("stopped seat not addressed", got)
		}
		if _, err := f.svc.SendTo(ctx, pa, "beta", nexus.Message{Text: "public fixture"}); err != nil {
			t.Fatal("send to stopped seat:", err)
		}
		// an archived seat session falls back to the ordinary name rules
		f.setStatus(b.ID, nexus.SessionDone)
		got, err = f.svc.ResolveSession(ctx, pa, "beta")
		must(t, err)
		if got != outsider.ID {
			t.Fatal("archived seat still addressed", got)
		}
		// a session outside any team keeps the ordinary rules
		_, po := f.member("loner")
		_ = pb
		if _, err := f.svc.ResolveSession(ctx, po, "alpha"); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("teams_review_round1", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		// generated seat names never collide with a member's own title
		a, pa := f.member("dev")
		b, _ := f.member("dev")
		c, _ := f.member("dev #2")
		f.send(pa, b.ID)
		f.send(pa, c.ID)
		v := f.teamOf(a.ID)
		names := map[string]bool{}
		for _, s := range v.Seats {
			if names[strings.ToLower(s.Name)] {
				t.Fatalf("duplicate seat name %q in %+v", s.Name, v.Seats)
			}
			names[strings.ToLower(s.Name)] = true
		}
		if seatOf(v, c.ID).Name != "dev #2" {
			t.Fatal("member lost its own title", seatOf(v, c.ID).Name)
		}
		// an observer session never takes a seat (it could not be reattached or replaced)
		w, pw := f.member("worker")
		observer, err := f.svc.CreateObserver(ctx, f.person, nexus.RootRequest{Title: "observer", Runner: nexus.Local, Scope: []string{"observe:progress"}})
		must(t, err)
		must(t, f.svc.Touch(ctx, nexus.SessionPrincipal(f.account, observer.Session.ID)))
		f.send(pw, observer.Session.ID)
		p, err := f.svc.PreviewTeam(ctx, f.person, w.ID)
		must(t, err)
		if len(p.Members) != 1 || p.Members[0].SessionID != w.ID {
			t.Fatal("observer joined the closure", memberIDs(p))
		}
		_, err = f.svc.PreviewTeam(ctx, f.person, observer.Session.ID)
		wantErr(t, err, nexus.ErrInvalid)
		// excluded neighbors are bounded too: a fixed refusal, not unbounded lookups
		hub, _ := f.member("hub")
		must(t, f.store.Update(ctx, func(tx nexus.Tx) error {
			for i := 0; i < 8*nexus.TeamMax+1; i++ {
				id := ids.Session(ids.New(ids.KindSession))
				if err := tx.PutSession(nexus.Session{ID: id, AccountID: f.account, Kind: nexus.Worker, Runner: nexus.Local, Title: "archived", Status: nexus.SessionDone, CreatedAt: f.now, UpdatedAt: f.now}); err != nil {
					return err
				}
				if err := tx.PutMessageEdge(f.account, hub.ID, id, f.now); err != nil {
					return err
				}
			}
			return nil
		}))
		_, err = f.svc.PreviewTeam(ctx, f.person, hub.ID)
		wantErr(t, err, nexus.ErrClosureTooLarge)
	})

	t.Run("teams_review_round2", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		// one fold key for allocation, addition and resolution ("s" and "ſ" are one name)
		a, pa := f.member("s")
		b, _ := f.member("ſ")
		f.send(pa, b.ID)
		v := f.teamOf(a.ID)
		keys := map[string]bool{}
		for _, s := range v.Seats {
			k := nexus.SeatNameKey(s.Name)
			if keys[k] {
				t.Fatalf("fold-equal seat names: %+v", v.Seats)
			}
			keys[k] = true
		}
		_, err := f.svc.AddSeat(ctx, f.person, v.Team.ID, " S ")
		wantErr(t, err, nexus.ErrConflict)
		got, err := f.svc.ResolveSession(ctx, pa, "S")
		must(t, err)
		if got != a.ID {
			t.Fatal("fold-equal name resolved elsewhere", got)
		}
		// bounded, ordered adjacency pages
		hub, hp := f.member("hub")
		var spokes []ids.Session
		for i := 0; i < 6; i++ {
			x, _ := f.member(fmt.Sprintf("spoke-%d", i))
			f.send(hp, x.ID)
			spokes = append(spokes, x.ID)
		}
		must(t, f.store.View(ctx, func(tx nexus.Tx) error {
			page, err := tx.MessageEdges(f.account, hub.ID, 4)
			if err != nil {
				return err
			}
			want := sortedIDs(spokes...)[:4]
			if !sameIDs(page, want) {
				t.Fatalf("page %v want %v", page, want)
			}
			if _, err := tx.MessageEdges(f.account, hub.ID, 0); err == nil {
				t.Fatal("zero limit accepted")
			}
			return nil
		}))
		// team of a session: the person or that session; members only
		got2, err := f.svc.TeamOfSession(ctx, f.person, a.ID)
		must(t, err)
		if got2.Team.ID != v.Team.ID {
			t.Fatal("team of session", got2.Team.ID)
		}
		if _, err := f.svc.TeamOfSession(ctx, pa, a.ID); err != nil {
			t.Fatal("session cannot see its own team:", err)
		}
		_, err = f.svc.TeamOfSession(ctx, hp, a.ID)
		wantErr(t, err, nexus.ErrForbidden)
		_, err = f.svc.TeamOfSession(ctx, f.person, hub.ID)
		wantErr(t, err, nexus.ErrNotFound)
	})

	t.Run("teams_message_edge_backfill", func(t *testing.T) {
		f := newFixture(t, open)
		ctx := context.Background()
		a, _ := f.member("alpha")
		b, _ := f.member("beta")
		c, _ := f.member("gamma")
		// messages recorded before edges existed: raw ledger events only
		for _, pair := range [][2]ids.Session{{a.ID, b.ID}, {c.ID, b.ID}} {
			from, to := pair[0], pair[1]
			must(t, f.store.Update(ctx, func(tx nexus.Tx) error {
				_, err := tx.AppendEvent(nexus.Event{ID: ids.Event(ids.New(ids.KindEvent)), AccountID: f.account, SessionID: to, At: f.now, Source: "bot", Kind: "message", Actor: nexus.SessionPrincipal(f.account, from), Payload: json.RawMessage(`{"text":"public fixture"}`)})
				return err
			}))
		}
		must(t, f.store.View(ctx, func(tx nexus.Tx) error {
			edges, err := tx.MessageEdges(f.account, b.ID, 10)
			if err != nil || len(edges) != 0 {
				t.Fatalf("edges before backfill: %v %v", edges, err)
			}
			return nil
		}))
		p, err := f.svc.PreviewTeam(ctx, f.person, a.ID)
		must(t, err)
		if want := sortedIDs(a.ID, b.ID, c.ID); !sameIDs(memberIDs(p), want) {
			t.Fatalf("backfilled closure %v want %v", memberIDs(p), want)
		}
		must(t, f.store.View(ctx, func(tx nexus.Tx) error {
			mark, err := tx.EdgeMark(f.account)
			if err != nil || mark.Done < mark.Target {
				t.Fatalf("mark %+v %v", mark, err)
			}
			return nil
		}))
	})
}

func hasHubKind(events []nexus.Event, kind string) bool {
	for _, e := range events {
		if e.Kind == kind && e.Source == "hub" {
			return true
		}
	}
	return false
}
func wantKeys(t *testing.T, m map[string]any, keys ...string) {
	t.Helper()
	if len(m) != len(keys) {
		t.Fatalf("keys %v want %v", m, keys)
	}
	for _, k := range keys {
		if _, ok := m[k]; !ok {
			t.Fatalf("missing %q in %v", k, m)
		}
	}
}
