package nexus

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

// Team bounds (docs/team-implementation-plan.md).
const (
	TeamMax             = 32               // members a closure may gather
	closureExamineMax   = 8 * TeamMax      // distinct sessions a closure may look at, excluded ones included
	SeatLeaseTTL        = 90 * time.Second // one attach holder per seat
	MaxPreviousSessions = 16
	edgeBackfillBatch   = 1000
	edgeBackfillPerCall = 50000 // events scanned per preview before "retry"
)

// ErrClosureTooLarge and ErrBackfillIncomplete are fixed refusals of a team
// preview; ErrRosterChanged means the confirmed roster no longer matches.
var (
	ErrClosureTooLarge    = fmt.Errorf("%w: team closure too large (over %d members or %d examined sessions)", ErrConflict, TeamMax, closureExamineMax)
	ErrBackfillIncomplete = fmt.Errorf("%w: message history is still being indexed; retry", ErrConflict)
	ErrRosterChanged      = fmt.Errorf("%w: the roster changed since it was shown; preview again", ErrConflict)
	ErrSeatAttached       = fmt.Errorf("%w: seat is attached elsewhere", ErrConflict)
	ErrLeaseLost          = fmt.Errorf("%w: seat lease lost", ErrConflict)
)

type TeamMember struct {
	SessionID ids.Session   `json:"session_id"`
	Title     string        `json:"title"`
	Status    SessionStatus `json:"status"`
}
type TeamPreview struct {
	Seed       ids.Session  `json:"seed"`
	Members    []TeamMember `json:"members"`
	RosterHash string       `json:"roster_hash"`
}

// SeatView is the public projection of a seat: no lease holder, verifier or
// token, and no authority.
type SeatView struct {
	ID            ids.Seat      `json:"id"`
	Name          string        `json:"name"`
	SessionID     ids.Session   `json:"session_id,omitempty"`
	SessionStatus SessionStatus `json:"session_status,omitempty"`
	State         SeatState     `json:"state"`
	MovedTo       ids.Team      `json:"moved_to,omitempty"`
	Previous      []ids.Session `json:"previous,omitempty"`
	Attached      bool          `json:"attached"`
}
type TeamView struct {
	Team  Team       `json:"team"`
	Seats []SeatView `json:"seats"`
}

// SeatAttach is the result of attach/renew. Reattachable tells the client to
// reattach SessionID (root issuance with to_session_id); otherwise it creates
// a fresh root and binds it with RebindSeat. LeaseToken is returned only to
// the holder that just obtained it and is never stored in plain form.
type SeatAttach struct {
	TeamID       ids.Team    `json:"team_id"`
	SeatID       ids.Seat    `json:"seat_id"`
	SeatName     string      `json:"seat_name"`
	SessionID    ids.Session `json:"session_id,omitempty"`
	Reattachable bool        `json:"reattachable"`
	LeaseToken   string      `json:"lease_token,omitempty"`
	Epoch        int64       `json:"epoch"`
	ExpiresAt    time.Time   `json:"expires_at"`
}

func sha256Hex(s string) string { sum := sha256.Sum256([]byte(s)); return hex.EncodeToString(sum[:]) }

func newLeaseToken() (string, error) {
	var b [32]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b[:]), nil
}

// installHash checks the client's installation identifier and returns the
// only form the server keeps.
func installHash(install string) (string, error) {
	if len(install) < 16 || len(install) > 128 {
		return "", ErrInvalid
	}
	for _, r := range install {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
			return "", ErrInvalid
		}
	}
	return sha256Hex("newtype-install\x00" + install), nil
}

// teamEligible: same account (the caller checks), a worker session (an
// observer can never be reattached or replaced, so it never takes a seat),
// and live: running, waiting, or requested and actually started (a requested
// container session with no presence ever is a delegated sub-task nobody
// started). A local root is run by the person's own process from issuance
// on; a model-only TUI root may never report presence, so presence is not
// required of it.
//
// Stopped, archived (done) and suspended sessions are neither members nor
// hops of the chain (2026-10-05: a TUI restart used to leave one stopped
// session per restart, and every one of them joined the roster). A stopped
// session that was the only link between two live ones does not connect
// them: the person names the missing member explicitly (it must still be
// reachable through live sessions) or has the two exchange a message first.
func teamEligible(x Session) bool {
	if x.Kind != Worker {
		return false
	}
	switch x.Status {
	case SessionRunning, SessionWaiting:
		return true
	case SessionRequested:
		return x.Runner != Container || !x.SeenAt.IsZero()
	}
	return false
}

// recordMessageEdge is called by Send in the same transaction: one
// session-to-session message is one undirected edge.
func recordMessageEdge(tx Tx, e Event) error {
	if e.Kind != "message" || e.Source != "bot" || e.Actor.Kind != PrincipalSession || e.Actor.SessionID == "" || e.Actor.SessionID == e.SessionID {
		return nil
	}
	return tx.PutMessageEdge(e.AccountID, e.Actor.SessionID, e.SessionID, e.At)
}

// backfillEdges indexes the messages that existed before edges were recorded
// by Send. It is resumable and bounded per call; until it has caught up with
// the target it reports ErrBackfillIncomplete rather than a partial closure.
func (s *Service) backfillEdges(ctx context.Context, actor Principal) error {
	finished := false
	err := s.update(ctx, actor, func(tx Tx) error {
		mark, err := tx.EdgeMark(actor.AccountID)
		if err == nil && mark.Done >= mark.Target {
			finished = true // already indexed; Send keeps it current
			return nil
		}
		if errors.Is(err, ErrNotFound) {
			cur, err := tx.Cursor(actor.AccountID)
			if err != nil {
				return err
			}
			mark = EdgeMark{AccountID: actor.AccountID, Target: cur}
		} else if err != nil {
			return err
		}
		scanned := 0
		for mark.Done < mark.Target && scanned < edgeBackfillPerCall {
			events, err := tx.EventsSince(actor.AccountID, mark.Done, edgeBackfillBatch)
			if err != nil {
				return err
			}
			if len(events) == 0 {
				mark.Done = mark.Target
				break
			}
			for _, e := range events {
				if e.Cursor > mark.Target {
					break
				}
				if err := recordMessageEdge(tx, e); err != nil {
					return err
				}
				mark.Done = e.Cursor
			}
			if events[len(events)-1].Cursor > mark.Target {
				mark.Done = mark.Target
			}
			scanned += len(events)
		}
		finished = mark.Done >= mark.Target
		return tx.PutEdgeMark(mark)
	})
	if err != nil {
		return err
	}
	if !finished {
		return ErrBackfillIncomplete
	}
	return nil
}

// closure gathers, from seed, the eligible sessions connected by message
// edges (ineligible sessions are not traversed). Deterministic order. More
// than maxMembers eligible sessions is ErrClosureTooLarge.
func closure(tx Tx, account ids.Account, seed ids.Session, maxMembers int) ([]Session, error) {
	first, err := sessionIn(tx, account, seed)
	if err != nil {
		return nil, err
	}
	if !teamEligible(first) {
		return nil, fmt.Errorf("%w: the session is not live (stopped, archived, suspended or never started)", ErrInvalid)
	}
	members := map[ids.Session]Session{seed: first}
	examined := map[ids.Session]bool{seed: true} // bounds lookups of excluded neighbors too
	queue := []ids.Session{seed}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		budget := closureExamineMax - len(examined) + 1 // one more than may still be examined
		next, err := tx.MessageEdges(account, cur, budget)
		if err != nil {
			return nil, err
		}
		if len(next) >= budget {
			return nil, ErrClosureTooLarge // a full page: possibly more than may still be examined
		}
		for _, id := range next {
			if examined[id] {
				continue
			}
			examined[id] = true
			if len(examined) > closureExamineMax {
				return nil, ErrClosureTooLarge
			}
			x, err := sessionIn(tx, account, id)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			if !teamEligible(x) {
				continue
			}
			members[id] = x
			if len(members) > maxMembers {
				return nil, ErrClosureTooLarge
			}
			queue = append(queue, id)
		}
	}
	out := make([]Session, 0, len(members))
	for _, x := range members {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

func rosterOf(account ids.Account, seed ids.Session, members []Session) TeamPreview {
	p := TeamPreview{Seed: seed, Members: make([]TeamMember, 0, len(members))}
	for _, x := range members {
		p.Members = append(p.Members, TeamMember{SessionID: x.ID, Title: x.Title, Status: x.Status})
	}
	raw, _ := json.Marshal(struct {
		Account ids.Account  `json:"account"`
		Seed    ids.Session  `json:"seed"`
		Members []TeamMember `json:"members"`
	}{account, seed, p.Members})
	p.RosterHash = "sha256:" + sha256Hex(string(raw))
	return p
}

// TeamMemberError refuses one entry of an explicit member list. Index is the
// entry's position in the list as sent; the entry itself is never echoed.
type TeamMemberError struct {
	Index  int
	Reason error
}

func (e *TeamMemberError) Error() string {
	return fmt.Sprintf("team member %d: %v", e.Index+1, e.Reason)
}
func (e *TeamMemberError) Unwrap() error { return e.Reason }

// Reasons an explicit member is refused (TeamMemberError.Reason).
var (
	ErrMemberNotFound     = fmt.Errorf("%w: no such session in this account", ErrNotFound)
	ErrMemberNotLive      = fmt.Errorf("%w: the session is not live (stopped, archived, suspended or never started)", ErrInvalid)
	ErrMemberAmbiguous    = fmt.Errorf("%w: several live sessions have that name; use the slv_ session ID", ErrInvalid)
	ErrMemberNotConnected = fmt.Errorf("%w: the session is not reachable from this session through messages between live sessions", ErrInvalid)
)

// teamRoster is the roster a team created from seed has: the whole live
// message chain of seed when members is empty; otherwise seed plus the named
// members, each a live session of the account (a session ID, or a name that
// exactly one live session has) that is in seed's live message chain. The
// explicit list can only narrow the chain, never reach past it.
func teamRoster(tx Tx, account ids.Account, seed ids.Session, members []string) ([]Session, error) {
	if len(members) == 0 {
		return closure(tx, account, seed, TeamMax)
	}
	if len(members) > TeamMax {
		return nil, ErrClosureTooLarge
	}
	chain, err := closure(tx, account, seed, closureExamineMax)
	if err != nil {
		return nil, err
	}
	inChain := map[ids.Session]Session{}
	for _, x := range chain {
		inChain[x.ID] = x
	}
	var all []Session // the account's sessions, read once for name lookups
	picked := map[ids.Session]Session{seed: inChain[seed]}
	for i, raw := range members {
		ref := strings.TrimSpace(raw)
		if ref == "" || len(ref) > 512 {
			return nil, &TeamMemberError{Index: i, Reason: ErrInvalid}
		}
		var x Session
		if id, perr := ids.ParseSession(ref); perr == nil {
			x, err = sessionIn(tx, account, id)
			if errors.Is(err, ErrNotFound) {
				return nil, &TeamMemberError{Index: i, Reason: ErrMemberNotFound}
			}
			if err != nil {
				return nil, err
			}
			if !teamEligible(x) {
				return nil, &TeamMemberError{Index: i, Reason: ErrMemberNotLive}
			}
		} else {
			if all == nil {
				if all, err = tx.SessionsByAccount(account); err != nil {
					return nil, err
				}
			}
			var live []Session
			named := false
			for _, c := range all {
				if c.AccountID != account || !strings.EqualFold(strings.TrimSpace(c.Title), ref) {
					continue
				}
				named = true
				if teamEligible(c) {
					live = append(live, c)
				}
			}
			switch {
			case len(live) > 1:
				return nil, &TeamMemberError{Index: i, Reason: ErrMemberAmbiguous}
			case len(live) == 0 && named:
				return nil, &TeamMemberError{Index: i, Reason: ErrMemberNotLive}
			case len(live) == 0:
				return nil, &TeamMemberError{Index: i, Reason: ErrMemberNotFound}
			}
			x = live[0]
		}
		if _, ok := inChain[x.ID]; !ok {
			return nil, &TeamMemberError{Index: i, Reason: ErrMemberNotConnected}
		}
		picked[x.ID] = inChain[x.ID]
	}
	out := make([]Session, 0, len(picked))
	for _, x := range picked {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}

// PreviewTeam shows the roster a team created from seed would have (the
// whole live chain). Only a person may ask.
func (s *Service) PreviewTeam(ctx context.Context, actor Principal, seed ids.Session) (TeamPreview, error) {
	return s.PreviewTeamMembers(ctx, actor, seed, nil)
}

// PreviewTeamMembers shows the roster a team created from seed would have:
// the live chain, or seed plus the named members (teamRoster). Only a person
// may ask (teams are created by a person's command only).
func (s *Service) PreviewTeamMembers(ctx context.Context, actor Principal, seed ids.Session, members []string) (TeamPreview, error) {
	if actor.Kind != PrincipalUser {
		return TeamPreview{}, ErrForbidden
	}
	if _, err := ids.ParseSession(string(seed)); err != nil {
		return TeamPreview{}, ErrInvalid
	}
	if err := s.view(ctx, actor, func(tx Tx) error { _, err := sessionIn(tx, actor.AccountID, seed); return err }); err != nil {
		return TeamPreview{}, err
	}
	if err := s.backfillEdges(ctx, actor); err != nil {
		return TeamPreview{}, err
	}
	var out TeamPreview
	err := s.view(ctx, actor, func(tx Tx) error {
		members, err := teamRoster(tx, actor.AccountID, seed, members)
		if err != nil {
			return err
		}
		out = rosterOf(actor.AccountID, seed, members)
		return nil
	})
	return out, err
}

// CreateTeam creates a team of the whole live chain of seed.
func (s *Service) CreateTeam(ctx context.Context, actor Principal, seed ids.Session, name, rosterHash string) (TeamView, error) {
	return s.CreateTeamMembers(ctx, actor, seed, name, rosterHash, nil)
}

// CreateTeamMembers recomputes the roster (the same member list as the
// preview) in the same transaction and creates the team only when it still
// matches the roster the person confirmed.
func (s *Service) CreateTeamMembers(ctx context.Context, actor Principal, seed ids.Session, name, rosterHash string, selected []string) (TeamView, error) {
	if actor.Kind != PrincipalUser {
		return TeamView{}, ErrForbidden
	}
	if _, err := ids.ParseSession(string(seed)); err != nil || !strings.HasPrefix(rosterHash, "sha256:") {
		return TeamView{}, ErrInvalid
	}
	if strings.TrimSpace(name) != "" {
		var err error
		if name, err = cleanTitle(name); err != nil {
			return TeamView{}, err
		}
	}
	if err := s.view(ctx, actor, func(tx Tx) error { _, err := sessionIn(tx, actor.AccountID, seed); return err }); err != nil {
		return TeamView{}, err
	}
	if err := s.backfillEdges(ctx, actor); err != nil {
		return TeamView{}, err
	}
	var out TeamView
	err := s.update(ctx, actor, func(tx Tx) error {
		now := s.now().UTC()
		members, err := teamRoster(tx, actor.AccountID, seed, selected)
		if err != nil {
			return err
		}
		if rosterOf(actor.AccountID, seed, members).RosterHash != rosterHash {
			return ErrRosterChanged
		}
		teamName := name
		if teamName == "" {
			first, _ := sessionIn(tx, actor.AccountID, seed)
			teamName = first.Title
		}
		team := Team{ID: ids.Team(ids.New(ids.KindTeam)), AccountID: actor.AccountID, Name: teamName, CreatedAt: now, CreatedBy: actor.Email}
		if err := tx.PutTeam(team); err != nil {
			return err
		}
		used := map[string]bool{}
		for _, x := range members {
			used[SeatNameKey(x.Title)] = true
		}
		taken := map[string]bool{}
		seats := []Seat{}
		for _, x := range members {
			// one session, one team: an active seat elsewhere moves here
			if old, err := tx.ActiveSeatBySession(actor.AccountID, x.ID); err == nil {
				old.State, old.MovedTo, old.Lease, old.UpdatedAt = SeatMoved, team.ID, SeatLease{Epoch: old.Lease.Epoch}, now
				if err := tx.PutSeat(old); err != nil {
					return err
				}
			} else if !errors.Is(err, ErrNotFound) {
				return err
			}
			// unique within the team: a generated suffix never takes another
			// member's own title (reserved) or an earlier name (taken)
			seatName := x.Title
			for n := 2; taken[SeatNameKey(seatName)]; n++ {
				if c := fmt.Sprintf("%s #%d", x.Title, n); !used[SeatNameKey(c)] {
					seatName = c
				}
			}
			taken[SeatNameKey(seatName)] = true
			seat := Seat{ID: ids.Seat(ids.New(ids.KindSeat)), TeamID: team.ID, AccountID: actor.AccountID, Name: seatName, SessionID: x.ID, State: SeatActive, CreatedAt: now, UpdatedAt: now}
			if err := tx.PutSeat(seat); err != nil {
				return err
			}
			seats = append(seats, seat)
		}
		for _, seat := range seats {
			if _, err := hubEvent(tx, actor, seat.SessionID, "", "team.joined", map[string]any{"team_id": team.ID, "team_name": team.Name, "seat_id": seat.ID, "seat_name": seat.Name}, now); err != nil {
				return err
			}
		}
		out, err = teamView(tx, team, now)
		return err
	})
	return out, err
}

func teamView(tx Tx, team Team, now time.Time) (TeamView, error) {
	seats, err := tx.SeatsByTeam(team.ID)
	if err != nil {
		return TeamView{}, err
	}
	v := TeamView{Team: team, Seats: make([]SeatView, 0, len(seats))}
	for _, x := range seats {
		sv := SeatView{ID: x.ID, Name: x.Name, SessionID: x.SessionID, State: x.State, MovedTo: x.MovedTo, Previous: x.Previous, Attached: x.State == SeatActive && x.Lease.heldAt(now)}
		if x.SessionID != "" {
			if sess, err := sessionIn(tx, team.AccountID, x.SessionID); err == nil {
				sv.SessionStatus = sess.Status
			}
		}
		v.Seats = append(v.Seats, sv)
	}
	return v, nil
}

func teamIn(tx Tx, account ids.Account, id ids.Team) (Team, error) {
	x, err := tx.Team(id)
	if err != nil {
		return Team{}, err
	}
	if x.AccountID != account {
		return Team{}, ErrNotFound
	}
	return x, nil
}
func seatIn(tx Tx, team Team, id ids.Seat) (Seat, error) {
	x, err := tx.Seat(id)
	if err != nil {
		return Seat{}, err
	}
	if x.AccountID != team.AccountID || x.TeamID != team.ID {
		return Seat{}, ErrNotFound
	}
	return x, nil
}

// Teams lists the account's teams (a person or a session of the account).
func (s *Service) Teams(ctx context.Context, actor Principal) ([]Team, error) {
	if actor.Kind != PrincipalUser && actor.Kind != PrincipalSession {
		return nil, ErrForbidden
	}
	var out []Team
	err := s.view(ctx, actor, func(tx Tx) error {
		var err error
		out, err = tx.TeamsByAccount(actor.AccountID)
		return err
	})
	return out, err
}

// TeamRoster: a person of the account, or a session holding an active seat
// of that team. Others (other accounts included) see not found.
func (s *Service) TeamRoster(ctx context.Context, actor Principal, id ids.Team) (TeamView, error) {
	if actor.Kind != PrincipalUser && actor.Kind != PrincipalSession {
		return TeamView{}, ErrForbidden
	}
	var out TeamView
	err := s.view(ctx, actor, func(tx Tx) error {
		team, err := teamIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		if actor.Kind == PrincipalSession {
			seat, err := tx.ActiveSeatBySession(actor.AccountID, actor.SessionID)
			if err != nil || seat.TeamID != team.ID {
				return ErrNotFound
			}
		}
		out, err = teamView(tx, team, s.now().UTC())
		return err
	})
	return out, err
}

// LastTeam is the team this installation last attached to (person only).
func (s *Service) LastTeam(ctx context.Context, actor Principal, install string) (TeamInstall, error) {
	if actor.Kind != PrincipalUser {
		return TeamInstall{}, ErrForbidden
	}
	h, err := installHash(install)
	if err != nil {
		return TeamInstall{}, err
	}
	var out TeamInstall
	err = s.view(ctx, actor, func(tx Tx) error {
		x, err := tx.TeamInstall(actor.AccountID, h)
		if err != nil {
			return err
		}
		if t, err := teamIn(tx, actor.AccountID, x.TeamID); err != nil || t.ID != x.TeamID {
			return ErrNotFound
		}
		out = x
		return nil
	})
	return out, err
}

// AddSeat adds an empty seat (no session yet) when no free seat exists.
func (s *Service) AddSeat(ctx context.Context, actor Principal, id ids.Team, name string) (SeatView, error) {
	if actor.Kind != PrincipalUser {
		return SeatView{}, ErrForbidden
	}
	name, err := cleanTitle(name)
	if err != nil {
		return SeatView{}, err
	}
	var out SeatView
	err = s.update(ctx, actor, func(tx Tx) error {
		now := s.now().UTC()
		team, err := teamIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		seats, err := tx.SeatsByTeam(team.ID)
		if err != nil {
			return err
		}
		active := 0
		for _, x := range seats {
			if x.State == SeatActive {
				active++
				if SeatNameKey(x.Name) == SeatNameKey(name) {
					return fmt.Errorf("%w: a seat with that name exists", ErrConflict)
				}
			}
		}
		if active >= TeamMax {
			return ErrClosureTooLarge
		}
		seat := Seat{ID: ids.Seat(ids.New(ids.KindSeat)), TeamID: team.ID, AccountID: actor.AccountID, Name: name, State: SeatActive, CreatedAt: now, UpdatedAt: now}
		if err := tx.PutSeat(seat); err != nil {
			return err
		}
		out = SeatView{ID: seat.ID, Name: seat.Name, State: seat.State}
		return nil
	})
	return out, err
}

// AttachSeat obtains the seat's single attach lease for this installation.
// A held lease is handed over only to the same installation presenting the
// current token (its successor process after a restart); anyone else waits
// for expiry. A person attaches (the client has no session header yet).
func (s *Service) AttachSeat(ctx context.Context, actor Principal, teamID ids.Team, seatID ids.Seat, install, token string) (SeatAttach, error) {
	if actor.Kind != PrincipalUser {
		return SeatAttach{}, ErrForbidden
	}
	h, err := installHash(install)
	if err != nil {
		return SeatAttach{}, err
	}
	fresh, err := newLeaseToken()
	if err != nil {
		return SeatAttach{}, err
	}
	var out SeatAttach
	err = s.update(ctx, actor, func(tx Tx) error {
		now := s.now().UTC()
		team, err := teamIn(tx, actor.AccountID, teamID)
		if err != nil {
			return err
		}
		seat, err := seatIn(tx, team, seatID)
		if err != nil {
			return err
		}
		if seat.State != SeatActive {
			return fmt.Errorf("%w: the seat moved to another team", ErrConflict)
		}
		if seat.Lease.heldAt(now) && !(seat.Lease.Install == h && token != "" && seat.Lease.Verifier == sha256Hex(token)) {
			return ErrSeatAttached
		}
		reattachable := false
		if seat.SessionID != "" {
			if sess, err := sessionIn(tx, actor.AccountID, seat.SessionID); err == nil {
				if sess.Status == SessionSuspended {
					return ErrForbidden // a person's stop is not undone by attaching
				}
				reattachable = sess.Status != SessionDone && sess.Kind == Worker
			} else if !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		seat.Lease = SeatLease{Install: h, Verifier: sha256Hex(fresh), Epoch: seat.Lease.Epoch + 1, ExpiresAt: now.Add(SeatLeaseTTL)}
		seat.UpdatedAt = now
		if err := tx.PutSeat(seat); err != nil {
			return err
		}
		if err := tx.PutTeamInstall(TeamInstall{AccountID: actor.AccountID, Install: h, TeamID: team.ID, SeatID: seat.ID, UpdatedAt: now}); err != nil {
			return err
		}
		if reattachable {
			if err := teamNotice(tx, actor, team, seat, "team.seat.reattached", now); err != nil {
				return err
			}
		}
		out = SeatAttach{TeamID: team.ID, SeatID: seat.ID, SeatName: seat.Name, SessionID: seat.SessionID, Reattachable: reattachable, LeaseToken: fresh, Epoch: seat.Lease.Epoch, ExpiresAt: seat.Lease.ExpiresAt}
		return nil
	})
	if err != nil {
		return SeatAttach{}, err
	}
	return out, nil
}

// teamNotice tells the other active members (non-inbox hub events: never a
// turn, never a wake).
func teamNotice(tx Tx, actor Principal, team Team, seat Seat, kind string, now time.Time) error {
	seats, err := tx.SeatsByTeam(team.ID)
	if err != nil {
		return err
	}
	for _, o := range seats {
		if o.State != SeatActive || o.SessionID == "" || o.ID == seat.ID {
			continue
		}
		if _, err := sessionIn(tx, team.AccountID, o.SessionID); err != nil {
			continue
		}
		if _, err := hubEvent(tx, actor, o.SessionID, "", kind, map[string]any{"team_id": team.ID, "seat_id": seat.ID, "seat_name": seat.Name, "session_id": seat.SessionID}, now); err != nil {
			return err
		}
	}
	return nil
}

func leaseHolder(seat Seat, token string, epoch int64, now time.Time) bool {
	return token != "" && seat.Lease.heldAt(now) && seat.Lease.Verifier == sha256Hex(token) && seat.Lease.Epoch == epoch
}

// RenewSeat extends the lease; only the seat's own session holding the
// current token and epoch may. A mismatch is ErrLeaseLost: the client stops.
func (s *Service) RenewSeat(ctx context.Context, actor Principal, teamID ids.Team, seatID ids.Seat, token string, epoch int64) (SeatAttach, error) {
	if actor.Kind != PrincipalSession {
		return SeatAttach{}, ErrForbidden
	}
	var out SeatAttach
	err := s.update(ctx, actor, func(tx Tx) error {
		now := s.now().UTC()
		team, err := teamIn(tx, actor.AccountID, teamID)
		if err != nil {
			return err
		}
		seat, err := seatIn(tx, team, seatID)
		if err != nil {
			return err
		}
		if seat.State != SeatActive || seat.SessionID != actor.SessionID || !leaseHolder(seat, token, epoch, now) {
			return ErrLeaseLost
		}
		seat.Lease.ExpiresAt, seat.UpdatedAt = now.Add(SeatLeaseTTL), now
		if err := tx.PutSeat(seat); err != nil {
			return err
		}
		out = SeatAttach{TeamID: team.ID, SeatID: seat.ID, SeatName: seat.Name, SessionID: seat.SessionID, Reattachable: true, Epoch: seat.Lease.Epoch, ExpiresAt: seat.Lease.ExpiresAt}
		return nil
	})
	return out, err
}

// ReleaseSeat gives the lease up (the holder's session, or a person with the
// token). An already lost lease is not an error to report as success.
func (s *Service) ReleaseSeat(ctx context.Context, actor Principal, teamID ids.Team, seatID ids.Seat, token string, epoch int64) error {
	if actor.Kind != PrincipalSession && actor.Kind != PrincipalUser {
		return ErrForbidden
	}
	return s.update(ctx, actor, func(tx Tx) error {
		now := s.now().UTC()
		team, err := teamIn(tx, actor.AccountID, teamID)
		if err != nil {
			return err
		}
		seat, err := seatIn(tx, team, seatID)
		if err != nil {
			return err
		}
		if !leaseHolder(seat, token, epoch, now) || (actor.Kind == PrincipalSession && seat.SessionID != actor.SessionID) {
			return ErrLeaseLost
		}
		seat.Lease, seat.UpdatedAt = SeatLease{Epoch: seat.Lease.Epoch}, now
		return tx.PutSeat(seat)
	})
}

// RebindSeat puts a fresh session in a seat whose session can no longer be
// reattached (archived, missing, or none yet). The old ID is kept in
// Previous; other members are told (non-inbox).
func (s *Service) RebindSeat(ctx context.Context, actor Principal, teamID ids.Team, seatID ids.Seat, token string, epoch int64, session ids.Session) (SeatView, error) {
	if actor.Kind != PrincipalUser {
		return SeatView{}, ErrForbidden
	}
	if _, err := ids.ParseSession(string(session)); err != nil {
		return SeatView{}, ErrInvalid
	}
	var out SeatView
	err := s.update(ctx, actor, func(tx Tx) error {
		now := s.now().UTC()
		team, err := teamIn(tx, actor.AccountID, teamID)
		if err != nil {
			return err
		}
		seat, err := seatIn(tx, team, seatID)
		if err != nil {
			return err
		}
		if seat.State != SeatActive || !leaseHolder(seat, token, epoch, now) {
			return ErrLeaseLost
		}
		if seat.SessionID == session {
			out = SeatView{ID: seat.ID, Name: seat.Name, SessionID: seat.SessionID, State: seat.State, Previous: seat.Previous, Attached: true}
			return nil
		}
		if seat.SessionID != "" {
			old, err := sessionIn(tx, actor.AccountID, seat.SessionID)
			if err == nil && old.Status != SessionDone {
				return fmt.Errorf("%w: the seat's session can still be reattached", ErrConflict)
			}
			if err != nil && !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		next, err := sessionIn(tx, actor.AccountID, session)
		if err != nil {
			return err
		}
		if next.Kind != Worker || next.Status == SessionDone || next.Status == SessionSuspended {
			return ErrInvalid
		}
		if other, err := tx.ActiveSeatBySession(actor.AccountID, session); err == nil && other.ID != seat.ID {
			return fmt.Errorf("%w: that session already holds a seat", ErrConflict)
		} else if err != nil && !errors.Is(err, ErrNotFound) {
			return err
		}
		if seat.SessionID != "" {
			seat.Previous = append(seat.Previous, seat.SessionID)
			if len(seat.Previous) > MaxPreviousSessions {
				seat.Previous = seat.Previous[len(seat.Previous)-MaxPreviousSessions:]
			}
		}
		seat.SessionID, seat.UpdatedAt = session, now
		if err := tx.PutSeat(seat); err != nil {
			return err
		}
		if err := teamNotice(tx, actor, team, seat, "team.seat.replaced", now); err != nil {
			return err
		}
		if _, err := hubEvent(tx, actor, session, "", "team.joined", map[string]any{"team_id": team.ID, "team_name": team.Name, "seat_id": seat.ID, "seat_name": seat.Name}, now); err != nil {
			return err
		}
		out = SeatView{ID: seat.ID, Name: seat.Name, SessionID: seat.SessionID, SessionStatus: next.Status, State: seat.State, Previous: seat.Previous, Attached: true}
		return nil
	})
	return out, err
}

// resolveSeat maps a seat name of the sender's own team to the seat's
// session. A stopped session still receives (its inbox is kept for the
// restart); an archived or suspended one does not, and the ordinary name
// rules apply instead.
func resolveSeat(tx Tx, actor Principal, name string) (ids.Session, bool, error) {
	mine, err := tx.ActiveSeatBySession(actor.AccountID, actor.SessionID)
	if errors.Is(err, ErrNotFound) {
		return "", false, nil
	}
	if err != nil {
		return "", false, err
	}
	seats, err := tx.SeatsByTeam(mine.TeamID)
	if err != nil {
		return "", false, err
	}
	for _, x := range seats {
		if x.State != SeatActive || x.SessionID == "" || x.AccountID != actor.AccountID || SeatNameKey(x.Name) != SeatNameKey(name) {
			continue
		}
		sess, err := sessionIn(tx, actor.AccountID, x.SessionID)
		if errors.Is(err, ErrNotFound) {
			return "", false, nil
		}
		if err != nil {
			return "", false, err
		}
		if sess.Status == SessionDone || sess.Status == SessionSuspended {
			return "", false, nil
		}
		return x.SessionID, true, nil
	}
	return "", false, nil
}

// TeamOfSession is the team in which session holds an active seat (a person
// of the account, or that session itself); ErrNotFound when it holds none.
// A running process that was not started on a team discovers membership
// with it (e.g. after another member created the team).
func (s *Service) TeamOfSession(ctx context.Context, actor Principal, session ids.Session) (TeamView, error) {
	if actor.Kind != PrincipalUser && !(actor.Kind == PrincipalSession && actor.SessionID == session) {
		return TeamView{}, ErrForbidden
	}
	if _, err := ids.ParseSession(string(session)); err != nil {
		return TeamView{}, ErrInvalid
	}
	var out TeamView
	err := s.view(ctx, actor, func(tx Tx) error {
		if _, err := sessionIn(tx, actor.AccountID, session); err != nil {
			return err
		}
		seat, err := tx.ActiveSeatBySession(actor.AccountID, session)
		if err != nil {
			return err
		}
		team, err := teamIn(tx, actor.AccountID, seat.TeamID)
		if err != nil {
			return err
		}
		out, err = teamView(tx, team, s.now().UTC())
		return err
	})
	return out, err
}
