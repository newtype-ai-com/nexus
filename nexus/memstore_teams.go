package nexus

import (
	"sort"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

type edgePair struct {
	account ids.Account
	a, b    ids.Session
}
type installKey struct {
	account ids.Account
	install string
}

// teamData is the MemStore part for teams (copied with the snapshot).
type teamData struct {
	teams    map[ids.Team]Team
	seats    map[ids.Seat]Seat
	installs map[installKey]TeamInstall
	edges    map[edgePair]time.Time
	adj      map[ids.Account]map[ids.Session][]ids.Session // sorted neighbors (bounded reads)
	marks    map[ids.Account]EdgeMark
}

func newTeamData() *teamData {
	return &teamData{teams: map[ids.Team]Team{}, seats: map[ids.Seat]Seat{}, installs: map[installKey]TeamInstall{},
		edges: map[edgePair]time.Time{}, adj: map[ids.Account]map[ids.Session][]ids.Session{}, marks: map[ids.Account]EdgeMark{}}
}
func cloneSeat(x Seat) Seat { x.Previous = append([]ids.Session(nil), x.Previous...); return x }
func (d *teamData) clone() *teamData {
	n := newTeamData()
	if d == nil {
		return n
	}
	for k, v := range d.teams {
		n.teams[k] = v
	}
	for k, v := range d.seats {
		n.seats[k] = cloneSeat(v)
	}
	for k, v := range d.installs {
		n.installs[k] = v
	}
	for k, v := range d.edges {
		n.edges[k] = v
	}
	for acc, m := range d.adj {
		nm := make(map[ids.Session][]ids.Session, len(m))
		for s, list := range m {
			nm[s] = list // copy-on-write: never mutated in place
		}
		n.adj[acc] = nm
	}
	for k, v := range d.marks {
		n.marks[k] = v
	}
	return n
}
func (t *memTx) teamsData() *teamData {
	if t.data.teams == nil {
		t.data.teams = newTeamData()
	}
	return t.data.teams
}

func (t *memTx) Team(id ids.Team) (Team, error) {
	if err := t.check(false); err != nil {
		return Team{}, err
	}
	x, ok := t.teamsData().teams[id]
	if !ok {
		return Team{}, ErrNotFound
	}
	return x, nil
}
func (t *memTx) PutTeam(x Team) error {
	if err := t.check(true); err != nil {
		return err
	}
	if valid(ids.KindTeam, string(x.ID)) != nil || valid(ids.KindAccount, string(x.AccountID)) != nil {
		return ErrInvalid
	}
	d := t.teamsData()
	if old, ok := d.teams[x.ID]; ok && old.AccountID != x.AccountID {
		return ErrConflict
	}
	d.teams[x.ID] = x
	return nil
}
func (t *memTx) TeamsByAccount(account ids.Account) ([]Team, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := []Team{}
	for _, x := range t.teamsData().teams {
		if x.AccountID == account {
			out = append(out, x)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (t *memTx) Seat(id ids.Seat) (Seat, error) {
	if err := t.check(false); err != nil {
		return Seat{}, err
	}
	x, ok := t.teamsData().seats[id]
	if !ok {
		return Seat{}, ErrNotFound
	}
	return cloneSeat(x), nil
}

// PutSeat enforces the store-level invariants: same account and team for an
// existing seat, and at most one active seat per session in an account.
func (t *memTx) PutSeat(x Seat) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !validSeat(x) {
		return ErrInvalid
	}
	d := t.teamsData()
	if old, ok := d.seats[x.ID]; ok && (old.AccountID != x.AccountID || old.TeamID != x.TeamID) {
		return ErrConflict
	}
	if x.State == SeatActive && x.SessionID != "" {
		for _, o := range d.seats {
			if o.ID != x.ID && o.AccountID == x.AccountID && o.State == SeatActive && o.SessionID == x.SessionID {
				return ErrConflict
			}
		}
	}
	d.seats[x.ID] = cloneSeat(x)
	return nil
}
func (t *memTx) SeatsByTeam(team ids.Team) ([]Seat, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	out := []Seat{}
	for _, x := range t.teamsData().seats {
		if x.TeamID == team {
			out = append(out, cloneSeat(x))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out, nil
}
func (t *memTx) ActiveSeatBySession(account ids.Account, session ids.Session) (Seat, error) {
	if err := t.check(false); err != nil {
		return Seat{}, err
	}
	for _, x := range t.teamsData().seats {
		if x.AccountID == account && x.State == SeatActive && x.SessionID == session && session != "" {
			return cloneSeat(x), nil
		}
	}
	return Seat{}, ErrNotFound
}
func (t *memTx) TeamInstall(account ids.Account, install string) (TeamInstall, error) {
	if err := t.check(false); err != nil {
		return TeamInstall{}, err
	}
	x, ok := t.teamsData().installs[installKey{account, install}]
	if !ok {
		return TeamInstall{}, ErrNotFound
	}
	return x, nil
}
func (t *memTx) PutTeamInstall(x TeamInstall) error {
	if err := t.check(true); err != nil {
		return err
	}
	if valid(ids.KindAccount, string(x.AccountID)) != nil || valid(ids.KindTeam, string(x.TeamID)) != nil ||
		valid(ids.KindSeat, string(x.SeatID)) != nil || x.Install == "" {
		return ErrInvalid
	}
	t.teamsData().installs[installKey{x.AccountID, x.Install}] = x
	return nil
}
func (t *memTx) MessageEdges(account ids.Account, session ids.Session, limit int) ([]ids.Session, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, ErrInvalid
	}
	list := t.teamsData().adj[account][session]
	if len(list) > limit {
		list = list[:limit]
	}
	return append([]ids.Session{}, list...), nil
}

// addNeighbor inserts b into a's sorted neighbor list (copy-on-write).
func (d *teamData) addNeighbor(account ids.Account, a, b ids.Session) {
	m := d.adj[account]
	if m == nil {
		m = map[ids.Session][]ids.Session{}
		d.adj[account] = m
	}
	old := m[a]
	i := sort.Search(len(old), func(i int) bool { return old[i] >= b })
	if i < len(old) && old[i] == b {
		return
	}
	next := make([]ids.Session, 0, len(old)+1)
	next = append(next, old[:i]...)
	next = append(next, b)
	next = append(next, old[i:]...)
	m[a] = next
}
func (t *memTx) PutMessageEdge(account ids.Account, a, b ids.Session, at time.Time) error {
	if err := t.check(true); err != nil {
		return err
	}
	if valid(ids.KindAccount, string(account)) != nil || valid(ids.KindSession, string(a)) != nil ||
		valid(ids.KindSession, string(b)) != nil || a == b {
		return ErrInvalid
	}
	a, b = edgeKey(a, b)
	k := edgePair{account, a, b}
	d := t.teamsData()
	if old, ok := d.edges[k]; !ok || at.After(old) {
		d.edges[k] = at
	}
	d.addNeighbor(account, a, b)
	d.addNeighbor(account, b, a)
	return nil
}
func (t *memTx) EdgeMark(account ids.Account) (EdgeMark, error) {
	if err := t.check(false); err != nil {
		return EdgeMark{}, err
	}
	x, ok := t.teamsData().marks[account]
	if !ok {
		return EdgeMark{}, ErrNotFound
	}
	return x, nil
}
func (t *memTx) PutEdgeMark(x EdgeMark) error {
	if err := t.check(true); err != nil {
		return err
	}
	if valid(ids.KindAccount, string(x.AccountID)) != nil || x.Target < 0 || x.Done < 0 {
		return ErrInvalid
	}
	t.teamsData().marks[x.AccountID] = x
	return nil
}
