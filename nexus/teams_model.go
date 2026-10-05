package nexus

import (
	"strings"
	"time"
	"unicode"

	"github.com/newtype-ai-com/nexus/ids"
)

// Team groups fixed sessions ("seats") of one account under one team ID
// (docs/team-restore.md, docs/team-implementation-plan.md). It is created only
// by a person; it carries no authority of any kind.
type Team struct {
	ID        ids.Team    `json:"id"`
	AccountID ids.Account `json:"account_id"`
	Name      string      `json:"name"`
	CreatedAt time.Time   `json:"created_at"`
	CreatedBy string      `json:"created_by"` // the creating person's email
}

type SeatState string

const (
	SeatActive SeatState = "active"
	SeatMoved  SeatState = "moved" // the session joined a newer team; this record stays
)

// Seat is one member of a team: one fixed session. Previous lists sessions
// the seat held before its session could no longer be reattached (bounded).
// No delegation scope, depth, approval or budget is ever stored here.
type Seat struct {
	ID        ids.Seat      `json:"id"`
	TeamID    ids.Team      `json:"team_id"`
	AccountID ids.Account   `json:"account_id"`
	Name      string        `json:"name"`
	SessionID ids.Session   `json:"session_id,omitempty"`
	Previous  []ids.Session `json:"previous,omitempty"`
	State     SeatState     `json:"state"`
	MovedTo   ids.Team      `json:"moved_to,omitempty"`
	Lease     SeatLease     `json:"lease"`
	CreatedAt time.Time     `json:"created_at"`
	UpdatedAt time.Time     `json:"updated_at"`
}

// SeatLease makes attach single: at most one holder per seat. It is NOT the
// presence record (Session.SeenAt is a liveness hint, never a lease). Only
// hashes are stored: the installation identifier's and the lease token's.
type SeatLease struct {
	Install   string    `json:"install,omitempty"`
	Verifier  string    `json:"verifier,omitempty"`
	Epoch     int64     `json:"epoch"`
	ExpiresAt time.Time `json:"expires_at,omitempty"`
}

func (l SeatLease) heldAt(now time.Time) bool { return l.Verifier != "" && now.Before(l.ExpiresAt) }

// TeamInstall remembers the team an installation last joined.
type TeamInstall struct {
	AccountID ids.Account `json:"account_id"`
	Install   string      `json:"install"`
	TeamID    ids.Team    `json:"team_id"`
	SeatID    ids.Seat    `json:"seat_id"`
	UpdatedAt time.Time   `json:"updated_at"`
}

// EdgeMark is the progress of the one-time message-edge backfill of an
// account: events up to Target existed before edges were recorded by Send.
type EdgeMark struct {
	AccountID ids.Account `json:"account_id"`
	Target    int64       `json:"target"`
	Done      int64       `json:"done"`
}

// TeamTx is the team part of Tx. Message edges are undirected and stored
// normalized (a < b); MessageEdges returns at most limit other ends of one
// session in ascending order (bounded work: callers pass their remaining
// examination budget and treat a full page as "more").
type TeamTx interface {
	Team(ids.Team) (Team, error)
	PutTeam(Team) error
	TeamsByAccount(ids.Account) ([]Team, error)
	Seat(ids.Seat) (Seat, error)
	PutSeat(Seat) error
	SeatsByTeam(ids.Team) ([]Seat, error)
	ActiveSeatBySession(ids.Account, ids.Session) (Seat, error)
	TeamInstall(ids.Account, string) (TeamInstall, error)
	PutTeamInstall(TeamInstall) error
	MessageEdges(account ids.Account, session ids.Session, limit int) ([]ids.Session, error)
	PutMessageEdge(ids.Account, ids.Session, ids.Session, time.Time) error
	EdgeMark(ids.Account) (EdgeMark, error)
	PutEdgeMark(EdgeMark) error
}

// SeatNameKey is the one comparison for seat names (allocation, addition and
// resolution): trimmed, each rune mapped to the smallest rune of its simple
// case-fold orbit — exactly the equivalence strings.EqualFold uses, so "s"
// and "ſ" (or "K" and the Kelvin sign) are one name.
func SeatNameKey(name string) string {
	name = strings.TrimSpace(name)
	var b strings.Builder
	for _, r := range name {
		low := r
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < low {
				low = f
			}
		}
		b.WriteRune(low)
	}
	return b.String()
}

func edgeKey(a, b ids.Session) (ids.Session, ids.Session) {
	if b < a {
		return b, a
	}
	return a, b
}

func validSeat(x Seat) bool {
	if ids.Check(ids.KindSeat, string(x.ID)) != nil || ids.Check(ids.KindTeam, string(x.TeamID)) != nil ||
		ids.Check(ids.KindAccount, string(x.AccountID)) != nil {
		return false
	}
	if x.SessionID != "" && ids.Check(ids.KindSession, string(x.SessionID)) != nil {
		return false
	}
	if x.State != SeatActive && x.State != SeatMoved {
		return false
	}
	return x.State != SeatMoved || ids.Check(ids.KindTeam, string(x.MovedTo)) == nil
}
