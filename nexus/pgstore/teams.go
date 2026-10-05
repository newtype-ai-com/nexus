package pgstore

import (
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func (t *transaction) Team(id ids.Team) (nexus.Team, error) {
	return one[nexus.Team](t, "SELECT body FROM teams WHERE id=$1", string(id))
}
func (t *transaction) PutTeam(x nexus.Team) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !valid(ids.KindTeam, string(x.ID)) || !valid(ids.KindAccount, string(x.AccountID)) {
		return nexus.ErrInvalid
	}
	return t.put(`INSERT INTO teams(id,account_id,body) VALUES($1,$2,$3)
 ON CONFLICT(id) DO UPDATE SET body=EXCLUDED.body WHERE teams.account_id=EXCLUDED.account_id`, x, string(x.ID), string(x.AccountID))
}
func (t *transaction) TeamsByAccount(id ids.Account) ([]nexus.Team, error) {
	return many[nexus.Team](t, "SELECT body FROM teams WHERE account_id=$1 ORDER BY id", string(id))
}
func (t *transaction) Seat(id ids.Seat) (nexus.Seat, error) {
	return one[nexus.Seat](t, "SELECT body FROM team_seats WHERE id=$1", string(id))
}

// PutSeat: account and team of an existing seat never change; the partial
// unique index keeps one active seat per session (a violation is retried by
// Update and then refused by the service's own check).
func (t *transaction) PutSeat(x nexus.Seat) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !validSeatRecord(x) {
		return nexus.ErrInvalid
	}
	return t.put(`INSERT INTO team_seats(id,account_id,team_id,session_id,state,body) VALUES($1,$2,$3,$4,$5,$6)
 ON CONFLICT(id) DO UPDATE SET session_id=EXCLUDED.session_id,state=EXCLUDED.state,body=EXCLUDED.body
 WHERE team_seats.account_id=EXCLUDED.account_id AND team_seats.team_id=EXCLUDED.team_id`,
		x, string(x.ID), string(x.AccountID), string(x.TeamID), string(x.SessionID), string(x.State))
}
func validSeatRecord(x nexus.Seat) bool {
	if !valid(ids.KindSeat, string(x.ID)) || !valid(ids.KindTeam, string(x.TeamID)) || !valid(ids.KindAccount, string(x.AccountID)) {
		return false
	}
	if x.SessionID != "" && !valid(ids.KindSession, string(x.SessionID)) {
		return false
	}
	switch x.State {
	case nexus.SeatActive:
		return true
	case nexus.SeatMoved:
		return valid(ids.KindTeam, string(x.MovedTo))
	}
	return false
}
func (t *transaction) SeatsByTeam(id ids.Team) ([]nexus.Seat, error) {
	return many[nexus.Seat](t, "SELECT body FROM team_seats WHERE team_id=$1 ORDER BY id", string(id))
}
func (t *transaction) ActiveSeatBySession(account ids.Account, session ids.Session) (nexus.Seat, error) {
	if session == "" {
		return nexus.Seat{}, nexus.ErrNotFound
	}
	return one[nexus.Seat](t, "SELECT body FROM team_seats WHERE account_id=$1 AND session_id=$2 AND state='active'", string(account), string(session))
}
func (t *transaction) TeamInstall(account ids.Account, install string) (nexus.TeamInstall, error) {
	return one[nexus.TeamInstall](t, "SELECT body FROM team_installs WHERE account_id=$1 AND install=$2", string(account), install)
}
func (t *transaction) PutTeamInstall(x nexus.TeamInstall) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !valid(ids.KindAccount, string(x.AccountID)) || !valid(ids.KindTeam, string(x.TeamID)) || !valid(ids.KindSeat, string(x.SeatID)) || x.Install == "" {
		return nexus.ErrInvalid
	}
	return t.put(`INSERT INTO team_installs(account_id,install,body) VALUES($1,$2,$3)
 ON CONFLICT(account_id,install) DO UPDATE SET body=EXCLUDED.body`, x, string(x.AccountID), x.Install)
}
func (t *transaction) MessageEdges(account ids.Account, session ids.Session, limit int) ([]ids.Session, error) {
	if err := t.check(false); err != nil {
		return nil, err
	}
	if limit <= 0 {
		return nil, nexus.ErrInvalid
	}
	// each side is index-ordered and limited before the merge: bounded work
	rows, err := t.tx.Query(t.ctx, `SELECT s FROM (
  (SELECT b AS s FROM message_edges WHERE account_id=$1 AND a=$2 ORDER BY b LIMIT $3)
  UNION
  (SELECT a AS s FROM message_edges WHERE account_id=$1 AND b=$2 ORDER BY a LIMIT $3)
 ) n ORDER BY s LIMIT $3`, string(account), string(session), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ids.Session{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, err
		}
		out = append(out, ids.Session(s))
	}
	return out, rows.Err()
}
func (t *transaction) PutMessageEdge(account ids.Account, a, b ids.Session, at time.Time) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !valid(ids.KindAccount, string(account)) || !valid(ids.KindSession, string(a)) || !valid(ids.KindSession, string(b)) || a == b {
		return nexus.ErrInvalid
	}
	if b < a {
		a, b = b, a
	}
	_, err := t.tx.Exec(t.ctx, `INSERT INTO message_edges(account_id,a,b,last_at) VALUES($1,$2,$3,$4)
 ON CONFLICT(account_id,a,b) DO UPDATE SET last_at=GREATEST(message_edges.last_at,EXCLUDED.last_at)`, string(account), string(a), string(b), at.UTC())
	return err
}
func (t *transaction) EdgeMark(account ids.Account) (nexus.EdgeMark, error) {
	return one[nexus.EdgeMark](t, "SELECT body FROM message_edge_marks WHERE account_id=$1", string(account))
}
func (t *transaction) PutEdgeMark(x nexus.EdgeMark) error {
	if err := t.check(true); err != nil {
		return err
	}
	if !valid(ids.KindAccount, string(x.AccountID)) || x.Target < 0 || x.Done < 0 {
		return nexus.ErrInvalid
	}
	return t.put(`INSERT INTO message_edge_marks(account_id,body) VALUES($1,$2)
 ON CONFLICT(account_id) DO UPDATE SET body=EXCLUDED.body`, x, string(x.AccountID))
}
