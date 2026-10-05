package nexus

import (
	"context"
	"errors"
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/newtype-ai-com/nexus/ids"
)

type Peer struct {
	SessionID     ids.Session   `json:"session_id"`
	Title         string        `json:"title"`
	Runner        Runner        `json:"runner"`
	Status        SessionStatus `json:"status"`
	TaskID        ids.Task      `json:"task_id,omitempty"`
	Relation      string        `json:"relation"`
	LastActive    time.Time     `json:"last_active"`
	WorkingTaskID ids.Task      `json:"working_task_id,omitempty"`
	WorkingTitle  string        `json:"working_title,omitempty"`
	Step          string        `json:"step,omitempty"`
}

func (s *Service) Peers(ctx context.Context, actor Principal) ([]Peer, error) {
	var out []Peer
	err := s.view(ctx, actor, func(tx Tx) error {
		out = []Peer{}
		if actor.Kind == PrincipalSession {
			if _, err := held(tx, actor, s.now()); err != nil {
				return err
			}
		}
		all, err := tx.SessionsByAccount(actor.AccountID)
		if err != nil {
			return err
		}
		for _, x := range all {
			if x.ID == actor.SessionID || x.Status == SessionDone || x.Status == SessionStopped || x.Status == SessionSuspended {
				continue
			}
			if err = hasLive(tx, actor.AccountID, x.ID, s); err != nil {
				if errors.Is(err, ErrRevoked) {
					continue
				}
				return err
			}
			relation := "peer"
			if actor.Kind == PrincipalSession {
				relation, err = relationOf(tx, actor.AccountID, x.ID, actor.SessionID, s.now())
				if err != nil {
					return err
				}
			}
			peer := Peer{SessionID: x.ID, Title: x.Title, Runner: x.Runner, Status: x.Status, TaskID: x.EntryTaskID, Relation: relation, LastActive: x.UpdatedAt}
			peer.WorkingTaskID, err = currentTaskOf(tx, actor.AccountID, x, s.now())
			if err != nil {
				return err
			}
			if peer.WorkingTaskID != "" {
				task, err := taskIn(tx, actor.AccountID, peer.WorkingTaskID)
				if err != nil {
					return err
				}
				peer.WorkingTitle = task.Title
				steps, err := tx.TasksByParent(task.ID)
				if err != nil {
					return err
				}
				for _, step := range steps {
					if step.AccountID != actor.AccountID {
						return ErrConflict
					}
					if step.Kind == "step" && step.Status == "in_progress" {
						peer.Step = step.ActiveForm
						if peer.Step == "" {
							peer.Step = step.Title
						}
						break
					}
				}
			}
			out = append(out, peer)
		}
		sort.Slice(out, func(i, j int) bool {
			if (out[i].Status == SessionRunning) != (out[j].Status == SessionRunning) {
				return out[i].Status == SessionRunning
			}
			if out[i].LastActive.Equal(out[j].LastActive) {
				return out[i].SessionID < out[j].SessionID
			}
			return out[i].LastActive.After(out[j].LastActive)
		})
		if len(out) > 50 {
			out = out[:50]
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) SessionByName(ctx context.Context, actor Principal, name string) (*Session, error) {
	if actor.Kind != PrincipalUser {
		return nil, ErrForbidden
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, ErrInvalid
	}
	var out *Session
	err := s.view(ctx, actor, func(tx Tx) error {
		out = nil
		all, err := tx.SessionsByAccount(actor.AccountID)
		if err != nil {
			return err
		}
		for _, x := range all {
			if x.Status != SessionDone && strings.EqualFold(strings.TrimSpace(x.Title), name) && (out == nil || x.CreatedAt.After(out.CreatedAt) || (x.CreatedAt.Equal(out.CreatedAt) && x.ID > out.ID)) {
				copy := x
				out = &copy
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (s *Service) RenameSession(ctx context.Context, actor Principal, id ids.Session, title string) (Session, error) {
	if actor.Kind != PrincipalUser && actor.Kind != PrincipalSession {
		return Session{}, ErrForbidden
	}
	title, err := cleanTitle(strings.Join(strings.Fields(title), " "))
	if err != nil {
		return Session{}, err
	}
	if utf8.RuneCountInString(title) > 80 {
		return Session{}, ErrInvalid
	}
	var out Session
	err = s.update(ctx, actor, func(tx Tx) error {
		out = Session{}
		x, err := sessionIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		if actor.Kind == PrincipalSession {
			if actor.SessionID != id {
				return ErrForbidden
			}
			if _, err = held(tx, actor, s.now()); err != nil {
				return err
			}
		}
		if x.Status == SessionDone || x.Status == SessionStopped {
			return ErrConflict
		}
		all, err := tx.SessionsByAccount(actor.AccountID)
		if err != nil {
			return err
		}
		for _, other := range all {
			if other.ID == id || other.Status == SessionDone || other.Status == SessionStopped || !strings.EqualFold(strings.TrimSpace(other.Title), title) {
				continue
			}
			err = hasLive(tx, actor.AccountID, other.ID, s)
			if err == nil {
				return ErrConflict
			}
			if !errors.Is(err, ErrRevoked) {
				return err
			}
		}
		if x.Title == title {
			out = x
			return nil
		}
		old := x.Title
		x.Title = title
		x.UpdatedAt = s.now().UTC()
		if err = tx.PutSession(x); err != nil {
			return err
		}
		if _, err = hubEvent(tx, actor, id, x.EntryTaskID, "session.renamed", map[string]string{"from": old, "to": title}, s.now()); err != nil {
			return err
		}
		out = x
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	return out, nil
}

func archiveSession(tx Tx, actor Principal, id ids.Session, reason string, now time.Time) (Session, error) {
	x, err := sessionIn(tx, actor.AccountID, id)
	if err != nil {
		return Session{}, err
	}
	if x.Status == SessionDone {
		return x, nil
	}
	all, err := tx.DelegationsByDelegate(id)
	if err != nil {
		return Session{}, err
	}
	for _, d := range all {
		current, err := delegationIn(tx, actor.AccountID, d.ID)
		if err != nil {
			return Session{}, err
		}
		if current.EndedAt == nil {
			if _, err = endDelegation(tx, actor.AccountID, d.ID, "revoked", now); err != nil {
				return Session{}, err
			}
		}
	}
	x.Status = SessionDone
	x.UpdatedAt = now.UTC()
	if err = tx.PutSession(x); err != nil {
		return Session{}, err
	}
	_, err = hubEvent(tx, actor, id, x.EntryTaskID, "session.archived", map[string]string{"reason": reason}, now)
	return x, err
}
func (s *Service) Archive(ctx context.Context, actor Principal, id ids.Session, reason string) (Session, error) {
	if actor.Kind != PrincipalUser && actor.Kind != PrincipalSystem {
		return Session{}, ErrForbidden
	}
	if len(reason) > 4096 {
		return Session{}, ErrInvalid
	}
	var out Session
	err := s.update(ctx, actor, func(tx Tx) error {
		var err error
		out, err = archiveSession(tx, actor, id, reason, s.now())
		return err
	})
	if err != nil {
		return Session{}, err
	}
	return out, nil
}

const PresenceGrace = 5 * time.Minute
const PresenceWrite = time.Minute

// RequestedGrace is how long a bot-requested container may wait for a runner.
const RequestedGrace = 15 * time.Minute
const ArchiveAfter = 7 * 24 * time.Hour

// Presence caches observations newer than the throttled shared SeenAt record.
// Neither the cache nor the persisted hint is a source of authority.
type presence struct {
	mu   sync.Mutex
	seen map[ids.Session]time.Time
}

func (s *Service) Touch(ctx context.Context, actor Principal) error {
	if actor.Kind != PrincipalSession {
		return nil
	}
	if err := checkActor(actor); err != nil {
		return err
	}
	now := s.now().UTC()
	restored := false
	// The shared timestamp is checked inside the account transaction, so two
	// instances cannot overwrite a newer observation or bypass the write limit.
	// Do not Notify for ordinary heartbeats: that would wake long-poll readers
	// whose next request touches the session again.
	err := s.store.Update(WithAccount(ctx, actor.AccountID), func(tx Tx) error {
		restored = false
		x, err := sessionIn(tx, actor.AccountID, actor.SessionID)
		if err != nil {
			return err
		}
		if x.Status == SessionStopped && x.StoppedBy == PrincipalSystem {
			if err := hasLive(tx, actor.AccountID, x.ID, s); err != nil {
				return err
			}
			x.Status, x.StoppedBy = SessionWaiting, ""
			x.UpdatedAt = now
			restored = true
		}
		// Unknown legacy stop provenance fails closed. Explicit stops, archive
		// and suspension are not undone merely by receiving an HTTP request.
		if x.Status == SessionStopped || x.Status == SessionDone || x.Status == SessionSuspended {
			return nil
		}
		if !restored && !x.SeenAt.IsZero() && now.Sub(x.SeenAt) < PresenceWrite {
			return nil
		}
		if now.After(x.SeenAt) {
			x.SeenAt = now
		}
		if err := tx.PutSession(x); err != nil {
			return err
		}
		if restored {
			_, err = hubEvent(tx, SystemPrincipal(x.AccountID), x.ID, "", "session.status", map[string]string{"status": "waiting", "reason": "presence restored"}, now)
		}
		return err
	})
	if err != nil {
		return err
	}
	s.presence.mu.Lock()
	if s.presence.seen == nil {
		s.presence.seen = map[ids.Session]time.Time{}
	}
	if now.After(s.presence.seen[actor.SessionID]) {
		s.presence.seen[actor.SessionID] = now
	}
	s.presence.mu.Unlock()
	if restored {
		s.Notify()
	}
	return nil
}
func (s *Service) LastSeen(id ids.Session) time.Time {
	s.presence.mu.Lock()
	defer s.presence.mu.Unlock()
	return s.presence.seen[id]
}

type SweepResult struct {
	Stopped  int `json:"stopped"`
	Archived int `json:"archived"`
}

// Sweep rechecks each candidate in its account transaction, preserving concurrent
// status changes. The caller is a trusted scheduler, not an HTTP client.
func (s *Service) Sweep(ctx context.Context, since time.Time, grace, archiveAfter time.Duration) (SweepResult, error) {
	if grace <= 0 || archiveAfter <= 0 {
		return SweepResult{}, ErrInvalid
	}
	var all []Session
	if err := s.store.View(ctx, func(tx Tx) error { var err error; all, err = tx.OpenSessions(); return err }); err != nil {
		return SweepResult{}, err
	}
	out := SweepResult{}
	for _, candidate := range all {
		stopped, archived := false, false
		err := s.update(ctx, SystemPrincipal(candidate.AccountID), func(tx Tx) error {
			stopped, archived = false, false
			x, err := sessionIn(tx, candidate.AccountID, candidate.ID)
			if err != nil {
				return err
			}
			now := s.now()
			switch x.Status {
			case SessionRunning, SessionWaiting:
				last := s.LastSeen(x.ID)
				if last.IsZero() {
					last = since
				}
				if x.SeenAt.After(last) {
					last = x.SeenAt
				}
				if x.UpdatedAt.After(last) {
					last = x.UpdatedAt
				}
				if now.Sub(last) < grace {
					return nil
				}
				x.Status = SessionStopped
				x.StoppedBy = PrincipalSystem
				x.UpdatedAt = now.UTC()
				if err = tx.PutSession(x); err != nil {
					return err
				}
				_, err = hubEvent(tx, SystemPrincipal(x.AccountID), x.ID, "", "session.status", map[string]string{"status": "stopped", "stopped_by": string(PrincipalSystem)}, now)
				stopped = err == nil
				return err
			case SessionRequested:
				// Recheck provenance and presence under the same account transaction
				// as settlement. An attached or human-created session is not orphaned
				// merely because it also holds a bot-issued grant.
				if x.Runner != Container || x.EntryTaskID == "" || !x.SeenAt.IsZero() || !s.LastSeen(x.ID).IsZero() || now.Sub(x.UpdatedAt) < RequestedGrace {
					return nil
				}
				task, err := taskIn(tx, x.AccountID, x.EntryTaskID)
				if err != nil {
					return err
				}
				if task.DelegationID == "" || task.Assignee != x.ID || task.Kind != "delegated" {
					return nil
				}
				d, err := delegationIn(tx, x.AccountID, task.DelegationID)
				if err != nil {
					return err
				}
				if d.ParentID == "" || d.EndedAt != nil || d.Delegator.Kind != PrincipalSession || d.Delegate != x.ID || d.Task != task.ID || !d.IssuedAt.Equal(x.CreatedAt) {
					return nil
				}
				// Use the existing child-before-parent accounting and ledger API;
				// never delete a requested session or manually refund its budget.
				_, err = endDelegation(tx, x.AccountID, d.ID, "no runner took the session within "+RequestedGrace.String()+"; hand the work to a session that runs", now)
				if err != nil {
					return err
				}
				fresh, err := sessionIn(tx, x.AccountID, x.ID)
				stopped = err == nil && fresh.Status == SessionStopped
				return err
			case SessionStopped:
				if now.Sub(x.UpdatedAt) < archiveAfter {
					return nil
				}
				_, err = archiveSession(tx, SystemPrincipal(x.AccountID), x.ID, "presence timeout", now)
				archived = err == nil
				return err
			}
			return nil
		})
		if err != nil {
			return out, err
		}
		if stopped {
			out.Stopped++
		}
		if archived {
			out.Archived++
			s.presence.mu.Lock()
			delete(s.presence.seen, candidate.ID)
			s.presence.mu.Unlock()
		}
	}
	return out, nil
}
func (s *Service) Janitor(ctx context.Context, interval time.Duration) error {
	if interval <= 0 {
		return ErrInvalid
	}
	since := s.now()
	tick := time.NewTicker(interval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-tick.C:
			if _, err := s.Sweep(ctx, since, PresenceGrace, ArchiveAfter); err != nil {
				return err
			}
		}
	}
}
