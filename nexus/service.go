package nexus

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/seal"
)

// Service is the trusted domain API. Authentication supplies Principal; never
// construct a principal from an untrusted request's account_id.
type Service struct {
	store    Store
	now      func() time.Time
	mu       sync.Mutex
	changed  chan struct{}
	presence presence
	sealer   *seal.Sealer
	issuer   string

	// RefuseUnstartable selects the M16 refusal for new bot sessions.
	// Configure before serving. NewService enables it; disabling it does NOT
	// enable a runner: phase one still refuses all fresh Delegate targets.
	RefuseUnstartable bool
}

// UnstartableMessage is the M16 guidance. The placeholder is a title;
// transports use a fixed public description rather than reflecting input.
const UnstartableMessage = "nothing here starts a new session: no runner would take %q. " +
	"Hand the work to a session that runs — name it with to (hub_peers lists them) — or do it yourself"

// NewService accepts an injectable clock for deterministic expiry tests.
func NewService(store Store, clock func() time.Time) *Service {
	if clock == nil {
		clock = time.Now
	}
	return &Service{store: store, now: clock, changed: make(chan struct{}), RefuseUnstartable: true}
}

// Changed must be captured BEFORE reading to avoid losing a concurrent commit.
func (s *Service) Changed() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changed
}
func (s *Service) Notify() {
	s.mu.Lock()
	defer s.mu.Unlock()
	close(s.changed)
	s.changed = make(chan struct{})
}
func (s *Service) update(ctx context.Context, actor Principal, fn func(Tx) error) error {
	if err := checkActor(actor); err != nil {
		return err
	}
	err := s.store.Update(WithAccount(ctx, actor.AccountID), fn)
	if err == nil {
		s.Notify()
	}
	return err
}
func (s *Service) view(ctx context.Context, actor Principal, fn func(Tx) error) error {
	if err := checkActor(actor); err != nil {
		return err
	}
	return s.store.View(WithAccount(ctx, actor.AccountID), fn)
}
func checkActor(p Principal) error {
	if _, err := ids.ParseAccount(string(p.AccountID)); err != nil {
		return fmt.Errorf("%w: no valid account", ErrForbidden)
	}
	switch p.Kind {
	case PrincipalUser, PrincipalSystem:
		if p.SessionID != "" {
			return ErrForbidden
		}
	case PrincipalSession:
		if _, err := ids.ParseSession(string(p.SessionID)); err != nil {
			return ErrForbidden
		}
	default:
		return ErrForbidden
	}
	return nil
}
func sessionIn(tx Tx, account ids.Account, id ids.Session) (Session, error) {
	x, err := tx.Session(id)
	if err != nil {
		return Session{}, err
	}
	if x.AccountID != account {
		return Session{}, ErrNotFound
	}
	return x, nil
}
func taskIn(tx Tx, account ids.Account, id ids.Task) (Task, error) {
	x, err := tx.Task(id)
	if err != nil {
		return Task{}, err
	}
	if x.AccountID != account {
		return Task{}, ErrNotFound
	}
	return x, nil
}

// liveChain fails closed on missing, cross-account or cyclic ancestors, even
// when a partial restore has left a child apparently live after parent revoke.
func liveChain(tx Tx, account ids.Account, d Delegation, now time.Time) error {
	seen := make(map[ids.Delegation]bool)
	for {
		if d.AccountID != account {
			return ErrNotFound
		}
		if seen[d.ID] || len(seen) >= 64 {
			return ErrConflict
		}
		seen[d.ID] = true
		if d.EndedAt != nil {
			return ErrRevoked
		}
		if !now.Before(d.ExpiresAt) {
			return ErrExpired
		}
		if d.ParentID == "" {
			return nil
		}
		parent, err := tx.Delegation(d.ParentID)
		if err != nil {
			return err
		}
		d = parent
	}
}
func held(tx Tx, actor Principal, now time.Time) ([]Delegation, error) {
	session, err := sessionIn(tx, actor.AccountID, actor.SessionID)
	if err != nil {
		return nil, err
	}
	if session.Status == SessionSuspended {
		return nil, ErrForbidden
	}
	if session.Status == SessionDone || session.Status == SessionStopped {
		return nil, ErrRevoked
	}
	all, err := tx.DelegationsByDelegate(actor.SessionID)
	if err != nil {
		return nil, err
	}
	out := make([]Delegation, 0, len(all))
	for _, d := range all {
		err := liveChain(tx, actor.AccountID, d, now)
		if err == nil {
			out = append(out, d)
			continue
		}
		if !errors.Is(err, ErrExpired) && !errors.Is(err, ErrRevoked) {
			return nil, err
		}
	}
	if len(out) == 0 {
		return nil, ErrRevoked
	}
	return out, nil
}
func reaches(tx Tx, account ids.Account, root, target ids.Task) (bool, error) {
	if root == "" || target == "" {
		return false, nil
	}
	seen := make(map[ids.Task]bool)
	for target != "" {
		if seen[target] || len(seen) >= 64 {
			return false, ErrConflict
		}
		seen[target] = true
		t, err := taskIn(tx, account, target)
		if err != nil {
			return false, err
		}
		if target == root {
			return true, nil
		}
		target = t.ParentID
	}
	return false, nil
}

type visibility int

const (
	invisible visibility = iota
	progress
	full
)

func sees(tx Tx, actor Principal, target Session, grants []Delegation) (visibility, error) {
	if target.AccountID != actor.AccountID {
		return invisible, ErrNotFound
	}
	if actor.Kind != PrincipalSession || actor.SessionID == target.ID {
		return full, nil
	}
	others, err := tx.DelegationsByDelegate(target.ID)
	if err != nil {
		return invisible, err
	}
	result := invisible
	for _, d := range grants {
		covered := false
		if d.Task == "" {
			covered = slices.Contains(d.Scope, "observe:progress") || slices.Contains(d.Scope, "read:transcript")
		} else {
			for _, other := range others {
				if other.AccountID != actor.AccountID {
					return invisible, ErrNotFound
				}
				yes, err := reaches(tx, actor.AccountID, d.Task, other.Task)
				if err != nil {
					return invisible, err
				}
				covered = covered || yes
			}
		}
		if covered {
			result = progress
			if slices.Contains(d.Scope, "read:transcript") {
				return full, nil
			}
		}
	}
	return result, nil
}

// grantsForRead preserves the explicit right to read one's own historical
// ledger, but only live, non-suspended grants confer rights to other sessions.
func grantsForRead(tx Tx, actor Principal, now time.Time) ([]Delegation, error) {
	if actor.Kind != PrincipalSession {
		return nil, nil
	}
	grants, err := held(tx, actor, now)
	if errors.Is(err, ErrRevoked) || errors.Is(err, ErrForbidden) {
		return nil, nil
	}
	return grants, err
}

func (s *Service) Session(ctx context.Context, actor Principal, id ids.Session) (Session, error) {
	var out Session
	err := s.view(ctx, actor, func(tx Tx) error {
		out = Session{}
		target, err := sessionIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		grants, err := grantsForRead(tx, actor, s.now())
		if err != nil {
			return err
		}
		vis, err := sees(tx, actor, target, grants)
		if err != nil {
			return err
		}
		if vis == invisible {
			return ErrForbidden
		}
		out = target
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	return out, nil
}
func (s *Service) Sessions(ctx context.Context, actor Principal) ([]Session, error) {
	var out []Session
	err := s.view(ctx, actor, func(tx Tx) error {
		out = nil
		if actor.Kind == PrincipalSession {
			grants, err := held(tx, actor, s.now())
			if err != nil {
				return err
			}
			allowed := false
			for _, d := range grants {
				allowed = allowed || (d.Task == "" && slices.Contains(d.Scope, "observe:progress"))
			}
			if !allowed {
				return ErrForbidden
			}
		}
		var err error
		out, err = tx.SessionsByAccount(actor.AccountID)
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
