package nexus

import (
	"context"
	"errors"
	"strings"

	"github.com/newtype-ai-com/nexus/ids"
)

// CreateObserver grants read visibility without reserving a worker budget.
// TaskID optionally restricts visibility to one root request.
func (s *Service) CreateObserver(ctx context.Context, actor Principal, req RootRequest) (Issued, error) {
	if actor.Kind != PrincipalUser {
		return Issued{}, ErrForbidden
	}
	title, err := cleanTitle(req.Title)
	if err != nil {
		return Issued{}, err
	}
	scope, err := normalizeScopes(req.Scope)
	if err != nil {
		return Issued{}, err
	}
	for _, sc := range scope {
		if sc != "observe:progress" && sc != "read:transcript" && sc != "newtype:run" && !strings.HasPrefix(sc, "model:") {
			return Issued{}, ErrInvalid
		}
	}
	if err = validLimits(req.Limits); err != nil {
		return Issued{}, err
	}
	if req.Limits.SubSessions != 0 || req.Limits.Spend != 0 {
		return Issued{}, ErrInvalid
	}
	req.Limits.MaxDepth = 0
	if req.TTL < 0 || req.TTL > MaxTTL {
		return Issued{}, ErrInvalid
	}
	if req.TTL == 0 {
		req.TTL = MaxTTL
	}
	p, err := makePolicy(actor.AccountID, req.Rules, req.Approver)
	if err != nil {
		return Issued{}, err
	}
	runner, err := runnerOf(req.Runner)
	if err != nil {
		return Issued{}, err
	}
	var out Issued
	err = s.update(ctx, actor, func(tx Tx) error {
		out = Issued{}
		now := s.now().UTC()
		if req.TaskID != "" {
			task, err := taskIn(tx, actor.AccountID, req.TaskID)
			if err != nil {
				return err
			}
			if task.Kind != "request" || task.ParentID != "" {
				return ErrInvalid
			}
		}
		session := Session{ID: ids.Session(ids.New(ids.KindSession)), AccountID: actor.AccountID, Kind: Observer, Runner: runner, Title: title, Status: SessionRequested, CreatedAt: now, UpdatedAt: now}
		if req.ToSessionID != "" {
			session, err = sessionIn(tx, actor.AccountID, req.ToSessionID)
			if err != nil {
				return err
			}
			if session.Runner == Remote {
				return ErrForbidden
			}
			if _, err = held(tx, SessionPrincipal(actor.AccountID, session.ID), now); err != nil {
				return err
			}
		}
		did := ids.Delegation(ids.New(ids.KindDelegation))
		d := Delegation{ID: did, AccountID: actor.AccountID, Principal: actor, Delegator: actor, Delegate: session.ID, Task: req.TaskID, RootID: did, Scope: scope, Policy: policyRef(p), Limits: req.Limits, IssuedAt: now, ExpiresAt: now.Add(req.TTL)}
		if err = tx.PutPolicy(p); err != nil {
			return err
		}
		if err = tx.PutSession(session); err != nil {
			return err
		}
		if err = tx.PutDelegation(d); err != nil {
			return err
		}
		if _, err = hubEvent(tx, actor, session.ID, "", "delegation.issued", issuanceSummary(d), now); err != nil {
			return err
		}
		out = Issued{Session: session, Delegation: d, Policy: p}
		return nil
	})
	if err != nil {
		return Issued{}, err
	}
	return out, nil
}

// DelegationInfo is intentionally unavailable to sessions. Sealed credentials
// for the delegate are issued separately by Credentials.
type DelegationDetails struct {
	Delegation  Delegation  `json:"delegation"`
	Remaining   Limits      `json:"remaining"`
	PolicyChain []PolicyRef `json:"policy_chain"`
	Rules       [][]Rule    `json:"rules"`
}

func (s *Service) DelegationInfo(ctx context.Context, actor Principal, id ids.Delegation) (DelegationDetails, error) {
	if actor.Kind != PrincipalUser && actor.Kind != PrincipalSystem {
		return DelegationDetails{}, ErrForbidden
	}
	var out DelegationDetails
	err := s.update(ctx, actor, func(tx Tx) error {
		out = DelegationDetails{}
		d, err := delegationIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		usage, err := tx.Usage(id)
		if err != nil {
			return err
		}
		left, err := remaining(d.Limits, usage)
		if err != nil {
			return err
		}
		out = DelegationDetails{Delegation: d, Remaining: left}
		seen := map[ids.Delegation]bool{}
		for {
			if seen[d.ID] || len(seen) >= 64 {
				return ErrConflict
			}
			seen[d.ID] = true
			p, err := tx.Policy(d.Policy.ID, d.Policy.Version)
			if err != nil {
				return err
			}
			if p.AccountID != actor.AccountID {
				return ErrNotFound
			}
			if p.Hash() != d.Policy.Hash {
				return ErrConflict
			}
			out.PolicyChain = append(out.PolicyChain, d.Policy)
			out.Rules = append(out.Rules, p.Rules)
			if d.ParentID == "" {
				break
			}
			d, err = delegationIn(tx, actor.AccountID, d.ParentID)
			if err != nil {
				return err
			}
		}
		_, err = hubEvent(tx, actor, out.Delegation.Delegate, out.Delegation.Task, "delegation.read", map[string]any{"delegation_id": id}, s.now())
		return err
	})
	if err != nil {
		return DelegationDetails{}, err
	}
	return out, nil
}

// hasLive ignores stopped status for the explicit session restart path.
func hasLive(tx Tx, account ids.Account, id ids.Session, s *Service) error {
	all, err := tx.DelegationsByDelegate(id)
	if err != nil {
		return err
	}
	for _, d := range all {
		err = liveChain(tx, account, d, s.now())
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrRevoked) && !errors.Is(err, ErrExpired) {
			return err
		}
	}
	return ErrRevoked
}
func (s *Service) SetSessionStatus(ctx context.Context, actor Principal, id ids.Session, status SessionStatus) (Session, error) {
	switch status {
	case SessionRunning, SessionWaiting, SessionStopped, SessionDone:
	default:
		return Session{}, ErrInvalid
	}
	var out Session
	err := s.update(ctx, actor, func(tx Tx) error {
		out = Session{}
		session, err := sessionIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		if actor.Kind == PrincipalSession && (actor.SessionID != id || status == SessionDone) {
			return ErrForbidden
		}
		if session.Status == SessionDone {
			if status != SessionDone {
				return ErrConflict
			}
			out = session
			return nil
		}
		if session.Status == SessionSuspended {
			return ErrForbidden
		}
		if session.Status == status && (status != SessionStopped || session.StoppedBy == actor.Kind) {
			out = session
			return nil
		}
		if session.Status == SessionStopped || status == SessionRunning || status == SessionWaiting {
			if err = hasLive(tx, actor.AccountID, id, s); err != nil {
				return err
			}
		}
		session.Status = status
		session.StoppedBy = ""
		if status == SessionStopped {
			session.StoppedBy = actor.Kind
		}
		session.UpdatedAt = s.now().UTC()
		if err = tx.PutSession(session); err != nil {
			return err
		}
		if _, err = hubEvent(tx, actor, id, "", "session.status", map[string]any{"status": status, "stopped_by": session.StoppedBy}, s.now()); err != nil {
			return err
		}
		out = session
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	return out, nil
}
func (s *Service) Suspend(ctx context.Context, actor Principal, id ids.Session, reason string) (Session, error) {
	if actor.Kind != PrincipalUser && actor.Kind != PrincipalSystem {
		return Session{}, ErrForbidden
	}
	return s.changeSuspension(ctx, actor, id, true, reason)
}
func (s *Service) Resume(ctx context.Context, actor Principal, id ids.Session) (Session, error) {
	if actor.Kind != PrincipalUser {
		return Session{}, ErrForbidden
	}
	return s.changeSuspension(ctx, actor, id, false, "")
}
func (s *Service) changeSuspension(ctx context.Context, actor Principal, id ids.Session, suspend bool, reason string) (Session, error) {
	var out Session
	err := s.update(ctx, actor, func(tx Tx) error {
		out = Session{}
		session, err := sessionIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		if session.Status == SessionDone || session.Status == SessionStopped {
			return ErrConflict
		}
		if suspend {
			if session.Status == SessionSuspended {
				out = session
				return nil
			}
			session.Status = SessionSuspended
		} else {
			if session.Status != SessionSuspended {
				return ErrConflict
			}
			if err = hasLive(tx, actor.AccountID, id, s); err != nil {
				return err
			}
			session.Status = SessionRunning
		}
		session.UpdatedAt = s.now().UTC()
		if err = tx.PutSession(session); err != nil {
			return err
		}
		kind := "session.resumed"
		if suspend {
			kind = "session.suspended"
		}
		if _, err = hubEvent(tx, actor, id, session.EntryTaskID, kind, map[string]string{"reason": reason}, s.now()); err != nil {
			return err
		}
		out = session
		return nil
	})
	if err != nil {
		return Session{}, err
	}
	return out, nil
}
