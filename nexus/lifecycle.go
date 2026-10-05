package nexus

import (
	"context"
	"errors"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

// endDelegation settles children before parents. Expired-but-unsettled grants
// are included: expiration must not make their reserved budget disappear.
func endDelegation(tx Tx, account ids.Account, id ids.Delegation, reason string, now time.Time) ([]ids.Delegation, error) {
	var ordered []Delegation
	seen := map[ids.Delegation]bool{}
	var walk func(ids.Delegation, int) error
	walk = func(id ids.Delegation, depth int) error {
		if depth >= 64 || seen[id] {
			return ErrConflict
		}
		seen[id] = true
		d, err := delegationIn(tx, account, id)
		if err != nil {
			return err
		}
		children, err := tx.DelegationsByParent(id)
		if err != nil {
			return err
		}
		for _, child := range children {
			if err = walk(child.ID, depth+1); err != nil {
				return err
			}
		}
		if d.EndedAt == nil {
			ordered = append(ordered, d)
		}
		return nil
	}
	if err := walk(id, 0); err != nil {
		return nil, err
	}
	ended := make([]ids.Delegation, 0, len(ordered))
	for _, d := range ordered {
		usage, err := tx.Usage(d.ID)
		if err != nil {
			return nil, err
		}
		if _, err = remaining(d.Limits, usage); err != nil {
			return nil, err
		}
		if usage.Reserved.ModelTokens != 0 || usage.Reserved.RuntimeMinutes != 0 || usage.Reserved.SubSessions != 0 || usage.Reserved.Spend != 0 {
			return nil, ErrConflict
		}
		if d.ParentID != "" {
			parent, err := delegationIn(tx, account, d.ParentID)
			if err != nil {
				return nil, err
			}
			if parent.EndedAt != nil {
				return nil, ErrConflict
			}
			pu, err := tx.Usage(parent.ID)
			if err != nil {
				return nil, err
			}
			pu.Reserved, err = subLimits(pu.Reserved, d.Limits)
			if err != nil {
				return nil, err
			}
			pu.Consumed, err = addLimits(pu.Consumed, usage.Consumed)
			if err != nil {
				return nil, err
			}
			if _, err = remaining(parent.Limits, pu); err != nil {
				return nil, err
			}
			if err = tx.PutUsage(parent.ID, pu); err != nil {
				return nil, err
			}
		}
		at := now.UTC()
		d.EndedAt = &at
		d.EndReason = reason
		if err = tx.PutDelegation(d); err != nil {
			return nil, err
		}
		if d.Task != "" {
			task, err := taskIn(tx, account, d.Task)
			if err != nil {
				return nil, err
			}
			// Task-scoped observers do not govern the observed request.
			if task.DelegationID == d.ID {
				if err = cancelTaskTree(tx, account, d.Task, 0, map[ids.Task]bool{}); err != nil {
					return nil, err
				}
			}
		}
		if _, err = hubEvent(tx, SystemPrincipal(account), d.Delegate, d.Task, "delegation.ended", map[string]any{"delegation_id": d.ID, "reason": reason}, now); err != nil {
			return nil, err
		}
		ended = append(ended, d.ID)
	}
	// Only after all grants have ended can a multiply-assigned session be closed.
	sessions := map[ids.Session]bool{}
	for _, d := range ordered {
		sessions[d.Delegate] = true
	}
	for sid := range sessions {
		all, err := tx.DelegationsByDelegate(sid)
		if err != nil {
			return nil, err
		}
		live, allDone := false, true
		for _, d := range all {
			err := liveChain(tx, account, d, now)
			if err == nil {
				live = true
			} else if !errors.Is(err, ErrRevoked) && !errors.Is(err, ErrExpired) {
				return nil, err
			}
			justEnded := false
			for _, closed := range ordered {
				justEnded = justEnded || closed.ID == d.ID
			}
			if !justEnded {
				continue
			}
			if d.EndReason != "completed" || d.Task == "" {
				allDone = false
				continue
			}
			task, err := taskIn(tx, account, d.Task)
			if err != nil {
				return nil, err
			}
			if task.Status != "done" {
				allDone = false
			}
		}
		if live {
			continue
		}
		session, err := sessionIn(tx, account, sid)
		if err != nil {
			return nil, err
		}
		if session.Status == SessionDone || session.Status == SessionStopped {
			continue
		}
		session.Status = SessionStopped
		if allDone {
			session.Status = SessionDone
		}
		session.UpdatedAt = now.UTC()
		if err = tx.PutSession(session); err != nil {
			return nil, err
		}
	}
	return ended, nil
}
func cancelTaskTree(tx Tx, account ids.Account, id ids.Task, depth int, seen map[ids.Task]bool) error {
	if depth >= 64 || seen[id] {
		return ErrConflict
	}
	seen[id] = true
	t, err := taskIn(tx, account, id)
	if err != nil {
		return err
	}
	if !terminalTask(t.Status) {
		t.Status = "cancelled"
		if err = tx.PutTask(t); err != nil {
			return err
		}
	}
	children, err := tx.TasksByParent(id)
	if err != nil {
		return err
	}
	for _, child := range children {
		if err = cancelTaskTree(tx, account, child.ID, depth+1, seen); err != nil {
			return err
		}
	}
	return nil
}
func sweepExpired(tx Tx, account ids.Account, parent ids.Delegation, now time.Time) error {
	children, err := tx.DelegationsByParent(parent)
	if err != nil {
		return err
	}
	for _, child := range children {
		if child.AccountID != account {
			return ErrNotFound
		}
		if child.EndedAt == nil && !now.Before(child.ExpiresAt) {
			if _, err = endDelegation(tx, account, child.ID, "expired", now); err != nil {
				return err
			}
		}
	}
	return nil
}

// A session can revoke strict descendants only, and its own grant plus all
// ancestors must still be live. A revoked target remains idempotent for users.
func mayRevoke(tx Tx, actor Principal, target Delegation, now time.Time) error {
	if actor.Kind == PrincipalUser {
		return nil
	}
	if actor.Kind != PrincipalSession || target.Delegate == actor.SessionID {
		return ErrForbidden
	}
	if _, err := held(tx, actor, now); err != nil {
		return err
	}
	seen := map[ids.Delegation]bool{}
	for target.ParentID != "" {
		if seen[target.ID] || len(seen) >= 64 {
			return ErrConflict
		}
		seen[target.ID] = true
		var err error
		target, err = delegationIn(tx, actor.AccountID, target.ParentID)
		if err != nil {
			return err
		}
		if target.Delegate == actor.SessionID {
			return liveChain(tx, actor.AccountID, target, now)
		}
	}
	return ErrForbidden
}
func (s *Service) Revoke(ctx context.Context, actor Principal, id ids.Delegation, reason string) ([]ids.Delegation, error) {
	var out []ids.Delegation
	err := s.update(ctx, actor, func(tx Tx) error {
		out = nil
		d, err := delegationIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		if err = mayRevoke(tx, actor, d, now); err != nil {
			return err
		}
		if d.EndedAt != nil {
			out = []ids.Delegation{}
			return nil
		}
		out, err = endDelegation(tx, actor.AccountID, id, "revoked", now)
		if err != nil {
			return err
		}
		if reason != "" {
			_, err = hubEvent(tx, actor, d.Delegate, d.Task, "delegation.revoke_reason", map[string]string{"reason": reason}, now)
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
func (s *Service) SetTaskStatus(ctx context.Context, actor Principal, id ids.Task, status string) (Task, error) {
	switch status {
	case "pending", "in_progress", "waiting_person", "done", "failed", "cancelled":
	default:
		return Task{}, ErrInvalid
	}
	var out Task
	err := s.update(ctx, actor, func(tx Tx) error {
		out = Task{}
		task, err := taskIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		if actor.Kind == PrincipalSession {
			if task.Assignee != actor.SessionID {
				return ErrForbidden
			}
			if _, err = held(tx, actor, now); err != nil {
				return err
			}
			gov, err := governingDelegation(tx, actor.AccountID, task)
			if err != nil {
				return err
			}
			d, err := delegationIn(tx, actor.AccountID, gov)
			if err != nil {
				return err
			}
			if d.Delegate != actor.SessionID {
				return ErrForbidden
			}
			if err = liveChain(tx, actor.AccountID, d, now); err != nil {
				return err
			}
		}
		if terminalTask(task.Status) {
			if task.Status != status {
				return ErrConflict
			}
			out = task
			return nil
		}
		task.Status = status
		if err = tx.PutTask(task); err != nil {
			return err
		}
		if terminalTask(status) {
			// Steps do not own a mandate, but delegated descendants under them do.
			if err = completeTaskTree(tx, actor.AccountID, task, now, 0, map[ids.Task]bool{}); err != nil {
				return err
			}
		}
		event, err := hubEvent(tx, actor, task.Assignee, task.ID, "task.status", map[string]any{"task_id": task.ID, "status": status}, now)
		if err != nil {
			return err
		}
		if task.ParentID != "" {
			parent, err := taskIn(tx, actor.AccountID, task.ParentID)
			if err != nil {
				return err
			}
			if parent.Assignee != task.Assignee {
				if _, err = hubEvent(tx, actor, parent.Assignee, parent.ID, "subtask.status", map[string]any{"task_id": task.ID, "status": status}, now, event.ID); err != nil {
					return err
				}
			}
		}
		out = task
		return nil
	})
	if err != nil {
		return Task{}, err
	}
	return out, nil
}
func completeTaskTree(tx Tx, account ids.Account, task Task, now time.Time, depth int, seen map[ids.Task]bool) error {
	if depth >= 64 || seen[task.ID] {
		return ErrConflict
	}
	seen[task.ID] = true
	if task.DelegationID != "" {
		if _, err := endDelegation(tx, account, task.DelegationID, "completed", now); err != nil {
			return err
		}
	}
	children, err := tx.TasksByParent(task.ID)
	if err != nil {
		return err
	}
	for _, child := range children {
		if child.AccountID != account {
			return ErrNotFound
		}
		if err = completeTaskTree(tx, account, child, now, depth+1, seen); err != nil {
			return err
		}
		fresh, err := taskIn(tx, account, child.ID)
		if err != nil {
			return err
		}
		if !terminalTask(fresh.Status) {
			fresh.Status = "cancelled"
			if err = tx.PutTask(fresh); err != nil {
				return err
			}
		}
	}
	return nil
}
