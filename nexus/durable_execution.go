package nexus

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

// ExecutionState contains no arguments, provider errors, credentials or output.
// Immutable ledger transitions are the durable source of truth on every replica.
type ExecutionState struct {
	ID              ids.Invocation `json:"id"`
	Actor           Principal      `json:"actor"`
	Delegation      ids.Delegation `json:"delegation_id"`
	Action          string         `json:"action"`
	InputHash       string         `json:"input_hash"`
	Status          string         `json:"status"`
	ApprovalExpires time.Time      `json:"approval_expires_at,omitempty"`
	Budget          int64          `json:"budget"`
	Metered         bool           `json:"metered"`
	Used            int64          `json:"used"`
	Charged         int64          `json:"charged"`
	QuotaMonth      string         `json:"quota_month,omitempty"`
	// Owner is set only by the trusted model Gate after it verified the
	// configured owner's own person credentials (never from HTTP input). An
	// owner execution is not charged to the monthly account quota and its
	// reservation shrinks to what the delegation has left instead of being
	// refused; delegation usage and settlement are recorded as usual.
	Owner bool `json:"owner,omitempty"`
}

func executionEvent(tx Tx, x ExecutionState, phase string, actor Principal, now time.Time) error {
	raw, err := json.Marshal(x)
	if err != nil {
		return err
	}
	_, err = tx.AppendEvent(Event{ID: ids.Event(ids.New(ids.KindEvent)), AccountID: x.Actor.AccountID, SessionID: x.Actor.SessionID, At: now.UTC(), Source: "hub", Kind: "execution." + phase, Actor: actor, InvocationID: x.ID, ClientEventID: "durable:" + string(x.ID) + ":" + phase, Payload: raw, PayloadHash: hashPayload(raw)})
	return err
}
func executionState(tx Tx, account ids.Account, session ids.Session, id ids.Invocation) (ExecutionState, error) {
	var x ExecutionState
	// Fixed transition keys avoid replaying an unbounded ledger.
	for _, phase := range []string{"settled", "cancelled", "started", "approval", "requested"} {
		e, err := tx.EventByClientID(session, "durable:"+string(id)+":"+phase)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return x, err
		}
		if e.AccountID != account || e.Source != "hub" || e.Kind != "execution."+phase || e.InvocationID != id {
			return x, ErrConflict
		}
		if json.Unmarshal(e.Payload, &x) != nil || x.Actor.AccountID != account || x.Actor.SessionID != session || x.ID != id {
			return ExecutionState{}, ErrConflict
		}
		return x, nil
	}
	return x, ErrNotFound
}
func executionFor(tx Tx, actor Principal, id ids.Invocation) (ExecutionState, error) {
	if actor.Kind == PrincipalSession {
		return executionState(tx, actor.AccountID, actor.SessionID, id)
	}
	sessions, err := tx.SessionsByAccount(actor.AccountID)
	if err != nil {
		return ExecutionState{}, err
	}
	for _, session := range sessions {
		x, err := executionState(tx, actor.AccountID, session.ID, id)
		if err == nil {
			return x, nil
		}
		if !errors.Is(err, ErrNotFound) {
			return ExecutionState{}, err
		}
	}
	return ExecutionState{}, ErrNotFound
}
func (s *Service) Execution(ctx context.Context, actor Principal, id ids.Invocation) (ExecutionState, error) {
	var out ExecutionState
	err := s.view(ctx, actor, func(tx Tx) error {
		var err error
		out, err = executionFor(tx, actor, id)
		if err == nil && (out.Status == "pending" || out.Status == "approved") && !s.now().Before(out.ApprovalExpires) {
			out.Status = "expired"
		}
		return err
	})
	if err != nil {
		return ExecutionState{}, err
	}
	return out, nil
}

// PrepareExecution is a trusted admission boundary. Budget/Metered/TTL come
// from server configuration, never from HTTP input or model-produced output.
func (s *Service) PrepareExecution(ctx context.Context, actor Principal, x ExecutionState, ttl time.Duration) (ExecutionState, error) {
	if actor.Kind != PrincipalSession || x.Budget < 0 || ttl <= 0 || ttl > 24*time.Hour || !validAction(x.Action, false) || len(x.InputHash) != 64 {
		return ExecutionState{}, ErrInvalid
	}
	if _, err := hex.DecodeString(x.InputHash); err != nil {
		return ExecutionState{}, ErrInvalid
	}
	if _, err := ids.ParseInvocation(string(x.ID)); err != nil {
		return ExecutionState{}, ErrInvalid
	}
	var out ExecutionState
	err := s.update(ctx, actor, func(tx Tx) error {
		out = ExecutionState{}
		// A legacy receipt may represent an already dispatched side effect. Switching
		// adapters must never turn that invocation into a fresh durable execution.
		if _, err := tx.EventByClientID(actor.SessionID, "execution:"+string(x.ID)); err == nil {
			return ErrConflict
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		old, err := executionState(tx, actor.AccountID, actor.SessionID, x.ID)
		if err == nil {
			if old.Delegation != x.Delegation || old.Action != x.Action || old.InputHash != x.InputHash || old.Budget != x.Budget || old.Metered != x.Metered || old.Owner != x.Owner {
				return ErrConflict
			}
			out = old
			return nil
		}
		if !errors.Is(err, ErrNotFound) {
			return err
		}
		d, err := delegationIn(tx, actor.AccountID, x.Delegation)
		if err != nil {
			return err
		}
		if d.Delegate != actor.SessionID {
			return ErrForbidden
		}
		decision, err := decide(tx, actor.AccountID, d, x.Action, s.now())
		if err != nil {
			return err
		}
		if decision.Effect == "deny" {
			return ErrForbidden
		}
		out = ExecutionState{ID: x.ID, Actor: actor, Delegation: x.Delegation, Action: x.Action, InputHash: x.InputHash, Budget: x.Budget, Metered: x.Metered, Owner: x.Owner, Status: "ready"}
		if decision.Effect == "ask" {
			if decision.Approver != "" && decision.Approver != "user" {
				return ErrForbidden
			}
			out.Status = "pending"
			out.ApprovalExpires = s.now().Add(ttl)
			if d.ExpiresAt.Before(out.ApprovalExpires) {
				out.ApprovalExpires = d.ExpiresAt
			}
		}
		return executionEvent(tx, out, "requested", actor, s.now())
	})
	if err != nil {
		return ExecutionState{}, err
	}
	return out, nil
}
func (s *Service) DecideExecution(ctx context.Context, actor Principal, id ids.Invocation, hash string, approve bool) (ExecutionState, error) {
	if actor.Kind != PrincipalUser {
		return ExecutionState{}, ErrForbidden
	}
	var out ExecutionState
	err := s.update(ctx, actor, func(tx Tx) error {
		var err error
		out, err = executionFor(tx, actor, id)
		if err != nil {
			return err
		}
		if out.Status != "pending" || out.InputHash != hash {
			return ErrConflict
		}
		if !s.now().Before(out.ApprovalExpires) {
			return ErrExpired
		}
		d, err := delegationIn(tx, actor.AccountID, out.Delegation)
		if err != nil {
			return err
		}
		decision, err := decide(tx, actor.AccountID, d, out.Action, s.now())
		if err != nil {
			return err
		}
		if decision.Effect != "ask" || (decision.Approver != "" && decision.Approver != "user") {
			return ErrForbidden
		}
		out.Status = "denied"
		if approve {
			out.Status = "approved"
		}
		return executionEvent(tx, out, "approval", actor, s.now())
	})
	if err != nil {
		return ExecutionState{}, err
	}
	return out, nil
}
func (s *Service) StartExecution(ctx context.Context, actor Principal, id ids.Invocation) (ExecutionState, bool, error) {
	if actor.Kind != PrincipalSession {
		return ExecutionState{}, false, ErrForbidden
	}
	var out ExecutionState
	fresh := false
	err := s.update(ctx, actor, func(tx Tx) error {
		fresh = false
		var err error
		out, err = executionFor(tx, actor, id)
		if err != nil {
			return err
		}
		if out.Status != "ready" && out.Status != "approved" {
			return nil
		}
		if out.Status == "approved" && !s.now().Before(out.ApprovalExpires) {
			return ErrExpired
		}
		d, err := delegationIn(tx, actor.AccountID, out.Delegation)
		if err != nil {
			return err
		}
		decision, err := decide(tx, actor.AccountID, d, out.Action, s.now())
		if err != nil {
			return err
		}
		if decision.Effect != "auto" && !(decision.Effect == "ask" && out.Status == "approved" && (decision.Approver == "" || decision.Approver == "user")) {
			return ErrForbidden
		}
		usage, err := tx.Usage(d.ID)
		if err != nil {
			return err
		}
		left, err := remaining(d.Limits, usage)
		if err != nil {
			return err
		}
		if out.Owner && out.Budget > left.ModelTokens {
			// The owner's large ceiling never refuses on its own: it reserves
			// what the root has left (an unlimited root has effectively all).
			out.Budget = left.ModelTokens
		}
		if out.Budget > left.ModelTokens || (out.Metered && out.Budget == 0) {
			return ErrLimit
		}
		// Conservatively charge the ceiling before dispatch. A crash never frees a
		// possibly spent budget. Settlement refunds only verified unused capacity.
		// The owner is exempt from the monthly account quota (QuotaMonth stays
		// empty, so settlement leaves the quota alone too).
		if out.Budget > 0 && !out.Owner {
			out.QuotaMonth, err = chargeAccountQuota(tx, actor.AccountID, s.now(), out.Budget)
			if err != nil {
				return err
			}
		}
		usage.Consumed.ModelTokens += out.Budget
		if err = tx.PutUsage(d.ID, usage); err != nil {
			return err
		}
		out.Status = "running"
		out.Charged = out.Budget
		err = executionEvent(tx, out, "started", actor, s.now())
		fresh = err == nil
		return err
	})
	if err != nil {
		return ExecutionState{}, false, err
	}
	return out, fresh, nil
}
func (s *Service) CancelExecution(ctx context.Context, actor Principal, id ids.Invocation) (ExecutionState, error) {
	if actor.Kind == PrincipalSystem {
		return ExecutionState{}, ErrForbidden
	}
	var out ExecutionState
	err := s.update(ctx, actor, func(tx Tx) error {
		var err error
		out, err = executionFor(tx, actor, id)
		if err != nil {
			return err
		}
		switch out.Status {
		case "ready", "pending", "approved":
			out.Status = "cancelled"
		case "running":
			out.Status = "cancelling"
		default:
			return nil
		}
		return executionEvent(tx, out, "cancelled", actor, s.now())
	})
	if err != nil {
		return ExecutionState{}, err
	}
	return out, nil
}

// SettleExecution is server-only. Actual usage comes from a trusted provider;
// unknown usage (negative) retains the entire ceiling. It is idempotent across
// retries and propagates refunds through already-settled old ancestry.
func (s *Service) SettleExecution(ctx context.Context, actor Principal, session ids.Session, id ids.Invocation, status string, used int64) (ExecutionState, error) {
	if actor.Kind != PrincipalSystem {
		return ExecutionState{}, ErrForbidden
	}
	if status != "completed" && status != "failed" && status != "cancelled" && status != "indeterminate" {
		return ExecutionState{}, ErrInvalid
	}
	var out ExecutionState
	err := s.update(ctx, actor, func(tx Tx) error {
		var err error
		out, err = executionState(tx, actor.AccountID, session, id)
		if err != nil {
			return err
		}
		if out.Status != "running" && out.Status != "cancelling" {
			return nil
		}
		charge := out.Budget
		if out.Metered && used >= 0 {
			charge = min(out.Budget, used)
		}
		accountUsed := out.Budget
		if out.Metered && used >= 0 {
			accountUsed = used
		}
		if err = settleAccountQuota(tx, actor.AccountID, out.QuotaMonth, out.Budget, accountUsed); err != nil {
			return err
		}
		refund := out.Budget - charge
		d, err := delegationIn(tx, actor.AccountID, out.Delegation)
		if err != nil {
			return err
		}
		seen := map[ids.Delegation]bool{}
		for refund > 0 {
			if seen[d.ID] || len(seen) >= 64 {
				return ErrConflict
			}
			seen[d.ID] = true
			u, err := tx.Usage(d.ID)
			if err != nil {
				return err
			}
			if u.Consumed.ModelTokens < refund {
				return ErrConflict
			}
			u.Consumed.ModelTokens -= refund
			if err = tx.PutUsage(d.ID, u); err != nil {
				return err
			}
			if d.EndedAt == nil || d.ParentID == "" {
				break
			}
			d, err = delegationIn(tx, actor.AccountID, d.ParentID)
			if err != nil {
				return err
			}
		}
		if out.Metered && used > out.Budget {
			if _, err = hubEvent(tx, actor, session, "", "limit.reached", map[string]any{"delegation_id": out.Delegation, "limit": "model_tokens", "used": used, "charged": charge}, s.now()); err != nil {
				return err
			}
		}
		if out.Status == "cancelling" {
			status = "cancelled"
		}
		out.Status = status
		out.Used = used
		out.Charged = charge
		return executionEvent(tx, out, "settled", actor, s.now())
	})
	if err != nil {
		return ExecutionState{}, err
	}
	return out, nil
}
