package nexus

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

type Decision struct {
	Effect   string `json:"effect"`
	Approver string `json:"approver,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

func decide(tx Tx, account ids.Account, d Delegation, action string, now time.Time) (Decision, error) {
	deny := Decision{Effect: "deny"}
	if err := liveChain(tx, account, d, now); err != nil {
		return deny, err
	}
	session, err := sessionIn(tx, account, d.Delegate)
	if err != nil {
		return deny, err
	}
	if session.Status == SessionSuspended {
		deny.Reason = "suspended until the person re-approves"
		return deny, nil
	}
	if session.Status == SessionDone || session.Status == SessionStopped {
		deny.Reason = "session is not active"
		return deny, nil
	}
	result := Decision{}
	required := requiredScope(action)
	rank := map[string]int{"": -1, "auto": 0, "ask": 1, "deny": 2}
	// liveChain has already bounded and validated the ancestry.
	for {
		if required != "" && !covers(d.Scope, required) {
			deny.Reason = fmt.Sprintf("scope %s is not granted by %s", required, d.ID)
			return deny, nil
		}
		p, err := tx.Policy(d.Policy.ID, d.Policy.Version)
		if err != nil {
			return deny, err
		}
		if p.AccountID != account {
			return deny, ErrNotFound
		}
		if p.Hash() != d.Policy.Hash {
			return deny, ErrConflict
		}
		if _, err = normalizeRules(p.Rules); err != nil {
			return deny, ErrConflict
		}
		if _, err = normalizeApprover(p.Approver); err != nil {
			return deny, ErrConflict
		}
		effect, mentioned := p.decide(action)
		if mentioned {
			if rank[effect] > rank[result.Effect] {
				result.Effect = effect
			}
			if effect == "ask" {
				if result.Approver == "" || p.Approver == "user" || p.Approver == "" {
					result.Approver = p.Approver
					if result.Approver == "" {
						result.Approver = "user"
					}
				}
			}
		}
		if d.ParentID == "" {
			break
		}
		d, err = delegationIn(tx, account, d.ParentID)
		if err != nil {
			return deny, err
		}
	}
	if result.Effect == "" {
		deny.Reason = "no rule in the chain allows " + action
		return deny, nil
	}
	if result.Effect != "ask" {
		result.Approver = ""
	} else {
		result.Reason = "approval required by the delegation chain"
	}
	return result, nil
}
func (s *Service) Authorize(ctx context.Context, actor Principal, id ids.Delegation, action string) (Decision, error) {
	action = strings.TrimSpace(action)
	if !validAction(action, false) {
		return Decision{Effect: "deny"}, ErrInvalid
	}
	out := Decision{Effect: "deny"}
	err := s.view(ctx, actor, func(tx Tx) error {
		out = Decision{Effect: "deny"}
		d, err := delegationIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		if actor.Kind == PrincipalSession && d.Delegate != actor.SessionID {
			return ErrForbidden
		}
		out, err = decide(tx, actor.AccountID, d, action, s.now())
		return err
	})
	if err != nil {
		return Decision{Effect: "deny"}, err
	}
	return out, nil
}
func (s *Service) AuthorizeSession(ctx context.Context, actor Principal, action string) (Decision, error) {
	if actor.Kind != PrincipalSession {
		return Decision{Effect: "deny"}, ErrForbidden
	}
	action = strings.TrimSpace(action)
	if !validAction(action, false) {
		return Decision{Effect: "deny"}, ErrInvalid
	}
	out := Decision{Effect: "deny"}
	err := s.view(ctx, actor, func(tx Tx) error {
		out = Decision{Effect: "deny"}
		if _, err := sessionIn(tx, actor.AccountID, actor.SessionID); err != nil {
			return err
		}
		all, err := tx.DelegationsByDelegate(actor.SessionID)
		if err != nil {
			return err
		}
		live := false
		for _, d := range all {
			if err = liveChain(tx, actor.AccountID, d, s.now()); err != nil {
				if errors.Is(err, ErrRevoked) || errors.Is(err, ErrExpired) {
					continue
				}
				return err
			}
			live = true
			out, err = decide(tx, actor.AccountID, d, action, s.now())
			if err != nil {
				return err
			}
			if out.Effect == "auto" {
				return nil
			}
		}
		if !live {
			return ErrRevoked
		}
		return nil
	})
	if err != nil {
		return Decision{Effect: "deny"}, err
	}
	return out, nil
}
func (s *Service) Consume(ctx context.Context, actor Principal, id ids.Delegation, amount Limits) (Usage, error) {
	if actor.Kind != PrincipalSession {
		return Usage{}, ErrForbidden
	}
	if err := validLimits(amount); err != nil {
		return Usage{}, err
	}
	if amount.MaxDepth != 0 {
		return Usage{}, ErrInvalid
	}
	var out Usage
	err := s.update(ctx, actor, func(tx Tx) error {
		out = Usage{}
		d, err := delegationIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		if d.Delegate != actor.SessionID {
			return ErrForbidden
		}
		if err = liveChain(tx, actor.AccountID, d, s.now()); err != nil {
			return err
		}
		session, err := sessionIn(tx, actor.AccountID, d.Delegate)
		if err != nil {
			return err
		}
		if session.Status == SessionSuspended {
			return ErrForbidden
		}
		if session.Status == SessionDone || session.Status == SessionStopped {
			return ErrRevoked
		}
		if amount.Spend > 0 && amount.Currency != d.Limits.Currency {
			return ErrInvalid
		}
		usage, err := tx.Usage(id)
		if err != nil {
			return err
		}
		left, err := remaining(d.Limits, usage)
		if err != nil {
			return err
		}
		if !fits(amount, left) {
			return ErrLimit
		}
		if amount.ModelTokens > 0 {
			if _, err = chargeAccountQuota(tx, actor.AccountID, s.now(), amount.ModelTokens); err != nil {
				return err
			}
		}
		usage.Consumed, err = addLimits(usage.Consumed, amount)
		if err != nil {
			return err
		}
		if err = tx.PutUsage(id, usage); err != nil {
			return err
		}
		out = usage
		return nil
	})
	if err != nil {
		return Usage{}, err
	}
	return out, nil
}
