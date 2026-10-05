package nexus

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/newtype-ai-com/nexus/ids"
)

// BeginExecution is a TRUSTED server boundary for the local fixed-cost runner.
// Approved must come from a server-owned, exact-input, one-use approval, never
// from an HTTP body. It is not a replacement for Gate's variable usage charging.
// A start receipt, policy recheck and usage charge commit in one transaction.
// Reusing invocation with different parameters fails; a matching receipt returns
// fresh=false, so callers must NOT execute again (including after a restart).
func (s *Service) BeginExecution(ctx context.Context, actor Principal, delegation ids.Delegation, invocation ids.Invocation, action, inputHash string, tokens int64, approved bool) (fresh bool, err error) {
	if actor.Kind != PrincipalSession || tokens < 0 || len(inputHash) != 64 || !validAction(action, false) {
		return false, ErrInvalid
	}
	if _, err := hex.DecodeString(inputHash); err != nil {
		return false, ErrInvalid
	}
	if _, err := ids.ParseInvocation(string(invocation)); err != nil {
		return false, ErrInvalid
	}
	payload, _ := json.Marshal(struct {
		Delegation ids.Delegation `json:"delegation_id"`
		Action     string         `json:"action"`
		InputHash  string         `json:"input_hash"`
		Tokens     int64          `json:"tokens"`
	}{delegation, action, inputHash, tokens})
	err = s.update(ctx, actor, func(tx Tx) error {
		fresh = false
		if _, e := executionState(tx, actor.AccountID, actor.SessionID, invocation); e == nil {
			return ErrConflict
		} else if !errors.Is(e, ErrNotFound) {
			return e
		}
		d, e := delegationIn(tx, actor.AccountID, delegation)
		if e != nil {
			return e
		}
		if d.Delegate != actor.SessionID {
			return ErrForbidden
		}
		decision, e := decide(tx, actor.AccountID, d, action, s.now())
		if e != nil {
			return e
		}
		if decision.Effect != "auto" && !(decision.Effect == "ask" && approved) {
			return ErrForbidden
		}
		key := "execution:" + string(invocation)
		old, e := tx.EventByClientID(actor.SessionID, key)
		if e == nil {
			if old.Kind != "execution.started" || old.PayloadHash != hashPayload(payload) {
				return ErrConflict
			}
			return nil
		}
		if !errors.Is(e, ErrNotFound) {
			return e
		}
		usage, e := tx.Usage(delegation)
		if e != nil {
			return e
		}
		left, e := remaining(d.Limits, usage)
		if e != nil {
			return e
		}
		if tokens > left.ModelTokens {
			return ErrLimit
		}
		if tokens > 0 {
			if _, e = chargeAccountQuota(tx, actor.AccountID, s.now(), tokens); e != nil {
				return e
			}
		}
		usage.Consumed.ModelTokens += tokens
		if e = tx.PutUsage(delegation, usage); e != nil {
			return e
		}
		_, e = tx.AppendEvent(Event{
			ID: ids.Event(ids.New(ids.KindEvent)), AccountID: actor.AccountID,
			SessionID: actor.SessionID, At: s.now().UTC(), Source: "hub",
			Kind: "execution.started", Actor: actor, TaskID: d.Task,
			InvocationID: invocation, ClientEventID: key,
			Payload: payload, PayloadHash: hashPayload(payload),
		})
		fresh = e == nil
		return e
	})
	if err != nil {
		return false, err
	}
	return fresh, nil
}
