package nexus

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

// Receipt is a claim by the authenticated recipient, never execution authority.
// TurnID identifies the model input which consumed this message. Displaying or
// polling Inbox is deliberately insufficient to create a read receipt.
type Receipt struct {
	Event  ids.Event `json:"event_id"`
	TurnID string    `json:"turn_id,omitempty"`
}

type MessageStatus struct {
	Event         ids.Event     `json:"event_id"`
	To            ids.Session   `json:"to"`
	Status        string        `json:"status"`
	SentAt        time.Time     `json:"sent_at"`
	DeliveredAt   *time.Time    `json:"delivered_at,omitempty"`
	ReadAt        *time.Time    `json:"read_at,omitempty"`
	TurnID        string        `json:"turn_id,omitempty"`
	SessionStatus SessionStatus `json:"session_status"`
	LastSeen      *time.Time    `json:"last_seen,omitempty"` // latest local/shared liveness hint, not authority
	ReplyID       ids.Event     `json:"reply_id,omitempty"`
}

func recordMessageReply(tx Tx, actor Principal, m Message, reply Event) error {
	if actor.Kind != PrincipalSession || m.ReplyTo == "" {
		return nil
	}
	original, err := inboxEvent(tx, actor.AccountID, actor.SessionID, m.ReplyTo)
	if errors.Is(err, ErrNotFound) {
		return nil
	} // retain legacy unlinked reply semantics
	if err != nil {
		return err
	}
	if original.Kind != "message" || original.Actor != SessionPrincipal(actor.AccountID, m.To) {
		return nil
	}
	if _, err := receiptEvent(tx, original, "reply"); err == nil {
		return nil
	} else if !errors.Is(err, ErrNotFound) {
		return err
	}
	raw, _ := json.Marshal(struct {
		ReplyID ids.Event `json:"reply_id"`
	}{reply.ID})
	_, err = tx.AppendEvent(Event{ID: ids.Event(ids.New(ids.KindEvent)), AccountID: actor.AccountID, SessionID: actor.SessionID, At: reply.At, Source: "hub", Kind: "message.reply", Actor: actor, TaskID: original.TaskID, ClientEventID: receiptKey("reply", original.ID), CausedBy: []ids.Event{original.ID}, Payload: raw, PayloadHash: hashPayload(raw)})
	return err
}

// inboxReceipts reads trusted receipt events in the same snapshot as the page.
// Recipients may reconcile their own inbox; sender-only status access stays unchanged.
func inboxReceipts(tx Tx, original Event, item *Received) error {
	for _, kind := range []string{"delivered", "read"} {
		r, err := receiptEvent(tx, original, kind)
		if errors.Is(err, ErrNotFound) {
			continue
		}
		if err != nil {
			return err
		}
		var receipt Receipt
		if json.Unmarshal(r.Payload, &receipt) != nil || receipt.Event != original.ID {
			return ErrConflict
		}
		at := r.At
		if kind == "delivered" {
			item.DeliveredAt = &at
		} else {
			if ids.Check(ids.KindTask, receipt.TurnID) != nil {
				return ErrConflict
			}
			item.ReadAt, item.ReadTurnID = &at, receipt.TurnID
		}
	}
	return nil
}

func receiptKey(kind string, event ids.Event) string { return "message." + kind + ":" + string(event) }

func inboxEvent(tx Tx, account ids.Account, to ids.Session, id ids.Event) (Event, error) {
	e, err := tx.EventByID(to, id)
	if err != nil {
		return Event{}, err
	}
	if e.AccountID != account || e.SessionID != to || e.Actor.AccountID != account || !ForInbox(e) {
		return Event{}, ErrNotFound
	}
	return e, nil
}

func receiptEvent(tx Tx, original Event, kind string) (Event, error) {
	e, err := tx.EventByClientID(original.SessionID, receiptKey(kind, original.ID))
	if err != nil {
		return Event{}, err
	}
	// A client may choose arbitrary client_event_id strings. Such a collision
	// must never be interpreted as a trusted receipt.
	if e.AccountID != original.AccountID || e.Source != "hub" || e.Kind != "message."+kind || e.Actor != SessionPrincipal(original.AccountID, original.SessionID) || len(e.CausedBy) != 1 || e.CausedBy[0] != original.ID {
		return Event{}, ErrConflict
	}
	return e, nil
}

func appendReceipt(tx Tx, original Event, kind, turn string, at time.Time) error {
	_, err := receiptEvent(tx, original, kind)
	if err == nil {
		return nil
	} // first observation is immutable across retries
	if !errors.Is(err, ErrNotFound) {
		return err
	}
	raw, _ := json.Marshal(Receipt{Event: original.ID, TurnID: turn})
	_, err = tx.AppendEvent(Event{ID: ids.Event(ids.New(ids.KindEvent)), AccountID: original.AccountID, SessionID: original.SessionID, At: at, Source: "hub", Kind: "message." + kind, Actor: SessionPrincipal(original.AccountID, original.SessionID), TaskID: original.TaskID, ClientEventID: receiptKey(kind, original.ID), CausedBy: []ids.Event{original.ID}, Payload: raw, PayloadHash: hashPayload(raw)})
	return err
}

func (s *Service) messageReceipt(ctx context.Context, actor Principal, receipt Receipt, read bool) error {
	if actor.Kind != PrincipalSession {
		return ErrForbidden
	}
	if _, err := ids.ParseEvent(string(receipt.Event)); err != nil {
		return ErrInvalid
	}
	// Core request/turn ids use req_ ids. No arbitrary strings enter audit records.
	if read {
		if err := ids.Check(ids.KindTask, receipt.TurnID); err != nil {
			return ErrInvalid
		}
	} else if receipt.TurnID != "" {
		return ErrInvalid
	}
	return s.update(ctx, actor, func(tx Tx) error {
		if _, err := held(tx, actor, s.now()); err != nil {
			return err
		}
		e, err := inboxEvent(tx, actor.AccountID, actor.SessionID, receipt.Event)
		if err != nil {
			return err
		}
		now := s.now().UTC()
		// Reading entails delivery; reorder/retry cannot regress state.
		if err := appendReceipt(tx, e, "delivered", "", now); err != nil {
			return err
		}
		if read {
			return appendReceipt(tx, e, "read", receipt.TurnID, now)
		}
		return nil
	})
}

func (s *Service) MessageDelivered(ctx context.Context, actor Principal, receipt Receipt) error {
	return s.messageReceipt(ctx, actor, receipt, false)
}
func (s *Service) MessageRead(ctx context.Context, actor Principal, receipt Receipt) error {
	return s.messageReceipt(ctx, actor, receipt, true)
}

// MessageDelivery is visible to the actual sender (not payload mentions or an
// unrelated observer), or the account's human principal. No message body leaves
// this endpoint. Recipients acknowledge their own Inbox through receipt routes.
func (s *Service) MessageDelivery(ctx context.Context, actor Principal, to ids.Session, id ids.Event) (MessageStatus, error) {
	if actor.Kind != PrincipalSession && actor.Kind != PrincipalUser {
		return MessageStatus{}, ErrForbidden
	}
	if _, err := ids.ParseSession(string(to)); err != nil {
		return MessageStatus{}, ErrInvalid
	}
	if _, err := ids.ParseEvent(string(id)); err != nil {
		return MessageStatus{}, ErrInvalid
	}
	var out MessageStatus
	err := s.view(ctx, actor, func(tx Tx) error {
		out = MessageStatus{}
		if actor.Kind == PrincipalSession {
			if _, err := held(tx, actor, s.now()); err != nil {
				return err
			}
		}
		target, err := sessionIn(tx, actor.AccountID, to)
		if err != nil {
			return err
		}
		e, err := inboxEvent(tx, actor.AccountID, to, id)
		if err != nil {
			return err
		}
		if e.Kind != "message" {
			return ErrNotFound
		}
		if actor.Kind == PrincipalSession && e.Actor != actor {
			return ErrForbidden
		}
		out = MessageStatus{Event: id, To: to, Status: "sent", SentAt: e.At, SessionStatus: target.Status}
		if !target.SeenAt.IsZero() {
			last := target.SeenAt
			out.LastSeen = &last
		}
		for _, kind := range []string{"delivered", "read"} {
			r, err := receiptEvent(tx, e, kind)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return err
			}
			if kind == "delivered" {
				at := r.At
				out.DeliveredAt = &at
				out.Status = "delivered"
			} else {
				var receipt Receipt
				if json.Unmarshal(r.Payload, &receipt) != nil || receipt.Event != id {
					return ErrConflict
				}
				at := r.At
				out.ReadAt, out.TurnID, out.Status = &at, receipt.TurnID, "read"
			}
		}
		reply, err := receiptEvent(tx, e, "reply")
		if err == nil {
			var ref struct {
				ReplyID ids.Event `json:"reply_id"`
			}
			if json.Unmarshal(reply.Payload, &ref) != nil {
				return ErrConflict
			}
			out.ReplyID = ref.ReplyID
		} else if !errors.Is(err, ErrNotFound) {
			return err
		}
		return nil
	})
	if err != nil {
		return MessageStatus{}, err
	}
	if last := s.LastSeen(to); !last.IsZero() && (out.LastSeen == nil || last.After(*out.LastSeen)) {
		out.LastSeen = &last
	}
	return out, nil
}
