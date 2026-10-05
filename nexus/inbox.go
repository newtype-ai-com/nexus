package nexus

import (
	"context"
	"encoding/json"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

// Received is a view of a recipient's ledger, not an execution permission.
// An assignment identifies the mandate the recipient must validate before work.
type Received struct {
	Event      ids.Event      `json:"event_id"`
	To         ids.Session    `json:"to"`
	Seq        int64          `json:"seq"`
	At         time.Time      `json:"at"`
	From       ids.Session    `json:"from,omitempty"`
	FromTitle  string         `json:"from_title,omitempty"`
	Relation   string         `json:"relation"`
	Text       string         `json:"text"`
	ReplyTo    ids.Event      `json:"reply_to,omitempty"`
	Task       ids.Task       `json:"task_id,omitempty"`
	Title      string         `json:"title,omitempty"`
	Deleg      ids.Delegation `json:"delegation_id,omitempty"`
	About      ids.Task       `json:"about_task_id,omitempty"`
	AboutTitle string         `json:"about_title,omitempty"`
	SenderTask ids.Task       `json:"sender_task_id,omitempty"`
	// Kind and SenderKind come from the stored event, never its payload.
	// Receipt metadata is for recipient reconciliation, not execution authority.
	Kind        string        `json:"kind,omitempty"`
	SenderKind  PrincipalKind `json:"sender_kind,omitempty"`
	DeliveredAt *time.Time    `json:"delivered_at,omitempty"`
	ReadAt      *time.Time    `json:"read_at,omitempty"`
	ReadTurnID  string        `json:"read_turn_id,omitempty"`
}

// ForInbox also gates stream wakeups. A fresh session starts with its assignment
// already; only existing recipients need mail. Client ledger entries must not
// impersonate trusted assignments, even if their kind and payload match.
func ForInbox(e Event) bool {
	switch e.Kind {
	case "message":
		return (e.Source == "user" && e.Actor.Kind == PrincipalUser) || (e.Source == "bot" && e.Actor.Kind == PrincipalSession)
	case "task.assigned":
		var p struct {
			Inbox bool `json:"inbox"`
		}
		return e.Source == "hub" && json.Unmarshal(e.Payload, &p) == nil && p.Inbox
	default:
		return false
	}
}

func received(e Event) (Received, error) {
	var out Received
	if e.Kind == "task.assigned" {
		var p struct {
			Task  ids.Task       `json:"task_id"`
			Title string         `json:"title"`
			Brief string         `json:"brief"`
			Deleg ids.Delegation `json:"delegation_id"`
			From  ids.Session    `json:"from_session"`
		}
		if err := json.Unmarshal(e.Payload, &p); err != nil {
			return Received{}, err
		}
		out = Received{From: p.From, Relation: "delegator", Text: p.Brief, Task: p.Task, Title: p.Title, Deleg: p.Deleg}
	} else if err := json.Unmarshal(e.Payload, &out); err != nil {
		return Received{}, err
	}
	out.Event, out.To, out.Seq, out.At = e.ID, e.SessionID, e.Seq, e.At
	out.Kind, out.SenderKind = e.Kind, e.Actor.Kind
	out.DeliveredAt, out.ReadAt, out.ReadTurnID = nil, nil, ""
	return out, nil
}

// Inbox reads only the authenticated session's own ledger. next advances over
// non-mail too; clients persist it to avoid rescanning. No read state is mutated.
func (s *Service) Inbox(ctx context.Context, actor Principal, after int64, limit int) ([]Received, int64, error) {
	if actor.Kind != PrincipalSession {
		return nil, after, ErrForbidden
	}
	if after < 0 || limit < 0 {
		return nil, after, ErrInvalid
	}
	if limit == 0 || limit > 100 {
		limit = 100
	}
	var out []Received
	next := after
	err := s.view(ctx, actor, func(tx Tx) error {
		out, next = []Received{}, after
		if _, err := sessionIn(tx, actor.AccountID, actor.SessionID); err != nil {
			return err
		}
		for {
			events, err := tx.Events(actor.SessionID, next, MaxBatch)
			if err != nil {
				return err
			}
			for _, e := range events {
				if ForInbox(e) {
					item, err := received(e)
					if err != nil {
						return err
					}
					if err := inboxReceipts(tx, e, &item); err != nil {
						return err
					}
					out = append(out, item)
				}
				next = e.Seq
				if len(out) == limit {
					return nil
				}
			}
			if len(events) < MaxBatch {
				return nil
			}
		}
	})
	if err != nil {
		return nil, after, err
	}
	return out, next, nil
}
