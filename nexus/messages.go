package nexus

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/redact"
)

type Message struct {
	To      ids.Session `json:"to"`
	Text    string      `json:"text"`
	ReplyTo ids.Event   `json:"reply_to,omitempty"`
	Task    ids.Task    `json:"task_id,omitempty"`
	About   ids.Task    `json:"about_task_id,omitempty"`
	// ClientEventID is scoped to sender and recipient. Replays never add mail.
	ClientEventID string `json:"client_event_id,omitempty"`
}

// relationOf is descriptive only: it never grants authority.
func relationOf(tx Tx, account ids.Account, sender, reader ids.Session, now time.Time) (string, error) {
	above := func(ancestor, child ids.Session) (bool, error) {
		grants, err := tx.DelegationsByDelegate(child)
		if err != nil {
			return false, err
		}
		for _, d := range grants {
			if err = liveChain(tx, account, d, now); err != nil {
				if errors.Is(err, ErrRevoked) || errors.Is(err, ErrExpired) {
					continue
				}
				return false, err
			}
			for d.ParentID != "" {
				d, err = delegationIn(tx, account, d.ParentID)
				if err != nil {
					return false, err
				}
				if d.Delegate == ancestor {
					return true, nil
				}
			}
		}
		return false, nil
	}
	yes, err := above(sender, reader)
	if err != nil {
		return "", err
	}
	if yes {
		return "delegator", nil
	}
	yes, err = above(reader, sender)
	if err != nil {
		return "", err
	}
	if yes {
		return "delegate", nil
	}
	return "peer", nil
}

func (s *Service) Send(ctx context.Context, actor Principal, m Message) (Received, error) {
	if actor.Kind != PrincipalUser && actor.Kind != PrincipalSession {
		return Received{}, ErrForbidden
	}
	m.Text = strings.TrimSpace(m.Text)
	if !utf8.ValidString(m.Text) || len(m.Text) == 0 || len(m.Text) > 65536 || len(m.ClientEventID) > 128 {
		return Received{}, ErrInvalid
	}
	if m.To == "" && m.About == "" {
		return Received{}, ErrInvalid
	}
	if m.To != "" && ids.Check(ids.KindSession, string(m.To)) != nil {
		return Received{}, ErrInvalid
	}
	for _, task := range []ids.Task{m.Task, m.About} {
		if task != "" && ids.Check(ids.KindTask, string(task)) != nil {
			return Received{}, ErrInvalid
		}
	}
	if m.ReplyTo != "" {
		if _, err := ids.ParseEvent(string(m.ReplyTo)); err != nil {
			return Received{}, ErrInvalid
		}
	}
	if actor.Kind == PrincipalSession && actor.SessionID == m.To {
		return Received{}, ErrInvalid
	}
	var out Received
	err := s.update(ctx, actor, func(tx Tx) error {
		out = Received{}
		message := m // transaction retries must not retain derived routing
		if message.To == "" {
			task, err := taskIn(tx, actor.AccountID, message.About)
			if err != nil {
				return err
			}
			if task.Assignee == "" {
				return ErrConflict
			}
			message.To = task.Assignee
		}
		m := message
		if actor.Kind == PrincipalSession && actor.SessionID == m.To {
			return ErrInvalid
		}
		target, err := sessionIn(tx, actor.AccountID, m.To)
		if err != nil {
			return err
		}
		if target.Status == SessionDone || target.Status == SessionSuspended {
			return ErrConflict
		}
		// A stopped recipient may store mail, but a revoked/expired mandate
		// cannot receive new work even from the account's human principal.
		if target.Status == SessionStopped {
			if err := hasLive(tx, actor.AccountID, m.To, s); err != nil {
				if errors.Is(err, ErrRevoked) || errors.Is(err, ErrExpired) {
					return ErrConflict
				}
				return err
			}
		}
		payload := Received{Text: m.Text, ReplyTo: m.ReplyTo, Relation: "person"}
		now := s.now().UTC()
		if actor.Kind == PrincipalSession {
			if _, err = held(tx, actor, now); err != nil {
				return err
			}
			if err = hasLive(tx, actor.AccountID, m.To, s); err != nil {
				if errors.Is(err, ErrRevoked) || errors.Is(err, ErrExpired) || errors.Is(err, ErrForbidden) {
					return ErrConflict
				}
				return err
			}
			sender, err := sessionIn(tx, actor.AccountID, actor.SessionID)
			if err != nil {
				return err
			}
			payload.From, payload.FromTitle = sender.ID, sender.Title
			payload.Relation, err = relationOf(tx, actor.AccountID, sender.ID, m.To, now)
			if err != nil {
				return err
			}
		}
		if m.Task != "" {
			task, err := taskIn(tx, actor.AccountID, m.Task)
			if err != nil {
				return err
			}
			// Task metadata is descriptive, but a bot cannot impersonate another
			// session's task. Host adapters attach only a server-bound task.
			if actor.Kind == PrincipalSession && task.Assignee != actor.SessionID {
				return ErrForbidden
			}
			payload.SenderTask = m.Task
		}
		about, title, err := messageAbout(tx, actor, target, m, now)
		if err != nil {
			return err
		}
		payload.About, payload.AboutTitle = about, title
		raw, _ := json.Marshal(payload)
		clean, count, err := redact.JSON(raw)
		if err != nil {
			return ErrInvalid
		}
		key := ""
		if m.ClientEventID != "" {
			identity, _ := json.Marshal(struct {
				Actor Principal
				Key   string
			}{actor, m.ClientEventID})
			key = "message:" + hashPayload(identity)
			old, err := tx.EventByClientID(m.To, key)
			if err == nil {
				var prev Received
				if !ForInbox(old) || old.Kind != "message" || old.Actor != actor || json.Unmarshal(old.Payload, &prev) != nil {
					return ErrConflict
				}
				// Names/relations can legitimately change between retries.
				var cleaned Received
				if json.Unmarshal(clean, &cleaned) != nil {
					return ErrInvalid
				}
				if prev.Text != cleaned.Text || prev.ReplyTo != cleaned.ReplyTo || prev.SenderTask != m.Task || (m.About != "" && prev.About != m.About) {
					return ErrConflict
				}
				out, err = received(old)
				return err
			}
			if !errors.Is(err, ErrNotFound) {
				return err
			}
		}
		source := "user"
		if actor.Kind == PrincipalSession {
			source = "bot"
		}
		e, err := tx.AppendEvent(Event{ID: ids.Event(ids.New(ids.KindEvent)), AccountID: actor.AccountID, SessionID: m.To, At: now, Source: source, Kind: "message", Actor: actor, TaskID: target.EntryTaskID, ClientEventID: key, Payload: clean, PayloadHash: hashPayload(clean), Redactions: count})
		if err != nil {
			return err
		}
		if actor.Kind == PrincipalSession {
			sender, err := sessionIn(tx, actor.AccountID, actor.SessionID)
			if err != nil {
				return err
			}
			_, err = hubEvent(tx, actor, actor.SessionID, sender.EntryTaskID, "message.sent", map[string]any{"to": m.To, "to_title": target.Title, "relation": payload.Relation, "event_id": e.ID, "reply_to": m.ReplyTo, "sender_task_id": payload.SenderTask, "about_task_id": payload.About, "about_title": payload.AboutTitle}, now, e.ID)
			if err != nil {
				return err
			}

		}
		if err := recordMessageReply(tx, actor, m, e); err != nil {
			return err
		}
		if err := recordMessageEdge(tx, e); err != nil { // team closure index, same transaction
			return err
		}
		out, err = received(e)
		return err
	})
	if err != nil {
		return Received{}, err
	}
	return out, nil
}

func (s *Service) Tell(ctx context.Context, actor Principal, to ids.Session, text string) (Received, error) {
	if actor.Kind != PrincipalUser {
		return Received{}, ErrForbidden
	}
	return s.Send(ctx, actor, Message{To: to, Text: text})
}

func (s *Service) ResolveSession(ctx context.Context, actor Principal, name string) (ids.Session, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return "", ErrInvalid
	}
	if id, err := ids.ParseSession(name); err == nil {
		err = s.view(ctx, actor, func(tx Tx) error { _, e := sessionIn(tx, actor.AccountID, id); return e })
		return id, err
	}
	var out ids.Session
	err := s.view(ctx, actor, func(tx Tx) error {
		out = ""
		if actor.Kind == PrincipalSession {
			if _, err := held(tx, actor, s.now()); err != nil {
				return err
			}
			// a seat name in the sender's own team wins (the seat's fixed session)
			if id, ok, err := resolveSeat(tx, actor, name); err != nil || ok {
				out = id
				return err
			}
		}
		sessions, err := tx.SessionsByAccount(actor.AccountID)
		if err != nil {
			return err
		}
		for _, x := range sessions {
			if !strings.EqualFold(strings.TrimSpace(x.Title), name) || x.Status == SessionDone || x.Status == SessionStopped || x.Status == SessionSuspended {
				continue
			}
			if err = hasLive(tx, actor.AccountID, x.ID, s); err != nil {
				if errors.Is(err, ErrRevoked) {
					continue
				}
				return err
			}
			if out != "" {
				return ErrConflict
			}
			out = x.ID
		}
		if out == "" {
			return ErrNotFound
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return out, nil
}

func (s *Service) SendTo(ctx context.Context, actor Principal, to string, m Message) (Received, error) {
	if task, err := ids.ParseTask(strings.TrimSpace(to)); err == nil {
		if m.About != "" && m.About != task {
			return Received{}, ErrInvalid
		}
		m.To, m.About = "", task
		return s.Send(ctx, actor, m)
	}
	if strings.TrimSpace(to) == "" && m.About != "" {
		m.To = ""
		return s.Send(ctx, actor, m)
	}
	id, err := s.ResolveSession(ctx, actor, to)
	if err != nil {
		return Received{}, err
	}
	m.To = id
	return s.Send(ctx, actor, m)
}
