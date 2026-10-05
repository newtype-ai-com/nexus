package nexus

import (
	"encoding/json"
	"errors"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

func currentTaskOf(tx Tx, account ids.Account, session Session, now time.Time) (ids.Task, error) {
	grants, err := tx.DelegationsByDelegate(session.ID)
	if err != nil {
		return "", err
	}
	var latest Delegation
	for _, d := range grants {
		if err := liveChain(tx, account, d, now); err != nil {
			if errors.Is(err, ErrRevoked) || errors.Is(err, ErrExpired) {
				continue
			}
			return "", err
		}
		if d.ID > latest.ID {
			latest = d
		}
	}
	if latest.ID != "" {
		return latest.Task, nil
	}
	return session.EntryTaskID, nil
}

func messageAbout(tx Tx, actor Principal, target Session, m Message, now time.Time) (ids.Task, string, error) {
	account := actor.AccountID
	pick := func(id ids.Task) (ids.Task, string, error) {
		if id == "" {
			return "", "", nil
		}
		t, err := taskIn(tx, account, id)
		if err != nil {
			return "", "", err
		}
		if t.Assignee != target.ID {
			return "", "", ErrInvalid
		}
		return t.ID, t.Title, nil
	}
	if m.About != "" {
		return pick(m.About)
	}
	if m.ReplyTo != "" && actor.Kind == PrincipalSession {
		// Read the exact original in this sender's inbox. Its authenticated
		// sender must be this reply's recipient; payload substrings do not count.
		original, err := inboxEvent(tx, account, actor.SessionID, m.ReplyTo)
		if err != nil && !errors.Is(err, ErrNotFound) {
			return "", "", err
		}
		if err == nil && original.Kind == "message" && original.Actor == SessionPrincipal(account, target.ID) {
			var data Received
			if json.Unmarshal(original.Payload, &data) != nil {
				return "", "", ErrConflict
			}
			if data.SenderTask != "" {
				return pick(data.SenderTask)
			}
		}
	}
	if m.Task != "" {
		grants, err := tx.DelegationsByDelegate(target.ID)
		if err != nil {
			return "", "", err
		}
		var best ids.Task
		var newest ids.Delegation
		for _, d := range grants {
			if err := liveChain(tx, account, d, now); err != nil {
				if errors.Is(err, ErrRevoked) || errors.Is(err, ErrExpired) {
					continue
				}
				return "", "", err
			}
			id := d.Task
			seen := map[ids.Task]bool{}
			for id != "" {
				if seen[id] || len(seen) >= 64 {
					return "", "", ErrConflict
				}
				seen[id] = true
				if id == m.Task {
					if d.ID > newest {
						best, newest = d.Task, d.ID
					}
					break
				}
				task, err := taskIn(tx, account, id)
				if err != nil {
					return "", "", err
				}
				id = task.ParentID
			}
		}
		if best != "" {
			return pick(best)
		}
	}
	id, err := currentTaskOf(tx, account, target, now)
	if err != nil {
		return "", "", err
	}
	return pick(id)
}
