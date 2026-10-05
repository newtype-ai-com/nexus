package nexus

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"unicode/utf8"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/redact"
)

const MaxBatch = 500

func hashPayload(payload []byte) string {
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func (s *Service) AppendEvents(ctx context.Context, actor Principal, sessionID ids.Session, inputs []EventInput) ([]Event, error) {
	if err := checkActor(actor); err != nil {
		return nil, err
	}
	if len(inputs) > MaxBatch {
		return nil, ErrInvalid
	}
	if len(inputs) == 0 {
		return []Event{}, nil
	}
	var out []Event
	err := s.update(ctx, actor, func(tx Tx) error {
		out = nil // Store may roll back and retry this closure.
		if _, err := sessionIn(tx, actor.AccountID, sessionID); err != nil {
			return err
		}
		var grants []Delegation
		if actor.Kind == PrincipalSession {
			if actor.SessionID != sessionID {
				return ErrForbidden
			}
			var err error
			grants, err = held(tx, actor, s.now())
			if err != nil {
				return err
			}
		}
		for _, input := range inputs {
			kind := strings.TrimSpace(input.Kind)
			if !utf8.ValidString(kind) || utf8.RuneCountInString(kind) < 1 || utf8.RuneCountInString(kind) > 64 || len(input.ClientEventID) > 128 {
				return ErrInvalid
			}
			if strings.HasPrefix(input.ClientEventID, "message.") {
				return ErrForbidden // reserved for service-owned receipt/reply keys
			}
			// Delivery is a domain mutation, never a client-authored ledger kind.
			if actor.Kind != PrincipalSystem && (kind == "message" || strings.HasPrefix(kind, "message.")) {
				return ErrForbidden
			}
			source := input.Source
			if source == "" {
				source = "engine"
			}
			switch source {
			case "user", "model", "tool", "engine", "bot":
			case "hub":
				// Clients may not forge trusted progress records visible to observers.
				if actor.Kind != PrincipalSystem {
					return ErrForbidden
				}
			default:
				return ErrInvalid
			}
			if input.InvocationID != "" {
				if _, err := ids.ParseInvocation(string(input.InvocationID)); err != nil {
					return ErrInvalid
				}
			}
			for _, id := range input.CausedBy {
				if _, err := ids.ParseEvent(string(id)); err != nil {
					return ErrInvalid
				}
			}
			if input.TaskID != "" {
				if _, err := taskIn(tx, actor.AccountID, input.TaskID); err != nil {
					return err
				}
				if actor.Kind == PrincipalSession {
					allowed := false
					for _, d := range grants {
						yes, err := reaches(tx, actor.AccountID, d.Task, input.TaskID)
						if err != nil {
							return err
						}
						allowed = allowed || yes
					}
					if !allowed {
						return ErrForbidden
					}
				}
			}
			payload := []byte(input.Payload)
			if len(payload) == 0 {
				payload = []byte("null")
			}
			cleaned, count, err := redact.JSON(payload)
			if err != nil {
				return fmt.Errorf("%w: invalid payload", ErrInvalid)
			}
			hash := hashPayload(cleaned)
			if input.ClientEventID != "" {
				old, err := tx.EventByClientID(sessionID, input.ClientEventID)
				if err == nil {
					if old.PayloadHash != hash || old.Kind != kind || old.TaskID != input.TaskID {
						return ErrConflict
					}
					out = append(out, old)
					continue
				}
				if !errors.Is(err, ErrNotFound) {
					return err
				}
			}
			event, err := tx.AppendEvent(Event{
				ID: ids.Event(ids.New(ids.KindEvent)), AccountID: actor.AccountID,
				SessionID: sessionID, At: s.now().UTC(), Source: source, Kind: kind,
				Actor: actor, TaskID: input.TaskID, InvocationID: input.InvocationID,
				ClientEventID: input.ClientEventID, Payload: cleaned, PayloadHash: hash,
				Redactions: count, CausedBy: input.CausedBy,
			})
			if err != nil {
				return err
			}
			out = append(out, event)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

func pageLimit(limit int) int {
	if limit <= 0 || limit > 1000 {
		return 1000
	}
	return limit
}
func (s *Service) Events(ctx context.Context, actor Principal, id ids.Session, after int64, limit int) ([]Event, int64, error) {
	if after < 0 {
		return nil, after, ErrInvalid
	}
	var out []Event
	next := after
	err := s.view(ctx, actor, func(tx Tx) error {
		out, next = nil, after
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
		if vis != full {
			return ErrForbidden
		}
		out, err = tx.Events(id, after, pageLimit(limit))
		if err != nil {
			return err
		}
		if len(out) > 0 {
			next = out[len(out)-1].Seq
		}
		return nil
	})
	if err != nil {
		return nil, after, err
	}
	return out, next, nil
}

// Feed advances next over invisible events too. Limit bounds scanned records,
// not visible results, so callers must follow next even when events is empty.
func (s *Service) Feed(ctx context.Context, actor Principal, after int64, limit int) ([]Event, int64, error) {
	if after < 0 {
		return nil, after, ErrInvalid
	}
	var out []Event
	next := after
	err := s.view(ctx, actor, func(tx Tx) error {
		out, next = nil, after
		grants, err := grantsForRead(tx, actor, s.now())
		if err != nil {
			return err
		}
		events, err := tx.EventsSince(actor.AccountID, after, pageLimit(limit))
		if err != nil {
			return err
		}
		cache := make(map[ids.Session]visibility)
		for _, event := range events {
			vis, known := cache[event.SessionID]
			if !known {
				target, err := sessionIn(tx, actor.AccountID, event.SessionID)
				if err != nil {
					return err
				}
				vis, err = sees(tx, actor, target, grants)
				if err != nil {
					return err
				}
				cache[event.SessionID] = vis
			}
			next = event.Cursor
			if vis == full || (vis == progress && event.Source == "hub") {
				out = append(out, event)
			}
		}
		return nil
	})
	if err != nil {
		return nil, after, err
	}
	return out, next, nil
}
func (s *Service) Cursor(ctx context.Context, actor Principal) (int64, error) {
	var out int64
	err := s.view(ctx, actor, func(tx Tx) error {
		out = 0
		if actor.Kind == PrincipalSession {
			if _, err := sessionIn(tx, actor.AccountID, actor.SessionID); err != nil {
				return err
			}
		}
		var err error
		out, err = tx.Cursor(actor.AccountID)
		return err
	})
	if err != nil {
		return 0, err
	}
	return out, nil
}
