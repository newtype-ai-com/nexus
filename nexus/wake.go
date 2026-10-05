package nexus

import (
	"context"
	"time"
)

const WakeHeader = "X-Newtype-Wake"

// InboxWake is an advisory bit for the authenticated recipient only. Delivered
// but unread mail still needs a wake after a local crash. No receipt is changed.
// This first implementation scans the ledger; the context bounds hint latency.
func (s *Service) InboxWake(ctx context.Context, actor Principal) (bool, error) {
	if actor.Kind != PrincipalSession {
		return false, ErrForbidden
	}
	wake := false
	err := s.view(ctx, actor, func(tx Tx) error {
		wake = false
		if _, err := held(tx, actor, s.now()); err != nil {
			return err
		}
		var after int64
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			events, err := tx.Events(actor.SessionID, after, MaxBatch)
			if err != nil {
				return err
			}
			for _, e := range events {
				after = e.Seq
				if !ForInbox(e) {
					continue
				}
				item := Received{}
				if err := inboxReceipts(tx, e, &item); err != nil {
					return err
				}
				if item.ReadAt == nil {
					wake = true
					return nil
				}
			}
			if len(events) < MaxBatch {
				return nil
			}
		}
	})
	return wake, err
}

// WakeHint is best-effort and bounded. Failure omits the hint, never changes a
// normal API's outcome or disables independent receiver polling.
func (s *Service) WakeHint(ctx context.Context, actor Principal) bool {
	if actor.Kind != PrincipalSession {
		return false
	}
	ctx, cancel := context.WithTimeout(ctx, 250*time.Millisecond)
	defer cancel()
	wake, err := s.InboxWake(ctx, actor)
	return err == nil && wake
}
