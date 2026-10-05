package nexus

import (
	"context"

	"github.com/newtype-ai-com/nexus/ids"
)

// Left returns only a numeric budget snapshot, not a certificate, authorization
// or reservation. Session callers may query only their own live delegation.
// Ended/expired chains fail closed until historical-balance policy is settled.
func (s *Service) Left(ctx context.Context, actor Principal, id ids.Delegation) (Limits, error) {
	if actor.Kind != PrincipalSession && actor.Kind != PrincipalUser {
		return Limits{}, ErrForbidden
	}
	if ids.Check(ids.KindDelegation, string(id)) != nil {
		return Limits{}, ErrInvalid
	}
	var out Limits
	err := s.view(ctx, actor, func(tx Tx) error {
		out = Limits{}
		d, err := delegationIn(tx, actor.AccountID, id)
		if err != nil {
			return err
		}
		if actor.Kind == PrincipalSession && d.Delegate != actor.SessionID {
			return ErrForbidden
		}
		if err = liveChain(tx, actor.AccountID, d, s.now()); err != nil {
			return err
		}
		session, err := sessionIn(tx, actor.AccountID, d.Delegate)
		if err != nil {
			return err
		}
		if session.Status == SessionStopped || session.Status == SessionSuspended || session.Status == SessionDone {
			return ErrForbidden
		}
		usage, err := tx.Usage(id)
		if err != nil {
			return err
		}
		out, err = remaining(d.Limits, usage)
		return err
	})
	if err != nil {
		return Limits{}, err
	}
	return out, nil
}
