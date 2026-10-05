package nexus

import "context"

// LiveSession validates identity and live ancestry without selecting an action.
// It returns no mandate plaintext to the session.
func (s *Service) LiveSession(ctx context.Context, actor Principal) (Session, error) {
	if actor.Kind != PrincipalSession {
		return Session{}, ErrForbidden
	}
	var out Session
	err := s.view(ctx, actor, func(tx Tx) error {
		out = Session{}
		if _, err := held(tx, actor, s.now()); err != nil {
			return err
		}
		var err error
		out, err = sessionIn(tx, actor.AccountID, actor.SessionID)
		return err
	})
	if err != nil {
		return Session{}, err
	}
	return out, nil
}
