package gate

import (
	"context"
	"strings"
)

// OwnerCredentials restricts access to the owner and their email-approved users.
// It does not grant authority: normal expiry, revocation and account checks still
// run in the authenticator. Agent credentials are closed until a runner can prove
// their relationship to the configured owner.
type OwnerCredentials struct {
	store  CredentialStore
	email  string
	strict bool
}

func NewOwnerCredentials(store CredentialStore, email string) (*OwnerCredentials, error) {
	return NewOwnerCredentialsWithPolicy(store, email, false)
}

// NewOwnerCredentialsWithPolicy closes admission lookup in strict mode, including
// existing credentials and offline provisioning. It never grants authority.
func NewOwnerCredentialsWithPolicy(store CredentialStore, email string, strict bool) (*OwnerCredentials, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if store == nil || !validEmail(email) || strings.Contains(email, "*") {
		return nil, ErrUnauthenticated
	}
	return &OwnerCredentials{store: store, email: email, strict: strict}, nil
}

func (s *OwnerCredentials) allowed(ctx context.Context, c Credential) bool {
	if c.Kind != "licence" && c.Kind != "login" {
		return false
	}
	if strings.ToLower(c.Email) == s.email {
		return true
	}
	if s.strict {
		return false
	}
	if admissions, ok := s.store.(interface {
		Admitted(context.Context, string, string) (bool, error)
	}); ok {
		allowed, err := admissions.Admitted(ctx, s.email, strings.ToLower(c.Email))
		return err == nil && allowed
	}
	return false
}
func (s *OwnerCredentials) LookupCredential(ctx context.Context, verifier string) (Credential, error) {
	c, err := s.store.LookupCredential(ctx, verifier)
	if err != nil || !s.allowed(ctx, c) {
		return Credential{}, ErrUnauthenticated
	}
	return c, nil
}
func (s *OwnerCredentials) PutCredential(ctx context.Context, c Credential) error {
	if !s.allowed(ctx, c) {
		return ErrUnauthenticated
	}
	return s.store.PutCredential(ctx, c)
}

// Admits reports whether a credential passes this owner policy (the remote
// MCP endpoint re-checks consents against it).
func (s *OwnerCredentials) Admits(ctx context.Context, c Credential) bool { return s.allowed(ctx, c) }
