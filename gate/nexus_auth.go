package gate

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

var ErrUnauthenticated = errors.New("unauthenticated")

// Credential contains only a SHA-256 verifier. Provisioning is a trusted server
// boundary after verified enrolment, not a public token-minting endpoint.
type Credential struct {
	Verifier string      `json:"verifier"`
	Kind     string      `json:"kind"` // licence, login, agent
	Account  ids.Account `json:"account_id"`
	Email    string      `json:"email,omitempty"`
	Session  ids.Session `json:"session_id,omitempty"`
	Expires  time.Time   `json:"expires_at"`
	Revoked  bool        `json:"revoked"`
}
type CredentialStore interface {
	LookupCredential(context.Context, string) (Credential, error)
	PutCredential(context.Context, Credential) error
}

func Verifier(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
func validCredential(c Credential) bool {
	if _, err := ids.ParseAccount(string(c.Account)); err != nil {
		return false
	}
	if len(c.Verifier) != 64 {
		return false
	}
	if _, err := hex.DecodeString(c.Verifier); err != nil {
		return false
	}
	if c.Expires.IsZero() {
		return false
	}
	switch c.Kind {
	case "licence", "login":
		return c.Session == "" && c.Email != ""
	case "agent":
		_, err := ids.ParseSession(string(c.Session))
		return err == nil
	default:
		return false
	}
}

type MemoryCredentials struct {
	mu      sync.RWMutex
	records map[string]Credential
}

func NewMemoryCredentials() *MemoryCredentials {
	return &MemoryCredentials{records: map[string]Credential{}}
}
func (m *MemoryCredentials) PutCredential(ctx context.Context, c Credential) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !validCredential(c) {
		return nexus.ErrInvalid
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.records[c.Verifier]; ok {
		if old.Account != c.Account || old.Kind != c.Kind || old.Session != c.Session || old.Email != c.Email {
			return nexus.ErrConflict
		}
		c.Revoked = c.Revoked || old.Revoked
	}
	m.records[c.Verifier] = c
	return nil
}
func (m *MemoryCredentials) LookupCredential(ctx context.Context, verifier string) (Credential, error) {
	if err := ctx.Err(); err != nil {
		return Credential{}, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out Credential
	found := false
	for _, c := range m.records {
		if subtle.ConstantTimeCompare([]byte(c.Verifier), []byte(verifier)) == 1 {
			out = c
			found = true
		}
	}
	if !found {
		return Credential{}, ErrUnauthenticated
	}
	return out, nil
}

type NexusAuth struct {
	Store   CredentialStore
	Service *nexus.Service
	Clock   func() time.Time
}

func (a NexusAuth) Authenticate(r *http.Request) (nexus.Principal, error) {
	return a.authenticate(r, true)
}

// Reauthenticate checks a still-open request without reporting fresh presence.
// In particular it cannot restore a system-stopped agent on a heartbeat.
func (a NexusAuth) Reauthenticate(r *http.Request) (nexus.Principal, error) {
	return a.authenticate(r, false)
}

func (a NexusAuth) authenticate(r *http.Request, reportPresence bool) (nexus.Principal, error) {
	if a.Store == nil || a.Service == nil {
		return nexus.Principal{}, ErrUnauthenticated
	}
	now := time.Now()
	if a.Clock != nil {
		now = a.Clock()
	}
	auth := r.Header.Values("Authorization")
	if len(auth) != 1 {
		return nexus.Principal{}, ErrUnauthenticated
	}
	parts := strings.Fields(auth[0])
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || len(parts[1]) < 24 || len(parts[1]) > 4096 {
		return nexus.Principal{}, ErrUnauthenticated
	}
	lookup := func(token, kind string) (Credential, error) {
		if len(token) < 24 || len(token) > 4096 {
			return Credential{}, ErrUnauthenticated
		}
		c, err := a.Store.LookupCredential(r.Context(), Verifier(token))
		if err != nil || !validCredential(c) || c.Kind != kind || c.Revoked || !now.Before(c.Expires) {
			return Credential{}, ErrUnauthenticated
		}
		return c, nil
	}
	headers := r.Header.Values("X-Newtype-Session")
	if len(headers) > 1 {
		return nexus.Principal{}, ErrUnauthenticated
	}
	sid := r.Header.Get("X-Newtype-Session")
	if strings.HasPrefix(parts[1], "nta_") {
		if sid != "" || r.Header.Get("X-Newtype-Login") != "" {
			return nexus.Principal{}, ErrUnauthenticated
		}
		c, err := lookup(parts[1], "agent")
		if err != nil {
			return nexus.Principal{}, err
		}
		p := nexus.SessionPrincipal(c.Account, c.Session)
		session, err := a.Service.Session(r.Context(), nexus.UserPrincipal(c.Account, c.Email), c.Session)
		if err != nil || session.Runner != nexus.Container || (session.Status == nexus.SessionStopped && session.StoppedBy != nexus.PrincipalSystem) || session.Status == nexus.SessionDone || session.Status == nexus.SessionSuspended {
			return nexus.Principal{}, ErrUnauthenticated
		}
		// Credential identity is verified above. Only a system-presence stop
		// may be restored, with live ancestry rechecked by Touch atomically.
		if reportPresence {
			if err = a.Service.Touch(r.Context(), p); err != nil {
				return nexus.Principal{}, ErrUnauthenticated
			}
		}
		if _, err = a.Service.LiveSession(r.Context(), p); err != nil {
			return nexus.Principal{}, ErrUnauthenticated
		}
		return p, nil
	}
	lic, err := lookup(parts[1], "licence")
	if err != nil {
		return nexus.Principal{}, err
	}
	logins := r.Header.Values("X-Newtype-Login")
	if len(logins) != 1 {
		return nexus.Principal{}, ErrUnauthenticated
	}
	login, err := lookup(logins[0], "login")
	if err != nil || login.Account != lic.Account {
		return nexus.Principal{}, ErrUnauthenticated
	}
	p := nexus.UserPrincipal(login.Account, login.Email)
	if sid != "" {
		id, err := ids.ParseSession(sid)
		if err != nil {
			return nexus.Principal{}, ErrUnauthenticated
		}
		session, err := a.Service.Session(r.Context(), p, id)
		if err != nil || session.Runner != nexus.Local || session.Status == nexus.SessionSuspended || session.Status == nexus.SessionDone {
			return nexus.Principal{}, ErrUnauthenticated
		}
		p = nexus.SessionPrincipal(login.Account, id)
	}
	return p, nil
}
