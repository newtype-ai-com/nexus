// Package mcpauth is the OAuth 2.1 side of the remote MCP endpoint
// (docs/nmcp-remote-endpoint.md §2): a protected-resource check for /mcp, an
// in-process authorization server (dynamic registration, PKCE, resource
// indicators, rotating refresh tokens), the person's consent by an emailed
// one-time link or a CLI code, and the connector that turns a consent into a
// remote Nexus session with a tool-only delegation. Tokens say "may connect";
// the session's delegation says "may do".
package mcpauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"slices"
	"sync"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
)

var (
	ErrNotFound = errors.New("mcpauth: not found")
	ErrUsed     = errors.New("mcpauth: already used")
)

// Client is a dynamically registered public client (no secret).
type Client struct {
	ID           string    `json:"client_id"`
	Name         string    `json:"client_name"`
	RedirectURIs []string  `json:"redirect_uris"`
	Created      time.Time `json:"created_at"`
	// Consented: a person has consented to this client at least once.
	// Registrations that never got a consent expire (PurgeClients).
	Consented bool `json:"-"`
}

// Consent links a person's account to a client: one remote session each.
type Consent struct {
	ID       string      `json:"consent_id"`
	ClientID string      `json:"client_id"`
	Name     string      `json:"client_name"`
	Account  ids.Account `json:"account_id"`
	Email    string      `json:"email"`
	Session  ids.Session `json:"session_id,omitempty"`
	Via      string      `json:"via"` // mail | cli
	Created  time.Time   `json:"created_at"`
	// Expires is the absolute end of the consent (refresh never extends it).
	Expires time.Time `json:"expires_at"`
	Revoked bool      `json:"revoked"`
	// Delegation is the connection session's current root (reused while live).
	Delegation ids.Delegation `json:"-"`
}

// Code is a one-time authorization code (stored by verifier).
type Code struct {
	Verifier  string
	ClientID  string
	Redirect  string
	Challenge string
	Resource  string
	Scope     string
	ConsentID string
	Expires   time.Time
	Used      bool
}

// Token is an access or refresh token (stored by verifier).
type Token struct {
	Verifier  string
	Kind      string // access | refresh
	ClientID  string
	ConsentID string
	Account   ids.Account
	Email     string
	Audience  string
	Scope     string
	Expires   time.Time
	Revoked   bool
}

// Settings are the endpoint's person-controlled switches (one row).
type Settings struct {
	// MailConsent: the consent page offers the emailed one-time link. Off by
	// default: anyone who opens a consent page can then make Nexus mail the
	// owner (within the daily budgets).
	MailConsent bool      `json:"mail_consent"`
	UpdatedAt   time.Time `json:"updated_at,omitzero"`
	UpdatedBy   string    `json:"updated_by,omitempty"`
}

type Store interface {
	Settings(context.Context) (Settings, error)
	PutSettings(context.Context, Settings) error
	PutClient(context.Context, Client) error
	Client(context.Context, string) (Client, error)
	MarkConsented(context.Context, string) error
	// PurgeClients deletes registrations that never got a consent and were
	// created before the given time.
	PurgeClients(context.Context, time.Time) error
	PutConsent(context.Context, Consent) error
	Consent(context.Context, string) (Consent, error)
	Consents(context.Context, ids.Account) ([]Consent, error)
	// RevokeConsent revokes the consent and every token issued under it.
	RevokeConsent(context.Context, string) error
	PutCode(context.Context, Code) error
	// TakeCode marks a code used and returns it; a second take is ErrUsed
	// (with the code, so the caller can revoke what it issued).
	TakeCode(context.Context, string) (Code, error)
	PutToken(context.Context, Token) error
	Token(context.Context, string) (Token, error)
	RevokeToken(context.Context, string) error
	// ConsumeRefresh atomically retires a live refresh token; a token that is
	// already retired (a parallel or replayed use) is ErrUsed.
	ConsumeRefresh(context.Context, string) error
}

// Verifier is the stored form of a token or code.
func Verifier(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func random(prefix string) string {
	var b [32]byte
	_, _ = rand.Read(b[:])
	return prefix + hex.EncodeToString(b[:])
}

// MemoryStore is the in-memory Store (tests, development).
type MemoryStore struct {
	mu       sync.Mutex
	settings Settings
	clients  map[string]Client
	consents map[string]Consent
	codes    map[string]Code
	tokens   map[string]Token
}

func NewMemoryStore() *MemoryStore {
	return &MemoryStore{clients: map[string]Client{}, consents: map[string]Consent{}, codes: map[string]Code{}, tokens: map[string]Token{}}
}

func (m *MemoryStore) Settings(context.Context) (Settings, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.settings, nil
}

func (m *MemoryStore) PutSettings(_ context.Context, s Settings) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.settings = s
	return nil
}

func (m *MemoryStore) PutClient(_ context.Context, c Client) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c.RedirectURIs = slices.Clone(c.RedirectURIs)
	m.clients[c.ID] = c
	return nil
}

func (m *MemoryStore) Client(_ context.Context, id string) (Client, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[id]
	if !ok {
		return Client{}, ErrNotFound
	}
	c.RedirectURIs = slices.Clone(c.RedirectURIs)
	return c, nil
}

func (m *MemoryStore) MarkConsented(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.clients[id]
	if !ok {
		return ErrNotFound
	}
	c.Consented = true
	m.clients[id] = c
	return nil
}

func (m *MemoryStore) PurgeClients(_ context.Context, before time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	for id, c := range m.clients {
		if !c.Consented && c.Created.Before(before) {
			delete(m.clients, id)
		}
	}
	return nil
}

func (m *MemoryStore) ConsumeRefresh(_ context.Context, v string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[v]
	if !ok || t.Kind != "refresh" || t.Revoked {
		return ErrUsed
	}
	t.Revoked = true
	m.tokens[v] = t
	return nil
}

func (m *MemoryStore) PutConsent(_ context.Context, c Consent) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.consents[c.ID]; ok {
		if old.Account != c.Account || old.ClientID != c.ClientID {
			return ErrUsed
		}
		c.Revoked = c.Revoked || old.Revoked // revocation is sticky
	}
	m.consents[c.ID] = c
	return nil
}

func (m *MemoryStore) Consent(_ context.Context, id string) (Consent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.consents[id]
	if !ok {
		return Consent{}, ErrNotFound
	}
	return c, nil
}

func (m *MemoryStore) Consents(_ context.Context, account ids.Account) ([]Consent, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []Consent
	for _, c := range m.consents {
		if c.Account == account {
			out = append(out, c)
		}
	}
	slices.SortFunc(out, func(a, b Consent) int { return a.Created.Compare(b.Created) })
	return out, nil
}

func (m *MemoryStore) RevokeConsent(_ context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.consents[id]
	if !ok {
		return ErrNotFound
	}
	c.Revoked = true
	m.consents[id] = c
	for v, t := range m.tokens {
		if t.ConsentID == id {
			t.Revoked = true
			m.tokens[v] = t
		}
	}
	return nil
}

func (m *MemoryStore) PutCode(_ context.Context, c Code) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.codes[c.Verifier] = c
	return nil
}

func (m *MemoryStore) TakeCode(_ context.Context, v string) (Code, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	c, ok := m.codes[v]
	if !ok {
		return Code{}, ErrNotFound
	}
	if c.Used {
		return c, ErrUsed
	}
	c.Used = true
	m.codes[v] = c
	return c, nil
}

func (m *MemoryStore) PutToken(_ context.Context, t Token) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if old, ok := m.tokens[t.Verifier]; ok && old.Revoked {
		t.Revoked = true
	}
	m.tokens[t.Verifier] = t
	return nil
}

func (m *MemoryStore) Token(_ context.Context, v string) (Token, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[v]
	if !ok {
		return Token{}, ErrNotFound
	}
	return t, nil
}

func (m *MemoryStore) RevokeToken(_ context.Context, v string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.tokens[v]
	if !ok {
		return ErrNotFound
	}
	t.Revoked = true
	m.tokens[v] = t
	return nil
}
