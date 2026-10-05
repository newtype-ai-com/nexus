package gate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// ModelRelayNotAllowed is the fixed refusal code (HTTP 403) for an account
// that may not use the relayed Nexus default model (decision 2026-10-05: the owner
// and the users the owner designates only; others contact sales).
const ModelRelayNotAllowed = "model_relay_not_allowed"

// ModelAccessEntry is one designated user of the relayed default model.
type ModelAccessEntry struct {
	Email   string      `json:"email"`
	Account ids.Account `json:"account_id"`
	AddedAt time.Time   `json:"added_at"`
	AddedBy string      `json:"added_by"`
}

// ModelAccess is the owner-managed allowlist of the relayed default model. It
// lives in one small private file beside the operator default-model store
// (no database schema change); an empty path keeps it in memory (owner only
// after a restart).
type ModelAccess struct {
	path string
	mu   sync.Mutex
	list map[ids.Account]ModelAccessEntry
}

// OpenModelAccess loads (or starts) the allowlist at path.
func OpenModelAccess(path string) (*ModelAccess, error) {
	a := &ModelAccess{path: path, list: map[ids.Account]ModelAccessEntry{}}
	if path == "" {
		return a, nil
	}
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, errors.New("gate: model access file must be an absolute clean path")
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil || len(raw) > 1<<20 {
		return nil, errors.New("gate: model access file unreadable")
	}
	var entries []ModelAccessEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, errors.New("gate: model access file malformed")
	}
	for _, e := range entries {
		if _, err := ids.ParseAccount(string(e.Account)); err != nil || !validEmail(e.Email) {
			return nil, errors.New("gate: model access file malformed")
		}
		a.list[e.Account] = e
	}
	return a, nil
}

// Allowed reports whether account is a designated user.
func (a *ModelAccess) Allowed(account ids.Account) bool {
	if a == nil {
		return false
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	_, ok := a.list[account]
	return ok
}

// List returns the designated users, oldest first.
func (a *ModelAccess) List() []ModelAccessEntry {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.sorted()
}

func (a *ModelAccess) sorted() []ModelAccessEntry {
	out := make([]ModelAccessEntry, 0, len(a.list))
	for _, e := range a.list {
		out = append(out, e)
	}
	slices.SortFunc(out, func(x, y ModelAccessEntry) int {
		if c := x.AddedAt.Compare(y.AddedAt); c != 0 {
			return c
		}
		return strings.Compare(x.Email, y.Email)
	})
	return out
}

// Allow adds (or refreshes) a designated user and persists the list.
func (a *ModelAccess) Allow(e ModelAccessEntry) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	old, had := a.list[e.Account]
	a.list[e.Account] = e
	if err := a.save(); err != nil {
		if had {
			a.list[e.Account] = old
		} else {
			delete(a.list, e.Account)
		}
		return err
	}
	return nil
}

// Revoke removes the designated user with this email; false when absent.
func (a *ModelAccess) Revoke(email string) (bool, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for account, e := range a.list {
		if SameEmail(e.Email, email) {
			delete(a.list, account)
			if err := a.save(); err != nil {
				a.list[account] = e
				return false, err
			}
			return true, nil
		}
	}
	return false, nil
}

// save writes the list atomically (temp file, fsync, rename, fsync dir), 0600.
func (a *ModelAccess) save() error {
	if a.path == "" {
		return nil
	}
	raw, err := json.MarshalIndent(a.sorted(), "", "  ")
	if err != nil {
		return err
	}
	dir := filepath.Dir(a.path)
	tmp, err := os.CreateTemp(dir, ".model-access-*")
	if err != nil {
		return errors.New("gate: model access file not writable")
	}
	ok := false
	defer func() {
		if !ok {
			os.Remove(tmp.Name())
		}
	}()
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return errors.New("gate: model access file not writable")
	}
	if _, err := tmp.Write(append(raw, '\n')); err != nil || tmp.Sync() != nil {
		tmp.Close()
		return errors.New("gate: model access file not writable")
	}
	if tmp.Close() != nil || os.Rename(tmp.Name(), a.path) != nil {
		return errors.New("gate: model access file not writable")
	}
	ok = true
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// ModelAccessConfig wires the owner management routes.
type ModelAccessConfig struct {
	Access          *ModelAccess
	Service         *nexus.Service
	Store           CredentialStore
	OwnerEmail      string
	AccountForEmail func(context.Context, string) (ids.Account, error)
	Audit           *Audit
	// Record writes a change into the ledger (the owner's operator seat).
	Record func(ctx context.Context, owner nexus.Principal, kind string, payload map[string]any)
	Clock  func() time.Time
}

// ModelAccessHandler serves GET/POST /v1/operator/model-access for the owner
// person only (the same owner check as the default-model operator). Adding a
// user is the owner's own confirmed action (CLI y/N or the TUI approval); no
// mail approval, so it never spends an approvals-store slot.
type ModelAccessHandler struct{ cfg ModelAccessConfig }

func NewModelAccessHandler(cfg ModelAccessConfig) (*ModelAccessHandler, error) {
	cfg.OwnerEmail = strings.ToLower(strings.TrimSpace(cfg.OwnerEmail))
	if cfg.Access == nil || cfg.Service == nil || cfg.Store == nil || !validEmail(cfg.OwnerEmail) {
		return nil, errors.New("gate: invalid model access config")
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	return &ModelAccessHandler{cfg: cfg}, nil
}

func (h *ModelAccessHandler) owner(w http.ResponseWriter, r *http.Request) (nexus.Principal, bool) {
	if len(r.Header.Values("X-Newtype-Session")) != 0 {
		gateError(w, 403, "owner_person_required")
		return nexus.Principal{}, false
	}
	token := bearer(r)
	if token == "" || strings.HasPrefix(token, "nta_") || strings.HasPrefix(token, nexus.ExecutorTokenPrefix) {
		gateError(w, 401, "unauthenticated")
		return nexus.Principal{}, false
	}
	p, err := NexusAuth{Store: h.cfg.Store, Service: h.cfg.Service, Clock: h.cfg.Clock}.Authenticate(r)
	if err != nil {
		gateError(w, 401, "unauthenticated")
		return nexus.Principal{}, false
	}
	lic, err := h.cfg.Store.LookupCredential(r.Context(), Verifier(token))
	if p.Kind != nexus.PrincipalUser || p.CredentialID != "" || p.SessionID != "" || !SameEmail(p.Email, h.cfg.OwnerEmail) ||
		err != nil || lic.Kind != "licence" || lic.Revoked || !h.cfg.Clock().Before(lic.Expires) || !SameEmail(lic.Email, h.cfg.OwnerEmail) || lic.Account != p.AccountID {
		gateError(w, 403, "forbidden")
		return nexus.Principal{}, false
	}
	return p, true
}

func (h *ModelAccessHandler) view() map[string]any {
	return map[string]any{"owner": h.cfg.OwnerEmail, "users": h.cfg.Access.List(),
		"note": "Nexus 기본 모델은 owner 와 여기 있는 사용자만 쓸 수 있습니다 · 그 밖에는 sales@newtype-ai.com 안내"}
}

func (h *ModelAccessHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	r = r.WithContext(ctx)
	if r.URL.Path != "/v1/operator/model-access" {
		gateError(w, 404, "not_found")
		return
	}
	p, ok := h.owner(w, r)
	if !ok {
		return
	}
	switch r.Method {
	case http.MethodGet:
		gateJSON(w, 200, h.view())
		return
	case http.MethodPost:
	default:
		gateError(w, 405, "method_not_allowed")
		return
	}
	var in struct {
		Action string `json:"action"`
		Email  string `json:"email"`
	}
	if gateDecode(w, r, &in) != nil {
		gateError(w, 400, "invalid_request")
		return
	}
	email := strings.ToLower(strings.TrimSpace(in.Email))
	if !validEmail(email) || strings.Contains(email, "*") || email == h.cfg.OwnerEmail {
		gateError(w, 400, "invalid_request")
		return
	}
	switch in.Action {
	case "allow":
		if h.cfg.AccountForEmail == nil {
			gateError(w, 503, "unavailable")
			return
		}
		account, err := h.cfg.AccountForEmail(r.Context(), email)
		if err != nil {
			gateError(w, 404, "account_not_found") // the person must enrol first
			return
		}
		if err := h.cfg.Access.Allow(ModelAccessEntry{Email: email, Account: account, AddedAt: h.cfg.Clock().UTC(), AddedBy: p.Email}); err != nil {
			gateError(w, 503, "unavailable")
			return
		}
	case "revoke":
		found, err := h.cfg.Access.Revoke(email)
		if err != nil {
			gateError(w, 503, "unavailable")
			return
		}
		if !found {
			gateError(w, 404, "not_found")
			return
		}
	default:
		gateError(w, 400, "invalid_request")
		return
	}
	if h.cfg.Audit != nil {
		h.cfg.Audit.Write(AuditEvent{Type: "model_access_" + in.Action, Established: AuditEstablished{AccountID: string(p.AccountID), Email: p.Email, Outcome: "ok"}})
	}
	if h.cfg.Record != nil {
		h.cfg.Record(r.Context(), p, "model_access.changed", map[string]any{"action": in.Action, "email": email, "by": p.Email})
	}
	gateJSON(w, 200, h.view())
}

// ModelScopeAllowed is the root-issuance check: a root that asks for one of the
// relayed models is allowed only for the owner person or a designated user.
func ModelScopeAllowed(store CredentialStore, owner string, access *ModelAccess, relayed []string) func(*http.Request, nexus.Principal, string) bool {
	isOwner := OwnerPersonFunc(store, owner)
	return func(r *http.Request, p nexus.Principal, model string) bool {
		if !slices.Contains(relayed, model) && !strings.ContainsAny(model, "*?[") {
			return true // not the relayed default model (a person's own model scope)
		}
		return (isOwner != nil && isOwner(r, p)) || access.Allowed(p.AccountID)
	}
}
