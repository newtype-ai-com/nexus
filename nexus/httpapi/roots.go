package httpapi

import (
	"net/http"
	"strings"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// RootWire never accepts an account or principal from the request. TaskID is
// optional for conflict detection on retries (duplicates return 409).
type RootWire struct {
	Title       string       `json:"title"`
	TaskID      ids.Task     `json:"task_id,omitempty"`
	ToSessionID ids.Session  `json:"to_session_id,omitempty"`
	Runner      nexus.Runner `json:"runner,omitempty"`
	Scope       []string     `json:"scope"`
	Rules       []nexus.Rule `json:"rules,omitempty"`
	Approver    string       `json:"approver,omitempty"`
	Limits      nexus.Limits `json:"limits"`
	TTLSeconds  int64        `json:"ttl_seconds"`
}

// UnlimitedOwnerOnly is the fixed refusal for limits.model_tokens = -1
// (unlimited) from anyone but the configured owner person.
const UnlimitedOwnerOnly = "unlimited_owner_only"

// GrantSummary does not expose a policy, raw certificate or credential. Issuing
// a container grant does not start a runner or issue an agent token.
type GrantSummary struct {
	Task       *nexus.Task    `json:"task,omitempty"`
	Session    nexus.Session  `json:"session"`
	Delegation ids.Delegation `json:"delegation_id"`
	ExpiresAt  time.Time      `json:"expires_at"`
}

func (a *API) registerGrants() {
	a.mux.HandleFunc("POST /v1/requests", a.issueRoot)
	a.mux.HandleFunc("POST /v1/observers", a.issueRoot)
	a.mux.HandleFunc("GET /v1/delegations/{id}", func(w http.ResponseWriter, r *http.Request) {
		if principal(r).Kind != nexus.PrincipalUser {
			fail(w, nexus.ErrForbidden)
			return
		}
		id, err := ids.ParseDelegation(r.PathValue("id"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.DelegationInfo(r.Context(), principal(r), id)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, out)
	})
	a.mux.HandleFunc("GET /v1/delegations/{id}/left", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseDelegation(r.PathValue("id"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		left, err := a.cfg.Service.Left(r.Context(), principal(r), id)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, map[string]any{"remaining": left})
	})
	a.mux.HandleFunc("POST /v1/delegations/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseDelegation(r.PathValue("id"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		var req struct {
			Reason string `json:"reason"`
		}
		if decode(w, r, &req) != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.Revoke(r.Context(), principal(r), id, req.Reason)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, map[string]any{"revoked": out})
	})
}

func (a *API) issueRoot(w http.ResponseWriter, r *http.Request) {
	if principal(r).Kind != nexus.PrincipalUser {
		fail(w, nexus.ErrForbidden)
		return
	}
	var req RootWire
	if decode(w, r, &req) != nil || req.TTLSeconds <= 0 || req.TTLSeconds > int64(nexus.MaxTTL/time.Second) {
		fail(w, nexus.ErrInvalid)
		return
	}
	if req.TaskID != "" {
		if _, err := ids.ParseTask(string(req.TaskID)); err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
	}
	if req.ToSessionID != "" {
		if _, err := ids.ParseSession(string(req.ToSessionID)); err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
	}
	if req.Runner == "" {
		req.Runner = nexus.Local
	}
	if req.Runner == nexus.Remote {
		fail(w, nexus.ErrInvalid) // only the remote MCP connector creates these, in process
		return
	}
	x := nexus.RootRequest{Title: req.Title, TaskID: req.TaskID, ToSessionID: req.ToSessionID, Runner: req.Runner, Scope: req.Scope, Rules: req.Rules, Approver: req.Approver, Limits: req.Limits, TTL: time.Duration(req.TTLSeconds) * time.Second}
	actor := principal(r)
	if a.cfg.ModelScope != nil {
		for _, scope := range req.Scope {
			if model, ok := strings.CutPrefix(scope, "model:"); ok && !a.cfg.ModelScope(r, actor, model) {
				write(w, http.StatusForbidden, map[string]string{"error": ModelRelayNotAllowed})
				return
			}
		}
	}
	if req.Limits.ModelTokens == nexus.UnlimitedModelTokens {
		// Unlimited model tokens: the verified owner person only, decided here
		// from the request's own credentials, never from a client flag.
		if r.Pattern != "POST /v1/requests" || a.cfg.OwnerPerson == nil || !a.cfg.OwnerPerson(r, actor) {
			write(w, http.StatusForbidden, map[string]string{"error": UnlimitedOwnerOnly})
			return
		}
		x.Limits.ModelTokens, x.UnlimitedModelTokens = 0, true
		actor.OwnBudgetAdmin = true
	}
	issue := a.cfg.Service.CreateRoot
	if r.Pattern == "POST /v1/observers" {
		issue = a.cfg.Service.CreateObserver
	}
	out, err := issue(r.Context(), actor, x)
	if err != nil {
		fail(w, err)
		return
	}
	summary := GrantSummary{Session: out.Session, Delegation: out.Delegation.ID, ExpiresAt: out.Delegation.ExpiresAt}
	if out.Task.ID != "" {
		summary.Task = &out.Task
	}
	write(w, http.StatusCreated, summary)
}
