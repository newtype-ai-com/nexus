package httpapi

import (
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"net/http"
	"time"
)

// DelegateWire keeps durations explicit and bounded instead of accepting Go's
// nanosecond duration representation. Identity always comes from Authenticate.
type DelegateWire struct {
	ParentID    ids.Delegation `json:"parent_id"`
	FromTaskID  ids.Task       `json:"from_task_id,omitempty"`
	Title       string         `json:"title"`
	Brief       string         `json:"brief"`
	ToSessionID ids.Session    `json:"to_session_id,omitempty"`
	Runner      nexus.Runner   `json:"runner,omitempty"`
	Scope       []string       `json:"scope"`
	Rules       []nexus.Rule   `json:"rules,omitempty"`
	Approver    string         `json:"approver,omitempty"`
	Limits      nexus.Limits   `json:"limits"`
	TTLSeconds  int64          `json:"ttl_seconds"`
}

func (a *API) delegate(w http.ResponseWriter, r *http.Request) {
	var req DelegateWire
	if decode(w, r, &req) != nil || req.TTLSeconds <= 0 || req.TTLSeconds > int64(nexus.MaxTTL/time.Second) {
		fail(w, nexus.ErrInvalid)
		return
	}
	if _, err := ids.ParseDelegation(string(req.ParentID)); err != nil || req.Runner == nexus.Remote {
		fail(w, nexus.ErrInvalid)
		return
	}
	out, err := a.cfg.Service.Delegate(r.Context(), principal(r), nexus.DelegateRequest{ParentID: req.ParentID, FromTaskID: req.FromTaskID, Title: req.Title, Brief: req.Brief, ToSessionID: req.ToSessionID, Runner: req.Runner, Scope: req.Scope, Rules: req.Rules, Approver: req.Approver, Limits: req.Limits, TTL: time.Duration(req.TTLSeconds) * time.Second})
	if err != nil {
		fail(w, err)
		return
	}
	// Issuing a grant is not a worker spawn or token issuance. Never return a
	// credential, raw policy or claim that the new worker is already running.
	write(w, 200, struct {
		Task       nexus.Task     `json:"task"`
		Session    nexus.Session  `json:"session"`
		Delegation ids.Delegation `json:"delegation_id"`
	}{out.Task, out.Session, out.Delegation.ID})
}
