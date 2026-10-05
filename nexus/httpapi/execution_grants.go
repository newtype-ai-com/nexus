package httpapi

import (
	"net/http"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// Execution grants (NMCP stage 3, 2026-10-04). Request bodies never carry the
// account, grantor or principal; the service enforces who may call what:
//
//	POST /v1/execution-grants                     person: issue
//	GET  /v1/execution-grants?session=<receiver>  person, or that session: list
//	POST /v1/execution-grants/{id}/revoke         person, or the receiver: revoke
//	POST /v1/execution-grants/{id}/decide         the receiver session: one tool call
func (a *API) registerExecutionGrants() {
	a.mux.HandleFunc("POST /v1/execution-grants", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Receiver   ids.Session    `json:"receiver"`
			Delegation ids.Delegation `json:"delegation_id"`
			Senders    []ids.Session  `json:"senders"`
			Tools      []string       `json:"tools"`
			Paths      []string       `json:"paths"`
			MaxTurns   int            `json:"max_turns"`
			TTLSeconds int64          `json:"ttl_seconds"`
			Note       string         `json:"note"`
		}
		if decode(w, r, &req) != nil || req.TTLSeconds < 60 || req.TTLSeconds > 7*86400 {
			fail(w, nexus.ErrInvalid)
			return
		}
		if _, err := ids.ParseDelegation(string(req.Delegation)); err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.IssueExecutionGrant(r.Context(), principal(r), nexus.ExecutionGrant{Receiver: req.Receiver,
			Delegation: req.Delegation, Senders: req.Senders, Tools: req.Tools, Paths: req.Paths, MaxTurns: req.MaxTurns,
			Note: req.Note}, time.Duration(req.TTLSeconds)*time.Second)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, http.StatusCreated, out)
	})
	a.mux.HandleFunc("GET /v1/execution-grants", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if len(q) != 1 || len(q["session"]) != 1 {
			fail(w, nexus.ErrInvalid)
			return
		}
		list, err := a.cfg.Service.ExecutionGrants(r.Context(), principal(r), ids.Session(q.Get("session")))
		if err != nil {
			fail(w, err)
			return
		}
		write(w, http.StatusOK, struct {
			Grants []nexus.ExecutionGrant `json:"grants"`
		}{list})
	})
	a.mux.HandleFunc("POST /v1/execution-grants/{id}/revoke", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Receiver ids.Session `json:"receiver"`
			Reason   string      `json:"reason"`
		}
		if decode(w, r, &req) != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.RevokeExecutionGrant(r.Context(), principal(r), req.Receiver, r.PathValue("id"), req.Reason)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, http.StatusOK, out)
	})
	a.mux.HandleFunc("POST /v1/execution-grants/{id}/decide", func(w http.ResponseWriter, r *http.Request) {
		var req nexus.GrantDecisionInput
		if decode(w, r, &req) != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.DecideExecutionGrant(r.Context(), principal(r), r.PathValue("id"), req)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, http.StatusOK, out)
	})
}
