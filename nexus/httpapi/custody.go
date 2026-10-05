package httpapi

import (
	"encoding/json"
	"net/http"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// custodyMaxBody bounds any custody listing response; above it the listing is
// refused rather than cut (clients read at most 64 KiB).
const custodyMaxBody = 60 << 10

// Custody routes (newtype.custody/1). Every response carries "version"; every
// key is always present. Request bodies never carry account or principal.
func (a *API) registerCustody() {
	a.mux.HandleFunc("POST /v1/custody/approvals", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Delegation ids.Delegation `json:"delegation_id"`
			Action     string         `json:"action"`
			InputHash  string         `json:"input_hash"`
			TTLSeconds int64          `json:"ttl_seconds"`
		}
		if decode(w, r, &req) != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		if _, err := ids.ParseDelegation(string(req.Delegation)); err != nil || req.TTLSeconds < 1 || req.TTLSeconds > 86400 {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.RequestCustodyApproval(r.Context(), principal(r), req.Delegation, req.Action, req.InputHash,
			time.Duration(req.TTLSeconds)*time.Second)
		custodyWrite(w, 201, out, err)
	})
	a.mux.HandleFunc("GET /v1/custody/approvals", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if len(q) != 1 || len(q["input_hash"]) != 1 {
			fail(w, nexus.ErrInvalid)
			return
		}
		hash := q.Get("input_hash")
		list, err := a.cfg.Service.CustodyApprovals(r.Context(), principal(r), hash)
		if err != nil {
			fail(w, err)
			return
		}
		// "complete" means: every approval for this hash visible to THIS
		// principal (a session: its own requests; the person: the account).
		body, err := json.Marshal(struct {
			Version   string                      `json:"version"`
			InputHash string                      `json:"input_hash"`
			Complete  bool                        `json:"complete"`
			Approvals []nexus.CustodyApprovalView `json:"approvals"`
		}{nexus.CustodyVersion, hash, true, list})
		if err != nil || len(body) > custodyMaxBody {
			fail(w, nexus.ErrConflict) // never a truncated listing
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(200)
		_, _ = w.Write(append(body, '\n'))
	})
	a.mux.HandleFunc("GET /v1/custody/approvals/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseApproval(r.PathValue("id"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.CustodyApproval(r.Context(), principal(r), id)
		custodyWrite(w, 200, out, err)
	})
	a.mux.HandleFunc("POST /v1/custody/approvals/{id}/decision", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseApproval(r.PathValue("id"))
		var req struct {
			InputHash string `json:"input_hash"`
			Approve   *bool  `json:"approve"`
		}
		if err != nil || decode(w, r, &req) != nil || req.Approve == nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.DecideCustodyApproval(r.Context(), principal(r), id, req.InputHash, *req.Approve)
		custodyWrite(w, 200, out, err)
	})
	a.mux.HandleFunc("POST /v1/custody/approvals/{id}/use", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseApproval(r.PathValue("id"))
		var req struct {
			InputHash string `json:"input_hash"`
		}
		if err != nil || decode(w, r, &req) != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.UseCustodyApproval(r.Context(), principal(r), id, req.InputHash)
		custodyWrite(w, 200, out, err)
	})
	a.mux.HandleFunc("GET /v1/custody/delegations/{id}", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseDelegation(r.PathValue("id"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.CustodyDelegation(r.Context(), principal(r), id)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, out)
	})
	a.mux.HandleFunc("GET /v1/custody/decision", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if len(q) != 2 || len(q["delegation_id"]) != 1 || len(q["action"]) != 1 {
			fail(w, nexus.ErrInvalid)
			return
		}
		id, err := ids.ParseDelegation(q.Get("delegation_id"))
		if err != nil || principal(r).Kind != nexus.PrincipalSession {
			fail(w, nexus.ErrForbidden)
			return
		}
		d, err := a.cfg.Service.Authorize(r.Context(), principal(r), id, q.Get("action"))
		if err != nil {
			fail(w, err)
			return
		}
		var approver *string
		if d.Effect == "ask" {
			who := d.Approver
			if who == "" {
				who = "user"
			}
			approver = &who
		}
		write(w, 200, struct {
			Version  string  `json:"version"`
			Effect   string  `json:"effect"`
			Approver *string `json:"approver"`
		}{nexus.CustodyVersion, d.Effect, approver})
	})
}

func custodyWrite(w http.ResponseWriter, code int, out nexus.CustodyApprovalView, err error) {
	if err != nil {
		fail(w, err)
		return
	}
	write(w, code, struct {
		Version string `json:"version"`
		nexus.CustodyApprovalView
	}{nexus.CustodyVersion, out})
}
