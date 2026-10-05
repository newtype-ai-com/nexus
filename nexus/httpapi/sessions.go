package httpapi

import (
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"net/http"
)

func (a *API) registerSessions() {
	a.mux.HandleFunc("GET /v1/peers", func(w http.ResponseWriter, r *http.Request) {
		x, err := a.cfg.Service.Peers(r.Context(), principal(r))
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, x)
	})
	a.mux.HandleFunc("GET /v1/sessions", func(w http.ResponseWriter, r *http.Request) {
		x, err := a.cfg.Service.Sessions(r.Context(), principal(r))
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, x)
	})
	a.mux.HandleFunc("GET /v1/session-names/{name}", func(w http.ResponseWriter, r *http.Request) {
		x, err := a.cfg.Service.SessionByName(r.Context(), principal(r), r.PathValue("name"))
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, x)
	})
	a.mux.HandleFunc("GET /v1/sessions/{session}", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseSession(r.PathValue("session"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		x, err := a.cfg.Service.Session(r.Context(), principal(r), id)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, x)
	})
	a.mux.HandleFunc("PATCH /v1/sessions/{session}", a.sessionChange)
	for _, op := range []string{"status", "archive", "suspend", "resume"} {
		a.mux.HandleFunc("POST /v1/sessions/{session}/"+op, a.sessionChange)
	}
	a.mux.HandleFunc("POST /v1/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		if principal(r).Kind != nexus.PrincipalSession {
			fail(w, nexus.ErrForbidden)
			return
		}
		write(w, 200, map[string]bool{"ok": true})
	})
}
func (a *API) sessionChange(w http.ResponseWriter, r *http.Request) {
	id, err := ids.ParseSession(r.PathValue("session"))
	if err != nil {
		fail(w, nexus.ErrInvalid)
		return
	}
	var req struct {
		Title  string              `json:"title"`
		Status nexus.SessionStatus `json:"status"`
		Reason string              `json:"reason"`
	}
	if err = decode(w, r, &req); err != nil {
		fail(w, err)
		return
	}
	var x nexus.Session
	switch r.Pattern {
	case "PATCH /v1/sessions/{session}":
		x, err = a.cfg.Service.RenameSession(r.Context(), principal(r), id, req.Title)
	case "POST /v1/sessions/{session}/status":
		x, err = a.cfg.Service.SetSessionStatus(r.Context(), principal(r), id, req.Status)
	case "POST /v1/sessions/{session}/archive":
		x, err = a.cfg.Service.Archive(r.Context(), principal(r), id, req.Reason)
	case "POST /v1/sessions/{session}/suspend":
		x, err = a.cfg.Service.Suspend(r.Context(), principal(r), id, req.Reason)
	case "POST /v1/sessions/{session}/resume":
		x, err = a.cfg.Service.Resume(r.Context(), principal(r), id)
	}
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, x)
}
