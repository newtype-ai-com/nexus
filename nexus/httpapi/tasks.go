package httpapi

import (
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"net/http"
)

func (a *API) registerTasks() {
	a.mux.HandleFunc("GET /v1/tasks", func(w http.ResponseWriter, r *http.Request) {
		out, err := a.cfg.Service.Overview(r.Context(), principal(r))
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, out)
	})
	a.mux.HandleFunc("GET /v1/tasks/{task}", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseTask(r.PathValue("task"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.Tree(r.Context(), principal(r), id)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, out)
	})
	a.mux.HandleFunc("PUT /v1/tasks/{task}/plan", a.plan)
	a.mux.HandleFunc("POST /v1/tasks/{task}/plan", a.plan)
	a.mux.HandleFunc("POST /v1/tasks/{task}/status", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseTask(r.PathValue("task"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		var req struct {
			Status string `json:"status"`
		}
		if err = decode(w, r, &req); err != nil {
			fail(w, err)
			return
		}
		out, err := a.cfg.Service.SetTaskStatus(r.Context(), principal(r), id, req.Status)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, out)
	})
	a.mux.HandleFunc("POST /v1/tasks/{task}/parent", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseTask(r.PathValue("task"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		var req struct {
			Parent ids.Task `json:"new_parent_id"`
			Accept bool     `json:"accept"`
		}
		if err = decode(w, r, &req); err != nil {
			fail(w, err)
			return
		}
		if req.Parent != "" {
			if _, err = ids.ParseTask(string(req.Parent)); err != nil {
				fail(w, nexus.ErrInvalid)
				return
			}
		}
		out, err := a.cfg.Service.Reparent(r.Context(), principal(r), id, req.Parent, req.Accept)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, out)
	})
}
func (a *API) plan(w http.ResponseWriter, r *http.Request) {
	id, err := ids.ParseTask(r.PathValue("task"))
	if err != nil {
		fail(w, nexus.ErrInvalid)
		return
	}
	var req struct {
		Steps []nexus.PlanStep `json:"steps"`
	}
	if err = decode(w, r, &req); err != nil {
		fail(w, err)
		return
	}
	out, err := a.cfg.Service.UpsertPlan(r.Context(), principal(r), id, req.Steps)
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, out)
}
