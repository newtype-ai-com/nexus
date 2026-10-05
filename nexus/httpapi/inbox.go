package httpapi

import (
	"net/http"
	"strconv"

	"github.com/newtype-ai-com/nexus/nexus"
)

func (a *API) inbox(w http.ResponseWriter, r *http.Request) {
	after, err := cursor(r)
	if err != nil {
		fail(w, err)
		return
	}
	limit := 0
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err = strconv.Atoi(raw)
		if err != nil || limit < 0 {
			fail(w, nexus.ErrInvalid)
			return
		}
	}
	messages, next, err := a.cfg.Service.Inbox(r.Context(), principal(r), after, limit)
	if err != nil {
		fail(w, err)
		return
	}
	write(w, http.StatusOK, map[string]any{"messages": messages, "next": next})
}
