package httpapi

import (
	"net/http"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func (a *API) registerCredentials() {
	a.mux.HandleFunc("GET /v1/delegation/keys", func(w http.ResponseWriter, r *http.Request) {
		keys := a.cfg.Service.DelegationKeys()
		if len(keys) == 0 {
			fail(w, nexus.ErrNotFound)
			return
		}
		write(w, http.StatusOK, map[string]any{"keys": keys})
	})
	a.mux.HandleFunc("POST /v1/sessions/{session}/credentials", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseSession(r.PathValue("session"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.Credentials(r.Context(), principal(r), id)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, http.StatusOK, map[string]any{"credentials": out})
	})
}
