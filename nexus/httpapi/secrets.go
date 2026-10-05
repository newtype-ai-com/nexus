package httpapi

import (
	"io"
	"net/http"

	"github.com/newtype-ai-com/nexus/nexus"
)

// Secret routes (person only). The value travels as the raw request body
// (never JSON, never a query or path element) and is never echoed back.
func (a *API) registerSecrets() {
	a.mux.HandleFunc("PUT /v1/secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		if principal(r).Kind != nexus.PrincipalUser || r.Header.Get("Content-Type") != "application/octet-stream" {
			fail(w, nexus.ErrForbidden)
			return
		}
		raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, nexus.SecretValueLimit+1))
		if err != nil || len(raw) == 0 || len(raw) > nexus.SecretValueLimit {
			clear(raw)
			fail(w, nexus.ErrInvalid)
			return
		}
		version, err := a.cfg.Service.PutSecret(r.Context(), principal(r), r.PathValue("name"), raw)
		clear(raw)
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, map[string]any{"name": r.PathValue("name"), "version": version})
	})
	a.mux.HandleFunc("DELETE /v1/secrets/{name}", func(w http.ResponseWriter, r *http.Request) {
		if err := a.cfg.Service.DeleteSecret(r.Context(), principal(r), r.PathValue("name")); err != nil {
			fail(w, err)
			return
		}
		write(w, 200, map[string]any{"name": r.PathValue("name"), "deleted": true})
	})
	a.mux.HandleFunc("GET /v1/secrets", func(w http.ResponseWriter, r *http.Request) {
		list, err := a.cfg.Service.ListSecrets(r.Context(), principal(r))
		if err != nil {
			fail(w, err)
			return
		}
		write(w, 200, map[string]any{"secrets": list})
	})
}
