package httpapi

import (
	"net/http"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func (a *API) messageDelivered(w http.ResponseWriter, r *http.Request) {
	a.receipt(w, r, false)
}
func (a *API) messageRead(w http.ResponseWriter, r *http.Request) {
	a.receipt(w, r, true)
}
func (a *API) receipt(w http.ResponseWriter, r *http.Request, read bool) {
	var req nexus.Receipt
	if err := decode(w, r, &req); err != nil {
		fail(w, err)
		return
	}
	var err error
	if read {
		err = a.cfg.Service.MessageRead(r.Context(), principal(r), req)
	} else {
		err = a.cfg.Service.MessageDelivered(r.Context(), principal(r), req)
	}
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, map[string]bool{"ok": true})
}
func (a *API) messageDelivery(w http.ResponseWriter, r *http.Request) {
	out, err := a.cfg.Service.MessageDelivery(r.Context(), principal(r), ids.Session(r.URL.Query().Get("to")), ids.Event(r.PathValue("id")))
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, out)
}
