package httpapi

import (
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"net/http"
)

func (a *API) message(w http.ResponseWriter, r *http.Request) {
	var req struct {
		To            string    `json:"to"`
		Text          string    `json:"text"`
		ReplyTo       ids.Event `json:"reply_to,omitempty"`
		Task          ids.Task  `json:"task_id,omitempty"`
		About         ids.Task  `json:"about_task_id,omitempty"`
		ClientEventID string    `json:"client_event_id,omitempty"`
	}
	if err := decode(w, r, &req); err != nil {
		fail(w, err)
		return
	}
	if target := r.PathValue("session"); target != "" {
		if principal(r).Kind != nexus.PrincipalUser {
			fail(w, nexus.ErrForbidden)
			return
		}
		req.To = target
	}
	out, err := a.cfg.Service.SendTo(r.Context(), principal(r), req.To, nexus.Message{Text: req.Text, ReplyTo: req.ReplyTo, Task: req.Task, About: req.About, ClientEventID: req.ClientEventID})
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, out)
}
