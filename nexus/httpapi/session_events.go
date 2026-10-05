package httpapi

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// MaxToolCallRecords bounds one POST /v1/sessions/{session}/events.
const MaxToolCallRecords = 20

// recordToolCalls lets a session write "tool.*" records into its OWN ledger
// (NMCP: every tool call of an external MCP client lands in its session's
// ledger). Source is always "tool"; message kinds, hub records and other
// sessions are refused by nexus.AppendEvents. A record is evidence of what
// the client says it did, never authority.
func (a *API) recordToolCalls(w http.ResponseWriter, r *http.Request) {
	p := principal(r)
	id, err := ids.ParseSession(r.PathValue("session"))
	if err != nil || p.Kind != nexus.PrincipalSession || p.SessionID != id {
		fail(w, nexus.ErrForbidden)
		return
	}
	var req struct {
		Events []struct {
			Kind          string          `json:"kind"`
			ClientEventID string          `json:"client_event_id,omitempty"`
			Payload       json.RawMessage `json:"payload,omitempty"`
		} `json:"events"`
	}
	if err := decode(w, r, &req); err != nil {
		fail(w, err)
		return
	}
	if len(req.Events) == 0 || len(req.Events) > MaxToolCallRecords {
		fail(w, nexus.ErrInvalid)
		return
	}
	in := make([]nexus.EventInput, 0, len(req.Events))
	for _, e := range req.Events {
		if !strings.HasPrefix(e.Kind, "tool.") {
			fail(w, nexus.ErrInvalid)
			return
		}
		in = append(in, nexus.EventInput{Source: "tool", Kind: e.Kind, ClientEventID: e.ClientEventID, Payload: e.Payload})
	}
	out, err := a.cfg.Service.AppendEvents(r.Context(), p, id, in)
	if err != nil {
		fail(w, err)
		return
	}
	recorded := make([]ids.Event, 0, len(out))
	for _, e := range out {
		recorded = append(recorded, e.ID)
	}
	write(w, 200, map[string]any{"recorded": recorded})
}
