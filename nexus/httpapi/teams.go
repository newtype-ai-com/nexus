package httpapi

import (
	"errors"
	"net/http"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// Team routes (docs/team-implementation-plan.md section 3-1). Authorization
// is decided by the service: create, preview, attach, rebind, last and new
// seat are person-only; renew is the seat's own session; other accounts see
// not found. Responses carry no lease holder, verifier or authority.
func (a *API) registerTeams() {
	a.mux.HandleFunc("POST /v1/teams/preview", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Seed    ids.Session `json:"seed_session"`
			Members []string    `json:"members,omitempty"`
		}
		if err := decode(w, r, &req); err != nil {
			fail(w, err)
			return
		}
		out, err := a.cfg.Service.PreviewTeamMembers(r.Context(), principal(r), req.Seed, req.Members)
		respond(w, out, err)
	})
	a.mux.HandleFunc("POST /v1/teams", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Seed       ids.Session `json:"seed_session"`
			Name       string      `json:"name,omitempty"`
			RosterHash string      `json:"roster_hash"`
			Members    []string    `json:"members,omitempty"`
		}
		if err := decode(w, r, &req); err != nil {
			fail(w, err)
			return
		}
		out, err := a.cfg.Service.CreateTeamMembers(r.Context(), principal(r), req.Seed, req.Name, req.RosterHash, req.Members)
		respond(w, out, err)
	})
	a.mux.HandleFunc("GET /v1/teams", func(w http.ResponseWriter, r *http.Request) {
		out, err := a.cfg.Service.Teams(r.Context(), principal(r))
		respond(w, map[string]any{"teams": out}, err)
	})
	a.mux.HandleFunc("GET /v1/sessions/{session}/team", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseSession(r.PathValue("session"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.TeamOfSession(r.Context(), principal(r), id)
		respond(w, out, err)
	})
	a.mux.HandleFunc("POST /v1/teams/last", func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Install string `json:"install"`
		}
		if err := decode(w, r, &req); err != nil {
			fail(w, err)
			return
		}
		out, err := a.cfg.Service.LastTeam(r.Context(), principal(r), req.Install)
		respond(w, map[string]any{"team_id": out.TeamID, "seat_id": out.SeatID}, err)
	})
	a.mux.HandleFunc("GET /v1/teams/{team}", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseTeam(r.PathValue("team"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		out, err := a.cfg.Service.TeamRoster(r.Context(), principal(r), id)
		respond(w, out, err)
	})
	a.mux.HandleFunc("POST /v1/teams/{team}/seats", func(w http.ResponseWriter, r *http.Request) {
		id, err := ids.ParseTeam(r.PathValue("team"))
		if err != nil {
			fail(w, nexus.ErrInvalid)
			return
		}
		var req struct {
			Name string `json:"name"`
		}
		if err := decode(w, r, &req); err != nil {
			fail(w, err)
			return
		}
		out, err := a.cfg.Service.AddSeat(r.Context(), principal(r), id, req.Name)
		respond(w, out, err)
	})
	type leaseReq struct {
		Install    string      `json:"install,omitempty"`
		LeaseToken string      `json:"lease_token,omitempty"`
		Epoch      int64       `json:"epoch,omitempty"`
		SessionID  ids.Session `json:"session_id,omitempty"`
	}
	seat := func(r *http.Request) (ids.Team, ids.Seat, error) {
		team, err := ids.ParseTeam(r.PathValue("team"))
		if err != nil {
			return "", "", nexus.ErrInvalid
		}
		s, err := ids.ParseSeat(r.PathValue("seat"))
		if err != nil {
			return "", "", nexus.ErrInvalid
		}
		return team, s, nil
	}
	a.mux.HandleFunc("POST /v1/teams/{team}/seats/{seat}/{op}", func(w http.ResponseWriter, r *http.Request) {
		team, s, err := seat(r)
		if err != nil {
			fail(w, err)
			return
		}
		var req leaseReq
		if err := decode(w, r, &req); err != nil {
			fail(w, err)
			return
		}
		p := principal(r)
		switch r.PathValue("op") {
		case "attach":
			out, err := a.cfg.Service.AttachSeat(r.Context(), p, team, s, req.Install, req.LeaseToken)
			respond(w, out, err)
		case "renew":
			out, err := a.cfg.Service.RenewSeat(r.Context(), p, team, s, req.LeaseToken, req.Epoch)
			respond(w, out, err)
		case "release":
			err := a.cfg.Service.ReleaseSeat(r.Context(), p, team, s, req.LeaseToken, req.Epoch)
			respond(w, map[string]bool{"released": true}, err)
		case "rebind":
			out, err := a.cfg.Service.RebindSeat(r.Context(), p, team, s, req.LeaseToken, req.Epoch, req.SessionID)
			respond(w, out, err)
		default:
			fail(w, nexus.ErrNotFound)
		}
	})
}

func respond(w http.ResponseWriter, out any, err error) {
	var member *nexus.TeamMemberError
	if errors.As(err, &member) {
		// one entry of an explicit member list: its position (never its text)
		// and a fixed reason the client turns into words
		code, label := 400, "invalid"
		switch {
		case errors.Is(err, nexus.ErrMemberNotFound):
			code, label = 404, "member_not_found"
		case errors.Is(err, nexus.ErrMemberNotLive):
			label = "member_not_live"
		case errors.Is(err, nexus.ErrMemberAmbiguous):
			label = "member_ambiguous"
		case errors.Is(err, nexus.ErrMemberNotConnected):
			label = "member_not_connected"
		}
		write(w, code, map[string]any{"error": label, "member_index": member.Index})
		return
	}
	if err != nil {
		fail(w, err)
		return
	}
	write(w, 200, out)
}
