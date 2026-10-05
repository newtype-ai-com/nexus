package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// Team routes over HTTP: person-only create/preview/attach, the seat's own
// session renews, other accounts see 404, strict input, no lease secrets in
// the roster.
func TestTeamHTTPBoundary(t *testing.T) {
	ctx := context.Background()
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "user@example.test")
	actor := user
	api, err := New(Config{Service: svc, Authenticate: func(*http.Request) (nexus.Principal, error) { return actor, nil }, Run: func(context.Context, string, json.RawMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string, want int) []byte {
		t.Helper()
		w := httptest.NewRecorder()
		api.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		if w.Code != want {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		return w.Body.Bytes()
	}
	a, err := svc.CreateRoot(ctx, user, nexus.RootRequest{Title: "alpha"})
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.CreateRoot(ctx, user, nexus.RootRequest{Title: "beta"})
	if err != nil {
		t.Fatal(err)
	}
	pa, pb := nexus.SessionPrincipal(user.AccountID, a.Session.ID), nexus.SessionPrincipal(user.AccountID, b.Session.ID)
	for _, p := range []nexus.Principal{pa, pb} {
		if err := svc.Touch(ctx, p); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.Send(ctx, pa, nexus.Message{To: b.Session.ID, Text: "public fixture"}); err != nil {
		t.Fatal(err)
	}
	seed := `{"seed_session":"` + string(a.Session.ID) + `"}`
	actor = pa
	call("POST", "/v1/teams/preview", seed, 403)
	actor = user
	call("POST", "/v1/teams/preview", `{"seed_session":"`+string(a.Session.ID)+`","extra":1}`, 400)
	var preview nexus.TeamPreview
	if err := json.Unmarshal(call("POST", "/v1/teams/preview", seed, 200), &preview); err != nil || len(preview.Members) != 2 {
		t.Fatalf("preview %+v %v", preview, err)
	}
	actor = pb
	call("POST", "/v1/teams", `{"seed_session":"`+string(a.Session.ID)+`","roster_hash":"`+preview.RosterHash+`"}`, 403)
	actor = user
	call("POST", "/v1/teams", `{"seed_session":"`+string(a.Session.ID)+`","roster_hash":"sha256:`+strings.Repeat("0", 64)+`"}`, 409)
	var team nexus.TeamView
	if err := json.Unmarshal(call("POST", "/v1/teams", `{"seed_session":"`+string(a.Session.ID)+`","name":"crew","roster_hash":"`+preview.RosterHash+`"}`, 200), &team); err != nil || len(team.Seats) != 2 {
		t.Fatalf("create %+v %v", team, err)
	}
	var seat nexus.SeatView
	for _, s := range team.Seats {
		if s.SessionID == a.Session.ID {
			seat = s
		}
	}
	base := "/v1/teams/" + string(team.Team.ID) + "/seats/" + string(seat.ID)
	install := `"install":"install-http-0123456789"`
	actor = pa
	call("POST", base+"/attach", `{`+install+`}`, 403)
	actor = user
	var held nexus.SeatAttach
	if err := json.Unmarshal(call("POST", base+"/attach", `{`+install+`}`, 200), &held); err != nil || held.LeaseToken == "" || !held.Reattachable {
		t.Fatalf("attach %+v %v", held, err)
	}
	call("POST", base+"/attach", `{"install":"install-other-0123456789"}`, 409)
	call("POST", base+"/frobnicate", `{}`, 404)
	lease := `"lease_token":"` + held.LeaseToken + `","epoch":1`
	actor = pb
	call("POST", base+"/renew", `{`+lease+`}`, 409)
	actor = pa
	call("POST", base+"/renew", `{`+lease+`}`, 200)
	roster := call("GET", "/v1/teams/"+string(team.Team.ID), "", 200)
	if strings.Contains(string(roster), held.LeaseToken) || strings.Contains(string(roster), "install-http") || strings.Contains(string(roster), "verifier") {
		t.Fatalf("roster leaks lease material: %s", roster)
	}
	actor = user
	last := call("POST", "/v1/teams/last", `{`+install+`}`, 200)
	if !strings.Contains(string(last), string(team.Team.ID)) {
		t.Fatalf("last %s", last)
	}
	call("GET", "/v1/teams", "", 200)
	call("GET", "/v1/teams/not-a-team", "", 400)
	actor = nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "other@example.test")
	call("GET", "/v1/teams/"+string(team.Team.ID), "", 404)
	call("POST", base+"/attach", `{`+install+`}`, 404)
	actor = pa
	call("POST", base+"/release", `{`+lease+`}`, 200)
}

// An explicit member list over HTTP: preview and create carry the same list,
// a refused entry comes back as its position and a fixed reason (never the
// entry's text), and a changed roster is 409.
func TestTeamHTTPExplicitMembers(t *testing.T) {
	ctx := context.Background()
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "user@example.test")
	api, err := New(Config{Service: svc, Authenticate: func(*http.Request) (nexus.Principal, error) { return user, nil }, Run: func(context.Context, string, json.RawMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	call := func(path, body string, want int) []byte {
		t.Helper()
		w := httptest.NewRecorder()
		api.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
		if w.Code != want {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		return w.Body.Bytes()
	}
	root := func(title string) ids.Session {
		r, err := svc.CreateRoot(ctx, user, nexus.RootRequest{Title: title})
		if err != nil {
			t.Fatal(err)
		}
		if err := svc.Touch(ctx, nexus.SessionPrincipal(user.AccountID, r.Session.ID)); err != nil {
			t.Fatal(err)
		}
		return r.Session.ID
	}
	seed, nmcp, op, gone := root("seed"), root("nmcp"), root("operator"), root("gone")
	for _, from := range []ids.Session{nmcp, op, gone} {
		if _, err := svc.Send(ctx, nexus.SessionPrincipal(user.AccountID, from), nexus.Message{To: seed, Text: "public fixture"}); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := svc.SetSessionStatus(ctx, nexus.SessionPrincipal(user.AccountID, gone), gone, nexus.SessionStopped); err != nil {
		t.Fatal(err)
	}
	var whole nexus.TeamPreview
	if err := json.Unmarshal(call("/v1/teams/preview", `{"seed_session":"`+string(seed)+`"}`, 200), &whole); err != nil || len(whole.Members) != 3 {
		t.Fatalf("live chain %+v %v", whole, err)
	}
	for _, m := range whole.Members {
		if m.SessionID == gone {
			t.Fatal("a stopped session in the preview")
		}
	}
	list := `"members":["nmcp"]`
	var picked nexus.TeamPreview
	if err := json.Unmarshal(call("/v1/teams/preview", `{"seed_session":"`+string(seed)+`",`+list+`}`, 200), &picked); err != nil || len(picked.Members) != 2 {
		t.Fatalf("explicit %+v %v", picked, err)
	}
	for body, want := range map[string]string{
		`"members":["nmcp","gone"]`:                           `{"error":"member_not_live","member_index":1}`,
		`"members":["` + ids.New(ids.KindSession) + `"]`:      `{"error":"member_not_found","member_index":0}`,
		`"members":["nmcp","operator","nobody by this name"]`: `{"error":"member_not_found","member_index":2}`,
	} {
		code := 400
		if strings.Contains(want, "not_found") {
			code = 404
		}
		got := strings.TrimSpace(string(call("/v1/teams/preview", `{"seed_session":"`+string(seed)+`",`+body+`}`, code)))
		if got != want {
			t.Fatalf("%s: %s want %s", body, got, want)
		}
	}
	// the whole chain's hash does not create the explicit team, and vice versa
	call("/v1/teams", `{"seed_session":"`+string(seed)+`","roster_hash":"`+whole.RosterHash+`",`+list+`}`, 409)
	call("/v1/teams", `{"seed_session":"`+string(seed)+`","roster_hash":"`+picked.RosterHash+`"}`, 409)
	var team nexus.TeamView
	if err := json.Unmarshal(call("/v1/teams", `{"seed_session":"`+string(seed)+`","roster_hash":"`+picked.RosterHash+`",`+list+`}`, 200), &team); err != nil || len(team.Seats) != 2 {
		t.Fatalf("create %+v %v", team, err)
	}
}
