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

func TestRootHTTPBoundary(t *testing.T) {
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "user@example.test")
	actor := user
	api, err := New(Config{Service: svc, Authenticate: func(*http.Request) (nexus.Principal, error) { return actor, nil }, Run: func(context.Context, string, json.RawMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		api.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		if w.Code != want {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		return w
	}
	body := `{"title":"fixture root","scope":["newtype:run","observe:progress"],"limits":{"model_tokens":100},"ttl_seconds":60}`
	w := call("POST", "/v1/requests", body, 201)
	var out GrantSummary
	if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Task == nil || out.Session.Runner != nexus.Local || out.Delegation == "" {
		t.Fatal("invalid grant summary")
	}
	if strings.Contains(w.Body.String(), `"rules"`) || strings.Contains(w.Body.String(), `"scope"`) || strings.Contains(w.Body.String(), `"policy"`) {
		t.Fatal("raw grant leaked")
	}
	call("GET", "/v1/delegations/"+string(out.Delegation), "", 200)
	for _, bad := range []string{strings.Replace(body, `60}`, `0}`, 1), strings.Replace(body, `60}`, `9223372036854775807}`, 1), strings.Replace(body, `"title":`, `"account_id":"forged","title":`, 1), strings.Replace(body, `"title":`, `"title":"duplicate","title":`, 1)} {
		call("POST", "/v1/requests", bad, 400)
	}
	actor = nexus.SessionPrincipal(user.AccountID, out.Session.ID)
	call("POST", "/v1/requests", body, 403)
	call("POST", "/v1/observers", body, 403)
	call("GET", "/v1/delegations/"+string(out.Delegation), "", 403)
	balance := call("GET", "/v1/delegations/"+string(out.Delegation)+"/left", "", 200)
	var snapshot map[string]json.RawMessage
	if json.Unmarshal(balance.Body.Bytes(), &snapshot) != nil || len(snapshot) != 1 || snapshot["remaining"] == nil {
		t.Fatal("balance exposed non-numeric delegation fields", balance.Body.String())
	}
	peer, err := svc.CreateRoot(context.Background(), user, nexus.RootRequest{Title: "peer"})
	if err != nil {
		t.Fatal(err)
	}
	actor = nexus.SessionPrincipal(user.AccountID, peer.Session.ID)
	call("GET", "/v1/delegations/"+string(out.Delegation)+"/left", "", 403)
	actor = nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "other@example.test")
	call("GET", "/v1/delegations/"+string(out.Delegation), "", 404)
	call("GET", "/v1/delegations/"+string(out.Delegation)+"/left", "", 404)
	call("POST", "/v1/delegations/"+string(out.Delegation)+"/revoke", `{"reason":"test"}`, 404)
	actor = user
	call("POST", "/v1/observers", `{"title":"observer","scope":["observe:progress"],"ttl_seconds":60,"task_id":"`+string(out.Task.ID)+`"}`, 201)
	call("POST", "/v1/delegations/"+string(out.Delegation)+"/revoke", `{"reason":"test"}`, 200)
	call("POST", "/v1/delegations/"+string(out.Delegation)+"/revoke", `{"reason":"test"}`, 200)
	call("GET", "/v1/delegations/"+string(out.Delegation)+"/left", "", 403)
	tid := ids.New(ids.KindTask)
	retry := strings.Replace(body, `"title":`, `"task_id":"`+tid+`","title":`, 1)
	call("POST", "/v1/requests", retry, 201)
	call("POST", "/v1/requests", retry, 409)
}
