package httpapi

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// An unlimited root (limits.model_tokens = -1) is decided by the trusted
// owner hook from the request, never by anything else the client sends.
func TestUnlimitedRootOwnerOnly(t *testing.T) {
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "owner@example.test")
	isOwner := false
	var seen nexus.Principal
	hook := func(r *http.Request, p nexus.Principal) bool { seen = p; return isOwner }
	newAPI := func(owner func(*http.Request, nexus.Principal) bool) *API {
		api, err := New(Config{Service: svc, Authenticate: func(*http.Request) (nexus.Principal, error) { return user, nil }, Run: func(context.Context, string, json.RawMessage) error { return nil }, OwnerPerson: owner})
		if err != nil {
			t.Fatal(err)
		}
		return api
	}
	call := func(api *API, path, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		w := httptest.NewRecorder()
		api.ServeHTTP(w, httptest.NewRequest("POST", path, strings.NewReader(body)))
		if w.Code != want {
			t.Fatalf("%s: %d %s", path, w.Code, w.Body.String())
		}
		return w
	}
	unlimited := `{"title":"tui","scope":["model:fixture"],"rules":[{"action":"model:fixture","effect":"auto"}],"limits":{"model_tokens":-1},"ttl_seconds":60}`
	api := newAPI(hook)
	if w := call(api, "/v1/requests", unlimited, 403); !strings.Contains(w.Body.String(), `"unlimited_owner_only"`) {
		t.Fatal(w.Body.String())
	}
	if seen != user {
		t.Fatal("hook did not see the authenticated principal")
	}
	call(newAPI(nil), "/v1/requests", unlimited, 403)
	isOwner = true
	call(api, "/v1/observers", unlimited, 403)
	call(api, "/v1/requests", strings.Replace(unlimited, "-1", "-2", 1), 400)
	w := call(api, "/v1/requests", unlimited, 201)
	var out GrantSummary
	if json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatal(w.Body.String())
	}
	left, err := svc.Left(context.Background(), user, out.Delegation)
	if err != nil || left.ModelTokens != math.MaxInt64 {
		t.Fatal(left, err)
	}
	info, err := svc.DelegationInfo(context.Background(), user, out.Delegation)
	if err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(info)
	if strings.Contains(string(raw), "OwnBudgetAdmin") || strings.Contains(strings.ToLower(string(raw)), "own_budget") {
		t.Fatal("owner flag stored with the grant")
	}
	// A finite budget from the owner stays finite.
	w = call(api, "/v1/requests", strings.Replace(unlimited, "-1", "200000", 1), 201)
	if json.Unmarshal(w.Body.Bytes(), &out) != nil {
		t.Fatal(w.Body.String())
	}
	if left, err = svc.Left(context.Background(), user, out.Delegation); err != nil || left.ModelTokens != 200000 {
		t.Fatal(left, err)
	}
}
