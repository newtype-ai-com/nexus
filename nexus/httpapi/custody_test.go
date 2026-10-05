package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// The wire must carry every key explicitly: no omitempty, literal booleans,
// null for absent times, and the contract version.
func TestCustodyHTTPWire(t *testing.T) {
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "user@example.test")
	actor := user
	api, err := New(Config{Service: svc, Authenticate: func(*http.Request) (nexus.Principal, error) { return actor, nil },
		Run: func(context.Context, string, json.RawMessage) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string, want int) map[string]json.RawMessage {
		t.Helper()
		w := httptest.NewRecorder()
		api.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(body)))
		if w.Code != want {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
		var out map[string]json.RawMessage
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return out
	}
	root, err := svc.CreateRoot(context.Background(), user, nexus.RootRequest{Title: "custody actor", Runner: nexus.Local,
		Scope: []string{"newtype:run"}, Rules: []nexus.Rule{{Action: "custody:bind-static-config", Effect: "ask"}}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	session := nexus.SessionPrincipal(user.AccountID, root.Session.ID)
	hash := "sha256:" + strings.Repeat("ab", 32)
	keys := []string{"version", "id", "session_id", "delegation_id", "action", "input_hash", "status", "standing", "revoked", "usable",
		"created_at", "expires_at", "decided_at", "decided_by", "used_at"}
	exact := func(got map[string]json.RawMessage) {
		t.Helper()
		if len(got) != len(keys) {
			t.Fatalf("keys %d want %d", len(got), len(keys))
		}
		for _, k := range keys {
			if _, ok := got[k]; !ok {
				t.Fatalf("missing %s", k)
			}
		}
		if string(got["standing"]) != "false" || string(got["version"]) != `"`+nexus.CustodyVersion+`"` {
			t.Fatalf("standing/version: %s %s", got["standing"], got["version"])
		}
	}

	actor = session
	d := call("GET", "/v1/custody/decision?delegation_id="+string(root.Delegation.ID)+"&action=custody:bind-static-config", "", 200)
	if string(d["effect"]) != `"ask"` || string(d["approver"]) != `"user"` || len(d) != 3 {
		t.Fatalf("decision %v", d)
	}
	req := `{"delegation_id":"` + string(root.Delegation.ID) + `","action":"custody:bind-static-config","input_hash":"` + hash + `","ttl_seconds":600}`
	created := call("POST", "/v1/custody/approvals", req, 201)
	exact(created)
	if string(created["decided_at"]) != "null" || string(created["used_at"]) != "null" || string(created["decided_by"]) != "null" || string(created["revoked"]) != "false" {
		t.Fatalf("nulls: %v", created)
	}
	var id string
	_ = json.Unmarshal(created["id"], &id)
	call("POST", "/v1/custody/approvals", req, 409)
	call("POST", "/v1/custody/approvals/"+id+"/decision", `{"input_hash":"`+hash+`","approve":true}`, 403)

	actor = user
	call("POST", "/v1/custody/approvals/"+id+"/decision", `{"input_hash":"`+hash+`"}`, 400) // approve is required
	exact(call("POST", "/v1/custody/approvals/"+id+"/decision", `{"input_hash":"`+hash+`","approve":true}`, 200))

	actor = session
	used := call("POST", "/v1/custody/approvals/"+id+"/use", `{"input_hash":"`+hash+`"}`, 200)
	exact(used)
	if string(used["status"]) != `"used"` || string(used["used_at"]) == "null" {
		t.Fatalf("%v", used)
	}
	call("POST", "/v1/custody/approvals/"+id+"/use", `{"input_hash":"`+hash+`"}`, 409)
	exact(call("GET", "/v1/custody/approvals/"+id, "", 200))
	list := call("GET", "/v1/custody/approvals?input_hash="+hash, "", 200)
	if string(list["complete"]) != "true" || string(list["version"]) != `"`+nexus.CustodyVersion+`"` || len(list) != 4 {
		t.Fatalf("%v", list)
	}
	var items []map[string]json.RawMessage
	if json.Unmarshal(list["approvals"], &items) != nil || len(items) != 1 || len(items[0]) != len(keys)-1 {
		t.Fatalf("items %s", list["approvals"])
	}
	call("GET", "/v1/custody/approvals?input_hash="+hash+"&extra=1", "", 400)
	call("GET", "/v1/custody/approvals?input_hash="+hash+"&input_hash="+hash, "", 400)
	dv := call("GET", "/v1/custody/delegations/"+string(root.Delegation.ID), "", 200)
	for _, k := range []string{"version", "id", "delegate", "expires_at", "ended", "end_reason", "revoked", "live", "session_active"} {
		if _, ok := dv[k]; !ok {
			t.Fatalf("delegation view missing %s", k)
		}
	}
	if string(dv["live"]) != "true" || string(dv["revoked"]) != "false" || string(dv["ended"]) != "false" || string(dv["end_reason"]) != "null" {
		t.Fatalf("%v", dv)
	}
	// forged principal fields in the body are refused
	call("POST", "/v1/custody/approvals", strings.Replace(req, `"action":`, `"account_id":"x","action":`, 1), 400)
	call("POST", "/v1/custody/approvals", strings.Replace(req, `600}`, `0}`, 1), 400)
	call("POST", "/v1/custody/approvals", strings.Replace(req, hash, strings.Repeat("ab", 32), 1), 400)
	// the person cannot ask for a non-consuming session decision
	actor = user
	call("GET", "/v1/custody/decision?delegation_id="+string(root.Delegation.ID)+"&action=custody:bind-static-config", "", 403)
}
