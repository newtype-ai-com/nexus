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

// The execution-grant wire: a person issues, only the receiving session decides,
// a session cannot issue, and the decision reflects the stored grant.
func TestExecutionGrantsHTTP(t *testing.T) {
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
	root := func(title string) nexus.Issued {
		r, err := svc.CreateRoot(context.Background(), user, nexus.RootRequest{Title: title, Runner: nexus.Local,
			Scope: []string{"newtype:run"}, Rules: []nexus.Rule{{Action: "tool:*", Effect: "auto"}}, TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	recv, send := root("receiver"), root("operator seat")
	receiver := nexus.SessionPrincipal(user.AccountID, recv.Session.ID)
	sender := nexus.SessionPrincipal(user.AccountID, send.Session.ID)
	issue := `{"receiver":"` + string(recv.Session.ID) + `","delegation_id":"` + string(recv.Delegation.ID) + `","senders":["` +
		string(send.Session.ID) + `"],"tools":["tool:edit_file"],"paths":["/repo/x/**"],"max_turns":3,"ttl_seconds":28800,"note":"ops"}`

	actor = sender
	call("POST", "/v1/execution-grants", issue, 403) // a session never issues
	actor = user
	g := call("POST", "/v1/execution-grants", issue, 201)
	var id string
	_ = json.Unmarshal(g["id"], &id)
	if string(g["status"]) != `"active"` || !strings.HasPrefix(id, "xgr_") {
		t.Fatalf("issued %v", g)
	}

	actor = sender
	msg, err := svc.Send(context.Background(), sender, nexus.Message{To: recv.Session.ID, Text: "edit please"})
	if err != nil {
		t.Fatal(err)
	}
	decide := `{"source_event":"` + string(msg.Event) + `","source_seq":` + jsonInt(msg.Seq) +
		`,"action":"tool:edit_file","paths":["/repo/x/main.go"],"input_hash":"` + strings.Repeat("c", 64) + `"}`
	call("POST", "/v1/execution-grants/"+id+"/decide", decide, 404) // not the sender's ledger
	actor = receiver
	d := call("POST", "/v1/execution-grants/"+id+"/decide", decide, 200)
	if string(d["effect"]) != `"allow"` || string(d["turn"]) != "1" {
		t.Fatalf("decision %v", d)
	}
	list := call("GET", "/v1/execution-grants?session="+string(recv.Session.ID), "", 200)
	if !strings.Contains(string(list["grants"]), `"turns_used":1`) {
		t.Fatalf("list %s", list["grants"])
	}
	call("POST", "/v1/execution-grants/"+id+"/revoke", `{"receiver":"`+string(recv.Session.ID)+`","reason":"done"}`, 200)
	d = call("POST", "/v1/execution-grants/"+id+"/decide", decide, 200)
	if string(d["effect"]) != `"deny"` {
		t.Fatalf("after revoke %v", d)
	}
}

func jsonInt(n int64) string { raw, _ := json.Marshal(n); return string(raw) }
