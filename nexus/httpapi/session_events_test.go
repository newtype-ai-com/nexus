package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestSessionRecordsToolCallsInOwnLedgerOnly(t *testing.T) {
	ctx := context.Background()
	svc := nexus.NewService(nexus.NewMemStore(), time.Now)
	person := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "owner@example.com")
	a, err := svc.CreateRoot(ctx, person, nexus.RootRequest{Title: "a", Runner: nexus.Local, Scope: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	b, err := svc.CreateRoot(ctx, person, nexus.RootRequest{Title: "b", Runner: nexus.Local, Scope: []string{}})
	if err != nil {
		t.Fatal(err)
	}
	actor := map[string]nexus.Principal{"a": nexus.SessionPrincipal(person.AccountID, a.Session.ID), "person": person}
	api, err := New(Config{Service: svc, Run: func(context.Context, string, json.RawMessage) error { return errors.New("no") }, Authenticate: func(r *http.Request) (nexus.Principal, error) {
		p, ok := actor[r.Header.Get("Authorization")]
		if !ok {
			return nexus.Principal{}, errors.New("no")
		}
		return p, nil
	}})
	if err != nil {
		t.Fatal(err)
	}
	post := func(who string, session ids.Session, body string) int {
		req := httptest.NewRequest("POST", "/v1/sessions/"+string(session)+"/events", bytes.NewBufferString(body))
		req.Header.Set("Authorization", who)
		rec := httptest.NewRecorder()
		api.ServeHTTP(rec, req)
		return rec.Code
	}
	ok := `{"events":[{"kind":"tool.call","client_event_id":"c1","payload":{"tool":"nexus_peers","outcome":"ok"}}]}`
	if code := post("a", a.Session.ID, ok); code != 200 {
		t.Fatalf("own ledger: %d", code)
	}
	if code := post("a", a.Session.ID, ok); code != 200 { // replay is idempotent
		t.Fatalf("replay: %d", code)
	}
	for name, c := range map[string]struct {
		who     string
		session ids.Session
		body    string
		want    int
	}{
		"other session": {"a", b.Session.ID, ok, 403},
		"person":        {"person", a.Session.ID, ok, 403},
		"message kind":  {"a", a.Session.ID, `{"events":[{"kind":"message.read"}]}`, 400},
		"non tool kind": {"a", a.Session.ID, `{"events":[{"kind":"task.done"}]}`, 400},
		"empty":         {"a", a.Session.ID, `{"events":[]}`, 400},
	} {
		if code := post(c.who, c.session, c.body); code != c.want {
			t.Fatalf("%s: %d want %d", name, code, c.want)
		}
	}
	events, _, err := svc.Events(ctx, person, a.Session.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, e := range events {
		if e.Kind == "tool.call" {
			n++
			if e.Source != "tool" || e.Actor != actor["a"] {
				t.Fatalf("record %+v", e)
			}
		}
	}
	if n != 1 {
		t.Fatalf("tool.call records = %d", n)
	}
}
