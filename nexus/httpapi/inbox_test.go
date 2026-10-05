package httpapi_test

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/nexus"
)

func TestAssignmentInboxHTTPAndStream(t *testing.T) {
	f := apiSetup(t, "auto")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	boss, err := f.service.CreateRoot(ctx, f.person, nexus.RootRequest{Title: "boss", Scope: []string{"session:delegate", "newtype:run"}})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(f.api)
	defer server.Close()
	r, err := http.NewRequestWithContext(ctx, "GET", server.URL+"/v1/sessions/"+string(f.actor.SessionID)+"/stream?after=1", nil)
	if err != nil {
		t.Fatal(err)
	}
	r.Header.Set("Authorization", "session")
	resp, err := server.Client().Do(r)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.Status)
	}
	assigned, err := f.service.Delegate(ctx, f.person, nexus.DelegateRequest{ParentID: boss.Delegation.ID, ToSessionID: f.actor.SessionID, Title: "wake worker", Brief: "run local test", Scope: []string{"newtype:run"}})
	if err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(resp.Body)
	var event nexus.Event
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "data: ") {
			if err := json.Unmarshal([]byte(strings.TrimPrefix(line, "data: ")), &event); err != nil {
				t.Fatal(err)
			}
			if nexus.ForInbox(event) {
				break
			}
		}
	}
	if !nexus.ForInbox(event) || event.TaskID != assigned.Task.ID {
		t.Fatal("SSE did not deliver assignment", event, scanner.Err())
	}
	w := f.request("GET", "/v1/inbox?limit=1", "", "session")
	code(t, w, 200)
	var page struct {
		Messages []nexus.Received `json:"messages"`
		Next     int64            `json:"next"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &page); err != nil {
		t.Fatal(err)
	}
	if len(page.Messages) != 1 || page.Messages[0].Event != event.ID || page.Messages[0].Deleg != assigned.Delegation.ID {
		t.Fatal(page)
	}
	w = f.request("GET", fmt.Sprintf("/v1/inbox?after=%d", page.Next), "", "session")
	code(t, w, 200)
	if !strings.Contains(w.Body.String(), `"messages":[]`) {
		t.Fatal("assignment replayed", w.Body.String())
	}
	code(t, f.request("GET", "/v1/inbox", "", "person"), 403)
	code(t, f.request("GET", "/v1/inbox", "", "other"), 403)
	code(t, f.request("GET", "/v1/inbox", "", ""), 401)
	for _, query := range []string{"after=-1", "after=bad", "limit=-1", "limit=bad"} {
		code(t, f.request("GET", "/v1/inbox?"+query, "", "session"), 400)
	}
}
