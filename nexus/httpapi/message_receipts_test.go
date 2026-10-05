package httpapi_test

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestMessageReceiptHTTP(t *testing.T) {
	f := apiSetup(t, "auto")
	m, err := f.service.Send(context.Background(), f.person, nexus.Message{To: f.actor.SessionID, Text: "display is not read"})
	if err != nil {
		t.Fatal(err)
	}
	path := "/v1/messages/" + string(m.Event) + "?to=" + string(f.actor.SessionID)
	status := func(want string) {
		w := f.request("GET", path, "", "person")
		code(t, w, 200)
		var out nexus.MessageStatus
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		if out.Status != want {
			t.Fatal(out)
		}
	}
	wake := func(want bool) {
		t.Helper()
		w := f.request("GET", "/v1/inbox", "", "session")
		code(t, w, 200)
		if (w.Header().Get(nexus.WakeHeader) == "1") != want {
			t.Fatalf("wake=%q want %v", w.Header().Get(nexus.WakeHeader), want)
		}
		if f.request("GET", "/v1/sessions", "", "person").Header().Get(nexus.WakeHeader) != "" {
			t.Fatal("user identity got a session hint")
		}
	}
	wake(true)
	status("sent")
	body := fmt.Sprintf(`{"event_id":%q}`, m.Event)
	code(t, f.request("POST", "/v1/messages/delivered", body, "person"), 403)
	code(t, f.request("POST", "/v1/messages/delivered", body, "session"), 200)
	code(t, f.request("POST", "/v1/messages/delivered", body, "session"), 200)
	status("delivered")
	wake(true) // Delivery is not model ingestion; keep recovering unread mail.
	code(t, f.request("POST", "/v1/messages/read", body, "session"), 400)
	body = fmt.Sprintf(`{"event_id":%q,"turn_id":%q}`, m.Event, ids.New(ids.KindTask))
	code(t, f.request("POST", "/v1/messages/read", body, "session"), 200)
	status("read")
	wake(false)
	code(t, f.request("GET", path, "", "session"), 403)
	code(t, f.request("GET", "/v1/messages/bad?to=bad", "", "person"), 400)
	code(t, f.request("POST", "/v1/messages/delivered", `{"event_id":"bad"}`, "session"), 400)
	code(t, f.request("POST", "/v1/messages/read", body, ""), 401)
}
