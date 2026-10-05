package gate

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestValidateWakeAuthenticatedSessionOnly(t *testing.T) {
	ctx := context.Background()
	s := nexus.NewService(nexus.NewMemStore(), time.Now)
	store := NewMemoryCredentials()
	account := ids.Account(ids.New(ids.KindAccount))
	person := nexus.UserPrincipal(account, "fixture@example.test")
	root, err := s.CreateRoot(ctx, person, nexus.RootRequest{Title: "wake", Runner: nexus.Local, Scope: []string{"newtype:run"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	m, err := s.Send(ctx, person, nexus.Message{To: root.Session.ID, Text: "wake only"})
	if err != nil {
		t.Fatal(err)
	}
	key, login := "lic_"+strings.Repeat("a", 32), "login_"+strings.Repeat("b", 32)
	for token, kind := range map[string]string{key: "licence", login: "login"} {
		if err := store.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: account, Email: person.Email, Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	h := ValidateHandlerWithWake(store, s)
	check := func(session string, duplicate bool, want bool) {
		t.Helper()
		r := httptest.NewRequest("POST", "/v1/validate", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		r.Header.Set("X-Newtype-Login", login)
		if session != "" {
			r.Header.Set("X-Newtype-Session", session)
		}
		if duplicate {
			r.Header.Add("X-Newtype-Session", session)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != 200 || (w.Header().Get(nexus.WakeHeader) == "1") != want {
			t.Fatalf("wake=%q code=%d", w.Header().Get(nexus.WakeHeader), w.Code)
		}
	}
	check(string(root.Session.ID), false, true)
	check("", false, false)
	check(string(root.Session.ID), true, false)
	check(ids.New(ids.KindSession), false, false)
	actor := nexus.SessionPrincipal(account, root.Session.ID)
	if err := s.MessageDelivered(ctx, actor, nexus.Receipt{Event: m.Event}); err != nil {
		t.Fatal(err)
	}
	check(string(root.Session.ID), false, true)
	if err := s.MessageRead(ctx, actor, nexus.Receipt{Event: m.Event, TurnID: ids.New(ids.KindTask)}); err != nil {
		t.Fatal(err)
	}
	check(string(root.Session.ID), false, false)
}
