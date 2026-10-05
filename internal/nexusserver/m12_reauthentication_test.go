package nexusserver

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

type m12CountingCredentials struct {
	*gate.MemoryCredentials
	lookups atomic.Int64
}

func (s *m12CountingCredentials) LookupCredential(ctx context.Context, v string) (gate.Credential, error) {
	s.lookups.Add(1)
	return s.MemoryCredentials.LookupCredential(ctx, v)
}

func TestM12ProductionHandlerRechecksWithoutTouch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	base := time.Now().UTC()
	var clock atomic.Int64
	clock.Store(base.UnixNano())
	svc := nexus.NewService(nexus.NewMemStore(), func() time.Time { return time.Unix(0, clock.Load()).UTC() })
	person := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "fixture@example.test")
	root, err := svc.CreateRoot(ctx, person, nexus.RootRequest{Title: "M12 wiring", Runner: nexus.Container, Scope: []string{"newtype:run"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	store := &m12CountingCredentials{MemoryCredentials: gate.NewMemoryCredentials()}
	token := "nta_" + strings.Repeat("p", 32)
	credential := gate.Credential{Verifier: gate.Verifier(token), Kind: "agent", Account: person.AccountID, Session: root.Session.ID, Expires: base.Add(time.Hour)}
	if err := store.PutCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(svc, store, func(context.Context) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	req, _ := http.NewRequestWithContext(ctx, "GET", server.URL+"/v1/sessions/"+string(root.Session.ID)+"/stream", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := server.Client().Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatal(resp.StatusCode)
	}
	clock.Store(base.Add(2 * time.Minute).UnixNano())
	before := store.lookups.Load()
	deadline := time.Now().Add(time.Second)
	for store.lookups.Load() < before+3 && time.Now().Before(deadline) {
		svc.Notify()
		time.Sleep(5 * time.Millisecond)
	}
	if store.lookups.Load() < before+3 {
		t.Fatal("production rechecks not exercised")
	}
	session, err := svc.Session(ctx, person, root.Session.ID)
	if err != nil || !session.SeenAt.Equal(base) || !svc.LastSeen(root.Session.ID).Equal(base) {
		t.Fatal("production recheck touched presence", err)
	}
	credential.Revoked = true
	if err := store.PutCredential(ctx, credential); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := io.Copy(io.Discard, resp.Body); done <- err }()
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(time.Second)
	defer timeout.Stop()
	for {
		select {
		case err := <-done:
			if err != nil {
				t.Fatal(err)
			}
			return
		case <-ticker.C:
			svc.Notify()
		case <-timeout.C:
			cancel()
			t.Fatal("revoked stream stayed open")
		}
	}
}
