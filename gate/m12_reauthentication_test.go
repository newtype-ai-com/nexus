package gate

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/httpapi"
)

func TestM12AgentReauthenticationDoesNotReportPresence(t *testing.T) {
	for _, ending := range []string{"life", "credential_revoked", "credential_expired", "delegation_revoked"} {
		t.Run(ending, func(t *testing.T) {
			ctx := context.Background()
			base := time.Now().UTC()
			var clock atomic.Int64
			clock.Store(base.UnixNano())
			now := func() time.Time { return time.Unix(0, clock.Load()).UTC() }
			svc := nexus.NewService(nexus.NewMemStore(), now)
			person := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "fixture@example.test")
			root, err := svc.CreateRoot(ctx, person, nexus.RootRequest{Title: "M12", Runner: nexus.Container, Scope: []string{"newtype:run"}, TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			actor := nexus.SessionPrincipal(person.AccountID, root.Session.ID)
			if _, err := svc.SetSessionStatus(ctx, actor, root.Session.ID, nexus.SessionRunning); err != nil {
				t.Fatal(err)
			}
			store := NewMemoryCredentials()
			token := "nta_" + strings.Repeat("m", 32)
			credential := Credential{Verifier: Verifier(token), Kind: "agent", Account: person.AccountID, Session: root.Session.ID, Expires: base.Add(30 * time.Minute)}
			if err := store.PutCredential(ctx, credential); err != nil {
				t.Fatal(err)
			}
			auth := NexusAuth{Store: store, Service: svc, Clock: now}
			var rechecks atomic.Int64
			api, err := httpapi.New(httpapi.Config{Service: svc, Authenticate: auth.Authenticate,
				Reauthenticate: func(r *http.Request) (nexus.Principal, error) { rechecks.Add(1); return auth.Reauthenticate(r) },
				Run:            func(context.Context, string, json.RawMessage) error { return nexus.ErrForbidden },
				StreamLife:     800 * time.Millisecond, Heartbeat: 10 * time.Millisecond})
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(api)
			defer server.Close()
			clock.Store(base.Add(2 * time.Minute).UnixNano())
			opened := now()
			req, _ := http.NewRequest("GET", server.URL+"/v1/sessions/"+string(root.Session.ID)+"/stream", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			resp, err := server.Client().Do(req)
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatal(resp.StatusCode)
			}
			clock.Store(base.Add(4 * time.Minute).UnixNano())
			prior := rechecks.Load()
			deadline := time.Now().Add(300 * time.Millisecond)
			for rechecks.Load() < prior+3 && time.Now().Before(deadline) {
				time.Sleep(time.Millisecond)
			}
			if rechecks.Load() < prior+3 {
				t.Fatal("heartbeat revalidation not exercised")
			}
			session, err := svc.Session(ctx, person, root.Session.ID)
			if err != nil {
				t.Fatal(err)
			}
			if !session.SeenAt.Equal(opened) || !svc.LastSeen(root.Session.ID).Equal(opened) {
				t.Fatal("reauthentication refreshed presence")
			}
			switch ending {
			case "credential_revoked":
				credential.Revoked = true
				if err := store.PutCredential(ctx, credential); err != nil {
					t.Fatal(err)
				}
			case "credential_expired":
				clock.Store(base.Add(31 * time.Minute).UnixNano())
			case "delegation_revoked":
				if _, err := svc.Revoke(ctx, person, root.Delegation.ID, ""); err != nil {
					t.Fatal(err)
				}
			}
			start := time.Now()
			if _, err := io.Copy(io.Discard, resp.Body); err != nil {
				t.Fatal(err)
			}
			if ending != "life" && time.Since(start) > 400*time.Millisecond {
				t.Fatal("stream did not promptly reject invalid authority")
			}
		})
	}
}

func TestM12AgentReauthenticationCannotRestoreSystemStop(t *testing.T) {
	ctx := context.Background()
	now := time.Now().UTC()
	base := now
	svc := nexus.NewService(nexus.NewMemStore(), func() time.Time { return now })
	person := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "fixture@example.test")
	root, err := svc.CreateRoot(ctx, person, nexus.RootRequest{Title: "M12 restore", Runner: nexus.Container, Scope: []string{"newtype:run"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	actor := nexus.SessionPrincipal(person.AccountID, root.Session.ID)
	if _, err := svc.SetSessionStatus(ctx, actor, root.Session.ID, nexus.SessionRunning); err != nil {
		t.Fatal(err)
	}
	store := NewMemoryCredentials()
	token := "nta_" + strings.Repeat("s", 32)
	if err := store.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: "agent", Account: person.AccountID, Session: root.Session.ID, Expires: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	auth := NexusAuth{Store: store, Service: svc, Clock: func() time.Time { return now }}
	req := httptest.NewRequest("GET", "/v1/inbox", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	if _, err := auth.Authenticate(req); err != nil {
		t.Fatal(err)
	}
	now = now.Add(6 * time.Minute)
	if _, err := svc.Sweep(ctx, base, nexus.PresenceGrace, 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Reauthenticate(req); err == nil {
		t.Fatal("stopped agent reauthenticated")
	}
	stopped, err := svc.Session(ctx, person, root.Session.ID)
	if err != nil || stopped.Status != nexus.SessionStopped || stopped.StoppedBy != nexus.PrincipalSystem {
		t.Fatal("recheck restored stopped session", err)
	}
	if !svc.LastSeen(root.Session.ID).Equal(base) {
		t.Fatal("recheck changed presence cache")
	}
	if _, err := auth.Authenticate(req); err != nil {
		t.Fatal("fresh request failed system-stop recovery", err)
	}
	restored, err := svc.Session(ctx, person, root.Session.ID)
	if err != nil || restored.Status != nexus.SessionWaiting {
		t.Fatal("M8 restoration lost", err)
	}
	if _, err := svc.Revoke(ctx, person, root.Delegation.ID, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := auth.Reauthenticate(req); err == nil {
		t.Fatal("revoked ancestry accepted")
	}
}
