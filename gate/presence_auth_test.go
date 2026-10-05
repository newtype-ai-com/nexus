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

func TestAgentAuthenticationRestoresOnlySystemPresenceStop(t *testing.T) {
	for _, mode := range []string{"system", "session", "user", "legacy", "revoked", "expired", "bad_token", "suspended", "done"} {
		t.Run(mode, func(t *testing.T) {
			ctx := context.Background()
			now := time.Now().UTC()
			start := now
			st := nexus.NewMemStore()
			svc := nexus.NewService(st, func() time.Time { return now })
			account := ids.Account(ids.New(ids.KindAccount))
			person := nexus.UserPrincipal(account, "owner@example.com")
			root, err := svc.CreateRoot(ctx, person, nexus.RootRequest{Title: "presence", Runner: nexus.Container, Scope: []string{"newtype:run"}, TTL: time.Hour})
			if err != nil {
				t.Fatal(err)
			}
			p := nexus.SessionPrincipal(account, root.Session.ID)
			if _, err = svc.SetSessionStatus(ctx, p, p.SessionID, nexus.SessionWaiting); err != nil {
				t.Fatal(err)
			}
			token := "nta_" + strings.Repeat("c", 32)
			creds := NewMemoryCredentials()
			cred := Credential{Verifier: Verifier(token), Kind: "agent", Account: account, Email: person.Email, Session: p.SessionID, Expires: now.Add(time.Hour)}
			if mode == "revoked" {
				cred.Revoked = true
			}
			if mode == "expired" {
				cred.Expires = now.Add(time.Minute)
			}
			if err = creds.PutCredential(ctx, cred); err != nil {
				t.Fatal(err)
			}
			now = now.Add(6 * time.Minute)
			if _, err = svc.Sweep(ctx, start, nexus.PresenceGrace, nexus.ArchiveAfter); err != nil {
				t.Fatal(err)
			}
			if err = st.Update(ctx, func(tx nexus.Tx) error {
				x, e := tx.Session(p.SessionID)
				if e != nil {
					return e
				}
				switch mode {
				case "session":
					x.StoppedBy = nexus.PrincipalSession
				case "user":
					x.StoppedBy = nexus.PrincipalUser
				case "legacy":
					x.StoppedBy = ""
				case "suspended":
					x.Status = nexus.SessionSuspended
				case "done":
					x.Status = nexus.SessionDone
				}
				return tx.PutSession(x)
			}); err != nil {
				t.Fatal(err)
			}
			if mode == "bad_token" {
				token = "nta_" + strings.Repeat("d", 32)
			}
			before, e := svc.Session(ctx, person, p.SessionID)
			if e != nil {
				t.Fatal(e)
			}
			cursor, e := svc.Cursor(ctx, person)
			if e != nil {
				t.Fatal(e)
			}
			r := httptest.NewRequest("GET", "/v1/inbox", nil)
			r.Header.Set("Authorization", "Bearer "+token)
			auth := NexusAuth{Store: creds, Service: svc, Clock: func() time.Time { return now }}
			got, err := auth.Authenticate(r)
			x, e := svc.Session(ctx, person, p.SessionID)
			if e != nil {
				t.Fatal(e)
			}
			if mode == "system" {
				if err != nil || got != p || x.Status != nexus.SessionWaiting || x.StoppedBy != "" {
					t.Fatal(got, err, x)
				}
			} else {
				after, e := svc.Cursor(ctx, person)
				if e != nil {
					t.Fatal(e)
				}
				if err == nil || x != before || cursor != after {
					t.Fatal("untrusted recovery mutated state", mode, err, x)
				}
			}
		})
	}
}
