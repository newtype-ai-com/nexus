package nexus_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/httpapi"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
	"github.com/newtype-ai-com/nexus/seal"
)

func TestCredentialsE2E(t *testing.T) {
	for _, backend := range []string{"memory", "postgres"} {
		t.Run(backend, func(t *testing.T) {
			ctx := context.Background()
			var store nexus.Store = nexus.NewMemStore()
			reopen := func() nexus.Store { return store }
			if backend == "postgres" {
				dsn := os.Getenv("NTS_NEXUS_TEST_DSN")
				if dsn == "" {
					t.Skip("requires disposable PostgreSQL")
				}
				name := "seal_test_" + strings.ToLower(ids.New(ids.KindEvent))
				db, err := pgstore.Open(ctx, pgstore.Config{DSN: dsn, Schema: name})
				if err != nil {
					t.Fatal(err)
				}
				if db.EnsureSchema(ctx, name) != nil || db.Migrate(ctx) != nil {
					t.Fatal("migration")
				}
				t.Cleanup(func() {
					_, _ = db.Pool().Exec(ctx, "DROP SCHEMA "+pgx.Identifier{name}.Sanitize()+" CASCADE")
					db.Close()
				})
				store = db
				reopen = func() nexus.Store {
					other, err := pgstore.Open(ctx, pgstore.Config{DSN: dsn, Schema: name})
					if err != nil {
						t.Fatal(err)
					}
					t.Cleanup(other.Close)
					return other
				}
			}
			_, private, _ := ed25519.GenerateKey(rand.Reader)
			signer, _ := seal.NewEd25519Signer(private, "test-v1")
			deriver, _ := seal.NewMasterDeriver(bytes.Repeat([]byte{17}, 32))
			sealer := &seal.Sealer{Signer: signer, Deriver: deriver}
			now := time.Now().UTC()
			clock := func() time.Time { return now }
			newService := func(st nexus.Store) *nexus.Service {
				s, err := nexus.NewServiceWithSealing(st, clock, sealer, "https://gate.example.test")
				if err != nil {
					t.Fatal(err)
				}
				return s
			}
			s := newService(store)
			user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "owner@example.test")
			req := nexus.RootRequest{Title: "sealed E2E", Runner: nexus.Local, Scope: []string{"newtype:run", "session:delegate", "model:*"}, Rules: []nexus.Rule{{Action: "tool:*", Effect: "auto"}, {Action: "model:*", Effect: "ask"}, {Action: "session:delegate", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 1000, RuntimeMinutes: 60, SubSessions: 3, MaxDepth: 3}, TTL: time.Hour}
			root, err := s.CreateRoot(ctx, user, req)
			if err != nil {
				t.Fatal(err)
			}
			actor := nexus.SessionPrincipal(user.AccountID, root.Session.ID)
			child, err := s.Delegate(ctx, actor, nexus.DelegateRequest{ParentID: root.Delegation.ID, ToSessionID: attachedWorker(t, store, user.AccountID, now), Title: "child", Runner: nexus.Local, Scope: req.Scope, Rules: req.Rules, Limits: nexus.Limits{ModelTokens: 100, RuntimeMinutes: 10, SubSessions: 1, MaxDepth: 3}, TTL: time.Minute * 10})
			if err != nil {
				t.Fatal(err)
			}
			childActor := nexus.SessionPrincipal(user.AccountID, child.Session.ID)
			get := func(p nexus.Principal, target ids.Session) ([]nexus.Credential, int) {
				a, err := httpapi.New(httpapi.Config{Service: s, Authenticate: func(*http.Request) (nexus.Principal, error) { return p, nil }, Run: func(context.Context, string, json.RawMessage) error { return nil }})
				if err != nil {
					t.Fatal(err)
				}
				server := httptest.NewTLSServer(a)
				defer server.Close()
				r, err := http.NewRequest("POST", server.URL+"/v1/sessions/"+string(target)+"/credentials", nil)
				if err != nil {
					t.Fatal(err)
				}
				response, err := server.Client().Do(r)
				if err != nil {
					t.Fatal(err)
				}
				defer response.Body.Close()
				body, err := io.ReadAll(io.LimitReader(response.Body, 2<<20))
				if err != nil {
					t.Fatal(err)
				}
				if response.Header.Get("Cache-Control") != "no-store" {
					t.Fatal("cache allowed")
				}
				var out struct {
					Credentials []nexus.Credential `json:"credentials"`
				}
				if response.StatusCode == 200 && json.Unmarshal(body, &out) != nil {
					t.Fatal("decode")
				}
				return out.Credentials, response.StatusCode
			}
			x, code := get(actor, actor.SessionID)
			if code != 200 || len(x) != 1 {
				t.Fatalf("credentials HTTP %d", code)
			}
			c, err := nexus.OpenCredential(x[0], s.DelegationKeys(), actor.AccountID, actor.SessionID, "https://gate.example.test", now)
			if err != nil || c.Principal != user || c.Task.ID != root.Task.ID {
				t.Fatal("certificate binding")
			}
			for _, action := range []string{"tool:read_file", "tool:run_command", "model:fixture", "session:delegate", "purchase", "secret:KEY", "send:external", "unknown:action"} {
				live, err := s.Authorize(ctx, actor, root.Delegation.ID, action)
				static := c.Can(action, now)
				if err != nil || live.Effect != static.Effect || live.Approver != static.Approver {
					t.Fatalf("decision mismatch %s", action)
				}
			}
			y, code := get(childActor, childActor.SessionID)
			if code != 200 || len(y) != 1 {
				t.Fatal("child credentials")
			}
			cc, err := nexus.OpenCredential(y[0], s.DelegationKeys(), actor.AccountID, childActor.SessionID, "https://gate.example.test", now)
			if err != nil || len(cc.Chain) != 1 || cc.Chain[0].ID != c.ID || cc.Principal != user {
				t.Fatal("child chain")
			}
			if _, _, err := seal.Open(x[0].Sealed.Sealed, y[0].Key); !errors.Is(err, seal.ErrOpen) {
				t.Fatal("child opens root")
			}
			if _, code := get(childActor, actor.SessionID); code != 403 {
				t.Fatal("cross-session accepted")
			}
			if _, code := get(user, actor.SessionID); code != 403 {
				t.Fatal("human received keys")
			}
			foreign := nexus.SessionPrincipal(ids.Account(ids.New(ids.KindAccount)), actor.SessionID)
			if _, err := s.Credentials(ctx, foreign, actor.SessionID); err == nil {
				t.Fatal("cross-account accepted")
			}
			for _, tt := range []struct {
				account ids.Account
				session ids.Session
				issuer  string
				at      time.Time
			}{
				{foreign.AccountID, actor.SessionID, "https://gate.example.test", now},
				{actor.AccountID, childActor.SessionID, "https://gate.example.test", now},
				{actor.AccountID, actor.SessionID, "https://evil.example.test", now},
				{actor.AccountID, actor.SessionID, "https://gate.example.test", now.Add(time.Hour)},
			} {
				if _, err := nexus.OpenCredential(x[0], s.DelegationKeys(), tt.account, tt.session, tt.issuer, tt.at); err == nil {
					t.Fatal("invalid binding accepted")
				}
			}
			// New pool/service simulates a server restart; keys are stable, IV fresh.
			s = newService(reopen())
			again, code := get(actor, actor.SessionID)
			if code != 200 || len(again) != 1 || !bytes.Equal(x[0].Key, again[0].Key) || x[0].Sealed.Sealed == again[0].Sealed.Sealed {
				t.Fatal("restart derivation")
			}
			events, _, err := s.Events(ctx, user, actor.SessionID, 0, 1000)
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, e := range events {
				if e.Kind == "credentials.issued" {
					found = true
				}
				if strings.Contains(string(e.Payload), base64.StdEncoding.EncodeToString(x[0].Key)) || strings.Contains(string(e.Payload), x[0].Sealed.Sealed) || strings.Contains(string(e.Payload), "owner@example.test") {
					t.Fatal("credential in ledger payload")
				}
			}
			if !found {
				t.Fatal("missing audit")
			}
			req.Runner = nexus.Container
			remote, err := s.CreateRoot(ctx, user, req)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := s.Credentials(ctx, nexus.SessionPrincipal(user.AccountID, remote.Session.ID), remote.Session.ID); !errors.Is(err, nexus.ErrForbidden) {
				t.Fatal("unsigned container accepted")
			}
			localReq := req
			localReq.ToSessionID = actor.SessionID
			if _, err := s.CreateRoot(ctx, user, localReq); err != nil {
				t.Fatal(err)
			}
			multiple, code := get(actor, actor.SessionID)
			if code != 200 || len(multiple) != 2 {
				t.Fatal("multiple requests did not receive separate credentials")
			}
			if _, err := s.Suspend(ctx, user, childActor.SessionID, "test"); err != nil {
				t.Fatal(err)
			}
			if _, err := s.Credentials(ctx, childActor, childActor.SessionID); !errors.Is(err, nexus.ErrForbidden) {
				t.Fatal("suspended session received credentials")
			}
			if _, err := s.Revoke(ctx, user, root.Delegation.ID, "test"); err != nil {
				t.Fatal(err)
			}
			remaining, err := s.Credentials(ctx, actor, actor.SessionID)
			if err != nil || len(remaining) != 1 || remaining[0].DelegationID == root.Delegation.ID {
				t.Fatal("revoked root credential included")
			}
			// A still-readable old certificate must not revive server authority.
			if _, err := s.Authorize(ctx, actor, root.Delegation.ID, "tool:read_file"); !errors.Is(err, nexus.ErrRevoked) {
				t.Fatal("old sealed credential revived authority")
			}
		})
	}
}
