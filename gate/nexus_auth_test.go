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

func TestNexusAuthCredentialsAndSessionBinding(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	svc := nexus.NewService(nexus.NewMemStore(), func() time.Time { return now })
	store := NewMemoryCredentials()
	account := ids.Account(ids.New(ids.KindAccount))
	person := nexus.UserPrincipal(account, "owner@example.com")
	issue := func(runner nexus.Runner) nexus.Issued {
		root, err := svc.CreateRoot(ctx, person, nexus.RootRequest{Title: "auth", Runner: runner, Scope: []string{"newtype:run"}, Rules: []nexus.Rule{{Action: "tool:*", Effect: "auto"}}, TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		return root
	}
	local := issue(nexus.Local)
	remote := issue(nexus.Container)
	licence := "lic_" + strings.Repeat("a", 32)
	login := "login_" + strings.Repeat("b", 32)
	agent := "nta_" + strings.Repeat("c", 32)
	put := func(token, kind string, session ids.Session) Credential {
		c := Credential{Verifier: Verifier(token), Kind: kind, Account: account, Email: person.Email, Session: session, Expires: now.Add(time.Hour)}
		if err := store.PutCredential(ctx, c); err != nil {
			t.Fatal(err)
		}
		return c
	}
	put(licence, "licence", "")
	put(login, "login", "")
	ac := put(agent, "agent", remote.Session.ID)
	auth := NexusAuth{Store: store, Service: svc, Clock: func() time.Time { return now }}
	check := func(token, loginToken, session string, want nexus.Principal, valid bool) {
		t.Helper()
		r := httptest.NewRequest("GET", "/v1/inbox", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		if loginToken != "" {
			r.Header.Set("X-Newtype-Login", loginToken)
		}
		if session != "" {
			r.Header.Set("X-Newtype-Session", session)
		}
		p, err := auth.Authenticate(r)
		if valid && (err != nil || p != want) {
			t.Fatalf("principal=%+v err=%v", p, err)
		}
		if !valid && err == nil {
			t.Fatal("accepted invalid credentials", p)
		}
	}
	check(licence, login, "", person, true)
	check(licence, login, string(local.Session.ID), nexus.SessionPrincipal(account, local.Session.ID), true)
	check(agent, "", "", nexus.SessionPrincipal(account, remote.Session.ID), true)
	check(licence, "", "", nexus.Principal{}, false)
	check(licence, login, string(remote.Session.ID), nexus.Principal{}, false)
	check(agent, login, "", nexus.Principal{}, false)
	check(agent, "", string(local.Session.ID), nexus.Principal{}, false)
	check("invalid", login, "", nexus.Principal{}, false)
	r := httptest.NewRequest("GET", "/", nil)
	r.Header.Add("Authorization", "Bearer "+agent)
	r.Header.Add("Authorization", "Bearer "+agent)
	if _, err := auth.Authenticate(r); err == nil {
		t.Fatal("duplicate auth accepted")
	}
	foreign := "login_" + strings.Repeat("d", 32)
	fc := Credential{Verifier: Verifier(foreign), Kind: "login", Account: ids.Account(ids.New(ids.KindAccount)), Email: "other@example.com", Expires: now.Add(time.Hour)}
	if err := store.PutCredential(ctx, fc); err != nil {
		t.Fatal(err)
	}
	check(licence, foreign, "", nexus.Principal{}, false)
	ac.Revoked = true
	if err := store.PutCredential(ctx, ac); err != nil {
		t.Fatal(err)
	}
	check(agent, "", "", nexus.Principal{}, false)
	ac.Revoked = false
	if err := store.PutCredential(ctx, ac); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Revoke(ctx, person, remote.Delegation.ID, ""); err != nil {
		t.Fatal(err)
	}
	check(agent, "", "", nexus.Principal{}, false)
	now = now.Add(time.Hour)
	check(licence, login, "", nexus.Principal{}, false)
}
