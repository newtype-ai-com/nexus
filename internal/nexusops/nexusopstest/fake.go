// Package nexusopstest is a fake Gate+Nexus for tests only: the real
// nexus.Service and httpapi behind a TLS loopback server, with an
// authenticator that mirrors the Gate rule (licence + login = the person;
// plus X-Newtype-Session = that local session). No network leaves loopback.
package nexusopstest

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/internal/nexusops"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/httpapi"
)

var (
	Key   = "ntl_" + strings.Repeat("a", 64)
	Login = "ntg_" + strings.Repeat("b", 64)
)

type Fake struct {
	Server  *httptest.Server
	Service *nexus.Service
	Person  nexus.Principal
	// LoginRevoked makes every request with the login fail like Gate (401).
	LoginRevoked atomic.Bool
	// Requests counts authentication attempts.
	Requests atomic.Int64
}

func New(t testing.TB) *Fake {
	t.Helper()
	f := &Fake{Service: nexus.NewService(nexus.NewMemStore(), time.Now)}
	f.Person = nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "owner@example.com")
	api, err := httpapi.New(httpapi.Config{Service: f.Service, Run: func(context.Context, string, json.RawMessage) error { return errors.New("must not execute") }, Authenticate: f.authenticate})
	if err != nil {
		t.Fatal(err)
	}
	f.Server = httptest.NewTLSServer(api)
	t.Cleanup(f.Server.Close)
	return f
}

func (f *Fake) authenticate(r *http.Request) (nexus.Principal, error) {
	f.Requests.Add(1)
	if f.LoginRevoked.Load() || r.Header.Get("Authorization") != "Bearer "+Key || r.Header.Get("X-Newtype-Login") != Login {
		return nexus.Principal{}, errors.New("unauthenticated")
	}
	sid := r.Header.Get("X-Newtype-Session")
	if sid == "" {
		return f.Person, nil
	}
	id, err := ids.ParseSession(sid)
	if err != nil {
		return nexus.Principal{}, err
	}
	s, err := f.Service.Session(r.Context(), f.Person, id)
	if err != nil || s.Runner != nexus.Local || s.Status == nexus.SessionSuspended || s.Status == nexus.SessionDone {
		return nexus.Principal{}, errors.New("unauthenticated")
	}
	return nexus.SessionPrincipal(f.Person.AccountID, id), nil
}

func (f *Fake) Identity() nexusops.Identity {
	return nexusops.Identity{Endpoint: f.Server.URL, Key: Key, Login: Login}
}

func (f *Fake) Transport() http.RoundTripper { return f.Server.Client().Transport }

// Root issues a local root for a fixture session (e.g. the TUI side).
func (f *Fake) Root(t testing.TB, title string, scope ...string) (nexus.Issued, nexus.Principal) {
	t.Helper()
	if scope == nil {
		scope = []string{}
	}
	out, err := f.Service.CreateRoot(context.Background(), f.Person, nexus.RootRequest{Title: title, Runner: nexus.Local, Scope: scope, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	return out, nexus.SessionPrincipal(f.Person.AccountID, out.Session.ID)
}

// SessionsTitled counts the account's sessions with this exact title.
func (f *Fake) SessionsTitled(t testing.TB, title string) int {
	t.Helper()
	all, err := f.Service.Sessions(context.Background(), f.Person)
	if err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, s := range all {
		if s.Title == title {
			n++
		}
	}
	return n
}
