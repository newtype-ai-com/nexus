package nexusserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

type person struct {
	account      ids.Account
	email        string
	key, login   string
	session      ids.Session
	delegation   ids.Delegation
	principalUsr nexus.Principal
}

func newPerson(t *testing.T, creds *gate.MemoryCredentials, email, fill string) *person {
	t.Helper()
	p := &person{account: ids.Account(ids.New(ids.KindAccount)), email: email, key: "ntl_" + strings.Repeat(fill, 64), login: "ntg_" + strings.Repeat(fill, 64)}
	for token, kind := range map[string]string{p.key: "licence", p.login: "login"} {
		if err := creds.PutCredential(context.Background(), gate.Credential{Verifier: gate.Verifier(token), Kind: kind, Account: p.account, Email: email, Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	p.principalUsr = nexus.UserPrincipal(p.account, email)
	return p
}

func (p *person) req(method, path, body string, session bool) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+p.key)
	r.Header.Set("X-Newtype-Login", p.login)
	if session {
		r.Header.Set("X-Newtype-Session", string(p.session))
		r.Header.Set("X-Newtype-Delegation", string(p.delegation))
	}
	return r
}

type accessFixture struct {
	svc                *nexus.Service
	creds              *gate.MemoryCredentials
	access             *gate.ModelAccess
	api                http.Handler
	relay              *gate.ModelHandler
	ops                *gate.ModelAccessHandler
	owner, user, other *person
	records            []map[string]any
	path               string
}

func newAccessFixture(t *testing.T) *accessFixture {
	t.Helper()
	f := &accessFixture{svc: nexus.NewService(nexus.NewMemStore(), nil), creds: gate.NewMemoryCredentials()}
	f.owner = newPerson(t, f.creds, "owner@example.test", "a")
	f.user = newPerson(t, f.creds, "user@example.test", "b")
	f.other = newPerson(t, f.creds, "other@example.test", "c")
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	f.path = filepath.Join(dir, "model-access.json")
	var err error
	if f.access, err = gate.OpenModelAccess(f.path); err != nil {
		t.Fatal(err)
	}
	if f.api, err = NewHandlerWithOptions(f.svc, f.creds, func(context.Context) error { return nil }, nil,
		HandlerOptions{ModelScope: gate.ModelScopeAllowed(f.creds, "owner@example.test", f.access, []string{"fixture"})}); err != nil {
		t.Fatal(err)
	}
	if f.relay, err = gate.NewModelHandler(gate.ModelConfig{Service: f.svc, Store: f.creds, Upstream: "https://provider.test/v1/responses", Key: "fixture-key",
		Models: []string{"fixture"}, Budget: 4096, MaxOutput: 256, OwnerEmail: "owner@example.test", Access: f.access}); err != nil {
		t.Fatal(err)
	}
	accounts := map[string]ids.Account{f.user.email: f.user.account, f.other.email: f.other.account}
	if f.ops, err = gate.NewModelAccessHandler(gate.ModelAccessConfig{Access: f.access, Service: f.svc, Store: f.creds, OwnerEmail: "owner@example.test",
		AccountForEmail: func(_ context.Context, email string) (ids.Account, error) {
			if a, ok := accounts[email]; ok {
				return a, nil
			}
			return "", nexus.ErrNotFound
		},
		Record: func(_ context.Context, owner nexus.Principal, kind string, payload map[string]any) {
			f.records = append(f.records, map[string]any{"kind": kind, "by": owner.Email, "action": payload["action"], "email": payload["email"]})
		}}); err != nil {
		t.Fatal(err)
	}
	// every person has a live session with a model-free root (messages work without the model)
	for _, p := range []*person{f.owner, f.user, f.other} {
		out, err := f.svc.CreateRoot(context.Background(), p.principalUsr, nexus.RootRequest{Title: "tui", Runner: nexus.Local, Scope: []string{"newtype:run"}, TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		p.session, p.delegation = out.Session.ID, out.Delegation.ID
	}
	return f
}

func serve(h http.Handler, r *http.Request) *httptest.ResponseRecorder {
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

const modelRoot = `{"title":"tui","scope":["model:fixture","newtype:run"],"rules":[{"action":"model:fixture","effect":"auto"}],"limits":{"model_tokens":1000},"ttl_seconds":60}`

func (f *accessFixture) allow(t *testing.T, as *person, action, email string) *httptest.ResponseRecorder {
	t.Helper()
	return serve(f.ops, as.req("POST", "/v1/operator/model-access", `{"action":"`+action+`","email":"`+email+`"}`, false))
}

// Owner allowed; a designated user allowed; everyone else refused at root
// issuance and at the relay with the fixed code; own models and model-free
// roots stay open; owner-only management is recorded and persisted.
func TestDefaultModelAccess(t *testing.T) {
	f := newAccessFixture(t)
	root := func(p *person, body string) *httptest.ResponseRecorder {
		return serve(f.api, p.req("POST", "/v1/requests", body, false))
	}
	relay := func(p *person) *httptest.ResponseRecorder {
		r := p.req("POST", "/v1/model/responses", `{}`, true)
		r.Header.Del("X-Newtype-Delegation") // stops right after the access check: 400 delegation_required when admitted
		return serve(f.relay, r)
	}
	refused := func(w *httptest.ResponseRecorder) bool {
		return w.Code == 403 && strings.Contains(w.Body.String(), gate.ModelRelayNotAllowed)
	}
	// owner
	if w := root(f.owner, modelRoot); w.Code != 201 {
		t.Fatalf("owner root %d %s", w.Code, w.Body)
	}
	if w := relay(f.owner); refused(w) {
		t.Fatal("owner refused at the relay")
	}
	// not designated: refused at root and at relay
	for _, p := range []*person{f.user, f.other} {
		if w := root(p, modelRoot); !refused(w) {
			t.Fatalf("%s root %d %s", p.email, w.Code, w.Body)
		}
		if w := relay(p); !refused(w) {
			t.Fatalf("%s relay %d %s", p.email, w.Code, w.Body)
		}
	}
	// a wildcard model scope is the relayed model too; own models and model-free roots stay open
	if w := root(f.other, `{"title":"x","scope":["model:*"],"limits":{"model_tokens":1},"ttl_seconds":60}`); !refused(w) {
		t.Fatalf("wildcard %d", w.Code)
	}
	if w := root(f.other, `{"title":"x","scope":["model:my-own","newtype:run"],"limits":{"model_tokens":1},"ttl_seconds":60}`); w.Code != 201 {
		t.Fatalf("own model %d %s", w.Code, w.Body)
	}
	if w := root(f.other, `{"title":"x","scope":["newtype:run"],"limits":{},"ttl_seconds":60}`); w.Code != 201 {
		t.Fatalf("model-free root %d %s", w.Code, w.Body)
	}
	// management is the owner's only
	if w := f.allow(t, f.user, "allow", f.user.email); w.Code != 403 {
		t.Fatalf("non-owner allow %d", w.Code)
	}
	if w := serve(f.ops, f.user.req("GET", "/v1/operator/model-access", "", false)); w.Code != 403 {
		t.Fatalf("non-owner list %d", w.Code)
	}
	if w := serve(f.ops, f.owner.req("GET", "/v1/operator/model-access", "", true)); w.Code != 403 {
		t.Fatalf("session principal list %d", w.Code)
	}
	if w := f.allow(t, f.owner, "allow", "nobody@example.test"); w.Code != 404 || !strings.Contains(w.Body.String(), "account_not_found") {
		t.Fatalf("unknown account %d %s", w.Code, w.Body)
	}
	w := f.allow(t, f.owner, "allow", "User@Example.test")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "user@example.test") {
		t.Fatalf("allow %d %s", w.Code, w.Body)
	}
	if len(f.records) != 1 || f.records[0]["kind"] != "model_access.changed" || f.records[0]["action"] != "allow" || f.records[0]["by"] != "owner@example.test" {
		t.Fatalf("ledger records %v", f.records)
	}
	// designated: allowed at root and relay; the other is still refused
	if w := root(f.user, modelRoot); w.Code != 201 {
		t.Fatalf("designated root %d %s", w.Code, w.Body)
	}
	if w := relay(f.user); refused(w) {
		t.Fatal("designated user refused at the relay")
	}
	if w := root(f.other, modelRoot); !refused(w) {
		t.Fatal("other admitted")
	}
	// persisted (0600) and reloaded
	if st, err := os.Stat(f.path); err != nil || st.Mode().Perm() != 0o600 {
		t.Fatalf("file %v", err)
	}
	again, err := gate.OpenModelAccess(f.path)
	if err != nil || !again.Allowed(f.user.account) || again.Allowed(f.other.account) {
		t.Fatalf("reload %v", err)
	}
	// revoke
	if w := f.allow(t, f.owner, "revoke", "user@example.test"); w.Code != 200 {
		t.Fatalf("revoke %d", w.Code)
	}
	if w := relay(f.user); !refused(w) {
		t.Fatal("revoked user still admitted")
	}
	var view struct {
		Users []gate.ModelAccessEntry `json:"users"`
	}
	_ = json.Unmarshal(serve(f.ops, f.owner.req("GET", "/v1/operator/model-access", "", false)).Body.Bytes(), &view)
	if len(view.Users) != 0 || len(f.records) != 2 {
		t.Fatalf("after revoke %+v records %d", view.Users, len(f.records))
	}
}
