package gate

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// ownerFixture: one account with the owner's person credentials and a
// guest's person credentials (same account, so the account quota is shared),
// plus a fake upstream that records each request body.
type ownerFixture struct {
	t                  *testing.T
	ctx                context.Context
	svc                *nexus.Service
	creds              *MemoryCredentials
	account            ids.Account
	ownerKey, ownerLog string
	guestKey, guestLog string
	usage              string
	mu                 sync.Mutex
	bodies             []map[string]any
	upstream           *httptest.Server
}

const ownerEmail = "owner@example.test"

func newOwnerFixture(t *testing.T) *ownerFixture {
	f := &ownerFixture{t: t, ctx: context.Background(), svc: nexus.NewService(nexus.NewMemStore(), nil), creds: NewMemoryCredentials(), account: ids.Account(ids.New(ids.KindAccount)), usage: `{"input_tokens":10,"output_tokens":5}`}
	f.ownerKey, f.ownerLog = "ntl_"+strings.Repeat("o", 64), "ntg_"+strings.Repeat("p", 64)
	f.guestKey, f.guestLog = "ntl_"+strings.Repeat("g", 64), "ntg_"+strings.Repeat("h", 64)
	for _, c := range []Credential{
		{Verifier: Verifier(f.ownerKey), Kind: "licence", Email: ownerEmail},
		{Verifier: Verifier(f.ownerLog), Kind: "login", Email: ownerEmail},
		{Verifier: Verifier(f.guestKey), Kind: "licence", Email: "guest@example.test"},
		{Verifier: Verifier(f.guestLog), Kind: "login", Email: "guest@example.test"},
	} {
		c.Account, c.Expires = f.account, time.Now().Add(time.Hour)
		if err := f.creds.PutCredential(f.ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	f.upstream = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b map[string]any
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.bodies = append(f.bodies, b)
		usage := f.usage
		f.mu.Unlock()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"type":"response.completed","response":{"usage":` + usage + `}}`))
	}))
	t.Cleanup(f.upstream.Close)
	return f
}

func (f *ownerFixture) handler(cfg ModelConfig) *ModelHandler {
	f.t.Helper()
	cfg.Service, cfg.Store, cfg.Key, cfg.Models, cfg.Transport = f.svc, f.creds, "fixture", []string{"fixture"}, f.upstream.Client().Transport
	cfg.Upstream = f.upstream.URL + "/v1/responses"
	if cfg.Budget == 0 {
		cfg.Budget, cfg.MaxOutput = 4096, 256
	}
	h, err := NewModelHandler(cfg)
	if err != nil {
		f.t.Fatal(err)
	}
	return h
}

func (f *ownerFixture) root(email string, tokens int64, unlimited bool) nexus.Issued {
	f.t.Helper()
	p := nexus.UserPrincipal(f.account, email)
	p.OwnBudgetAdmin = unlimited
	if unlimited {
		tokens = 0
	}
	root, err := f.svc.CreateRoot(f.ctx, p, nexus.RootRequest{Title: "owner limits", Runner: nexus.Local, Scope: []string{"model:fixture"}, Rules: []nexus.Rule{{Action: "model:fixture", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: tokens}, TTL: time.Hour, UnlimitedModelTokens: unlimited})
	if err != nil {
		f.t.Fatal(err)
	}
	return root
}

func (f *ownerFixture) call(h http.Handler, key, login string, root nexus.Issued, body string) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest("POST", "/v1/model/responses", strings.NewReader(body))
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("X-Newtype-Login", login)
	r.Header.Set("X-Newtype-Session", string(root.Session.ID))
	r.Header.Set("X-Newtype-Delegation", string(root.Delegation.ID))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func (f *ownerFixture) lastBody() map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.bodies[len(f.bodies)-1]
}

const smallTurn = `{"model":"fixture","input":"hi","store":false}`

func TestOwnerModelSkipsCallBudget(t *testing.T) {
	f := newOwnerFixture(t)
	path := budgetFixture(t, 1)
	h := f.handler(ModelConfig{OwnerEmail: ownerEmail, CallBudgetFile: path})
	owner, guest := f.root(ownerEmail, 0, true), f.root("guest@example.test", 100000, false)
	for i := 0; i < 3; i++ {
		if w := f.call(h, f.ownerKey, f.ownerLog, owner, smallTurn); w.Code != 200 {
			t.Fatal("owner refused by the call ledger", w.Code, w.Body.String())
		}
	}
	if st, err := InspectModelCallBudget(path); err != nil || st.Used != 0 {
		t.Fatal("owner consumed the call ledger", st, err)
	}
	if w := f.call(h, f.guestKey, f.guestLog, guest, smallTurn); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	if w := f.call(h, f.guestKey, f.guestLog, guest, smallTurn); w.Code != 403 || !strings.Contains(w.Body.String(), "model_call_budget_unavailable") {
		t.Fatal("non-owner not limited by the call ledger", w.Code, w.Body.String())
	}
	if w := f.call(h, f.ownerKey, f.ownerLog, owner, smallTurn); w.Code != 200 {
		t.Fatal("owner refused after the ledger was spent", w.Code)
	}
	// Without an owner configured, the same person is an ordinary caller.
	plain := f.handler(ModelConfig{CallBudgetFile: path})
	if w := f.call(plain, f.ownerKey, f.ownerLog, owner, smallTurn); w.Code != 403 {
		t.Fatal("owner limits applied without NEXUS_OWNER_EMAIL", w.Code)
	}
}

func TestOwnerModelSkipsMonthlyQuota(t *testing.T) {
	f := newOwnerFixture(t)
	h := f.handler(ModelConfig{OwnerEmail: ownerEmail})
	owner, guest := f.root(ownerEmail, 0, true), f.root("guest@example.test", 30_000_000, false)
	// The guest's reported usage spends the whole monthly account quota.
	f.usage = `{"input_tokens":10000000,"output_tokens":0}`
	if w := f.call(h, f.guestKey, f.guestLog, guest, smallTurn); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	q, err := f.svc.AccountQuota(f.ctx, nexus.UserPrincipal(f.account, ownerEmail))
	if err != nil || q.Remaining != 0 {
		t.Fatal(q, err)
	}
	f.usage = `{"input_tokens":10,"output_tokens":5}`
	if w := f.call(h, f.guestKey, f.guestLog, guest, smallTurn); w.Code != 403 || !strings.Contains(w.Body.String(), "limit_reached") {
		t.Fatal("non-owner not limited by the monthly quota", w.Code, w.Body.String())
	}
	f.usage = `{"input_tokens":2000000,"output_tokens":1000}`
	w := f.call(h, f.ownerKey, f.ownerLog, owner, smallTurn)
	if w.Code != 200 {
		t.Fatal("owner refused by the monthly quota", w.Code, w.Body.String())
	}
	after, err := f.svc.AccountQuota(f.ctx, nexus.UserPrincipal(f.account, ownerEmail))
	if err != nil || after.Used != q.Used {
		t.Fatal("owner charged to the account quota", after.Used, q.Used, err)
	}
	// Usage is still recorded on the owner's execution and root.
	state, err := f.svc.Execution(f.ctx, nexus.UserPrincipal(f.account, ownerEmail), ids.Invocation(w.Header().Get("X-Newtype-Invocation")))
	if err != nil || !state.Owner || state.Used != 2001000 || state.Status != "completed" || state.QuotaMonth != "" {
		t.Fatal(state, err)
	}
}

func TestOwnerModelCeilingAndOutputCap(t *testing.T) {
	f := newOwnerFixture(t)
	h := f.handler(ModelConfig{OwnerEmail: ownerEmail})
	owner, guest := f.root(ownerEmail, 0, true), f.root("guest@example.test", 1_000_000, false)
	big := `{"model":"fixture","input":"` + strings.Repeat("x", 8000) + `","store":false}`
	if w := f.call(h, f.guestKey, f.guestLog, guest, big); w.Code != 413 || !strings.Contains(w.Body.String(), "token_ceiling_exceeded") {
		t.Fatal("non-owner past MODEL_TOKEN_CEILING", w.Code)
	}
	if w := f.call(h, f.ownerKey, f.ownerLog, owner, big); w.Code != 200 {
		t.Fatal("owner held to MODEL_TOKEN_CEILING", w.Code, w.Body.String())
	}
	// Owner default output cap 0: nothing injected when the client sends none.
	if _, ok := f.lastBody()["max_output_tokens"]; ok {
		t.Fatal("owner got an injected output cap", f.lastBody())
	}
	// The client's own cap is passed through under the protocol's name.
	if w := f.call(h, f.ownerKey, f.ownerLog, owner, `{"model":"fixture","input":"hi","store":false,"max_tokens":5000,"max_output_tokens":7000}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if b := f.lastBody(); b["max_output_tokens"] != float64(5000) || b["max_tokens"] != nil {
		t.Fatal("client cap not passed through", b)
	}
	if w := f.call(h, f.ownerKey, f.ownerLog, owner, `{"model":"fixture","input":"hi","max_output_tokens":-1}`); w.Code != 400 {
		t.Fatal("invalid client cap accepted", w.Code)
	}
	// Input + client output cap still have to fit the owner ceiling.
	if w := f.call(h, f.ownerKey, f.ownerLog, owner, `{"model":"fixture","input":"hi","max_output_tokens":2000000}`); w.Code != 413 {
		t.Fatal("owner cap past MODEL_OWNER_TOKEN_CEILING", w.Code)
	}
	// Non-owner: the server cap replaces the client's, as before.
	if w := f.call(h, f.guestKey, f.guestLog, guest, `{"model":"fixture","input":"hi","max_tokens":5000}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if b := f.lastBody(); b["max_output_tokens"] != float64(256) || b["max_tokens"] != nil {
		t.Fatal("non-owner output cap", b)
	}
	// A configured owner cap is injected like the ordinary one.
	capped := f.handler(ModelConfig{OwnerEmail: ownerEmail, OwnerBudget: 20000, OwnerMaxOutput: 1234})
	if w := f.call(capped, f.ownerKey, f.ownerLog, owner, `{"model":"fixture","input":"hi","max_tokens":5000}`); w.Code != 200 {
		t.Fatal(w.Code)
	}
	if b := f.lastBody(); b["max_output_tokens"] != float64(1234) {
		t.Fatal("owner configured cap", b)
	}
	huge := `{"model":"fixture","input":"` + strings.Repeat("x", 30000) + `"}`
	if w := f.call(capped, f.ownerKey, f.ownerLog, owner, huge); w.Code != 413 {
		t.Fatal("MODEL_OWNER_TOKEN_CEILING not applied", w.Code)
	}
}

func TestOwnerModelRootBudgets(t *testing.T) {
	f := newOwnerFixture(t)
	h := f.handler(ModelConfig{OwnerEmail: ownerEmail})
	// An unlimited root is recorded as such and still records usage.
	owner := f.root(ownerEmail, 0, true)
	if w := f.call(h, f.ownerKey, f.ownerLog, owner, smallTurn); w.Code != 200 {
		t.Fatal(w.Code, w.Body.String())
	}
	left, err := f.svc.Left(f.ctx, nexus.UserPrincipal(f.account, ownerEmail), owner.Delegation.ID)
	if err != nil || left.ModelTokens != math.MaxInt64-15 {
		t.Fatal("unlimited root usage", left, err)
	}
	// A finite owner root (default 200000) is not refused by the owner's
	// 1,000,000 ceiling: the reservation shrinks to what is left.
	finite := f.root(ownerEmail, 200000, false)
	w := f.call(h, f.ownerKey, f.ownerLog, finite, smallTurn)
	if w.Code != 200 {
		t.Fatal("owner blocked by its finite root", w.Code, w.Body.String())
	}
	state, err := f.svc.Execution(f.ctx, nexus.UserPrincipal(f.account, ownerEmail), ids.Invocation(w.Header().Get("X-Newtype-Invocation")))
	if err != nil || state.Charged != 15 || state.Budget != 200000 {
		t.Fatal(state, err)
	}
	// The guest with a root smaller than the ordinary ceiling stays refused.
	guest := f.root("guest@example.test", 1000, false)
	if w := f.call(h, f.guestKey, f.guestLog, guest, smallTurn); w.Code != 403 {
		t.Fatal("non-owner root budget not enforced", w.Code)
	}
	// Only a person flagged by the Gate owner check may create an unlimited root.
	_, err = f.svc.CreateRoot(f.ctx, nexus.UserPrincipal(f.account, ownerEmail), nexus.RootRequest{Title: "x", Runner: nexus.Local, Scope: []string{"model:fixture"}, TTL: time.Hour, UnlimitedModelTokens: true})
	if !errors.Is(err, nexus.ErrForbidden) {
		t.Fatal("unlimited root without the owner flag", err)
	}
}

func TestOwnerPersonIdentity(t *testing.T) {
	f := newOwnerFixture(t)
	agent := "nta_" + strings.Repeat("a", 64)
	mixed := "ntg_" + strings.Repeat("m", 64)
	expired := "ntg_" + strings.Repeat("e", 64)
	for _, c := range []Credential{
		{Verifier: Verifier(mixed), Kind: "login", Email: "guest@example.test", Account: f.account, Expires: time.Now().Add(time.Hour)},
		{Verifier: Verifier(expired), Kind: "login", Email: ownerEmail, Account: f.account, Expires: time.Now().Add(-time.Minute)},
	} {
		if err := f.creds.PutCredential(f.ctx, c); err != nil {
			t.Fatal(err)
		}
	}
	check := func(key, login string, want bool) {
		t.Helper()
		r := httptest.NewRequest("POST", "/", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		if login != "" {
			r.Header.Set("X-Newtype-Login", login)
		}
		account, ok := OwnerPerson(r, f.creds, " Owner@Example.test ", time.Now())
		if ok != want || (ok && account != f.account) {
			t.Fatalf("owner person %v want %v", ok, want)
		}
	}
	check(f.ownerKey, f.ownerLog, true)
	check(f.ownerKey, "", false)         // licence alone
	check(f.ownerLog, f.ownerLog, false) // login as bearer
	check(f.ownerKey, mixed, false)      // another person's login
	check(f.guestKey, f.ownerLog, false) // another person's licence
	check(f.ownerKey, expired, false)    // expired login
	check(agent, f.ownerLog, false)      // agent credential
	check(nexus.ExecutorTokenPrefix+strings.Repeat("x", 40), f.ownerLog, false)
	r := httptest.NewRequest("POST", "/", nil)
	r.Header.Set("Authorization", "Bearer "+f.ownerKey)
	r.Header.Set("X-Newtype-Login", f.ownerLog)
	if _, ok := OwnerPerson(r, f.creds, "", time.Now()); ok {
		t.Fatal("owner without configuration")
	}
	fn := OwnerPersonFunc(f.creds, ownerEmail)
	if !fn(r, nexus.UserPrincipal(f.account, ownerEmail)) || fn(r, nexus.SessionPrincipal(f.account, ids.Session(ids.New(ids.KindSession)))) || fn(r, nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), ownerEmail)) {
		t.Fatal("owner hook principal checks")
	}
	if OwnerPersonFunc(f.creds, "") != nil {
		t.Fatal("hook without owner")
	}
	for _, cfg := range []ModelConfig{{OwnerEmail: "not-an-email"}, {OwnerEmail: ownerEmail, OwnerBudget: -1}, {OwnerEmail: ownerEmail, OwnerMaxOutput: -1}, {OwnerEmail: ownerEmail, OwnerBudget: 100, OwnerMaxOutput: 101}} {
		cfg.Service, cfg.Store, cfg.Key, cfg.Models, cfg.Upstream, cfg.Budget, cfg.MaxOutput = f.svc, f.creds, "k", []string{"fixture"}, "https://provider.test/v1/responses", 4096, 256
		if _, err := NewModelHandler(cfg); err == nil {
			t.Fatal("invalid owner limits accepted", cfg.OwnerEmail, cfg.OwnerBudget, cfg.OwnerMaxOutput)
		}
	}
}
