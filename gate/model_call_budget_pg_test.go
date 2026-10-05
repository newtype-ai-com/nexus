//go:build darwin || linux

package gate

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
)

// Disposable PG only; synthetic transport never contacts a provider. A second
// DB pool and handler read the original ledger after one successful dispatch.
func TestModelCallBudgetPostgresReopen(t *testing.T) {
	creds, db, schema := enrolmentDB(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.Migrate(ctx); err != nil {
		t.Fatal("fixture migration")
	}
	now := time.Date(2026, 10, 2, 0, 0, 0, 0, time.UTC)
	clock := func() time.Time { return now }
	svc := nexus.NewService(db, clock)
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "fixture@example.test")
	root, err := svc.CreateRoot(ctx, user, nexus.RootRequest{Title: "ledger PG fixture", Runner: nexus.Local, Scope: []string{"model:example-model"}, Rules: []nexus.Rule{{Action: "model:example-model", Effect: "auto"}}, Limits: nexus.Limits{ModelTokens: 8192}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	key, login := "ntl_"+strings.Repeat("a", 64), "ntg_"+strings.Repeat("b", 64)
	for token, kind := range map[string]string{key: "licence", login: "login"} {
		if err := creds.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: user.AccountID, Email: user.Email, Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	path := budgetFixture(t, 1)
	calls := 0
	cfg := ModelConfig{Service: svc, Store: creds, Upstream: "https://fixture.invalid/responses", Key: "fixture", Models: []string{"example-model"}, Budget: 4096, MaxOutput: 256, CallBudgetFile: path, Transport: budgetTransport(func(*http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"status":"completed","usage":{"input_tokens":2,"output_tokens":1}}`))}, nil
	})}
	request := func(h *ModelHandler) int {
		r := httptest.NewRequest("POST", "/v1/model/responses", strings.NewReader(`{"input":[],"store":false}`)).WithContext(ctx)
		r.Header.Set("Authorization", "Bearer "+key)
		r.Header.Set("X-Newtype-Login", login)
		r.Header.Set("X-Newtype-Session", string(root.Session.ID))
		r.Header.Set("X-Newtype-Delegation", string(root.Delegation.ID))
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	h, err := NewModelHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := request(h); got != 200 {
		t.Fatal("initial request", got)
	}
	second, err := pgstore.Open(ctx, pgstore.Config{DSN: os.Getenv("NTS_NEXUS_TEST_DSN"), Schema: schema})
	if err != nil {
		t.Fatal("fixture reopen")
	}
	defer second.Close()
	reader := nexus.NewService(second, clock)
	cfg.Service, cfg.Store = reader, NewPostgresCredentials(second.Pool())
	h, err = NewModelHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got := request(h); got != 403 || calls != 1 {
		t.Fatal("reopen bypassed cap", got, calls)
	}
	status, err := InspectModelCallBudget(path)
	if err != nil || status.Used != 1 {
		t.Fatal(status, err)
	}
	var usage nexus.Usage
	if err := second.View(ctx, func(tx nexus.Tx) error { var e error; usage, e = tx.Usage(root.Delegation.ID); return e }); err != nil {
		t.Fatal(err)
	}
	quota, err := reader.AccountQuota(ctx, user)
	if err != nil || quota.Used != 3 || usage.Consumed.ModelTokens != 3 || usage.Reserved.ModelTokens != 0 {
		t.Fatal("cap denial changed persistent accounting", usage, quota, err)
	}
	events, _, err := reader.Events(ctx, user, root.Session.ID, 0, 100)
	if err != nil {
		t.Fatal(err)
	}
	settled := 0
	for _, event := range events {
		if event.Kind == "execution.settled" {
			settled++
		}
	}
	if settled != 2 {
		t.Fatal("success and pre-dispatch denial must both settle", settled)
	}
}
