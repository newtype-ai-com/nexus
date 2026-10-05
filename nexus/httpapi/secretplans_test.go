package httpapi

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/seal"
)

func TestExecutorAudienceIsClosed(t *testing.T) {
	allowed := [][2]string{{"POST", "/v1/secret-plans"}, {"GET", "/v1/secret-plans"}, {"GET", "/v1/secret-plans/run_X"},
		{"POST", "/v1/secret-plans/run_X/release"}, {"POST", "/v1/secret-plans/run_X/finish"},
		{"POST", "/v1/custody/approvals"}, {"GET", "/v1/custody/approvals/apr_X"}}
	for _, c := range allowed {
		if !executorAudience(c[0], c[1]) {
			t.Errorf("%v refused", c)
		}
	}
	denied := [][2]string{{"POST", "/v1/custody/approvals/apr_X/decision"}, {"POST", "/v1/custody/approvals/apr_X/use"},
		{"GET", "/v1/custody/approvals"}, {"PUT", "/v1/secrets/X"}, {"GET", "/v1/secrets"}, {"POST", "/v1/requests"},
		{"DELETE", "/v1/secret-plans/run_X"}, {"POST", "/v1/secret-plans/run_X/other"}, {"GET", "/v1/sessions"},
		{"POST", "/v1/delegations/mnd_X/revoke"}, {"GET", "/v1/secret-plans/run_X/release"}}
	for _, c := range denied {
		if executorAudience(c[0], c[1]) {
			t.Errorf("%v allowed", c)
		}
	}
}

func TestSecretPlanHTTPAudienceEnforced(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	signer, _ := seal.NewEd25519Signer(ed25519.NewKeyFromSeed(seed), "fixture-v1")
	deriver, _ := seal.NewMasterDeriver(append(seed, seed...))
	svc, err := nexus.NewServiceWithSealing(nexus.NewMemStore(), nil, &seal.Sealer{Signer: signer, Deriver: deriver}, "https://gate.example.test")
	if err != nil {
		t.Fatal(err)
	}
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "user@example.test")
	root, err := svc.CreateRoot(context.Background(), user, nexus.RootRequest{Title: "executor", Runner: nexus.Local, Scope: []string{"newtype:run", "secrets:fd"},
		Rules: []nexus.Rule{{Action: "exec:secret-plan", Effect: "ask"}, {Action: "custody:bind-static-config", Effect: "ask"}}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := svc.IssueExecutorCredential(context.Background(), user, root.Session.ID, root.Delegation.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	api, err := New(Config{Service: svc, Run: func(context.Context, string, json.RawMessage) error { return nil },
		Authenticate: func(r *http.Request) (nexus.Principal, error) {
			if b := r.Header.Get("Authorization"); strings.HasPrefix(b, "Bearer nte_") {
				return svc.AuthenticateExecutor(r.Context(), strings.TrimPrefix(b, "Bearer "))
			}
			return user, nil
		}})
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string, want int) {
		t.Helper()
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		api.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s %s: %d %s", method, path, w.Code, w.Body.String())
		}
	}
	call("GET", "/v1/secrets", "", 401)
	call("GET", "/v1/custody/approvals?input_hash=sha256:"+strings.Repeat("a", 64), "", 401)
	call("POST", "/v1/requests", `{}`, 401)
	hash := "sha256:" + strings.Repeat("b", 64)
	// executors may request plan approvals only (not custody binding)
	call("POST", "/v1/custody/approvals", `{"delegation_id":"`+string(root.Delegation.ID)+`","action":"custody:bind-static-config","input_hash":"`+hash+`","ttl_seconds":60}`, 403)
	call("POST", "/v1/custody/approvals", `{"delegation_id":"`+string(root.Delegation.ID)+`","action":"exec:secret-plan","input_hash":"`+hash+`","ttl_seconds":60}`, 201)
	call("POST", "/v1/secret-plans", `{"plan":"{}","approval_id":"`+ids.New(ids.KindApproval)+`"}`, 400)
	call("POST", "/v1/secret-plans", `{"plan":"{}","plan":"{}","approval_id":"x"}`, 400)
	call("GET", "/v1/secret-plans?attempt=missing-attempt", "", 404)
}
