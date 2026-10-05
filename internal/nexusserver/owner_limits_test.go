package nexusserver

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestOwnerModelLimitsConfiguration(t *testing.T) {
	base := map[string]string{"DATABASE_URL": "postgres://user:fixture@127.0.0.1/db?sslmode=disable", "NEXUS_DB_SCHEMA": "private_test", "NEXUS_ALLOW_LOCAL_DB": "1",
		"MODEL_UPSTREAM": "https://provider.test/v1/responses", "MODEL_API_KEY": "fixture", "MODEL_NAMES": "fixture", "MODEL_TOKEN_CEILING": "4096", "MODEL_MAX_OUTPUT": "256"}
	get := func(k string) string { return base[k] }
	c, err := ConfigFromEnv(get)
	if err != nil || c.ModelConfig.OwnerEmail != "" || c.ModelConfig.OwnerBudget != 0 {
		t.Fatal("owner limits without an owner", err)
	}
	base["MODEL_OWNER_TOKEN_CEILING"] = "500000"
	if _, err := ConfigFromEnv(get); err == nil {
		t.Fatal("owner limits accepted without NEXUS_OWNER_EMAIL")
	}
	delete(base, "MODEL_OWNER_TOKEN_CEILING")
	base["NEXUS_OWNER_EMAIL"] = "Owner@Example.test"
	c, err = ConfigFromEnv(get)
	// Unset: defaults (1,000,000 ceiling, no injected output cap) apply in the handler.
	if err != nil || c.ModelConfig.OwnerEmail != "owner@example.test" || c.ModelConfig.OwnerBudget != 0 || c.ModelConfig.OwnerMaxOutput != 0 || c.ModelConfig.Budget != 4096 || c.ModelConfig.MaxOutput != 256 {
		t.Fatal("owner defaults", err)
	}
	base["MODEL_OWNER_TOKEN_CEILING"], base["MODEL_OWNER_MAX_OUTPUT"] = "2000000", "32000"
	if c, err = ConfigFromEnv(get); err != nil || c.ModelConfig.OwnerBudget != 2000000 || c.ModelConfig.OwnerMaxOutput != 32000 {
		t.Fatal("owner values", err)
	}
	for _, bad := range [][2]string{{"0", "0"}, {"-1", "0"}, {"x", "0"}, {"1000", "-1"}, {"1000", "1001"}, {"", "1000001"}} {
		base["MODEL_OWNER_TOKEN_CEILING"], base["MODEL_OWNER_MAX_OUTPUT"] = bad[0], bad[1]
		if bad[0] == "" {
			delete(base, "MODEL_OWNER_TOKEN_CEILING")
		}
		if _, err := ConfigFromEnv(get); err == nil {
			t.Fatal("invalid owner limits accepted", bad)
		}
	}
}

// The server wiring: an owner-filtered store lets exactly the owner person
// ask POST /v1/requests for an unlimited root; without an owner nobody can.
func TestOwnerUnlimitedRootWiring(t *testing.T) {
	ctx := context.Background()
	account := ids.Account(ids.New(ids.KindAccount))
	creds := gate.NewMemoryCredentials()
	key, login := "ntl_"+strings.Repeat("a", 64), "ntg_"+strings.Repeat("b", 64)
	for token, kind := range map[string]string{key: "licence", login: "login"} {
		if err := creds.PutCredential(ctx, gate.Credential{Verifier: gate.Verifier(token), Kind: kind, Account: account, Email: "owner@example.test", Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	owned, err := gate.NewOwnerCredentials(creds, "owner@example.test")
	if err != nil {
		t.Fatal(err)
	}
	body := `{"title":"tui","scope":["model:fixture"],"rules":[{"action":"model:fixture","effect":"auto"}],"limits":{"model_tokens":-1},"ttl_seconds":60}`
	for _, tc := range []struct {
		store gate.CredentialStore
		want  int
	}{{owned, 201}, {creds, 403}} {
		h, err := NewHandler(nexus.NewService(nexus.NewMemStore(), nil), tc.store, func(context.Context) error { return nil })
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/v1/requests", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+key)
		r.Header.Set("X-Newtype-Login", login)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.want || (tc.want == 403 && !strings.Contains(w.Body.String(), "unlimited_owner_only")) {
			t.Fatal(w.Code, w.Body.String())
		}
	}
}
