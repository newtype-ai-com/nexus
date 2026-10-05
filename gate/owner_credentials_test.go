package gate

import (
	"context"
	"errors"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

func TestOwnerCredentialsRestrictsExistingAccounts(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentials()
	restricted, err := NewOwnerCredentials(store, " Owner@Example.test ")
	if err != nil {
		t.Fatal(err)
	}
	account := ids.Account(ids.New(ids.KindAccount))
	now := time.Now()
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	tokens := map[string]string{}
	for _, email := range []string{"owner@example.test", "other@example.test"} {
		for _, kind := range []string{"licence", "login"} {
			token := strings.Repeat(kind+email, 3)
			tokens[kind+email] = token
			c := Credential{Verifier: Verifier(token), Kind: kind, Account: account, Email: email, Expires: now.Add(time.Hour)}
			if err := store.PutCredential(ctx, c); err != nil {
				t.Fatal(err)
			}
			_, err := restricted.LookupCredential(ctx, c.Verifier)
			if (err == nil) != (email == "owner@example.test") {
				t.Fatal("owner lookup restriction")
			}
			if email != "owner@example.test" && !errors.Is(restricted.PutCredential(ctx, c), ErrUnauthenticated) {
				t.Fatal("foreign provisioning")
			}
		}
	}
	auth := NexusAuth{Store: restricted, Service: svc}
	for _, email := range []string{"owner@example.test", "other@example.test"} {
		r := httptest.NewRequest("GET", "/v1/tasks", nil)
		r.Header.Set("Authorization", "Bearer "+tokens["licence"+email])
		r.Header.Set("X-Newtype-Login", tokens["login"+email])
		_, err := auth.Authenticate(r)
		if (err == nil) != (email == "owner@example.test") {
			t.Fatal("existing account bypassed owner restriction")
		}
	}
	token := tokens["loginowner@example.test"]
	c, _ := store.LookupCredential(ctx, Verifier(token))
	c.Revoked = true
	if err := store.PutCredential(ctx, c); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/v1/tasks", nil)
	r.Header.Set("Authorization", "Bearer "+tokens["licenceowner@example.test"])
	r.Header.Set("X-Newtype-Login", token)
	if _, err := auth.Authenticate(r); err == nil {
		t.Fatal("owner bypassed revocation")
	}
	agent := Credential{Verifier: Verifier("agent-fixture"), Kind: "agent", Account: account, Email: "owner@example.test", Session: ids.Session(ids.New(ids.KindSession)), Expires: now.Add(time.Hour)}
	if err := store.PutCredential(ctx, agent); err != nil {
		t.Fatal(err)
	}
	if _, err := restricted.LookupCredential(ctx, agent.Verifier); !errors.Is(err, ErrUnauthenticated) {
		t.Fatal("unverified agent admitted")
	}
	for _, email := range []string{"", "example.test", "*@example.test", "owner@example.test,other@example.test", "Owner <owner@example.test>"} {
		if _, err := NewOwnerCredentials(store, email); err == nil {
			t.Fatalf("invalid owner accepted: %s", email)
		}
	}
}
