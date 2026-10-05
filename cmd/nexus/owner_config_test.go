package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/newtype-ai-com/nexus/gate"
	"github.com/newtype-ai-com/nexus/internal/nexusserver"
	"github.com/newtype-ai-com/nexus/nexus"
)

// Self-host (G2): owner routes follow NEXUS_OWNER_EMAIL, not a fixed address.
func TestRegistrationFollowsConfiguredOwner(t *testing.T) {
	for _, tc := range []struct {
		owner string
		want  int // POST /v1/users/requests without credentials
	}{
		{"boss@selfhost.test", http.StatusUnauthorized},
		{gate.UserAdministrator, http.StatusUnauthorized},
		{"", http.StatusNotFound},
	} {
		mail := &registrationFixtureMailer{}
		svc := nexus.NewService(nexus.NewMemStore(), nil)
		creds := gate.NewMemoryCredentials()
		allow := []string{"selfhost.test"}
		if tc.owner != "" {
			allow = []string{tc.owner}
		}
		ec := gate.EnrolmentConfig{Store: &gate.PostgresCredentials{}, BaseURL: "https://gate.example.test", Allow: allow, OwnerEmail: tc.owner, Mailer: mail}
		registration, err := registrationHandler(nexusserver.Config{OwnerEmail: tc.owner}, ec, svc, creds, mail)
		if err != nil {
			t.Fatal(tc.owner, err)
		}
		outer, err := nexusserver.NewHandlerWithEnrolment(svc, creds, func(context.Context) error { return nil }, registration)
		if err != nil {
			t.Fatal(err)
		}
		for _, path := range []string{"/v1/users/requests", "/v1/quota/requests"} {
			w := httptest.NewRecorder()
			outer.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, strings.NewReader(`{}`)))
			if w.Code != tc.want {
				t.Fatalf("owner=%q %s status=%d want=%d", tc.owner, path, w.Code, tc.want)
			}
		}
	}
}

func TestApprovalsConfigFollowsConfiguredOwner(t *testing.T) {
	env := func(owner string) func(string) string {
		m := map[string]string{"BASE_URL": "https://lic.example", "NEXUS_OWNER_EMAIL": owner, "RESEND_API_KEY": "synthetic", "MAIL_FROM": "sender@example.com", "ADMIN_TOKEN": strings.Repeat("A", 40), "APPROVALS_STORE": "/var/lib/x/changes.jsonl", "APPROVALS_PUBLIC_ADDR": "127.0.0.1:18082", "APPROVALS_ADMIN_ADDR": "127.0.0.1:18083", "APPROVALS_MAX_REQUESTS": "5"}
		return func(k string) string { return m[k] }
	}
	for _, ok := range []string{"boss@selfhost.test", gate.UserAdministrator, " Boss@SelfHost.test "} {
		if c, err := approvalsConfigFromEnv(env(ok)); err != nil || !gate.ValidOwnerEmail(c.owner) {
			t.Fatalf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "*", "selfhost.test", "a@x.test,b@x.test"} {
		if _, err := approvalsConfigFromEnv(env(bad)); err == nil {
			t.Fatalf("%q accepted", bad)
		}
	}
}
