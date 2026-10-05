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

type registrationFixtureMailer struct{ calls int }

func (m *registrationFixtureMailer) SendVerification(context.Context, string, string) error {
	m.calls++
	return nil
}
func (m *registrationFixtureMailer) SendUserAdmission(context.Context, string, string, string) error {
	m.calls++
	return nil
}
func (m *registrationFixtureMailer) SendQuotaApproval(context.Context, string, string, string) error {
	m.calls++
	return nil
}

func TestRegistrationStrictAdmissionRoutesAbsent(t *testing.T) {
	for _, strict := range []bool{true, false} {
		name := "compat"
		if strict {
			name = "strict"
		}
		t.Run(name, func(t *testing.T) {
			mail := &registrationFixtureMailer{}
			svc := nexus.NewService(nexus.NewMemStore(), nil)
			creds := gate.NewMemoryCredentials()
			cfg := nexusserver.Config{OwnerEmail: gate.UserAdministrator, OwnerOnly: strict}
			// A nil PG pool intentionally proves these requests never touch PG.
			ec := gate.EnrolmentConfig{Store: &gate.PostgresCredentials{}, BaseURL: "https://gate.example.test", Allow: []string{gate.UserAdministrator}, OwnerEmail: gate.UserAdministrator, OwnerOnly: strict, Mailer: mail}
			registration, err := registrationHandler(cfg, ec, svc, creds, mail)
			if err != nil {
				t.Fatal(err)
			}
			outer, err := nexusserver.NewHandlerWithEnrolment(svc, creds, func(context.Context) error { return nil }, registration)
			if err != nil {
				t.Fatal(err)
			}
			for _, path := range []string{"/v1/users/requests", "/users/approve"} {
				// Method mismatch distinguishes an actually registered approval route from
				// an unregistered route, without needing an approval token or querying PG.
				method := http.MethodPost
				want := http.StatusUnauthorized
				if path == "/users/approve" {
					method = http.MethodPut
					want = http.StatusMethodNotAllowed
				}
				if strict {
					want = http.StatusNotFound
				}
				w := httptest.NewRecorder()
				outer.ServeHTTP(w, httptest.NewRequest(method, path, strings.NewReader(`{}`)))
				if w.Code != want {
					t.Fatalf("%s status=%d want=%d", path, w.Code, want)
				}
			}
			for _, tc := range []struct {
				method, path string
				want         int
			}{
				{http.MethodGet, "/v1/enrol/policy", 200},
				{http.MethodPost, "/v1/device", 401},
				{http.MethodGet, "/v1/quota", 401},
			} {
				w := httptest.NewRecorder()
				outer.ServeHTTP(w, httptest.NewRequest(tc.method, tc.path, strings.NewReader(`{}`)))
				if w.Code != tc.want {
					t.Fatalf("preserved route %s status=%d", tc.path, w.Code)
				}
			}
			if strict {
				w := httptest.NewRecorder()
				outer.ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/v1/enrol", strings.NewReader(`{"email":"admitted@example.test"}`)))
				if w.Code != 403 {
					t.Fatal("non-owner enrolment not denied before DB")
				}
			}
			if mail.calls != 0 {
				t.Fatal("route test sent mail")
			}
		})
	}
}
