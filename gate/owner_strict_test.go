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

type strictAdmissionFixture struct {
	CredentialStore
	lookups int
}

func (s *strictAdmissionFixture) Admitted(context.Context, string, string) (bool, error) {
	s.lookups++
	return true, nil
}

// This is a synthetic branch test, NOT a PostgreSQL admission-row test.
func TestStrictOwnerIgnoresAdmissions(t *testing.T) {
	ctx := context.Background()
	s := &strictAdmissionFixture{CredentialStore: NewMemoryCredentials()}
	strict, err := NewOwnerCredentialsWithPolicy(s, "owner@example.test", true)
	if err != nil {
		t.Fatal(err)
	}
	compat, _ := NewOwnerCredentials(s, "owner@example.test")
	for _, email := range []string{"owner@example.test", "admitted@example.test"} {
		for _, kind := range []string{"licence", "login"} {
			c := Credential{Verifier: Verifier(kind + email), Kind: kind, Email: email, Account: ids.Account(ids.New(ids.KindAccount)), Expires: time.Now().Add(time.Hour)}
			if err := s.PutCredential(ctx, c); err != nil {
				t.Fatal(err)
			}
			_, err = strict.LookupCredential(ctx, c.Verifier)
			if (err == nil) != (email == "owner@example.test") {
				t.Fatal("strict lookup")
			}
			if (strict.PutCredential(ctx, c) == nil) != (email == "owner@example.test") {
				t.Fatal("strict provision")
			}
			if s.lookups != 0 {
				t.Fatal("strict queried admission source")
			}
		}
	}
	if _, err := compat.LookupCredential(ctx, Verifier("licenceadmitted@example.test")); err != nil || s.lookups != 1 {
		t.Fatal("legacy admission behavior changed")
	}
}

type strictMailFixture struct{ calls int }

func (m *strictMailFixture) SendVerification(context.Context, string, string) error {
	m.calls++
	return nil
}
func TestStrictEnrolBeforeStoreOrMail(t *testing.T) {
	mail := &strictMailFixture{}
	// A nil pool deliberately proves the non-owner branch cannot touch storage.
	cfg := EnrolmentConfig{Store: &PostgresCredentials{}, Mailer: mail, BaseURL: "https://gate.example.test", Allow: []string{"owner@example.test"}, OwnerEmail: "owner@example.test", OwnerOnly: true}
	h, err := NewEnrolmentHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/enrol", strings.NewReader(`{"email":"admitted@example.test"}`))
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 || mail.calls != 0 {
		t.Fatalf("code=%d mail=%d", w.Code, mail.calls)
	}
	if h.allowed(context.Background(), "admitted@example.test") || !h.allowed(context.Background(), cfg.OwnerEmail) {
		t.Fatal("strict allow policy")
	}
	cfg.OwnerEmail = ""
	if _, err := NewEnrolmentHandler(cfg); err == nil {
		t.Fatal("strict missing owner")
	}
}

func TestStrictQuotaCrossAccountDenied(t *testing.T) {
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	owner := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), UserAdministrator)
	h := &QuotaHandler{cfg: QuotaConfig{Service: svc, OwnerOnly: true}}
	r := httptest.NewRequest("GET", "/v1/quota", nil)
	w := httptest.NewRecorder()
	if _, ok := h.target(w, r, owner, ids.Account(ids.New(ids.KindAccount))); ok || w.Code != 403 {
		t.Fatal("cross-account quota permitted")
	}
	if _, ok := h.target(httptest.NewRecorder(), r, owner, owner.AccountID); !ok {
		t.Fatal("own account denied")
	}
}
