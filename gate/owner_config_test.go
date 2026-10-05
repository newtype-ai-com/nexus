package gate

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

// Self-host (G2): owner features follow the configured owner, the hosted
// owner constant has no power elsewhere, and an empty owner enables nothing.
const customOwner = "boss@selfhost.test"

func TestValidOwnerEmail(t *testing.T) {
	for _, ok := range []string{customOwner, UserAdministrator} {
		if !ValidOwnerEmail(ok) {
			t.Fatal(ok)
		}
	}
	for _, bad := range []string{"", " ", "*", "*@x.test", "Boss@selfhost.test", " boss@selfhost.test", "selfhost.test", "a@x.test,b@x.test", "Boss <boss@selfhost.test>"} {
		if ValidOwnerEmail(bad) {
			t.Fatalf("%q accepted", bad)
		}
	}
}

func TestOwnerConfigConstructors(t *testing.T) {
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	creds := NewMemoryCredentials()
	a := NexusAuth{Store: creds, Service: svc}.Authenticate
	mail := &admissionMailer{}
	enrol := func(owner string) EnrolmentConfig {
		allow := []string{"example.test"}
		if owner != "" {
			allow = []string{owner}
		}
		return EnrolmentConfig{Store: &PostgresCredentials{}, BaseURL: "https://gate.example.test", Allow: allow, OwnerEmail: owner, Mailer: mail}
	}
	if _, err := NewUserAdmissionHandler(enrol(customOwner), a); err != nil {
		t.Fatal("custom owner admission", err)
	}
	if _, err := NewUserAdmissionHandler(enrol(""), a); err == nil {
		t.Fatal("empty owner admission enabled")
	}
	quota := func(owner string) error {
		_, err := NewQuotaHandler(QuotaConfig{Service: svc, Store: creds, Authenticate: a, Mailer: &quotaTestMailer{}, BaseURL: "https://gate.example.test", OwnerEmail: owner})
		return err
	}
	if quota(customOwner) != nil || quota("") == nil || quota("*") == nil {
		t.Fatal("quota owner policy")
	}
	change := func(owner string) error {
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil || os.Chmod(dir, 0700) != nil {
			t.Fatal("temp dir")
		}
		store, err := OpenFileChangeStore(filepath.Join(dir, "changes.jsonl"), 5)
		if err != nil {
			t.Fatal(err)
		}
		defer store.Close()
		_, err = NewChangeHandler(ChangeConfig{Store: store, Mailer: &changeFakeMail{}, BaseURL: "https://lic.example", OwnerEmail: owner, AdminToken: strings.Repeat("A", 40)})
		return err
	}
	if change(customOwner) != nil || change("") == nil || change("not-an-address") == nil {
		t.Fatal("change approvals owner policy")
	}
}

func TestUserAdmissionStoreRefusesEmptyOwner(t *testing.T) {
	// A nil pool proves the owner check runs before any database access.
	st := &PostgresCredentials{}
	ctx := context.Background()
	account := ids.Account(ids.New(ids.KindAccount))
	if _, _, err := st.BeginUserAdmission(ctx, account, "", "guest@example.test", "c", time.Now()); !errors.Is(err, nexus.ErrInvalid) {
		t.Fatal("empty owner began admission", err)
	}
	if err := st.DecideUserAdmission(ctx, "", "uap_x", true, time.Now()); !errors.Is(err, nexus.ErrForbidden) {
		t.Fatal("empty owner decided admission", err)
	}
}

func TestQuotaCustomOwnerTargetsAndOldConstantDoesNot(t *testing.T) {
	ctx := context.Background()
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	creds := NewMemoryCredentials()
	mail := &quotaTestMailer{}
	h, err := NewQuotaHandler(QuotaConfig{Service: svc, Store: creds, Authenticate: NexusAuth{Store: creds, Service: svc}.Authenticate, Mailer: mail, BaseURL: "https://gate.example.test", OwnerEmail: customOwner})
	if err != nil {
		t.Fatal(err)
	}
	user := ids.Account(ids.New(ids.KindAccount))
	person := func(email, c string) (string, string) {
		account := ids.Account(ids.New(ids.KindAccount))
		key, login := "ntl_"+strings.Repeat(c, 64), "ntg_"+strings.Repeat(c, 64)
		for token, kind := range map[string]string{key: "licence", login: "login"} {
			if err := creds.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: account, Email: email, Expires: time.Now().Add(time.Hour)}); err != nil {
				t.Fatal(err)
			}
		}
		return key, login
	}
	call := func(key, login, client string) int {
		r := httptest.NewRequest("POST", "/v1/quota/requests", strings.NewReader(`{"amount":5,"client_event_id":"`+client+`","account_id":"`+string(user)+`"}`))
		r.Header.Set("Authorization", "Bearer "+key)
		r.Header.Set("X-Newtype-Login", login)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	oldKey, oldLogin := person(UserAdministrator, "e")
	if got := call(oldKey, oldLogin, "old"); got != 403 || mail.calls != 0 {
		t.Fatalf("hosted owner constant acted on another account: %d", got)
	}
	ownerKey, ownerLogin := person(customOwner, "f")
	if got := call(ownerKey, ownerLogin, "owner"); got != 202 || mail.calls != 1 || mail.recipient != customOwner {
		t.Fatalf("custom owner: %d calls=%d to=%s", got, mail.calls, mail.recipient)
	}
}

func TestUserAdmissionCustomOwnerPostgres(t *testing.T) {
	st, _, _ := enrolmentDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	svc := nexus.NewService(nexus.NewMemStore(), func() time.Time { return now })
	type seat struct{ licence, login, session string }
	enrolPerson := func(email, c string) seat {
		account := ids.Account(ids.New(ids.KindAccount))
		root, err := svc.CreateRoot(ctx, nexus.UserPrincipal(account, email), nexus.RootRequest{Title: "admission", Runner: nexus.Local, Scope: []string{"newtype:run"}, TTL: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		s := seat{strings.Repeat(c, 40), strings.Repeat(strings.ToLower(c), 40), string(root.Session.ID)}
		for kind, token := range map[string]string{"licence": s.licence, "login": s.login} {
			if st.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: account, Email: email, Expires: now.Add(time.Hour)}) != nil {
				t.Fatal("provision")
			}
		}
		return s
	}
	owner, old := enrolPerson(customOwner, "Q"), enrolPerson(UserAdministrator, "W")
	auth := NexusAuth{Store: st, Service: svc, Clock: func() time.Time { return now }}
	mail := &admissionMailer{}
	cfg := EnrolmentConfig{Store: st, BaseURL: "https://gate.example.test", Allow: []string{customOwner}, OwnerEmail: customOwner, Mailer: mail, Clock: func() time.Time { return now }}
	h, err := NewUserAdmissionHandler(cfg, auth.Authenticate)
	if err != nil {
		t.Fatal(err)
	}
	call := func(s *seat, method, path, body string) int {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if s != nil {
			r.Header.Set("Authorization", "Bearer "+s.licence)
			r.Header.Set("X-Newtype-Login", s.login)
			r.Header.Set("X-Newtype-Session", s.session)
		} else {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.Header.Set("Origin", cfg.BaseURL)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	if got := call(&old, "POST", "/v1/users/requests", `{"email":"guest@example.test","client_event_id":"old"}`); got != 403 || mail.calls != 0 {
		t.Fatalf("hosted owner constant began admission: %d", got)
	}
	if got := call(&owner, "POST", "/v1/users/requests", `{"email":"guest@example.test","client_event_id":"one"}`); got != 202 || mail.to != customOwner {
		t.Fatalf("custom owner request: %d to=%s", got, mail.to)
	}
	link, _ := url.Parse(mail.link)
	if got := call(nil, "POST", link.RequestURI(), "decision=approve"); got != 200 {
		t.Fatalf("approve: %d", got)
	}
	enrol, err := NewEnrolmentHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !enrol.allowed(ctx, "guest@example.test") || enrol.allowed(ctx, "other@example.test") {
		t.Fatal("custom owner admission policy")
	}
	if ok, _ := st.Admitted(ctx, UserAdministrator, "guest@example.test"); ok {
		t.Fatal("admission recorded under the hosted owner")
	}
}
