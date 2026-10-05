package gate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
)

type admissionMailer struct {
	fixtureMailer
	to, target string
}

func (m *admissionMailer) SendUserAdmission(ctx context.Context, to, target, link string) error {
	m.to, m.target = to, target
	return m.SendVerification(ctx, to, link)
}

func TestUserAdmissionHTTPPostgres(t *testing.T) {
	st, db, schema := enrolmentDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	account := ids.Account(ids.New(ids.KindAccount))
	svc := nexus.NewService(nexus.NewMemStore(), func() time.Time { return now })
	person := nexus.UserPrincipal(account, UserAdministrator)
	root, err := svc.CreateRoot(ctx, person, nexus.RootRequest{Title: "admission", Runner: nexus.Local, Scope: []string{"newtype:run"}, TTL: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	licence, login := strings.Repeat("L", 40), strings.Repeat("G", 40)
	for kind, token := range map[string]string{"licence": licence, "login": login} {
		if st.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: account, Email: UserAdministrator, Expires: now.Add(time.Hour)}) != nil {
			t.Fatal("provision")
		}
	}
	restricted, _ := NewOwnerCredentials(st, UserAdministrator)
	auth := NexusAuth{Store: restricted, Service: svc, Clock: func() time.Time { return now }}
	mail := &admissionMailer{}
	cfg := EnrolmentConfig{Store: st, BaseURL: "https://gate.example.test", Allow: []string{UserAdministrator}, OwnerEmail: UserAdministrator, Mailer: mail, Clock: func() time.Time { return now }}
	h, err := NewUserAdmissionHandler(cfg, auth.Authenticate)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, body string, authenticated bool, origin string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+licence)
			r.Header.Set("X-Newtype-Login", login)
			r.Header.Set("X-Newtype-Session", string(root.Session.ID))
		}
		if strings.HasPrefix(body, "decision=") {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s status %d want %d", method, w.Code, want)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cache")
		}
		return w
	}
	body := `{"email":"Guest@Example.test","client_event_id":"one"}`
	call("POST", "/v1/users/requests", body, false, "", 401)
	call("POST", "/v1/users/requests", `{"email":"guest@example.test","client_event_id":"one","approved":true}`, true, "", 400)
	w := call("POST", "/v1/users/requests", body, true, "", 202)
	var admission UserAdmission
	if json.Unmarshal(w.Body.Bytes(), &admission) != nil || admission.Status != "pending" || strings.Contains(w.Body.String(), "uap_") {
		t.Fatal("request result")
	}
	if mail.calls != 1 || mail.to != UserAdministrator || mail.target != "guest@example.test" {
		t.Fatal("mail target")
	}
	link, _ := url.Parse(mail.link)
	token := link.Query().Get("t")
	call("POST", "/v1/users/requests", body, true, "", 202)
	if mail.calls != 1 {
		t.Fatal("idempotent request resent mail")
	}
	call("POST", "/v1/users/requests", `{"email":"other@example.test","client_event_id":"one"}`, true, "", 409)
	w = call("GET", link.RequestURI(), "", false, "", 200)
	if !strings.Contains(w.Body.String(), "guest@example.test") {
		t.Fatal("exact target absent")
	}
	enrol, err := NewEnrolmentHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if enrol.allowed(ctx, "guest@example.test") {
		t.Fatal("GET admitted user")
	}
	call("POST", link.RequestURI(), "decision=approve", false, "https://attacker.test", 403)
	call("POST", link.RequestURI(), "decision=approve&decision=deny", false, "", 400)
	// Restart store/handlers before the private email decision.
	second, err := pgstore.Open(ctx, pgstore.Config{DSN: os.Getenv("NTS_NEXUS_TEST_DSN"), Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	cfg.Store = NewPostgresCredentials(second.Pool())
	h, err = NewUserAdmissionHandler(cfg, auth.Authenticate)
	if err != nil {
		t.Fatal(err)
	}
	call("POST", link.RequestURI(), "decision=approve", false, cfg.BaseURL, 200)
	call("POST", link.RequestURI(), "decision=deny", false, cfg.BaseURL, 404)
	if ok, err := st.Admitted(ctx, UserAdministrator, "guest@example.test"); err != nil || !ok {
		t.Fatal("admission not persistent")
	}
	if !enrol.allowed(ctx, "guest@example.test") || enrol.allowed(ctx, "other@example.test") {
		t.Fatal("exact admission policy")
	}
	// Admission allows registration, not an automatic credential or admin role.
	var n int
	if db.Pool().QueryRow(ctx, `SELECT count(*) FROM gate_credentials WHERE email='guest@example.test'`).Scan(&n) != nil || n != 0 {
		t.Fatal("admission minted credentials")
	}
	guest := Credential{Verifier: Verifier(strings.Repeat("x", 40)), Kind: "licence", Account: ids.Account(ids.New(ids.KindAccount)), Email: "guest@example.test", Expires: now.Add(time.Hour)}
	if restricted.PutCredential(ctx, guest) != nil {
		t.Fatal("admitted user denied")
	}
	otherLogin := Credential{Verifier: Verifier(strings.Repeat("y", 40)), Kind: "login", Account: guest.Account, Email: guest.Email, Expires: now.Add(time.Hour)}
	if restricted.PutCredential(ctx, otherLogin) != nil {
		t.Fatal("guest login")
	}
	r := httptest.NewRequest("POST", "/v1/users/requests", strings.NewReader(`{"email":"third@example.test","client_event_id":"guest"}`))
	r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 40))
	r.Header.Set("X-Newtype-Login", strings.Repeat("y", 40))
	wr := httptest.NewRecorder()
	h.ServeHTTP(wr, r)
	if wr.Code != 403 {
		t.Fatal("guest gained administrator")
	}
	var stored string
	if db.Pool().QueryRow(ctx, `SELECT row_to_json(r)::text FROM gate_user_requests r WHERE id=$1`, admission.ID).Scan(&stored) != nil {
		t.Fatal("stored request")
	}
	if strings.Contains(stored, token) || strings.Contains(stored, licence) || strings.Contains(stored, login) {
		t.Fatal("plaintext secret persisted")
	}
}

func TestUserAdmissionConcurrencyDenialExpiryAndMailFailure(t *testing.T) {
	st, db, schema := enrolmentDB(t)
	ctx := context.Background()
	now := time.Now().UTC()
	account := ids.Account(ids.New(ids.KindAccount))
	second, err := pgstore.Open(ctx, pgstore.Config{DSN: os.Getenv("NTS_NEXUS_TEST_DSN"), Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	other := NewPostgresCredentials(second.Pool())
	var wg sync.WaitGroup
	var created atomic.Int32
	var token string
	var mu sync.Mutex
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := st
			if i%2 == 0 {
				s = other
			}
			_, v, e := s.BeginUserAdmission(ctx, account, UserAdministrator, "guest@example.test", "same", now)
			if e != nil {
				t.Error(e)
			}
			if v != "" {
				created.Add(1)
				mu.Lock()
				token = v
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if created.Load() != 1 {
		t.Fatal("duplicate mail capability")
	}
	var decisions atomic.Int32
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := st
			if i%2 == 0 {
				s = other
			}
			e := s.DecideUserAdmission(ctx, UserAdministrator, token, true, now)
			if e == nil {
				decisions.Add(1)
			} else if !errors.Is(e, nexus.ErrNotFound) {
				t.Error(e)
			}
		}(i)
	}
	wg.Wait()
	if decisions.Load() != 1 {
		t.Fatal("not one-shot")
	}
	for _, which := range []string{"denied", "expired", "failed"} {
		a, v, e := st.BeginUserAdmission(ctx, account, UserAdministrator, which+"@example.test", which, now)
		if e != nil {
			t.Fatal(e)
		}
		switch which {
		case "denied":
			if st.DecideUserAdmission(ctx, UserAdministrator, v, false, now) != nil {
				t.Fatal("deny")
			}
		case "expired":
			if !errors.Is(st.DecideUserAdmission(ctx, UserAdministrator, v, true, now.Add(30*time.Minute)), nexus.ErrNotFound) {
				t.Fatal("expired accepted")
			}
		case "failed":
			if st.FailUserAdmission(ctx, a.ID) != nil {
				t.Fatal("failed")
			}
		}
		if ok, e := st.Admitted(ctx, UserAdministrator, a.Email); e != nil || ok {
			t.Fatal("denied/expired/failed admitted")
		}
	}
	var count int
	if db.Pool().QueryRow(ctx, `SELECT count(*) FROM gate_admitted_users`).Scan(&count) != nil || count != 1 {
		t.Fatal("unexpected admissions")
	}
	// Existing approved login challenge must honor a tightened allow policy.
	key := strings.Repeat("k", 40)
	if st.PutCredential(ctx, Credential{Verifier: Verifier(key), Kind: "licence", Account: account, Email: "guest@example.test", Expires: now.Add(time.Hour)}) != nil {
		t.Fatal("fixture")
	}
	d, v, _, e := st.BeginDevice(ctx, key, now)
	if e != nil {
		t.Fatal(e)
	}
	if st.ConfirmDevice(ctx, v, false, now) != nil {
		t.Fatal("device approve")
	}
	if _, _, e = st.ClaimDeviceAllowed(ctx, d.Code, now, func(pgx.Tx, string) bool { return false }); !errors.Is(e, ErrDeviceDenied) {
		t.Fatal("device policy bypass")
	}
}
