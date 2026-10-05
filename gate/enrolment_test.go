package gate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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

type fixtureMailer struct {
	link  string
	fail  bool
	calls int
}

func (m *fixtureMailer) SendVerification(_ context.Context, _ string, link string) error {
	m.calls++
	m.link = link
	if m.fail {
		return errors.New("private provider failure")
	}
	return nil
}
func enrolmentDB(t *testing.T) (*PostgresCredentials, *pgstore.Store, string) {
	t.Helper()
	dsn := os.Getenv("NTS_NEXUS_TEST_DSN")
	if dsn == "" {
		t.Skip("requires disposable PostgreSQL")
	}
	ctx := context.Background()
	base, err := pgstore.Open(ctx, pgstore.Config{DSN: dsn})
	if err != nil {
		t.Fatal(err)
	}
	name := "enrol_test_" + strings.ToLower(ids.New(ids.KindEvent))
	if base.EnsureSchema(ctx, name) != nil {
		t.Fatal("schema create")
	}
	t.Cleanup(func() {
		defer base.Close()
		_, err := base.Pool().Exec(context.Background(), "DROP SCHEMA "+pgx.Identifier{name}.Sanitize()+" CASCADE")
		if err != nil {
			t.Error("schema cleanup")
		}
	})
	db, err := pgstore.Open(ctx, pgstore.Config{DSN: dsn, Schema: name})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	st := NewPostgresCredentials(db.Pool())
	if st.Migrate(ctx) != nil || st.MigrateEnrolments(ctx) != nil || st.MigrateEnrolments(ctx) != nil || st.CheckEnrolments(ctx) != nil {
		t.Fatal("migration")
	}
	return st, db, name
}
func TestEnrolmentPersistentOneShot(t *testing.T) {
	st, db, schema := enrolmentDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	mailer := &fixtureMailer{}
	cfg := EnrolmentConfig{Store: st, BaseURL: "https://gate.example.test", Allow: []string{"example.test"}, Mailer: mailer, AdminToken: strings.Repeat("a", 40), Clock: func() time.Time { return now }}
	h, err := NewEnrolmentHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	call := func(method, path, token, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s: status %d wanted %d", method, strings.Split(path, "?")[0], w.Code, want)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("cacheable response")
		}
		// no-referrer would make the browser's verify form POST carry "Origin: null".
		if w.Header().Get("Referrer-Policy") != "same-origin" {
			t.Fatal("referrer policy")
		}
		return w
	}
	call("POST", "/v1/enrol", "", `{"email":"denied@other.test"}`, 403)
	call("POST", "/v1/enrol", "", `{"email":"ok@example.test","email":"other@example.test"}`, 400)
	call("POST", "/v1/enrol", "", `{"email":"ok@example.test","account_id":"forged"}`, 400)
	if mailer.calls != 0 {
		t.Fatal("mail sent before validation")
	}
	start := call("POST", "/v1/enrol", "", `{"email":" User@Example.test "}`, 202)
	var issued struct {
		ID   string `json:"enrolment_id"`
		Poll string `json:"poll_token"`
	}
	if json.Unmarshal(start.Body.Bytes(), &issued) != nil || issued.ID == "" || issued.Poll == "" {
		t.Fatal("start response")
	}
	if strings.Contains(start.Body.String(), "vfy_") {
		t.Fatal("approval secret leaked")
	}
	link, err := url.Parse(mailer.link)
	if err != nil {
		t.Fatal(err)
	}
	verify := link.Query().Get("t")
	path := "/v1/enrol/" + issued.ID
	call("GET", path, "invalid-token-long-enough-for-check", "", 404)
	call("GET", path+"/key", issued.Poll, "", 404)
	call("GET", link.RequestURI(), "", "", 200)
	e, err := st.PollEnrolment(ctx, issued.ID, issued.Poll)
	if err != nil || e.Approved {
		t.Fatal("mail scanner GET approved")
	}
	// New handler AND pool mimic a restart before approval.
	second, err := pgstore.Open(ctx, pgstore.Config{DSN: os.Getenv("NTS_NEXUS_TEST_DSN"), Schema: schema})
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	cfg.Store = NewPostgresCredentials(second.Pool())
	h, err = NewEnrolmentHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	call("POST", link.RequestURI(), "", "", 200)
	call("POST", link.RequestURI(), "", "", 200)
	e, err = st.PollEnrolment(ctx, issued.ID, issued.Poll)
	if err != nil || !e.Approved || e.Account == "" {
		t.Fatal("approval not persistent")
	}
	call("HEAD", path+"/key", issued.Poll, "", 405)
	call("HEAD", path+"/session", issued.Poll, "", 405)
	var wg sync.WaitGroup
	var success, used atomic.Int32
	var token string
	var tokenMu sync.Mutex
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, secret, err := st.ClaimEnrolment(ctx, issued.ID, issued.Poll, "licence", now)
			if err == nil {
				success.Add(1)
				tokenMu.Lock()
				token = secret
				tokenMu.Unlock()
			} else if errors.Is(err, ErrAlreadyFetched) {
				used.Add(1)
			}
		}()
	}
	wg.Wait()
	if success.Load() != 1 || used.Load() != 19 {
		t.Fatalf("claim counts %d/%d", success.Load(), used.Load())
	}
	call("GET", path+"/key", issued.Poll, "", 410)
	loginResponse := call("GET", path+"/session", issued.Poll, "", 200)
	call("GET", path+"/session", issued.Poll, "", 410)
	var login struct {
		Token   string    `json:"session_token"`
		Expires time.Time `json:"expires_at"`
	}
	if json.Unmarshal(loginResponse.Body.Bytes(), &login) != nil || login.Token == "" || !login.Expires.Equal(now.Add(30*24*time.Hour)) {
		t.Fatal("login response")
	}
	auth := NexusAuth{Store: cfg.Store, Service: nexus.NewService(nexus.NewMemStore(), nil), Clock: cfg.Clock}
	r := httptest.NewRequest("GET", "/v1/sessions", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	r.Header.Set("X-Newtype-Login", login.Token)
	p, err := auth.Authenticate(r)
	if err != nil || p.AccountID != e.Account {
		t.Fatal("issued credentials not accepted")
	}
	for _, table := range []string{"gate_enrolments", "gate_credentials", "gate_accounts"} {
		rows, err := db.Pool().Query(ctx, "SELECT row_to_json(x)::text FROM "+table+" x")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var raw string
			_ = rows.Scan(&raw)
			for _, secret := range []string{token, login.Token, issued.Poll, verify} {
				if strings.Contains(raw, secret) {
					t.Fatal("plaintext secret stored")
				}
			}
		}
		rows.Close()
	}
	other, otherPoll, otherVerify, err := st.BeginEnrolment(ctx, "user@example.test", now)
	if err != nil {
		t.Fatal(err)
	}
	approved, err := cfg.Store.ApproveEnrolment(ctx, otherVerify, now)
	if err != nil || approved.Account != e.Account {
		t.Fatal("same email split accounts")
	}
	_, _, err = st.ClaimEnrolment(ctx, other.ID, otherPoll, "login", now.Add(31*time.Minute))
	if !errors.Is(err, nexus.ErrNotFound) {
		t.Fatal("expired enrolment claimed")
	}
	call("POST", "/v1/admin/revoke", "", `{"verifier":"`+Verifier(token)+`"}`, 403)
	call("POST", "/v1/admin/revoke", cfg.AdminToken, `{"verifier":"`+Verifier(token)+`"}`, 200)
	if _, err = auth.Authenticate(r); err == nil {
		t.Fatal("revoked credential accepted")
	}
	if err = st.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: "licence", Account: e.Account, Email: e.Email, Expires: now.Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	if _, err = auth.Authenticate(r); err == nil {
		t.Fatal("revocation undone")
	}
	if _, _, _, err = st.BeginEnrolment(ctx, "user@example.test", now); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err = st.BeginEnrolment(ctx, "user@example.test", now); !errors.Is(err, nexus.ErrLimit) {
		t.Fatal("rate limit missing")
	}
	mailer.fail = true
	call("POST", "/v1/enrol", "", `{"email":"failure@example.test"}`, 502)
	var count int
	if db.Pool().QueryRow(ctx, `SELECT count(*) FROM gate_enrolments WHERE email='failure@example.test'`).Scan(&count) != nil || count != 0 {
		t.Fatal("failed mail kept enrolment")
	}
}

func TestValidateLeaseAndMemoryRevocation(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentials()
	account := ids.Account(ids.New(ids.KindAccount))
	lic := strings.Repeat("l", 40)
	login := strings.Repeat("s", 40)
	c := Credential{Verifier: Verifier(lic), Kind: "licence", Account: account, Email: "user@example.test", Expires: time.Now().Add(time.Hour)}
	if store.PutCredential(ctx, c) != nil {
		t.Fatal("put")
	}
	l := c
	l.Kind = "login"
	l.Verifier = Verifier(login)
	l.Expires = time.Now().Add(10 * time.Second)
	_ = store.PutCredential(ctx, l)
	h := ValidateHandler(store)
	validate := func(want string) {
		t.Helper()
		r := httptest.NewRequest("POST", "/v1/validate", strings.NewReader("not JSON ignored"))
		r.Header.Set("Authorization", "Bearer "+lic)
		r.Header.Set("X-Newtype-Login", login)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		var out struct {
			Status string `json:"status"`
			Lease  int64  `json:"expires_in"`
		}
		if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Status != want {
			t.Fatal("validate status")
		}
		if out.Lease > 10 {
			t.Fatal("lease outlives login")
		}
	}
	validate("valid")
	c.Revoked = true
	_ = store.PutCredential(ctx, c)
	c.Revoked = false
	_ = store.PutCredential(ctx, c)
	validate("revoked")
	bad := c
	bad.Email = "other@example.test"
	if !errors.Is(store.PutCredential(ctx, bad), nexus.ErrConflict) {
		t.Fatal("identity changed")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }
func TestResendSafeFailure(t *testing.T) {
	m, err := NewResendMailer("fixture-mail-key", "Newtype <sender@example.test>")
	if err != nil {
		t.Fatal(err)
	}
	m.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		if r.URL.String() != "https://api.resend.com/emails" || r.Header.Get("Authorization") != "Bearer fixture-mail-key" {
			t.Fatal("mail destination")
		}
		return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{"https://other.test"}}, Body: io.NopCloser(strings.NewReader("private body")), Request: r}, nil
	})
	err = m.SendVerification(context.Background(), "user@example.test", "https://gate.example.test/private-link")
	if err == nil || strings.Contains(err.Error(), "private") {
		t.Fatal("mail error")
	}
}
