package gate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus/pgstore"
)

// This test requires explicitly authorized disposable PostgreSQL. The existing
// fixture creates/drops only its unique schema; mail remains an in-memory fake.
func TestStrictOwnerPostgresAdmissionsAndDevice(t *testing.T) {
	st, db, schema := enrolmentDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	owner, guest := UserAdministrator, "admitted@example.test"
	account := ids.Account(ids.New(ids.KindAccount))
	// Use the actual admission transition, not a synthetic Admitted() return value.
	_, link, err := st.BeginUserAdmission(ctx, account, owner, guest, "fixture-admission", now)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.DecideUserAdmission(ctx, owner, link, true, now); err != nil {
		t.Fatal(err)
	}
	second, err := pgstore.Open(ctx, pgstore.Config{DSN: os.Getenv("NTS_NEXUS_TEST_DSN"), Schema: schema})
	if err != nil {
		t.Fatal("reopen fixture pool")
	}
	t.Cleanup(second.Close)
	st = NewPostgresCredentials(second.Pool())
	if ok, err := st.Admitted(ctx, owner, guest); err != nil || !ok {
		t.Fatal("real admitted row missing after reopen")
	}
	strict, err := NewOwnerCredentialsWithPolicy(st, owner, true)
	if err != nil {
		t.Fatal(err)
	}
	compat, err := NewOwnerCredentials(st, owner)
	if err != nil {
		t.Fatal(err)
	}
	count := func(table string) int {
		t.Helper()
		var n int
		if err := db.Pool().QueryRow(ctx, "SELECT count(*) FROM "+pgx.Identifier{table}.Sanitize()).Scan(&n); err != nil {
			t.Fatal("fixture row count failed")
		}
		return n
	}
	keys := map[string]string{owner: strings.Repeat("o", 40), guest: strings.Repeat("g", 40)}
	for _, email := range []string{owner, guest} {
		accountID := ids.Account(ids.New(ids.KindAccount))
		for _, kind := range []string{"licence", "login"} {
			token := keys[email]
			if kind == "login" {
				token += "login"
			}
			c := Credential{Verifier: Verifier(token), Kind: kind, Account: accountID, Email: email, Expires: now.Add(time.Hour)}
			// Preexisting admitted credentials must remain denied after strict restart.
			if err := compat.PutCredential(ctx, c); err != nil {
				t.Fatal("compat positive control provisioning failed")
			}
			if _, err := compat.LookupCredential(ctx, c.Verifier); err != nil {
				t.Fatal("compat lookup failed")
			}
			_, err := strict.LookupCredential(ctx, c.Verifier)
			if email == owner && err != nil {
				t.Fatal("owner lookup blocked")
			}
			if email == guest && !errors.Is(err, ErrUnauthenticated) {
				t.Fatal("strict admitted lookup allowed")
			}
			before := count("gate_credentials")
			c.Verifier = Verifier(token + "fresh")
			err = strict.PutCredential(ctx, c)
			if email == owner {
				if err != nil || count("gate_credentials") != before+1 {
					t.Fatal("owner provision blocked")
				}
			} else if !errors.Is(err, ErrUnauthenticated) || count("gate_credentials") != before {
				t.Fatal("strict provision wrote guest credential")
			}
		}
	}
	mail := &fixtureMailer{}
	cfg := EnrolmentConfig{Store: st, BaseURL: "https://gate.example.test", Allow: []string{owner}, OwnerEmail: owner, OwnerOnly: true, Mailer: mail, Clock: func() time.Time { return now }}
	enrol, err := NewEnrolmentHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	device, err := NewDeviceHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	call := func(h http.Handler, path, token, body string, want int) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if token != "" {
			req.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, req)
		if w.Code != want {
			t.Fatalf("%s status=%d want=%d", path, w.Code, want)
		}
		return w
	}
	t.Run("strict_enrolment_no_mail_or_row", func(t *testing.T) {
		before := count("gate_enrolments")
		sent := mail.calls
		call(enrol, "/v1/enrol", "", `{"email":"admitted@example.test"}`, 403)
		if count("gate_enrolments") != before || mail.calls != sent {
			t.Fatal("denied enrolment side effect")
		}
		call(enrol, "/v1/enrol", "", `{"email":"`+owner+`"}`, 202)
		if count("gate_enrolments") != before+1 || mail.calls != sent+1 {
			t.Fatal("owner enrolment positive control")
		}
	})
	t.Run("previously_approved_enrolment_rechecked_at_claim", func(t *testing.T) {
		e, poll, verification, err := st.BeginEnrolment(ctx, guest, now)
		if err != nil {
			t.Fatal(err)
		}
		before := count("gate_credentials")
		call(enrol, "/enrol/verify?t="+verification, "", "", 404)
		pending, err := st.PollEnrolment(ctx, e.ID, poll)
		if err != nil || pending.Approved || count("gate_credentials") != before {
			t.Fatal("strict verification approved guest")
		}
		// Model a challenge already approved under the old compatibility policy.
		if _, err := st.ApproveEnrolment(ctx, verification, now); err != nil {
			t.Fatal(err)
		}
		before = count("gate_credentials")
		for _, suffix := range []string{"/key", "/session"} {
			r := httptest.NewRequest(http.MethodGet, "/v1/enrol/"+e.ID+suffix, nil)
			r.Header.Set("Authorization", "Bearer "+poll)
			w := httptest.NewRecorder()
			enrol.ServeHTTP(w, r)
			if w.Code != 404 || strings.Contains(w.Body.String(), "session_token") {
				t.Fatal("strict old enrolment claim escaped")
			}
		}
		after, err := st.PollEnrolment(ctx, e.ID, poll)
		if err != nil || after.KeyTaken || after.LoginTaken || count("gate_credentials") != before {
			t.Fatal("denied claims consumed or minted credential")
		}
	})
	t.Run("strict_device_start_no_mail_or_row", func(t *testing.T) {
		before := count("gate_devices")
		sent := mail.calls
		call(device, "/v1/device", keys[guest], `{}`, 403)
		if count("gate_devices") != before || mail.calls != sent {
			t.Fatal("denied device start side effect")
		}
		call(device, "/v1/device", keys[owner], `{}`, 200)
		if count("gate_devices") != before+1 || mail.calls != sent+1 {
			t.Fatal("owner device positive control")
		}
	})
	t.Run("previously_approved_device_rechecked_at_claim", func(t *testing.T) {
		d, approval, _, err := st.BeginDevice(ctx, keys[guest], now)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.ConfirmDevice(ctx, approval, false, now); err != nil {
			t.Fatal(err)
		}
		before := count("gate_credentials")
		sent := mail.calls
		raw, _ := json.Marshal(map[string]string{"device_code": d.Code})
		w := call(device, "/v1/device/token", "", string(raw), 400)
		if !strings.Contains(w.Body.String(), "access_denied") || strings.Contains(w.Body.String(), "session_token") || count("gate_credentials") != before || mail.calls != sent {
			t.Fatal("strict claim issued login or mail")
		}
		var consumed bool
		if err := db.Pool().QueryRow(ctx, `SELECT consumed FROM gate_devices WHERE device_hash=$1`, Verifier(d.Code)).Scan(&consumed); err != nil || consumed {
			t.Fatal("denial consumed challenge")
		}
		// Positive control on the exact same stored challenge proves denial was policy,
		// not an expired token, broken DB, or unusable fixture licence.
		cfg.OwnerOnly = false
		legacy, err := NewDeviceHandler(cfg)
		if err != nil {
			t.Fatal(err)
		}
		w = call(legacy, "/v1/device/token", "", string(raw), 200)
		var out struct {
			Token string `json:"session_token"`
		}
		if json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Token == "" || count("gate_credentials") != before+1 {
			t.Fatal("compat claim positive control")
		}
		if _, err := strict.LookupCredential(ctx, Verifier(out.Token)); !errors.Is(err, ErrUnauthenticated) {
			t.Fatal("compat minted guest login bypasses strict lookup")
		}
	})
}
