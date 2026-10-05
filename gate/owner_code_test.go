package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/nexus"
)

// Self-host G4: mail-free owner bootstrap via a one-time operator code.
func TestOwnerCodeRefusedWithoutOwner(t *testing.T) {
	st := &PostgresCredentials{} // nil pool: refusals happen before any DB use
	if _, _, err := st.BeginOwnerCode(context.Background(), "", time.Now()); !errors.Is(err, nexus.ErrInvalid) {
		t.Fatal("empty owner issued a code")
	}
	if _, _, err := st.RedeemOwnerCode(context.Background(), "", "eoc_"+strings.Repeat("a", 64), time.Now()); !errors.Is(err, nexus.ErrNotFound) {
		t.Fatal("empty owner redeemed")
	}
	h, err := NewEnrolmentHandler(EnrolmentConfig{Store: st, BaseURL: "https://gate.example.test", Allow: []string{"example.test"}, OwnerCode: true, Mailer: &fixtureMailer{}})
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("POST", "/v1/enrol/code", strings.NewReader(`{"code":"eoc_`+strings.Repeat("a", 64)+`"}`)))
	if w.Code != 404 {
		t.Fatalf("no-owner server redeemed: %d", w.Code)
	}
}

func TestOwnerCodePostgres(t *testing.T) {
	st, db, _ := enrolmentDB(t)
	ctx := context.Background()
	now := time.Now().UTC().Truncate(time.Microsecond)
	clock := now
	mail := &noticeMailer{}
	var auditOut bytes.Buffer
	audit, err := NewAudit(&auditOut)
	if err != nil {
		t.Fatal(err)
	}
	cfg := EnrolmentConfig{Store: st, BaseURL: "https://gate.example.test", Allow: []string{customOwner}, OwnerEmail: customOwner, OwnerCode: true, Audit: audit, Mailer: mail, Clock: func() time.Time { return clock }}
	h, err := NewEnrolmentHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	limited := st.LimitPublicAPI(h)
	call := func(method, path, token, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		limited.ServeHTTP(w, r)
		return w
	}
	redeem := func(code string) *httptest.ResponseRecorder {
		return call("POST", "/v1/enrol/code", "", `{"code":"`+code+`"}`)
	}
	e, code, err := st.BeginOwnerCode(ctx, customOwner, now)
	if err != nil || !strings.HasPrefix(code, "eoc_") || !strings.HasPrefix(e.ID, "eno_") || len(code) != 68 || e.Expires.Sub(now) != OwnerCodeTTL || OwnerCodeTTL > 15*time.Minute {
		t.Fatal("issue", err)
	}
	var stored int
	if db.Pool().QueryRow(ctx, `SELECT count(*) FROM gate_enrolments WHERE verify_hash=$1 OR poll_hash=$1 OR id=$2`, code, code).Scan(&stored) != nil || stored != 0 {
		t.Fatal("plaintext code stored")
	}
	// A code is not a mail verify token, and a wrong code redeems nothing.
	if w := call("POST", "/enrol/verify?t="+code, "", ""); w.Code != 404 {
		t.Fatalf("code accepted as mail link: %d", w.Code)
	}
	if w := redeem("eoc_" + strings.Repeat("0", 64)); w.Code != 404 {
		t.Fatalf("wrong code: %d", w.Code)
	}
	w := redeem(code)
	var out struct {
		ID     string `json:"enrolment_id"`
		Poll   string `json:"poll_token"`
		Status string `json:"status"`
	}
	if w.Code != 200 || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.ID != e.ID || !strings.HasPrefix(out.Poll, "enp_") || out.Status != "verified" {
		t.Fatalf("redeem: %d %s", w.Code, w.Body.String())
	}
	if w := redeem(code); w.Code != 404 {
		t.Fatalf("code reused: %d", w.Code)
	}
	if w := call("GET", "/v1/enrol/"+out.ID+"/key", out.Poll, ""); w.Code != 200 || !strings.HasPrefix(w.Body.String(), "ntl_") {
		t.Fatalf("licence claim: %d", w.Code)
	}
	if w := call("GET", "/v1/enrol/"+out.ID+"/key", out.Poll, ""); w.Code != http.StatusGone {
		t.Fatalf("licence claimed twice: %d", w.Code)
	}
	if w := call("GET", "/v1/enrol/"+out.ID+"/session", out.Poll, ""); w.Code != 200 || !strings.Contains(w.Body.String(), `"email":"`+customOwner+`"`) {
		t.Fatalf("login claim: %d", w.Code)
	}
	if mail.calls != 0 || mail.notices != 1 || mail.noticeTo != customOwner {
		t.Fatalf("notice mail: verify=%d notices=%d", mail.calls, mail.notices)
	}
	if audit.Close() != nil || !strings.Contains(auditOut.String(), `"type":"owner_code_redeemed"`) || !strings.Contains(auditOut.String(), e.ID) || strings.Contains(auditOut.String(), code) || strings.Contains(auditOut.String(), out.Poll) || strings.Contains(auditOut.String(), customOwner) {
		t.Fatalf("audit line: %s", auditOut.String())
	}
	// Public mail enrolments cannot block the operator code (L3), and owner
	// codes do not use up the mail limit.
	for i := 0; i < 3; i++ {
		if _, _, _, err := st.BeginEnrolment(ctx, customOwner, now); err != nil {
			t.Fatal("mail enrolment", i, err)
		}
	}
	if _, _, _, err := st.BeginEnrolment(ctx, customOwner, now); !errors.Is(err, nexus.ErrLimit) {
		t.Fatal("mail limit", err)
	}
	_, replaced, err := st.BeginOwnerCode(ctx, customOwner, now)
	if err != nil {
		t.Fatal("owner code blocked by mail enrolments", err)
	}
	// Issuing again replaces the unredeemed code: at most one is active.
	_, late, err := st.BeginOwnerCode(ctx, customOwner, now)
	if err != nil {
		t.Fatal(err)
	}
	if w := redeem(replaced); w.Code != 404 {
		t.Fatalf("replaced code still valid: %d", w.Code)
	}
	var active int
	if db.Pool().QueryRow(ctx, `SELECT count(*) FROM gate_enrolments WHERE email=$1 AND left(id,4)='eno_' AND approved_at IS NULL`, customOwner).Scan(&active) != nil || active != 1 {
		t.Fatalf("active owner codes: %d", active)
	}
	// Expired codes are refused.
	clock = now.Add(OwnerCodeTTL)
	if w := redeem(late); w.Code != 404 {
		t.Fatalf("expired code: %d", w.Code)
	}
	// A code issued for another owner is useless on this server.
	_, foreign, err := st.BeginOwnerCode(ctx, UserAdministrator, now)
	if err != nil {
		t.Fatal(err)
	}
	clock = now
	if w := redeem(foreign); w.Code != 404 {
		t.Fatalf("foreign owner code: %d", w.Code)
	}
	// Off unless NEXUS_OWNER_CODE: the route is 404 even for a live code.
	_, fresh, err := st.BeginOwnerCode(ctx, customOwner, now)
	if err != nil {
		t.Fatal(err)
	}
	off := cfg
	off.OwnerCode = false
	offHandler, err := NewEnrolmentHandler(off)
	if err != nil {
		t.Fatal(err)
	}
	ow := httptest.NewRecorder()
	offHandler.ServeHTTP(ow, httptest.NewRequest("POST", "/v1/enrol/code", strings.NewReader(`{"code":"`+fresh+`"}`)))
	if ow.Code != 404 {
		t.Fatalf("owner code route served while off: %d", ow.Code)
	}
	if w := redeem(fresh); w.Code != 200 {
		t.Fatalf("fresh code with route on: %d", w.Code)
	}
	// Same global enrolment bucket as POST /v1/enrol (30/min).
	limitedSeen := false
	for i := 0; i < 40 && !limitedSeen; i++ {
		limitedSeen = redeem("eoc_"+strings.Repeat("1", 64)).Code == 429
	}
	if !limitedSeen {
		t.Fatal("owner code redemption not rate limited")
	}
}

type noticeMailer struct {
	fixtureMailer
	notices  int
	noticeTo string
}

func (m *noticeMailer) SendOwnerCodeNotice(_ context.Context, to string) error {
	m.notices++
	m.noticeTo = to
	return nil
}
