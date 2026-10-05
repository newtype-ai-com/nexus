package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"html"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

const hostile = `<script>alert("x")</script>&<img src=x onerror=1>`

type capturedMail struct{ From, Subject, Text, HTML string }

func captureResend(t *testing.T, send func(*ResendMailer) error) capturedMail {
	t.Helper()
	m, err := NewResendMailer("fixture-mail-key-SECRET", "Newtype <sender@example.test>")
	if err != nil {
		t.Fatal(err)
	}
	var got capturedMail
	var raw []byte
	m.client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
		raw, _ = io.ReadAll(r.Body)
		return &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"id":"x"}`)), Request: r}, nil
	})
	if err := send(m); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"from", "to", "subject", "text", "html"} {
		if _, ok := payload[k]; !ok {
			t.Fatalf("payload lacks %s", k)
		}
	}
	if len(payload) != 5 || bytes.Contains(raw, []byte("SECRET")) {
		t.Fatal("unexpected payload fields or secret in mail")
	}
	got.From, got.Subject, got.Text, got.HTML = payload["from"].(string), payload["subject"].(string), payload["text"].(string), payload["html"].(string)
	return got
}

var hrefPattern = regexp.MustCompile(`<a href="([^"]*)"`)

func checkMailHTML(t *testing.T, m capturedMail, link string) {
	t.Helper()
	if !strings.HasSuffix(m.Text, "\n\n"+link) {
		t.Fatal("text part must end with the link")
	}
	h := m.HTML
	// Exactly one clickable anchor (plus the Outlook VML twin), pointing at the approval link.
	hrefs := hrefPattern.FindAllStringSubmatch(h, -1)
	if len(hrefs) != 1 || html.UnescapeString(hrefs[0][1]) != link {
		t.Fatalf("button href %v", hrefs)
	}
	if !strings.Contains(h, `href="`+html.EscapeString(link)+`"`) {
		t.Fatal("VML button href")
	}
	if !strings.Contains(h, ">"+html.EscapeString(link)+"</div>") {
		t.Fatal("plain-text copy of link")
	}
	for _, banned := range []string{"<script", "<img", "<link", ` src="`, "@import", "url(", "<iframe", "<form"} {
		if strings.Contains(strings.ToLower(h), banned) {
			t.Fatalf("mail html contains %q", banned)
		}
	}
	for _, need := range []string{"직접 요청한 것이 아니면 승인하지 마세요", "메일을 여는 것만으로는 승인되지 않습니다", "min-height:56px", "font-size:18px", "font-weight:800", "max-width:560px"} {
		if !strings.Contains(h, need) {
			t.Fatalf("mail html lacks %q", need)
		}
	}
}

func TestApprovalMailMultipartEscaped(t *testing.T) {
	ctx := context.Background()
	enrolLink := "https://gate.example.test/enrol/verify?t=vfy_" + strings.Repeat("a", 64)
	deviceLink := "https://gate.example.test/device/confirm?t=apv_" + strings.Repeat("b", 64)
	userLink := "https://gate.example.test/users/approve?t=uap_" + strings.Repeat("c", 64)
	quotaLink := "https://gate.example.test/quota/approve?account_id=acc&id=x&t=qap_" + strings.Repeat("d", 64)
	changeLink := "https://lic.example/change/approve?id=chg_1&t=" + strings.Repeat("e", 64)
	summary := "ID: chg_1\n종류: deploy\n대상: " + hostile + "\ndigest: abc\n만료: 2026-10-04T12:30:00Z"

	m := captureResend(t, func(r *ResendMailer) error { return r.SendVerification(ctx, "user@example.test", enrolLink) })
	checkMailHTML(t, m, enrolLink)
	if m.Subject != "Newtype 설치·로그인 승인" || !strings.Contains(m.HTML, "30분 안에 승인") {
		t.Fatal("install mail")
	}
	m = captureResend(t, func(r *ResendMailer) error { return r.SendVerification(ctx, "user@example.test", deviceLink) })
	checkMailHTML(t, m, deviceLink)
	if !strings.Contains(m.HTML, "10분 안에 승인") || !strings.Contains(m.HTML, "로그인을 승인") {
		t.Fatal("device mail")
	}

	m = captureResend(t, func(r *ResendMailer) error { return r.SendUserAdmission(ctx, UserAdministrator, hostile, userLink) })
	checkMailHTML(t, m, userLink)
	if !strings.Contains(m.Text, "사용자 추가 요청: "+hostile) || !strings.Contains(m.HTML, "&lt;script&gt;alert(&#34;x&#34;)&lt;/script&gt;") {
		t.Fatal("admission target")
	}

	m = captureResend(t, func(r *ResendMailer) error { return r.SendQuotaApproval(ctx, UserAdministrator, hostile, quotaLink) })
	checkMailHTML(t, m, quotaLink)

	m = captureResend(t, func(r *ResendMailer) error { return r.SendChangeApproval(ctx, UserAdministrator, summary, changeLink) })
	checkMailHTML(t, m, changeLink)
	pre := regexp.MustCompile(`(?s)<pre[^>]*>(.*?)</pre>`).FindStringSubmatch(m.HTML)
	if pre == nil || html.UnescapeString(pre[1]) != summary || !strings.HasPrefix(m.Text, summary+"\n") {
		t.Fatal("change summary must appear verbatim in a monospace block")
	}
}

func styleHashOf(t *testing.T, page string) string {
	t.Helper()
	parts := regexp.MustCompile(`(?s)<style>(.*?)</style>`).FindAllStringSubmatch(page, -1)
	if len(parts) != 1 || strings.Contains(page, " style=") {
		t.Fatal("page must have exactly one style element and no style attributes")
	}
	sum := sha256.Sum256([]byte(parts[0][1]))
	return "'sha256-" + base64.StdEncoding.EncodeToString(sum[:]) + "'"
}

func checkPage(t *testing.T, w *httptest.ResponseRecorder, csp string, forms ...string) string {
	t.Helper()
	body := w.Body.String()
	if w.Code != 200 || w.Header().Get("Content-Security-Policy") != csp || w.Header().Get("Content-Type") != "text/html; charset=utf-8" {
		t.Fatalf("page %d csp %q", w.Code, w.Header().Get("Content-Security-Policy"))
	}
	if !strings.Contains(csp, "style-src "+styleHashOf(t, body)+";") || strings.Contains(csp, "unsafe") {
		t.Fatal("style hash mismatch")
	}
	for _, f := range forms {
		if !strings.Contains(body, f) {
			t.Fatalf("page lacks %q", f)
		}
	}
	if strings.Count(body, "<form") != 1 && len(forms) > 0 {
		t.Fatal("exactly one form")
	}
	return body
}

func TestApprovalCSPExact(t *testing.T) {
	if approvalPageCSP != "default-src 'none'; style-src "+approvalStyleSource+"; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" {
		t.Fatal(approvalPageCSP)
	}
	if changeSurfaceCSP != "default-src 'none'; script-src 'self'; connect-src 'self'; style-src "+approvalStyleSource+"; form-action 'self'; frame-ancestors 'none'; base-uri 'none'" {
		t.Fatal(changeSurfaceCSP)
	}
}

func TestEnrolAndDevicePagesDesign(t *testing.T) {
	cfg := EnrolmentConfig{Store: &PostgresCredentials{}, BaseURL: "https://gate.example.test", Allow: []string{"example.test"}, Mailer: &fixtureMailer{}}
	e, err := NewEnrolmentHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	d, err := NewDeviceHandler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	get := func(h http.Handler, path string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		h.ServeHTTP(w, httptest.NewRequest("GET", path, nil))
		if w.Header().Get("Referrer-Policy") != "same-origin" || w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("headers")
		}
		return w
	}
	checkPage(t, get(e, "/enrol/verify?t=vfy_"+strings.Repeat("a", 64)), approvalPageCSP, `<form method="post"><button class="approve" type="submit">승인</button></form>`)
	checkPage(t, get(d, "/device/confirm?t=apv_"+strings.Repeat("a", 64)), approvalPageCSP, `<form method="post"><button class="approve" name="decision" value="approve">로그인 승인</button><button class="deny" name="decision" value="deny">거절</button></form>`)
	// Cross-origin POSTs are still refused before any store access.
	for _, c := range []struct {
		h    http.Handler
		path string
	}{{e, "/enrol/verify?t=vfy_" + strings.Repeat("a", 64)}, {d, "/device/confirm?t=apv_" + strings.Repeat("a", 64)}} {
		r := httptest.NewRequest("POST", c.path, strings.NewReader("decision=approve"))
		r.Header.Set("Origin", "https://evil.example")
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		c.h.ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatalf("origin check %d", w.Code)
		}
	}
	for _, page := range []string{enrolDoneHTML, deviceDoneHTML} {
		if !strings.Contains(approvalPageCSP, styleHashOf(t, page)) {
			t.Fatal("result page style hash")
		}
	}
}

func TestAdmissionPageDesign(t *testing.T) {
	var b bytes.Buffer
	if err := admissionPage.Execute(&b, UserAdmission{Email: hostile, Expires: time.Date(2026, 10, 4, 12, 30, 0, 0, time.UTC)}); err != nil {
		t.Fatal(err)
	}
	page := b.String()
	if strings.Contains(page, "<script>") || !strings.Contains(page, "&lt;script&gt;") || !strings.Contains(approvalPageCSP, styleHashOf(t, page)) {
		t.Fatal("admission escape or style")
	}
	if !strings.Contains(page, `<form method="post"><button class="approve" name="decision" value="approve">이 사용자 추가 승인</button><button class="deny" name="decision" value="deny">거절</button></form>`) {
		t.Fatal("admission form")
	}
}

func TestQuotaPageDesign(t *testing.T) {
	ctx := context.Background()
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	creds := NewMemoryCredentials()
	mail := &quotaTestMailer{}
	user := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), "user@example.test")
	key, login := "ntl_"+strings.Repeat("a", 64), "ntg_"+strings.Repeat("b", 64)
	for token, kind := range map[string]string{key: "licence", login: "login"} {
		if err := creds.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: user.AccountID, Email: user.Email, Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	auth := NexusAuth{Store: creds, Service: svc}
	h, err := NewQuotaHandler(QuotaConfig{Service: svc, Store: creds, Authenticate: auth.Authenticate, Mailer: mail, BaseURL: "https://gate.example.test", OwnerEmail: UserAdministrator})
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest("POST", "/v1/quota/requests", strings.NewReader(`{"amount":5000,"client_event_id":"p"}`))
	r.Header.Set("Authorization", "Bearer "+key)
	r.Header.Set("X-Newtype-Login", login)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 202 || mail.link == "" {
		t.Fatalf("start %d", w.Code)
	}
	u, _ := url.Parse(mail.link)
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", u.RequestURI(), nil))
	page := checkPage(t, w, approvalPageCSP, `<form method="post"><button class="approve" name="decision" value="approve">이 정확한 증액 승인</button><button class="deny" name="decision" value="deny">거절</button></form>`)
	if strings.Contains(page, u.Query().Get("t")) {
		t.Fatal("token reflected")
	}
	// GET twice never decides.
	w = httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest("GET", u.RequestURI(), nil))
	if w.Code != 200 {
		t.Fatal("GET must not consume")
	}
	r = httptest.NewRequest("POST", u.RequestURI(), strings.NewReader("decision=approve"))
	r.Header.Set("Origin", "https://evil.example")
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w = httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 403 {
		t.Fatal("origin")
	}
}

func TestChangePageDesign(t *testing.T) {
	f := newChangeFixture(t)
	in := changeTestInput()
	in.Target, in.Manifest = hostile, "line1\n"+hostile
	a := f.begin(in)
	u, _ := url.Parse(f.mail.link)
	w := f.request(false, "GET", u.RequestURI(), nil)
	page := checkPage(t, w, changeSurfaceCSP, `<form id="decision" method="post" action="/change/approve"><input type="hidden" name="digest" value="`+a.Digest+`"><button class="approve" disabled name="decision" value="approve">이 정확한 변경 승인</button><button class="deny" disabled name="decision" value="deny">거절</button></form>`, `<script src="/change/decision.js" defer></script>`, `<noscript>`)
	if strings.Count(page, "<script") != 1 || strings.Contains(page, "<script>alert") || w.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatal("change page escaping or headers")
	}
	w = f.request(false, "GET", "/change/decision.js", nil)
	if w.Body.String() != changeScript || w.Header().Get("Content-Security-Policy") != changeSurfaceCSP {
		t.Fatal("decision.js changed")
	}
}

// NEWTYPE_APPROVAL_PREVIEW_DIR=dir go test -run TestApprovalPreviews ./gate/
// writes sample mails and pages with fake data. It sends nothing.
func TestApprovalPreviews(t *testing.T) {
	dir := os.Getenv("NEWTYPE_APPROVAL_PREVIEW_DIR")
	if dir == "" {
		t.Skip("set NEWTYPE_APPROVAL_PREVIEW_DIR to write previews")
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	write := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mail := func(name string, v mailView) {
		s, err := renderMail(v)
		if err != nil {
			t.Fatal(err)
		}
		write(name, s)
	}
	base := "https://lic.newtype-ai.com"
	mail("mail-1-install.html", verificationMail(base+"/enrol/verify?t=vfy_FAKE0000000000000000000000000000000000000000000000000000000000000"))
	mail("mail-2-login.html", verificationMail(base+"/device/confirm?t=apv_FAKE0000000000000000000000000000000000000000000000000000000000000"))
	mail("mail-3-user-admission.html", userAdmissionMail("new.member@example.com", base+"/users/approve?t=uap_FAKE0000000000000000000000000000000000000000000000000000000000000"))
	mail("mail-4-quota.html", quotaMail("계정 acc_FAKE01 / 2026-10 (한국시간) / 기존 1000000 → 최종 1500000 토큰 / 증액 500000 토큰. 당월에만 적용하며 다음 달 이월되지 않습니다.", base+"/quota/approve?account_id=acc_FAKE01&id=2026-10_qtr_FAKE&t=qap_FAKE"))
	mail("mail-5-change.html", changeMail("ID: chg_FAKE01\n종류: deploy\n대상: example approvals\ndigest: 3f1c0d9a7b2e4c6f8a1b3d5e7f9a0c2e4b6d8f1a3c5e7092b4d6f8a1c3e5f7a9\n기준 상태: image newtype-approvals-nexus:acf170aeffcf running\n영향: 승인 서버 재시작 약 5초\n비용: 없음\n복구: 이전 이미지로 재기동\n만료: 2026-10-04T13:30:00+09:00", base+"/change/approve?id=chg_FAKE01&t=FAKE"))
	write("page-1-install.html", enrolVerifyHTML)
	write("page-1b-install-done.html", enrolDoneHTML)
	write("page-2-login.html", deviceConfirmHTML)
	write("page-2b-login-done.html", deviceDoneHTML)
	exp := time.Date(2026, 10, 4, 13, 30, 0, 0, time.FixedZone("KST", 9*3600))
	var b bytes.Buffer
	_ = admissionPage.Execute(&b, UserAdmission{Email: "new.member@example.com", Expires: exp})
	write("page-3-user-admission.html", b.String())
	b.Reset()
	_ = quotaPage.Execute(&b, nexus.QuotaRequest{AccountID: "acc_FAKE01", Month: "2026-10", PreviousLimit: 1000000, NewLimit: 1500000, Amount: 500000, ExpiresAt: exp})
	write("page-4-quota.html", b.String())
	b.Reset()
	_ = changePage.Execute(&b, ChangeApproval{ChangeInput: ChangeInput{Requester: "operator", Kind: "deploy", Target: "example approvals", Manifest: "image: newtype-approvals-nexus:acf170aeffcf\nrestart: once\nports: 127.0.0.1:18080, 127.0.0.1:18081", BaseState: "running", Impact: "승인 서버 재시작 약 5초", Cost: "없음", Recovery: "이전 이미지로 재기동"}, ID: "chg_FAKE01", Digest: "3f1c0d9a7b2e4c6f8a1b3d5e7f9a0c2e4b6d8f1a3c5e7092b4d6f8a1c3e5f7a9", Status: "pending", ExpiresAt: exp})
	write("page-5-change.html", b.String())
}
