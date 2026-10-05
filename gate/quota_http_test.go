package gate

import (
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
)

type quotaTestMailer struct {
	link, recipient string
	calls           int
	fail            bool
}

func (m *quotaTestMailer) SendQuotaApproval(_ context.Context, to, summary, link string) error {
	m.calls++
	m.link = link
	m.recipient = to
	if m.fail {
		return errors.New("test mail failure")
	}
	return nil
}
func TestQuotaHTTPExactMailApproval(t *testing.T) {
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
	call := func(method, path, body string, authenticated bool, want int) *httptest.ResponseRecorder {
		t.Helper()
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+key)
			r.Header.Set("X-Newtype-Login", login)
		}
		if strings.HasPrefix(path, "/quota/approve") {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != want {
			t.Fatalf("%s %s got %d want %d: %s", method, strings.Split(path, "?")[0], w.Code, want, w.Body.String())
		}
		return w
	}
	call("GET", "/v1/quota", "", false, 401)
	call("POST", "/v1/quota/requests", `{"amount":0,"client_event_id":"a"}`, true, 400)
	call("POST", "/v1/quota/requests", `{"amount":1,"client_event_id":"a","approved":true}`, true, 400)
	target := ids.New(ids.KindAccount)
	call("POST", "/v1/quota/requests", `{"amount":1,"client_event_id":"a","account_id":"`+target+`"}`, true, 403)
	body := `{"amount":1234567,"client_event_id":"a"}`
	w := call("POST", "/v1/quota/requests", body, true, 202)
	var a nexus.QuotaRequest
	if json.Unmarshal(w.Body.Bytes(), &a) != nil || a.Status != "pending" || a.ApprovalHash != "" || mail.calls != 1 || mail.recipient != UserAdministrator {
		t.Fatal("invalid public request or mail")
	}
	if strings.Contains(w.Body.String(), "qap_") || strings.Contains(w.Body.String(), "approval_hash") {
		t.Fatal("capability leaked")
	}
	call("POST", "/v1/quota/requests", body, true, 202)
	if mail.calls != 1 {
		t.Fatal("duplicate mail")
	}
	call("GET", "/v1/quota/requests/"+a.ID, "", true, 200)
	q, _ := svc.AccountQuota(ctx, user)
	if q.Increase != 0 {
		t.Fatal("request applied")
	}
	link, _ := url.Parse(mail.link)
	call("GET", link.RequestURI(), "", false, 200)
	q, _ = svc.AccountQuota(ctx, user)
	if q.Increase != 0 {
		t.Fatal("mail scanner applied")
	}
	call("POST", link.RequestURI(), "decision=approve", false, 200)
	call("POST", link.RequestURI(), "decision=approve", false, 404)
	q, _ = svc.AccountQuota(ctx, user)
	if q.Increase != 1234567 {
		t.Fatal(q)
	}
	mail.fail = true
	call("POST", "/v1/quota/requests", `{"amount":1,"client_event_id":"failed"}`, true, 502)
	failed, _ := url.Parse(mail.link)
	call("POST", failed.RequestURI(), "decision=approve", false, 404)
	q, _ = svc.AccountQuota(ctx, user)
	if q.Increase != 1234567 {
		t.Fatal("failed mail applied")
	}
	// Only the fixed administrator's real licence may target another account.
	admin := nexus.UserPrincipal(ids.Account(ids.New(ids.KindAccount)), UserAdministrator)
	key, login = "ntl_"+strings.Repeat("c", 64), "ntg_"+strings.Repeat("d", 64)
	for token, kind := range map[string]string{key: "licence", login: "login"} {
		if err := creds.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: admin.AccountID, Email: admin.Email, Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal(err)
		}
	}
	mail.fail = false
	w = call("POST", "/v1/quota/requests", `{"amount":7654321,"client_event_id":"admin-change","account_id":"`+string(user.AccountID)+`"}`, true, 202)
	if json.Unmarshal(w.Body.Bytes(), &a) != nil || a.Amount != 7654321 || a.AccountID != user.AccountID {
		t.Fatal("admin exact target")
	}
	call("GET", "/v1/quota?account_id="+string(user.AccountID), "", true, 200)
	link, _ = url.Parse(mail.link)
	call("POST", link.RequestURI(), "decision=approve", false, 200)
	q, _ = svc.AccountQuota(ctx, user)
	if q.Increase != 8888888 {
		t.Fatal(q)
	}
}
