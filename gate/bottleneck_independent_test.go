package gate

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/newtype-ai-com/nexus/ids"
	"github.com/newtype-ai-com/nexus/nexus"
	"github.com/newtype-ai-com/nexus/nexus/httpapi"
)

// This synthetic admitted store is a branch-coverage aid, NOT the required
// PostgreSQL admitted-row evidence for Section 2 cases 2-5 and 7.
type independentAdmittedCredentials struct {
	*MemoryCredentials
	admittedCalls atomic.Int32
	putCalls      atomic.Int32
}

func (s *independentAdmittedCredentials) Admitted(context.Context, string, string) (bool, error) {
	s.admittedCalls.Add(1)
	return true, nil
}
func (s *independentAdmittedCredentials) PutCredential(ctx context.Context, c Credential) error {
	s.putCalls.Add(1)
	return s.MemoryCredentials.PutCredential(ctx, c)
}

type independentDenyTransport struct{ calls atomic.Int32 }

func (s *independentDenyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	s.calls.Add(1)
	return nil, errors.New("synthetic upstream must not be called")
}

func TestIndependentBottleneckStrictAdmittedBranch(t *testing.T) {
	ctx := context.Background()
	s := &independentAdmittedCredentials{MemoryCredentials: NewMemoryCredentials()}
	now := time.Now()
	for _, email := range []string{"owner@example.test", "admitted@example.test"} {
		for _, kind := range []string{"licence", "login"} {
			token := "synthetic-" + kind + "-" + email + strings.Repeat("x", 32)
			c := Credential{Verifier: Verifier(token), Kind: kind, Account: ids.Account(ids.New(ids.KindAccount)), Email: email, Expires: now.Add(time.Hour)}
			if err := s.MemoryCredentials.PutCredential(ctx, c); err != nil {
				t.Fatal("fixture setup failed")
			}
			strict, err := NewOwnerCredentialsWithPolicy(s, " Owner@Example.test ", true)
			if err != nil {
				t.Fatal("strict constructor failed")
			}
			_, lookupErr := strict.LookupCredential(ctx, c.Verifier)
			putErr := strict.PutCredential(ctx, c)
			wantAllowed := email == "owner@example.test"
			if (lookupErr == nil) != wantAllowed || (putErr == nil) != wantAllowed {
				t.Fatal("strict owner lookup/provision policy bypass")
			}
		}
	}
	if s.admittedCalls.Load() != 0 || s.putCalls.Load() != 2 {
		t.Fatal("strict policy queried admissions or wrote a nonowner credential")
	}
	legacy, err := NewOwnerCredentialsWithPolicy(s, "owner@example.test", false)
	if err != nil {
		t.Fatal("legacy constructor failed")
	}
	token := "synthetic-licence-admitted@example.test" + strings.Repeat("x", 32)
	if _, err := legacy.LookupCredential(ctx, Verifier(token)); err != nil || s.admittedCalls.Load() != 1 {
		t.Fatal("strict-off admitted compatibility changed")
	}
}

// Section 2 case 3 auxiliary test: existing foreign credentials must be rejected
// before model transport, even if a mock admissions source returns true.
func TestIndependentBottleneckStrictCredentialsRejectAllSurfaces(t *testing.T) {
	ctx := context.Background()
	s := &independentAdmittedCredentials{MemoryCredentials: NewMemoryCredentials()}
	account := ids.Account(ids.New(ids.KindAccount))
	licence, login := "ntl_"+strings.Repeat("a", 64), "ntg_"+strings.Repeat("b", 64)
	for token, kind := range map[string]string{licence: "licence", login: "login"} {
		if err := s.MemoryCredentials.PutCredential(ctx, Credential{Verifier: Verifier(token), Kind: kind, Account: account, Email: "admitted@example.test", Expires: time.Now().Add(time.Hour)}); err != nil {
			t.Fatal("credential fixture failed")
		}
	}
	strict, err := NewOwnerCredentialsWithPolicy(s, "owner@example.test", true)
	if err != nil {
		t.Fatal("strict constructor failed")
	}
	svc := nexus.NewService(nexus.NewMemStore(), nil)
	api, err := httpapi.New(httpapi.Config{Service: svc, Authenticate: NexusAuth{Store: strict, Service: svc}.Authenticate, Reauthenticate: NexusAuth{Store: strict, Service: svc}.Reauthenticate,
		Run: func(context.Context, string, json.RawMessage) error { return nexus.ErrForbidden },
	})
	if err != nil {
		t.Fatal("API fixture failed")
	}
	upstream := &independentDenyTransport{}
	model, err := NewModelHandler(ModelConfig{Service: svc, Store: strict, Upstream: "https://upstream.example.test/v1/chat/completions", Key: "synthetic-model-key", Models: []string{"fixture"}, Budget: 100, MaxOutput: 10, Transport: upstream})
	if err != nil {
		t.Fatal("model fixture failed")
	}
	for _, tc := range []struct {
		name, path string
		handler    http.Handler
		status     int
	}{
		{"validate", "/v1/validate", ValidateHandlerWithWake(strict, svc), 200},
		{"requests", "/v1/requests", api, 401},
		{"model", "/v1/model/chat/completions", model, 401},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("POST", tc.path, strings.NewReader(`{"model":"fixture","messages":[{"role":"user","content":"synthetic"}],"stream":true}`))
			r.Header.Set("Authorization", "Bearer "+licence)
			r.Header.Set("X-Newtype-Login", login)
			w := httptest.NewRecorder()
			tc.handler.ServeHTTP(w, r)
			if w.Code != tc.status {
				t.Fatalf("status %d, want %d", w.Code, tc.status)
			}
			if tc.name == "validate" {
				var lease struct {
					Status  string `json:"status"`
					Expires int    `json:"expires_in"`
				}
				if json.Unmarshal(w.Body.Bytes(), &lease) != nil || lease.Status != "invalid" || lease.Expires != 0 {
					t.Fatal("nonowner received a valid lease")
				}
			}
		})
	}
	if upstream.calls.Load() != 0 || s.admittedCalls.Load() != 0 {
		t.Fatal("foreign credentials reached upstream or admissions under strict policy")
	}
}

func independentChangeStore(t *testing.T) (*FileChangeStore, string, time.Time) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal("private fixture directory failed")
	}
	path := filepath.Join(dir, "changes.jsonl")
	store, err := OpenFileChangeStore(path, 50)
	if err != nil {
		t.Fatal("change journal fixture failed")
	}
	t.Cleanup(func() { store.Close() })
	return store, path, time.Date(2026, 10, 2, 1, 0, 0, 0, time.UTC)
}

func independentChangeInput(client string) ChangeInput {
	return ChangeInput{Requester: "operator@example.test", Kind: "deploy", Target: "fixture-only", Manifest: "deploy synthetic candidate\n", BaseState: "synthetic-base", Impact: "none", Cost: "zero", Recovery: "discard fixture", ClientID: client}
}

func independentDeliveredChange(t *testing.T, s *FileChangeStore, now time.Time, client string) (ChangeApproval, string) {
	t.Helper()
	a, token, err := s.Begin(independentChangeInput(client), now)
	if err != nil || token == "" || s.Delivery(a.ID, true) != nil {
		t.Fatal("delivered change setup failed")
	}
	return a, token
}

func independentJournalBytes(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal("fixture journal read failed")
	}
	return raw
}

// Store-level coverage for Section 1 cases 2-6, 9-11. HTTP and fake-mail
// assertions remain separate; these results must not be counted as all 13.
func TestIndependentBottleneckChangeStoreDecisionAndPersistence(t *testing.T) {
	s, path, now := independentChangeStore(t)
	a, token := independentDeliveredChange(t, s, now, "first")
	b, otherToken := independentDeliveredChange(t, s, now, "second")
	_ = b
	sum := sha256.Sum256([]byte(a.Manifest))
	if a.Digest != hex.EncodeToString(sum[:]) || a.ExpiresAt.Sub(a.CreatedAt) != 30*time.Minute {
		t.Fatal("server digest or default expiry differs")
	}
	before := independentJournalBytes(t, path)
	for _, wrong := range []string{"cap_" + strings.Repeat("0", 64), otherToken} {
		if _, err := s.ByLink(a.ID, wrong, now); !errors.Is(err, ErrChangeNotFound) {
			t.Fatal("forged or swapped token accepted")
		}
	}
	if _, err := s.Decide(a.ID, token, strings.Repeat("0", 64), true, "127.0.0.1", "fixture", now); err == nil {
		t.Fatal("wrong digest accepted")
	}
	if _, err := s.Consume(a.ID, a.Manifest, now); err == nil {
		t.Fatal("pending change consumed")
	}
	if _, err := s.Decide(a.ID, token, a.Digest, true, "127.0.0.1", "fixture", a.ExpiresAt); err == nil {
		t.Fatal("expiry boundary decision accepted")
	}
	if !bytes.Equal(before, independentJournalBytes(t, path)) {
		t.Fatal("rejected decision changed durable state")
	}
	approved, err := s.Decide(a.ID, token, a.Digest, true, "127.0.0.1", "fixture", now.Add(time.Second))
	if err != nil || approved.Status != "approved" {
		t.Fatal("valid decision failed")
	}
	before = independentJournalBytes(t, path)
	if _, err := s.Decide(a.ID, token, a.Digest, false, "127.0.0.1", "fixture", now.Add(2*time.Second)); err == nil {
		t.Fatal("second decision accepted")
	}
	if _, err := s.Consume(a.ID, a.Manifest+" ", now.Add(2*time.Second)); err == nil {
		t.Fatal("changed manifest consumed")
	}
	if _, err := s.Consume(a.ID, a.Manifest, a.ExpiresAt); err == nil {
		t.Fatal("expired approval consumed")
	}
	if !bytes.Equal(before, independentJournalBytes(t, path)) {
		t.Fatal("rejected consume changed journal")
	}
	if _, err := s.Consume(a.ID, a.Manifest, now.Add(2*time.Second)); err != nil {
		t.Fatal("valid consume failed")
	}
	if _, err := s.Consume(a.ID, a.Manifest, now.Add(3*time.Second)); err == nil {
		t.Fatal("second consume accepted")
	}
	if _, err := s.Result(a.ID, "succeeded", now.Add(3*time.Second)); err != nil {
		t.Fatal("result failed")
	}
	if err := s.Close(); err != nil {
		t.Fatal("journal close failed")
	}
	reopened, err := OpenFileChangeStore(path, 50)
	if err != nil {
		t.Fatal("reopen failed")
	}
	defer reopened.Close()
	got, err := reopened.Get(a.ID, now.Add(4*time.Second))
	if err != nil || got.Status != "consumed" || got.Result != "succeeded" || !got.DecidedAt.Equal(approved.DecidedAt) || got.ConsumedAt.IsZero() {
		t.Fatal("decision/consume/result not durable")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("journal is not private")
	}
	raw := independentJournalBytes(t, path)
	if bytes.Contains(raw, []byte(token)) || bytes.Contains(raw, []byte(otherToken)) {
		t.Fatal("link token stored in journal")
	}
}

func TestIndependentBottleneckChangeDenialFailureAndIdempotency(t *testing.T) {
	s, path, now := independentChangeStore(t)
	a, token := independentDeliveredChange(t, s, now, "deny")
	if _, err := s.Decide(a.ID, token, a.Digest, false, "127.0.0.1", "fixture", now); err != nil {
		t.Fatal("deny failed")
	}
	before := independentJournalBytes(t, path)
	if _, err := s.Decide(a.ID, token, a.Digest, true, "127.0.0.1", "fixture", now); err == nil {
		t.Fatal("denial overwritten")
	}
	if _, err := s.Consume(a.ID, a.Manifest, now); err == nil {
		t.Fatal("denied change consumed")
	}
	if !bytes.Equal(before, independentJournalBytes(t, path)) {
		t.Fatal("denial changed")
	}
	again, newToken, err := s.Begin(independentChangeInput("deny"), now)
	if err != nil || again.ID != a.ID || newToken != "" {
		t.Fatal("identical client request not idempotent")
	}
	changed := independentChangeInput("deny")
	changed.Manifest += "changed"
	if _, _, err := s.Begin(changed, now); !errors.Is(err, ErrChangeConflict) {
		t.Fatal("client id reused for changed content")
	}
	failed, failedToken, err := s.Begin(independentChangeInput("failed"), now)
	if err != nil || s.Delivery(failed.ID, false) != nil {
		t.Fatal("failed delivery setup failed")
	}
	if _, err := s.Decide(failed.ID, failedToken, failed.Digest, true, "127.0.0.1", "fixture", now); err == nil {
		t.Fatal("failed delivery can be approved")
	}
	got, err := s.Get(failed.ID, now)
	if err != nil || got.Status != "failed" {
		t.Fatal("failed delivery not persisted")
	}
}

func TestIndependentBottleneckChangeConcurrentDecision(t *testing.T) {
	s, _, now := independentChangeStore(t)
	a, token := independentDeliveredChange(t, s, now, "concurrent")
	var wg sync.WaitGroup
	var success atomic.Int32
	start := make(chan struct{})
	for _, approve := range []bool{true, false} {
		wg.Add(1)
		go func(approve bool) {
			defer wg.Done()
			<-start
			if _, err := s.Decide(a.ID, token, a.Digest, approve, "127.0.0.1", "fixture", now); err == nil {
				success.Add(1)
			}
		}(approve)
	}
	close(start)
	wg.Wait()
	if success.Load() != 1 {
		t.Fatal("concurrent decisions not exactly one success")
	}
}

func TestIndependentBottleneckChangeJournalFailClosed(t *testing.T) {
	s, path, now := independentChangeStore(t)
	if second, err := OpenFileChangeStore(path, 50); err == nil {
		second.Close()
		t.Fatal("second journal owner accepted")
	}
	pending, token, err := s.Begin(independentChangeInput("interrupted-mail"), now)
	if err != nil {
		t.Fatal("pending setup failed")
	}
	s.Close()
	reopened, err := OpenFileChangeStore(path, 50)
	if err != nil {
		t.Fatal("reopen interrupted delivery failed")
	}
	got, err := reopened.Get(pending.ID, now)
	if err != nil || got.Status != "failed" {
		t.Fatal("interrupted delivery remains approvable")
	}
	if _, err := reopened.Decide(pending.ID, token, pending.Digest, true, "127.0.0.1", "fixture", now); err == nil {
		t.Fatal("interrupted delivery approved")
	}
	reopened.Close()
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		t.Fatal("torn tail setup failed")
	}
	_, writeErr := f.WriteString(`{"change":`)
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		t.Fatal("torn tail write failed")
	}
	before := independentJournalBytes(t, path)
	if damaged, err := OpenFileChangeStore(path, 50); err == nil {
		damaged.Close()
		t.Fatal("torn journal silently accepted")
	}
	if !bytes.Equal(before, independentJournalBytes(t, path)) {
		t.Fatal("torn journal silently rewritten")
	}
}

type independentChangeMail struct {
	links []string
	fail  bool
}

func (m *independentChangeMail) SendChangeApproval(_ context.Context, to, summary, link string) error {
	if to != UserAdministrator || !strings.Contains(summary, "digest:") {
		return errors.New("invalid synthetic mail")
	}
	m.links = append(m.links, link)
	if m.fail {
		return errors.New("SYNTHETIC-MAIL-SECRET")
	}
	return nil
}

// Section 1 HTTP cases 1-13 use only an in-process fake mailer and private journal.
func TestIndependentBottleneckChangeHTTP(t *testing.T) {
	s, path, now := independentChangeStore(t)
	mail := &independentChangeMail{}
	var auditBytes bytes.Buffer
	audit, err := NewAudit(&auditBytes)
	if err != nil {
		t.Fatal("audit setup failed")
	}
	defer audit.Close()
	adminToken := strings.Repeat("synthetic-admin-", 4)
	h, err := NewChangeHandler(ChangeConfig{Store: s, Mailer: mail, BaseURL: "https://approval.example.test", OwnerEmail: UserAdministrator, AdminToken: adminToken, Clock: func() time.Time { return now }, Audit: audit})
	if err != nil {
		t.Fatal("HTTP setup failed")
	}
	request := func(admin bool, method, target, body, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Authorization", "Bearer "+adminToken)
		values, _ := url.ParseQuery(body)
		r.Header.Set("User-Agent", "synthetic-agent "+adminToken+values.Get("t"))
		r.Header.Set("X-Forwarded-For", adminToken+values.Get("t"))
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		if admin {
			h.AdminHandler().ServeHTTP(w, r)
		} else {
			h.PublicHandler().ServeHTTP(w, r)
		}
		for _, secret := range []string{adminToken, "SYNTHETIC-MAIL-SECRET", values.Get("t"), r.URL.Query().Get("t")} {
			if secret != "" && strings.Contains(w.Body.String(), secret) {
				t.Error("HTTP response reflected synthetic secret")
			}
		}
		return w
	}
	begin := func(client string) (ChangeApproval, url.Values) {
		t.Helper()
		raw, _ := json.Marshal(independentChangeInput(client))
		w := request(true, "POST", "/v1/changes", string(raw), "")
		var a ChangeApproval
		if w.Code != 202 || json.Unmarshal(w.Body.Bytes(), &a) != nil {
			t.Fatal("HTTP begin failed")
		}
		u, e := url.Parse(mail.links[len(mail.links)-1])
		if e != nil {
			t.Fatal("mail link invalid")
		}
		q := u.Query()
		if strings.Contains(w.Body.String(), q.Get("t")) {
			t.Fatal("begin response exposes token")
		}
		q.Set("digest", a.Digest)
		q.Set("decision", "approve")
		return a, q
	}
	a, form := begin("http-main")
	link := "/change/approve?" + url.Values{"id": {a.ID}, "t": {form.Get("t")}}.Encode()
	t.Run("01_reads_unchanged", func(t *testing.T) {
		before := independentJournalBytes(t, path)
		for _, method := range []string{"GET", "HEAD", "GET", "HEAD"} {
			w := request(false, method, link, "", "")
			if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" || strings.Contains(w.Body.String(), form.Get("t")) {
				t.Fatal("read failed, cacheable or exposes link token")
			}
		}
		if !bytes.Equal(before, independentJournalBytes(t, path)) {
			t.Fatal("GET/HEAD changed journal")
		}
	})
	_, other := begin("http-other")
	t.Run("02_wrong_tokens", func(t *testing.T) {
		before := independentJournalBytes(t, path)
		for _, token := range []string{"cap_" + strings.Repeat("0", 64), other.Get("t")} {
			badLink := "/change/approve?" + url.Values{"id": {a.ID}, "t": {token}}.Encode()
			if request(false, "GET", badLink, "", "").Code != 404 {
				t.Fatal("wrong token not 404")
			}
		}
		if !bytes.Equal(before, independentJournalBytes(t, path)) {
			t.Fatal("wrong token changed journal")
		}
	})
	t.Run("07_invalid_forms", func(t *testing.T) {
		before := independentJournalBytes(t, path)
		for _, tc := range []struct{ target, body, origin string }{
			{"/change/approve", form.Encode(), "https://foreign.example.test"},
			{"/change/approve", form.Encode() + "&decision=deny", ""},
			{"/change/approve", "id=" + a.ID, ""},
			{link, form.Encode(), ""},
			{"/change/approve", form.Encode() + "&padding=" + strings.Repeat("x", 1024), ""},
		} {
			if request(false, "POST", tc.target, tc.body, tc.origin).Code < 400 {
				t.Fatal("invalid form accepted")
			}
		}
		if !bytes.Equal(before, independentJournalBytes(t, path)) {
			t.Fatal("invalid form changed journal")
		}
	})
	t.Run("03_expiry_05_digest_06_pending", func(t *testing.T) {
		before := independentJournalBytes(t, path)
		now = a.ExpiresAt
		if request(false, "POST", "/change/approve", form.Encode(), "").Code != 409 {
			t.Fatal("expired decision accepted")
		}
		now = a.CreatedAt
		bad := strings.Replace(form.Encode(), a.Digest, strings.Repeat("0", 64), 1)
		if request(false, "POST", "/change/approve", bad, "").Code != 409 {
			t.Fatal("wrong digest accepted")
		}
		raw, _ := json.Marshal(map[string]string{"manifest": a.Manifest})
		if request(true, "POST", "/v1/changes/"+a.ID+"/consume", string(raw), "").Code != 409 {
			t.Fatal("pending consume accepted")
		}
		if !bytes.Equal(before, independentJournalBytes(t, path)) {
			t.Fatal("rejected expiry/digest/consume changed journal")
		}
	})
	t.Run("09_idempotency", func(t *testing.T) {
		calls := len(mail.links)
		raw, _ := json.Marshal(independentChangeInput("http-main"))
		if request(true, "POST", "/v1/changes", string(raw), "").Code != 202 {
			t.Fatal("identical request failed")
		}
		changed := independentChangeInput("http-main")
		changed.Manifest += "changed"
		raw, _ = json.Marshal(changed)
		if request(true, "POST", "/v1/changes", string(raw), "").Code != 409 || len(mail.links) != calls {
			t.Fatal("changed id accepted or duplicate mail sent")
		}
	})
	t.Run("13_concurrent_04_repeated_decisions", func(t *testing.T) {
		var wg sync.WaitGroup
		var successes atomic.Int32
		for _, decision := range []string{"approve", "deny"} {
			wg.Add(1)
			go func(decision string) {
				defer wg.Done()
				body := strings.Replace(form.Encode(), "decision=approve", "decision="+decision, 1)
				if request(false, "POST", "/change/approve", body, "").Code == 200 {
					successes.Add(1)
				}
			}(decision)
		}
		wg.Wait()
		if successes.Load() != 1 {
			t.Fatal("concurrent HTTP decisions not exactly one success")
		}
		before := independentJournalBytes(t, path)
		if request(false, "POST", "/change/approve", form.Encode(), "").Code != 409 || request(false, "GET", link, "", "").Code != 200 || request(false, "HEAD", link, "", "").Code != 200 {
			t.Fatal("repeat decision or decided read contract failed")
		}
		if !bytes.Equal(before, independentJournalBytes(t, path)) {
			t.Fatal("repeat decision/read changed journal")
		}
	})
	t.Run("08_failed_mail", func(t *testing.T) {
		mail.fail = true
		raw, _ := json.Marshal(independentChangeInput("http-mail-fail"))
		w := request(true, "POST", "/v1/changes", string(raw), "")
		if w.Code != 502 || strings.Contains(w.Body.String(), "SYNTHETIC-MAIL-SECRET") {
			t.Fatal("mail failure status or secret leak")
		}
		u, _ := url.Parse(mail.links[len(mail.links)-1])
		q := u.Query()
		failed, err := s.Get(q.Get("id"), now)
		if err != nil || failed.Status != "failed" {
			t.Fatal("mail failure not persisted")
		}
		q.Set("digest", failed.Digest)
		q.Set("decision", "approve")
		if request(false, "POST", "/change/approve", q.Encode(), "").Code != 404 {
			t.Fatal("failed delivery link not rejected as unavailable")
		}
	})
	t.Run("12_listener_separation", func(t *testing.T) {
		for _, method := range []string{"GET", "HEAD", "POST", "PUT", "DELETE"} {
			for _, target := range []string{"/v1/changes", "/v1/changes/" + a.ID, "/v1/changes/" + a.ID + "/consume", "/v1/changes/" + a.ID + "/result"} {
				if request(false, method, target, `{}`, "").Code != 404 {
					t.Fatal("public admin route accessible")
				}
			}
		}
		w := httptest.NewRecorder()
		h.AdminHandler().ServeHTTP(w, httptest.NewRequest("GET", "/v1/changes/"+a.ID, nil))
		if w.Code != 401 {
			t.Fatal("admin authentication not required")
		}
	})
	t.Run("11_no_secret_in_journal_audit_responses", func(t *testing.T) {
		if audit.Close() != nil {
			t.Fatal("audit flush failed")
		}
		combined := append(independentJournalBytes(t, path), auditBytes.Bytes()...)
		combined = append(combined, request(true, "GET", "/v1/changes/"+a.ID, "", "").Body.Bytes()...)
		for _, link := range mail.links {
			u, _ := url.Parse(link)
			if bytes.Contains(combined, []byte(u.Query().Get("t"))) {
				t.Fatal("token leaked to durable or management output")
			}
		}
		for _, secret := range []string{adminToken, "SYNTHETIC-MAIL-SECRET"} {
			if bytes.Contains(combined, []byte(secret)) {
				t.Fatal("synthetic secret leaked")
			}
		}
	})
}

func TestIndependentBottleneckChangeDecisionMetadataDoesNotReflectToken(t *testing.T) {
	s, path, now := independentChangeStore(t)
	a, token := independentDeliveredChange(t, s, now, "metadata")
	out, err := s.Decide(a.ID, token, a.Digest, true, "127.0.0.1", "synthetic-agent "+token, now)
	if err != nil {
		t.Fatal("decision with untrusted metadata failed")
	}
	raw, err := json.Marshal(out)
	if err != nil || bytes.Contains(raw, []byte(token)) || bytes.Contains(independentJournalBytes(t, path), []byte(token)) {
		t.Fatal("decision metadata reflected link token")
	}
}
