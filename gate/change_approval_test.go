package gate

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type changeFakeMail struct {
	calls int
	link  string
	fail  bool
}

func (m *changeFakeMail) SendChangeApproval(_ context.Context, owner, summary, link string) error {
	m.calls++
	m.link = link
	if owner != UserAdministrator || !strings.Contains(summary, "digest:") {
		return errors.New("invalid mail")
	}
	if m.fail {
		return errors.New("synthetic secret mail error")
	}
	return nil
}

type changeFixture struct {
	t           *testing.T
	store       *FileChangeStore
	h           *ChangeHandler
	mail        *changeFakeMail
	now         time.Time
	path, admin string
}

func newChangeFixture(t *testing.T) *changeFixture {
	t.Helper()
	dir, e := filepath.EvalSymlinks(t.TempDir())
	if e != nil {
		t.Fatal(e)
	}
	if e = os.Chmod(dir, 0700); e != nil {
		t.Fatal(e)
	}
	f := &changeFixture{t: t, path: filepath.Join(dir, "changes.jsonl"), now: time.Date(2026, 10, 2, 12, 0, 0, 0, time.UTC), admin: strings.Repeat("A", 40), mail: &changeFakeMail{}}
	f.store, e = OpenFileChangeStore(f.path, 20)
	if e != nil {
		t.Fatal(e)
	}
	t.Cleanup(func() { f.store.Close() })
	f.h, e = NewChangeHandler(ChangeConfig{Store: f.store, Mailer: f.mail, BaseURL: "https://lic.example", OwnerEmail: UserAdministrator, AdminToken: f.admin, Clock: func() time.Time { return f.now }})
	if e != nil {
		t.Fatal(e)
	}
	return f
}
func changeTestInput() ChangeInput {
	return ChangeInput{Requester: "operator", Kind: "deploy", Target: "synthetic-host", Manifest: "digest-pinned synthetic deployment", BaseState: "not running", Impact: "loopback only", Cost: "zero fixture", Recovery: "stop fixture", ClientID: "fixture-1"}
}
func (f *changeFixture) request(admin bool, method, path string, body []byte) *httptest.ResponseRecorder {
	f.t.Helper()
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	if admin {
		r.Header.Set("Authorization", "Bearer "+f.admin)
		r.Header.Set("Content-Type", "application/json")
	} else {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	w := httptest.NewRecorder()
	h := f.h.PublicHandler()
	if admin {
		h = f.h.AdminHandler()
	}
	h.ServeHTTP(w, r)
	return w
}
func (f *changeFixture) begin(in ChangeInput) ChangeApproval {
	raw, _ := json.Marshal(in)
	w := f.request(true, "POST", "/v1/changes", raw)
	if w.Code != 202 {
		f.t.Fatalf("begin %d %s", w.Code, w.Body)
	}
	var a ChangeApproval
	if json.Unmarshal(w.Body.Bytes(), &a) != nil {
		f.t.Fatal("decode")
	}
	return a
}
func (f *changeFixture) form(a ChangeApproval) url.Values {
	u, _ := url.Parse(f.mail.link)
	return url.Values{"id": {a.ID}, "t": {u.Query().Get("t")}, "digest": {a.Digest}, "decision": {"approve"}}
}
func (f *changeFixture) decide(v url.Values) *httptest.ResponseRecorder {
	return f.request(false, "POST", "/change/approve", []byte(v.Encode()))
}

func TestChangeApprovalThirteen(t *testing.T) {
	t.Run("01_get_head_no_mutation", func(t *testing.T) {
		f := newChangeFixture(t)
		a := f.begin(changeTestInput())
		before, _ := os.ReadFile(f.path)
		for _, m := range []string{"GET", "HEAD", "GET"} {
			w := f.request(false, m, f.mail.link, nil)
			if w.Code != 200 {
				t.Fatal(w.Code)
			}
			if m == "HEAD" && w.Body.Len() != 0 {
				t.Fatal("HEAD body")
			}
		}
		after, _ := os.ReadFile(f.path)
		got, _ := f.store.Get(a.ID, f.now)
		if !bytes.Equal(before, after) || got.Status != "pending" {
			t.Fatal("GET mutated")
		}
	})
	t.Run("02_forged_cross_token", func(t *testing.T) {
		f := newChangeFixture(t)
		a := f.begin(changeTestInput())
		v := f.form(a)
		in := changeTestInput()
		in.ClientID = "second"
		b := f.begin(in)
		cross := f.form(b)
		v.Set("t", cross.Get("t"))
		if f.decide(v).Code != 404 {
			t.Fatal("cross accepted")
		}
		v.Set("t", strings.Repeat("x", 68))
		if f.decide(v).Code != 404 {
			t.Fatal("forgery accepted")
		}
	})
	t.Run("03_expired_post", func(t *testing.T) {
		f := newChangeFixture(t)
		a := f.begin(changeTestInput())
		v := f.form(a)
		before, _ := os.ReadFile(f.path)
		f.now = f.now.Add(time.Hour)
		if f.decide(v).Code != 409 {
			t.Fatal("expired accepted")
		}
		after, _ := os.ReadFile(f.path)
		if !bytes.Equal(before, after) {
			t.Fatal("mutated")
		}
	})
	t.Run("04_first_decision_wins", func(t *testing.T) {
		for _, decision := range []string{"approve", "deny"} {
			f := newChangeFixture(t)
			a := f.begin(changeTestInput())
			v := f.form(a)
			v.Set("decision", decision)
			if f.decide(v).Code != 200 {
				t.Fatal("first")
			}
			v.Set("decision", "approve")
			if f.decide(v).Code != 409 {
				t.Fatal("second")
			}
			w := f.request(false, "GET", f.mail.link, nil)
			if w.Code != 200 {
				t.Fatal("revisit")
			}
		}
	})
	t.Run("05_digest_manifest_binding", func(t *testing.T) {
		f := newChangeFixture(t)
		a := f.begin(changeTestInput())
		v := f.form(a)
		v.Set("digest", strings.Repeat("0", 64))
		if f.decide(v).Code != 409 {
			t.Fatal("digest")
		}
		v.Set("digest", a.Digest)
		if f.decide(v).Code != 200 {
			t.Fatal("approve")
		}
		if _, e := f.store.Consume(a.ID, a.Manifest+"changed", f.now); e != ErrChangeConflict {
			t.Fatal(e)
		}
	})
	t.Run("06_consume_single_use", func(t *testing.T) {
		for _, state := range []string{"pending", "denied", "expired", "approved"} {
			f := newChangeFixture(t)
			a := f.begin(changeTestInput())
			v := f.form(a)
			if state != "pending" {
				if state == "denied" {
					v.Set("decision", "deny")
				}
				f.decide(v)
			}
			if state == "expired" {
				f.now = f.now.Add(time.Hour)
			}
			_, e := f.store.Consume(a.ID, a.Manifest, f.now)
			if state == "approved" {
				if e != nil {
					t.Fatal(e)
				}
				if _, e = f.store.Consume(a.ID, a.Manifest, f.now); e != ErrChangeConflict {
					t.Fatal("reused")
				}
			} else if e != ErrChangeConflict {
				t.Fatal(state, e)
			}
		}
	})
	t.Run("07_origin_decision", func(t *testing.T) {
		f := newChangeFixture(t)
		a := f.begin(changeTestInput())
		v := f.form(a)
		r := httptest.NewRequest("POST", "/change/approve", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", "https://evil.example")
		w := httptest.NewRecorder()
		f.h.PublicHandler().ServeHTTP(w, r)
		if w.Code != 403 {
			t.Fatal(w.Code)
		}
		v.Add("decision", "deny")
		if f.decide(v).Code != 400 {
			t.Fatal("duplicate")
		}
		v.Del("decision")
		if f.decide(v).Code != 400 {
			t.Fatal("missing")
		}
	})
	t.Run("08_mail_failed_closed", func(t *testing.T) {
		f := newChangeFixture(t)
		f.mail.fail = true
		in := changeTestInput()
		raw, _ := json.Marshal(in)
		w := f.request(true, "POST", "/v1/changes", raw)
		if w.Code != 502 || strings.Contains(w.Body.String(), "secret") {
			t.Fatal(w.Code)
		}
		a := f.begin(in)
		if a.Status != "failed" || f.mail.calls != 1 {
			t.Fatal(a.Status, f.mail.calls)
		}
		if f.decide(f.form(a)).Code != 404 {
			t.Fatal("failed link")
		}
	})
	t.Run("09_idempotency", func(t *testing.T) {
		f := newChangeFixture(t)
		in := changeTestInput()
		a := f.begin(in)
		b := f.begin(in)
		if a.ID != b.ID || f.mail.calls != 1 {
			t.Fatal("duplicate")
		}
		in.Manifest += "changed"
		raw, _ := json.Marshal(in)
		if f.request(true, "POST", "/v1/changes", raw).Code != 409 || f.mail.calls != 1 {
			t.Fatal("conflict")
		}
	})
	t.Run("10_restart_recovery", func(t *testing.T) {
		f := newChangeFixture(t)
		a := f.begin(changeTestInput())
		if f.decide(f.form(a)).Code != 200 {
			t.Fatal("approve")
		}
		f.store.Consume(a.ID, a.Manifest, f.now)
		f.store.Result(a.ID, "succeeded", f.now)
		f.store.Close()
		s, e := OpenFileChangeStore(f.path, 20)
		if e != nil {
			t.Fatal(e)
		}
		defer s.Close()
		b, e := s.Get(a.ID, f.now)
		if e != nil || b.Status != "consumed" || b.Result != "succeeded" {
			t.Fatal(b, e)
		}
	})
	t.Run("11_no_token_reflection", func(t *testing.T) {
		f := newChangeFixture(t)
		a := f.begin(changeTestInput())
		v := f.form(a)
		token := v.Get("t")
		for _, w := range []*httptest.ResponseRecorder{f.request(false, "GET", f.mail.link, nil), f.request(false, "GET", "/change/decision.js", nil), f.request(true, "GET", "/v1/changes/"+a.ID, nil)} {
			if strings.Contains(w.Body.String()+fmtHeader(w), token) || strings.Contains(w.Body.String()+fmtHeader(w), f.admin) {
				t.Fatal("response secret")
			}
		}
		r := httptest.NewRequest("POST", "/change/approve", strings.NewReader(v.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("User-Agent", token+f.admin)
		w := httptest.NewRecorder()
		f.h.PublicHandler().ServeHTTP(w, r)
		raw, _ := os.ReadFile(f.path)
		if bytes.Contains(raw, []byte(token)) || bytes.Contains(raw, []byte(f.admin)) || strings.Contains(w.Body.String(), token) || strings.Contains(w.Body.String(), f.admin) {
			t.Fatal("persisted/reflected")
		}
		info, _ := os.Stat(f.path)
		if info.Mode().Perm() != 0600 {
			t.Fatal("mode")
		}
	})
	t.Run("12_public_admin_separation", func(t *testing.T) {
		f := newChangeFixture(t)
		for _, path := range []string{"/v1/changes", "/v1/changes/id", "/v1/changes/id/consume", "/v1/changes/id/result"} {
			for _, method := range []string{"GET", "POST"} {
				if f.request(false, method, path, nil).Code != 404 {
					t.Fatal(path)
				}
			}
		}
		r := httptest.NewRequest("POST", "/v1/changes", nil)
		w := httptest.NewRecorder()
		f.h.AdminHandler().ServeHTTP(w, r)
		if w.Code != 401 {
			t.Fatal(w.Code)
		}
	})
	t.Run("13_concurrent_decision", func(t *testing.T) {
		f := newChangeFixture(t)
		a := f.begin(changeTestInput())
		body := []byte(f.form(a).Encode())
		codes := make(chan int, 2)
		var wg sync.WaitGroup
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() { defer wg.Done(); codes <- f.request(false, "POST", "/change/approve", body).Code }()
		}
		wg.Wait()
		close(codes)
		counts := map[int]int{}
		for c := range codes {
			counts[c]++
		}
		if counts[200] != 1 || counts[409] != 1 {
			t.Fatal(counts)
		}
	})
}
func fmtHeader(w *httptest.ResponseRecorder) string {
	var b strings.Builder
	_ = w.Header().Write(&b)
	return b.String()
}
func TestChangeJournalSafety(t *testing.T) {
	f := newChangeFixture(t)
	if s, e := OpenFileChangeStore(f.path, 20); e == nil {
		s.Close()
		t.Fatal("second owner")
	}
	in := changeTestInput()
	a, _, e := f.store.Begin(in, f.now)
	if e != nil {
		t.Fatal(e)
	}
	f.store.Close()
	s, e := OpenFileChangeStore(f.path, 20)
	if e != nil {
		t.Fatal(e)
	}
	got, _ := s.Get(a.ID, f.now)
	if got.Status != "failed" {
		t.Fatal("uncertain delivery resurrected")
	}
	s.Close()
	file, e := os.OpenFile(f.path, os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		t.Fatal(e)
	}
	file.WriteString("{torn")
	file.Close()
	if s, e := OpenFileChangeStore(f.path, 20); e == nil {
		s.Close()
		t.Fatal("torn tail accepted")
	}
}
